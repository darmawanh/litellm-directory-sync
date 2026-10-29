"""The process use case: one event, one decision, one transaction.

The order is design 9.1's processing rules 1-7, and each step is visible below:

1. **Deduplicate** on ``event_id`` through ``processed_events``. A replay is
   ``DONE`` with no effect.
2. **Re-read the source.** The event is a trigger, not the truth, so the
   person, the email, the enabled flag and the memberships come from
   ``IdentitySource`` reads made now, never from the envelope.
3. **Recompute** with ``domain/policy.py``: ``decide_access`` over the
   memberships just read, then ``desired_access`` over that decision and the
   stored account.
4. **Apply** through ``Gateway``, which returns the account it read back, so a
   2xx is never mistaken for an effect.
5. **Write the audit row** in the same transaction as the state change (FR14,
   ER6).
6. **Mark processed** in that same transaction.
7. **Settle** in a second, short transaction, because the claim already
   committed.

The unit of work is a factory taking the event's source: ``audit_events.source``
is not a field of ``AuditEvent`` and the store takes it at construction
 (``adapters/persistence/access.py``). The factory is wiring, not a port method.

Two readings are recorded rather than left to the diff:

- **A tie commits its audit row and then raises.** ADR-003 section 3 makes the
  failure auditable before the event dies, so the row is written, committed, and
  only then does ``EqualPrecedenceError`` reach ``process`` and settle the outbox
  row ``PERMANENT``. No gateway call happens on that path.
- **An ambiguous link is a second audit row.** ADR-018 section 1 forbids
  unifying through a duplicated ``employee_number`` and requires the ambiguity to
  be recorded; ``AuditEvent`` has one free-text ``reason``, so the record is its
  own row with ``decision="ambiguous_link"`` rather than a suffix on the
  decision's fixed vocabulary. The object is still provisioned as its own
  person.

Budget resolution is design 10.7's four levels. The person and group override
tables are read in a later phase, so this use case passes ``None`` for the two
overrides and resolves the group's ``budget_mappings`` rule or the default. The
resolution's ``reason`` is the audit vocabulary D-115 fixes, and the policy's
name is what the entitlement stores.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import structlog

from identity_lifecycle.application.event_effects import (
    ambiguous_record,
    apply_access,
    audit_record,
    budget_for,
    policy_name,
    required,
)
from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import (
    ACTIVE,
    INACTIVE,
    AuditEvent,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceGroup,
    SourceIdentity,
)
from identity_lifecycle.domain.policy import (
    AccessAction,
    AccessDecision,
    BudgetPolicy,
    DecisionOutcome,
    DesiredAccess,
    EqualPrecedenceError,
    GroupMapping,
    decide_access,
    desired_access,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.gateway import Gateway
from identity_lifecycle.ports.identity_source import IdentitySource, IdentityUser
from identity_lifecycle.ports.unit_of_work import Settlement, UnitOfWork

logger = structlog.get_logger(__name__)


class ProcessEvent:
    """Apply one claimed event, then settle it."""

    def __init__(
        self,
        unit_of_work: UnitOfWorkFactory,
        gateway: Gateway,
        identity_sources: Mapping[str, IdentitySource],
        *,
        group_mappings: Sequence[GroupMapping],
        team_create_if_missing: Mapping[str, bool],
        budget_policies: Mapping[str, BudgetPolicy],
        group_budget_policies: Mapping[tuple[str, str], str],
        default_budget_policy: str,
        enabled_sources: frozenset[str],
        clock: Clock,
        grace_period_hours: int = 24,
        on_equal_precedence: Callable[[str], None] | None = None,
        on_revocation: Callable[[str, float], None] | None = None,
        on_processed: Callable[[str, str, str, float], None] | None = None,
    ) -> None:
        self._unit_of_work = unit_of_work
        self._gateway = gateway
        self._identity_sources = identity_sources
        self._group_mappings = tuple(group_mappings)
        self._team_create_if_missing = team_create_if_missing
        self._budget_policies = budget_policies
        self._group_budget_policies = group_budget_policies
        self._default_budget_policy = default_budget_policy
        self._enabled_sources = enabled_sources
        self._clock = clock
        self._grace_period_hours = max(0, grace_period_hours)
        self._on_equal_precedence = on_equal_precedence
        self._on_revocation = on_revocation
        self._on_processed = on_processed

    # the use case

    def process(self, event: CanonicalEvent) -> Settlement:
        """Apply ``event`` and settle it; return which of the three paths ran."""
        if event.source not in self._enabled_sources:
            # FR32: a disabled source's rows are still in the table after a
            # restart. Retrying them would spin, so the row dies with a reason.
            logger.warning("event_source_disabled", event_id=str(event.event_id))
            self._settle(event, Settlement.PERMANENT)
            return Settlement.PERMANENT
        start_time = time.monotonic()
        action: AccessAction | None = None
        try:
            action = self._apply(event)
        except EqualPrecedenceError as error:
            if self._on_equal_precedence is not None:
                self._on_equal_precedence(event.source)
            logger.warning(
                "event_failed_permanently",
                event_id=str(event.event_id),
                error=type(error).__name__,
            )
            self._settle(event, Settlement.PERMANENT)
            return Settlement.PERMANENT
        except PermanentError as error:
            logger.warning(
                "event_failed_permanently",
                event_id=str(event.event_id),
                error=type(error).__name__,
            )
            self._settle(event, Settlement.PERMANENT)
            return Settlement.PERMANENT
        except RetryableError as error:
            logger.info(
                "event_failed_retryably",
                event_id=str(event.event_id),
                error=type(error).__name__,
            )
            self._settle(event, Settlement.RETRYABLE)
            return Settlement.RETRYABLE
        self._settle(event, Settlement.DONE)
        if self._on_processed is not None:
            self._on_processed(
                event.source,
                action.value if action is not None else "none",
                "done",
                time.monotonic() - start_time,
            )
        return Settlement.DONE

    # the transaction

    def _apply(self, event: CanonicalEvent) -> AccessAction | None:
        # A replay has already had its effect committed. Check before reaching
        # out to the identity source so it is acknowledged without depending on
        # source availability. The check inside the write transaction below is
        # still required to close the race with another worker processing the
        # same event concurrently.
        with self._unit_of_work(event.source) as uow:
            if uow.processed_events.is_processed(event.event_id):
                logger.info("event_already_processed", event_id=str(event.event_id))
                return None

        if event.person is None:
            # A group-only event (``group.updated``) names nobody to provision.
            with self._unit_of_work(event.source) as uow:
                uow.processed_events.mark_processed(event.event_id)
                uow.commit()
            return None

        source = self._identity_sources.get(event.source)
        if source is None:
            # No adapter is wired for this source.
            # A bare ``KeyError`` would escape the typed-error contract.
            raise PermanentError(f"no identity source adapter is wired for source {event.source!r}")
        user = source.get_user(event.person.source_user_id)
        tie: AccessDecision | None = None
        desired_action: AccessAction | None = None
        with self._unit_of_work(event.source) as uow:
            if uow.processed_events.is_processed(event.event_id):
                logger.info("event_already_processed", event_id=str(event.event_id))
                return None
            identity = uow.identities.find(event.source, event.person.source_user_id)
            if user is None and identity is None:
                # The source no longer has the object and nothing was ever
                # resolved: there is no account to revoke (not an error).
                uow.processed_events.mark_processed(event.event_id)
                uow.commit()
                return None

            person, ambiguous = self._person_for(uow, event, user, identity)
            account = uow.accounts.get(person.person_id)
            previous = uow.entitlements.current_for(person.person_id)
            decision = decide_access(
                self._group_mappings,
                self._memberships(source, event, user),
                self._enabled_sources,
            )
            desired = desired_access(
                decision=decision, person=person, account=account, previous=previous
            )
            desired_action = desired.action
            refreshed_person = self._refreshed(person, user)
            uow.persons.save(refreshed_person)
            uow.identities.save(
                SourceIdentity(
                    source=event.source,
                    source_user_id=event.person.source_user_id,
                    person_id=person.person_id,
                )
            )
            if ambiguous:
                uow.audit.append(ambiguous_record(event, target=person.person_id, now=self._now()))

            if decision.outcome is DecisionOutcome.FAILED:
                uow.audit.append(self._audit(event, person.person_id, desired, decision))
                uow.processed_events.mark_processed(event.event_id)
                uow.commit()
                tie = decision
            else:
                applied = apply_access(
                    gateway=self._gateway,
                    desired=desired,
                    person=refreshed_person,
                    account=account,
                    budget=self._budget(decision),
                    team_create_if_missing=self._team_create_if_missing,
                )
                self._save_decision(uow, event, refreshed_person, applied, desired, decision)
                uow.audit.append(self._audit(event, person.person_id, desired, decision))
                uow.processed_events.mark_processed(event.event_id)
                uow.commit()
                if desired.action is AccessAction.REVOKE:
                    occurred = event.occurred_at
                    if occurred.tzinfo is None:
                        occurred = occurred.replace(tzinfo=UTC)
                    now = self._now()
                    if now.tzinfo is None:
                        now = now.replace(tzinfo=UTC)
                    diff = (now - occurred).total_seconds()
                    if self._on_revocation is not None:
                        self._on_revocation(event.source, diff)
        if tie is not None:
            # the row is audited and committed, then the event
            # fails permanently. ``process`` settles it ``PERMANENT``.
            raise EqualPrecedenceError(tie)
        return desired_action

    # resolution

    def _person_for(
        self,
        uow: UnitOfWork,
        event: CanonicalEvent,
        user: IdentityUser | None,
        identity: SourceIdentity | None,
    ) -> tuple[Person, bool]:
        """Return the person this object resolves to, and whether the link was ambiguous."""
        if identity is not None:
            stored = uow.persons.get(identity.person_id)
            if stored is not None:
                return self._refreshed(stored, user, preserve_inactive=True), False
        employee_number = None if user is None else user.employee_number
        if employee_number is None and event.person is not None:
            employee_number = event.person.employee_number
        if employee_number is not None:
            matches = uow.persons.find_all_by_employee_number(employee_number)
            if len(matches) == 1:
                return self._refreshed(matches[0], user, preserve_inactive=True), False
            if len(matches) > 1:
                # never unify, never guess, never fail.
                return self._new_person(event, user), True
        return self._new_person(event, user), False

    def _new_person(self, event: CanonicalEvent, user: IdentityUser | None) -> Person:
        if user is None:
            # An identity row pointing at a missing person, with no source user
            # to rebuild it from, is schema drift; retrying reads the same bytes.
            source_user_id = "" if event.person is None else event.person.source_user_id
            raise PermanentError(
                f"source identity {event.source}:{source_user_id} "
                "names no person row and the source no longer has the user"
            )
        return Person(
            person_id=str(uuid4()),
            employee_number=user.employee_number,
            email=user.email,
            display_name=user.display_name,
            status=ACTIVE if user.enabled else INACTIVE,
        )

    def _refreshed(
        self, person: Person, user: IdentityUser | None, *, preserve_inactive: bool = False
    ) -> Person:
        """Carry the source's current facts onto the stored person, keeping its id."""
        if user is None:
            return person
        status = (
            INACTIVE
            if (preserve_inactive and person.status == INACTIVE and user.enabled)
            else (ACTIVE if user.enabled else INACTIVE)
        )
        return Person(
            person_id=person.person_id,
            employee_number=user.employee_number,
            email=user.email,
            display_name=user.display_name,
            status=status,
        )

    def _memberships(
        self, source: IdentitySource, event: CanonicalEvent, user: IdentityUser | None
    ) -> tuple[SourceGroup, ...]:
        """Read this user's mapped groups from the source, paging through each group.

                A disabled user is not entitled, and the source no longer having
                the user is the deletion case: both answer "no membership" without a
                read. A read failure propagates as a retry, never as an empty group
        .
        """
        if user is None or not user.enabled:
            return ()
        held: list[SourceGroup] = []
        for mapping in self._group_mappings:
            if mapping.source != event.source or not mapping.enabled:
                continue
            cursor: str | None = None
            is_member = False
            while True:
                page = source.get_group_members(mapping.source_group_id, cursor)
                if any(member.source_user_id == user.source_user_id for member in page.items):
                    is_member = True
                    break
                if page.next_cursor is None:
                    break
                cursor = page.next_cursor
            if is_member:
                held.append(
                    SourceGroup(
                        source=mapping.source,
                        source_group_id=mapping.source_group_id,
                        name=mapping.source_group_id,
                    )
                )
        return tuple(held)

    # the records

    def _budget(self, decision: AccessDecision) -> BudgetPolicy:
        """Resolve the budget policy's order, as far as it is read here."""
        return budget_for(
            decision,
            group_budget_policies=self._group_budget_policies,
            budget_policies=self._budget_policies,
            default_policy_name=self._default_budget_policy,
        )

    def _save_decision(
        self,
        uow: UnitOfWork,
        event: CanonicalEvent,
        person: Person,
        account: LiteLLMAccount | None,
        desired: DesiredAccess,
        decision: AccessDecision,
    ) -> None:
        """Store the account as read back, and the entitlement the decision granted.

        The entitlement is written only for the three actions that write the
        gateway, and it is written after the gateway returned. A ``NO_CHANGE``
        carries no role or team by construction, and the account already holds
        the decision's values, so the entitlement in force is already the right
        one: writing a second row would close it and reopen an identical one on
        every repeated event. A ``REVOKE`` closes access and
        grants nothing.
        """
        if account is not None:
            delete_after: datetime | None = None
            if desired.action is AccessAction.REVOKE:
                delete_after = self._now() + timedelta(hours=self._grace_period_hours)
            elif desired.action is AccessAction.NO_CHANGE:
                delete_after = uow.accounts.get_delete_after(account.user_id)
            else:
                delete_after = None
            uow.accounts.save(account, delete_after=delete_after)
        granted = decision.outcome is DecisionOutcome.GRANTED
        writes = desired.action in (
            AccessAction.CREATE,
            AccessAction.UPDATE,
            AccessAction.REACTIVATE,
        )
        if granted and writes:
            uow.entitlements.save(
                Entitlement(
                    person_id=person.person_id,
                    role=required(desired.role, "role", desired),
                    team=required(desired.team, "team", desired),
                    budget_policy=policy_name(
                        decision,
                        group_budget_policies=self._group_budget_policies,
                        default_policy_name=self._default_budget_policy,
                    ),
                    source=event.source,
                    effective_from=self._now(),
                    effective_to=None,
                )
            )

    def _audit(
        self,
        event: CanonicalEvent,
        target: str,
        desired: DesiredAccess,
        decision: AccessDecision,
    ) -> AuditEvent:
        """The decision's audit row."""
        return audit_record(
            event, target=target, desired=desired, decision=decision, now=self._now()
        )

    def _now(self) -> datetime:
        return self._clock.now()

    # settle

    def _settle(self, event: CanonicalEvent, outcome: Settlement) -> None:
        """Record this attempt in its own short transaction."""
        with self._unit_of_work(event.source) as uow:
            uow.outbox.settle(event.event_id, outcome)
            uow.commit()
