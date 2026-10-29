"""Manual synchronization use case: target one employee or user.

Resolves an operator-specified person or user across configured identity sources,
evaluates directory state against gateway access and policy mappings, and
transactionally enqueues an immediate corrective event into the outbox.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from uuid import uuid4

import structlog

from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.models import (
    ACTIVE,
    INACTIVE,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceGroup,
)
from identity_lifecycle.domain.policy import (
    AccessDecision,
    DecisionOutcome,
    DesiredAccess,
    GroupMapping,
    decide_access,
    desired_access,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.gateway import Gateway
from identity_lifecycle.ports.identity_source import IdentitySource, IdentityUser

logger = structlog.get_logger(__name__)


class NotFoundError(PermanentError):
    """The requested user or employee was not found in directory sources or local state."""


class AmbiguousLinkError(PermanentError):
    """The specified employee number matches multiple persons or directory objects."""


@dataclass(frozen=True)
class ManualSyncResult:
    """The outcome of one manual synchronization evaluation."""

    person_id: str
    source: str
    source_user_id: str
    employee_number: str | None
    event_enqueued: CanonicalEvent
    decision: AccessDecision
    desired: DesiredAccess


class ManualSync:
    """Evaluate target directory identity and enqueue corrective outbox event."""

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWorkFactory,
        gateway: Gateway,
        identity_sources: Mapping[str, IdentitySource],
        clock: Clock,
        group_mappings: Sequence[GroupMapping],
        enabled_sources: frozenset[str],
    ) -> None:
        self._unit_of_work = unit_of_work
        self._gateway = gateway
        self._identity_sources = identity_sources
        self._clock = clock
        self._group_mappings = tuple(group_mappings)
        self._enabled_sources = enabled_sources

    def sync(
        self,
        *,
        employee_number: str | None = None,
        source_user_id: str | None = None,
    ) -> ManualSyncResult:
        """Resolve person, evaluate access against gateway, and enqueue outbox event."""
        if (employee_number is None and source_user_id is None) or (
            employee_number is not None and source_user_id is not None
        ):
            raise ValueError("Provide exactly one of employee_number or source_user_id")

        if employee_number is not None:
            source_name, user, resolved_person_id = self._locate_by_employee_number(employee_number)
        else:
            assert source_user_id is not None
            source_name, user, resolved_person_id = self._locate_by_source_user_id(source_user_id)

        target_source_uid = (
            user.source_user_id
            if user is not None
            else (source_user_id or (resolved_person_id if resolved_person_id else ""))
        )

        with self._unit_of_work(source_name) as uow:
            identity = uow.identities.find(source_name, target_source_uid)
            stored_person = (
                uow.persons.get(identity.person_id)
                if identity is not None
                else (uow.persons.get(resolved_person_id) if resolved_person_id else None)
            )

            if stored_person is None and user is not None and user.employee_number is not None:
                matches = uow.persons.find_all_by_employee_number(user.employee_number)
                if len(matches) == 1:
                    stored_person = matches[0]
                elif len(matches) > 1:
                    raise AmbiguousLinkError(
                        f"ambiguous employee_number={user.employee_number!r}: "
                        "matches multiple stored persons"
                    )

            if stored_person is not None:
                person_id = stored_person.person_id
                person_emp = stored_person.employee_number if user is None else user.employee_number
                person_email = stored_person.email if user is None else user.email
                person_name = stored_person.display_name if user is None else user.display_name
                person_status = INACTIVE if (user is None or not user.enabled) else ACTIVE
                person = Person(
                    person_id=person_id,
                    employee_number=person_emp,
                    email=person_email,
                    display_name=person_name,
                    status=person_status,
                )
            else:
                if user is None:
                    raise NotFoundError(
                        f"user {target_source_uid!r} has no stored person and is not in directory"
                    )
                person = Person(
                    person_id=str(uuid4()),
                    employee_number=user.employee_number,
                    email=user.email,
                    display_name=user.display_name,
                    status=ACTIVE if user.enabled else INACTIVE,
                )

            account = uow.accounts.get(person.person_id)
            if account is None:
                gw_account = self._gateway.get_user(user_id=person.person_id)
                if gw_account is not None:
                    account = LiteLLMAccount(
                        user_id=gw_account.user_id,
                        status=gw_account.status,
                        role=gw_account.role,
                        team=gw_account.team,
                        budget=gw_account.budget,
                        keys=gw_account.keys,
                    )

            previous = uow.entitlements.current_for(person.person_id)
            source = self._identity_sources[source_name]
            memberships = self._read_user_memberships(source, user)
            decision = decide_access(self._group_mappings, memberships, self._enabled_sources)
            desired = desired_access(
                decision=decision,
                person=person,
                account=account,
                previous=previous,
            )

            event = self._build_corrective_event(
                source_name=source_name,
                source_user_id=target_source_uid,
                user=user,
                person=person,
                decision=decision,
                account=account,
                previous=previous,
            )

            uow.outbox.enqueue(event)
            uow.commit()

        logger.info(
            "manual_sync_enqueued",
            source=source_name,
            source_user_id=target_source_uid,
            person_id=person.person_id,
            event_type=event.type.value,
            event_id=str(event.event_id),
        )

        return ManualSyncResult(
            person_id=person.person_id,
            source=source_name,
            source_user_id=target_source_uid,
            employee_number=person.employee_number,
            event_enqueued=event,
            decision=decision,
            desired=desired,
        )

    def _locate_by_employee_number(
        self, employee_number: str
    ) -> tuple[str, IdentityUser | None, str | None]:
        dir_matches: list[tuple[str, IdentityUser]] = []
        for source_name in sorted(self._enabled_sources):
            source = self._identity_sources.get(source_name)
            if source is None:
                continue
            cursor: str | None = None
            while True:
                page = source.list_users(cursor)
                for item in page.items:
                    if item.employee_number == employee_number:
                        dir_matches.append((source_name, item))
                if page.next_cursor is None:
                    break
                cursor = page.next_cursor

        if len(dir_matches) > 1:
            uids = tuple(f"{s}:{u.source_user_id}" for s, u in dir_matches)
            raise AmbiguousLinkError(
                f"ambiguous employee_number={employee_number!r}: "
                f"matches multiple directory users: {uids}"
            )

        stored_matches: list[tuple[str, str]] = []
        for source_name in sorted(self._enabled_sources):
            with self._unit_of_work(source_name) as uow:
                persons = uow.persons.find_all_by_employee_number(employee_number)
                for p in persons:
                    stored_matches.append((source_name, p.person_id))

        unique_person_ids = {pid for _, pid in stored_matches}
        if len(unique_person_ids) > 1:
            sorted_pids = tuple(sorted(unique_person_ids))
            raise AmbiguousLinkError(
                f"ambiguous employee_number={employee_number!r}: "
                f"matches multiple stored persons: {sorted_pids}"
            )

        if not dir_matches and not stored_matches:
            raise NotFoundError(f"no person found matching employee_number={employee_number!r}")

        if dir_matches:
            src, user = dir_matches[0]
            pid = next(iter(unique_person_ids)) if unique_person_ids else None
            return src, user, pid

        src, pid = stored_matches[0]
        return src, None, pid

    def _locate_by_source_user_id(
        self, source_user_id: str
    ) -> tuple[str, IdentityUser | None, str | None]:
        dir_matches: list[tuple[str, IdentityUser]] = []
        for source_name in sorted(self._enabled_sources):
            source = self._identity_sources.get(source_name)
            if source is None:
                continue
            user = source.get_user(source_user_id)
            if user is not None:
                dir_matches.append((source_name, user))

        if len(dir_matches) > 1:
            matched_sources = tuple(s for s, _ in dir_matches)
            raise AmbiguousLinkError(
                f"ambiguous source_user_id={source_user_id!r}: "
                f"matches across multiple sources: {matched_sources}"
            )

        if dir_matches:
            src, user = dir_matches[0]
            return src, user, None

        stored: list[tuple[str, str]] = []
        for source_name in sorted(self._enabled_sources):
            with self._unit_of_work(source_name) as uow:
                ident = uow.identities.find(source_name, source_user_id)
                if ident is not None:
                    stored.append((source_name, ident.person_id))

        if not stored:
            raise NotFoundError(f"no user found matching source_user_id={source_user_id!r}")

        if len(stored) > 1:
            stored_sources = tuple(s for s, _ in stored)
            raise AmbiguousLinkError(
                f"ambiguous source_user_id={source_user_id!r}: "
                f"linked across multiple sources: {stored_sources}"
            )

        src, pid = stored[0]
        return src, None, pid

    def _read_user_memberships(
        self, source: IdentitySource, user: IdentityUser | None
    ) -> tuple[SourceGroup, ...]:
        if user is None or not user.enabled:
            return ()
        held: list[SourceGroup] = []
        for mapping in self._group_mappings:
            if mapping.source != source.name() or not mapping.enabled:
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

    def _build_corrective_event(
        self,
        *,
        source_name: str,
        source_user_id: str,
        user: IdentityUser | None,
        person: Person,
        decision: AccessDecision,
        account: LiteLLMAccount | None,
        previous: Entitlement | None,
    ) -> CanonicalEvent:
        now = self._clock.now()
        event_id = uuid4()
        source_event_id = f"manual-sync-{uuid4()}"

        if user is None:
            return CanonicalEvent(
                event_id=event_id,
                source=source_name,
                source_event_id=source_event_id,
                type=EventType.USER_DELETED,
                occurred_at=now,
                person=EventPerson(
                    source_user_id=source_user_id,
                    employee_number=person.employee_number,
                ),
                group=None,
            )

        if not user.enabled:
            return CanonicalEvent(
                event_id=event_id,
                source=source_name,
                source_event_id=source_event_id,
                type=EventType.USER_DISABLED,
                occurred_at=now,
                person=EventPerson(
                    source_user_id=source_user_id,
                    employee_number=user.employee_number,
                ),
                group=None,
            )

        if decision.outcome is DecisionOutcome.GRANTED and decision.selected is not None:
            return CanonicalEvent(
                event_id=event_id,
                source=source_name,
                source_event_id=source_event_id,
                type=EventType.GROUP_MEMBER_ADDED,
                occurred_at=now,
                person=EventPerson(
                    source_user_id=source_user_id,
                    employee_number=user.employee_number,
                ),
                group=EventGroup(
                    source_group_id=decision.selected.source_group_id,
                    name="",
                ),
            )

        team = (
            (previous.team if previous else None)
            or (account.team if account else None)
            or "unentitled"
        )
        return CanonicalEvent(
            event_id=event_id,
            source=source_name,
            source_event_id=source_event_id,
            type=EventType.GROUP_MEMBER_REMOVED,
            occurred_at=now,
            person=EventPerson(
                source_user_id=source_user_id,
                employee_number=user.employee_number,
            ),
            group=EventGroup(
                source_group_id=team,
                name="",
            ),
        )
