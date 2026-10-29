"""The reconciliation use case: periodic directory and gateway state alignment.

Compares the full directory state against current gateway accounts and entitlements,
detecting drift (missing members, disabled accounts, orphan keys, unmapped accounts)
and emitting corrective events to the outbox.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from uuid import uuid4

import structlog

from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.models import AuditEvent, SourceGroup
from identity_lifecycle.domain.policy import (
    DecisionOutcome,
    GroupMapping,
    decide_access,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.gateway import Gateway
from identity_lifecycle.ports.identity_source import IdentitySource, IdentityUser
from identity_lifecycle.ports.unit_of_work import ReconciliationMiss

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ReconciliationDrift:
    """One detected discrepancy between directory truth and gateway enforcement."""

    kind: str
    source: str
    user_id: str
    detail: str


@dataclass(frozen=True)
class DeletionFailure:
    """A failure encountered while attempting to delete a gateway user upon grace-period expiry."""

    user_id: str
    error: str
    error_type: str


@dataclass(frozen=True)
class ReconciliationResult:
    """The outcome of one complete reconciliation pass."""

    drifts: tuple[ReconciliationDrift, ...]
    events_emitted: tuple[CanonicalEvent, ...]
    misses_recorded: tuple[ReconciliationMiss, ...]
    misses_cleared: tuple[str, ...]
    dry_run: bool
    deletion_failures: tuple[DeletionFailure, ...] = ()


def _is_user_already_absent(exc: PermanentError) -> bool:
    """Check if the permanent error indicates the gateway user is already absent (e.g. 404)."""
    msg = str(exc).lower()
    return "not exist" in msg or "not found" in msg or "404" in msg


class Reconcile:
    """Detect directory-to-gateway drift and enqueue corrective outbox events."""

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWorkFactory,
        gateway: Gateway,
        identity_sources: Mapping[str, IdentitySource],
        clock: Clock,
        group_mappings: Sequence[GroupMapping],
        allowlist: Sequence[str] = (),
        two_miss_rule: bool = True,
        dry_run: bool = False,
        batch_size: int = 100,
        grace_period_hours: int = 24,
    ) -> None:
        self._unit_of_work = unit_of_work
        self._gateway = gateway
        self._identity_sources = identity_sources
        self._clock = clock
        self._group_mappings = tuple(group_mappings)
        self._allowlist = frozenset(allowlist)
        self._two_miss_rule = two_miss_rule
        self._dry_run = dry_run
        self._batch_size = max(1, batch_size)
        self._grace_period_hours = max(0, grace_period_hours)

    def reconcile(self, *, dry_run: bool | None = None) -> ReconciliationResult:
        """Execute one full reconciliation pass across all enabled sources."""
        is_dry_run = self._dry_run if dry_run is None else dry_run
        now = self._clock.now()

        all_drifts: list[ReconciliationDrift] = []
        all_events: list[CanonicalEvent] = []
        all_misses: list[ReconciliationMiss] = []
        all_cleared: list[str] = []
        deletion_failures: list[DeletionFailure] = []
        handled_deletions: set[str] = set()

        for source_name, source in self._identity_sources.items():
            dir_users = self._read_all_users(source)
            memberships = self._read_all_group_members(source)

            with self._unit_of_work(source_name) as uow:
                stored_persons = {p.person_id: p for p in uow.persons.list_all()}
                stored_accounts = {a.user_id: a for a in uow.accounts.list_all()}
                source_identities = uow.identities.list_for_source(source_name)

                user_to_person = {i.source_user_id: i.person_id for i in source_identities}
                person_to_user = {i.person_id: i.source_user_id for i in source_identities}

                known_gateway_ids = set(stored_accounts.keys())
                for pid in stored_persons:
                    if pid in person_to_user:
                        known_gateway_ids.add(pid)

                # 1. Process directory users for this source
                for source_user_id, user in dir_users.items():
                    person_id = user_to_person.get(source_user_id)
                    groups = memberships.get(source_user_id, set())

                    account_lookup_id = person_id or source_user_id
                    gw_account = self._gateway.get_user(user_id=account_lookup_id)

                    is_entitled = user.enabled and bool(groups)

                    if is_entitled:
                        if person_id is not None:
                            uow.misses.clear(person_id, source_name)
                            all_cleared.append(person_id)

                        if gw_account is None or gw_account.status != "active":
                            winning_group_id = self._winning_group_id(source_name, groups)
                            drift = ReconciliationDrift(
                                kind="missing_preprovisioned_member",
                                source=source_name,
                                user_id=source_user_id,
                                detail=(
                                    f"entitled user missing from gateway "
                                    f"(group {winning_group_id})"
                                ),
                            )
                            all_drifts.append(drift)
                            event = CanonicalEvent(
                                event_id=uuid4(),
                                source=source_name,
                                source_event_id=f"reconcile-add-{uuid4()}",
                                type=EventType.GROUP_MEMBER_ADDED,
                                occurred_at=now,
                                person=EventPerson(
                                    source_user_id=source_user_id,
                                    employee_number=user.employee_number,
                                ),
                                group=EventGroup(source_group_id=winning_group_id, name=""),
                            )
                            all_events.append(event)

                    elif not user.enabled:
                        if gw_account is not None and (
                            gw_account.status == "active"
                            or len(gw_account.keys) > 0
                            or bool(gw_account.team)
                        ):
                            drift = ReconciliationDrift(
                                kind="disabled_account_active",
                                source=source_name,
                                user_id=source_user_id,
                                detail="disabled directory user has active gateway access or keys",
                            )
                            all_drifts.append(drift)
                            event = CanonicalEvent(
                                event_id=uuid4(),
                                source=source_name,
                                source_event_id=f"reconcile-disable-{uuid4()}",
                                type=EventType.USER_DISABLED,
                                occurred_at=now,
                                person=EventPerson(
                                    source_user_id=source_user_id,
                                    employee_number=user.employee_number,
                                ),
                                group=None,
                            )
                            all_events.append(event)

                    else:
                        # User enabled, but has no entitlement-granting group
                        if gw_account is not None and (
                            len(gw_account.keys) > 0 or bool(gw_account.team)
                        ):
                            drift = ReconciliationDrift(
                                kind="unentitled_member_active",
                                source=source_name,
                                user_id=source_user_id,
                                detail="unentitled directory user has active gateway keys or team",
                            )
                            all_drifts.append(drift)
                            group_name = gw_account.team or "unentitled"
                            event = CanonicalEvent(
                                event_id=uuid4(),
                                source=source_name,
                                source_event_id=f"reconcile-remove-{uuid4()}",
                                type=EventType.GROUP_MEMBER_REMOVED,
                                occurred_at=now,
                                person=EventPerson(
                                    source_user_id=source_user_id,
                                    employee_number=user.employee_number,
                                ),
                                group=EventGroup(source_group_id=group_name, name=""),
                            )
                            all_events.append(event)

                # 2. Check for orphaned gateway users missing from this directory
                for gid in sorted(known_gateway_ids):
                    source_uid = person_to_user.get(gid)
                    if source_uid is not None:
                        is_missing = source_uid not in dir_users
                        target_source_uid = source_uid
                        person = stored_persons.get(gid)
                    else:
                        is_missing = gid not in dir_users
                        target_source_uid = gid
                        person = stored_persons.get(gid)

                    if gid in self._allowlist or target_source_uid in self._allowlist:
                        continue

                    if not is_missing:
                        continue

                    person_id_key = gid
                    miss = uow.misses.record_miss(person_id_key, source_name, now)
                    all_misses.append(miss)
                    should_delete = (not self._two_miss_rule) or (miss.miss_count >= 2)

                    drift = ReconciliationDrift(
                        kind="orphaned_account",
                        source=source_name,
                        user_id=target_source_uid,
                        detail=(
                            "user deleted after two consecutive misses"
                            if should_delete
                            else "discrepancy recorded in miss table"
                        ),
                    )
                    all_drifts.append(drift)

                    if should_delete:
                        event = CanonicalEvent(
                            event_id=uuid4(),
                            source=source_name,
                            source_event_id=f"reconcile-delete-{uuid4()}",
                            type=EventType.USER_DELETED,
                            occurred_at=now,
                            person=EventPerson(
                                source_user_id=target_source_uid,
                                employee_number=person.employee_number if person else None,
                            ),
                            group=None,
                        )
                        all_events.append(event)

                # 3. Check for expired grace-period deletions
                pending_deletions = uow.accounts.list_pending_deletions(before=now)
                for uid in pending_deletions:
                    if uid in handled_deletions:
                        continue
                    if uid in person_to_user or not any(
                        ident.person_id == uid
                        for s in self._identity_sources
                        if s != source_name
                        for ident in uow.identities.list_for_source(s)
                    ):
                        handled_deletions.add(uid)
                        target_source_uid = person_to_user.get(uid, uid)
                        drift = ReconciliationDrift(
                            kind="grace_period_expired",
                            source=source_name,
                            user_id=target_source_uid,
                            detail="grace period expired; deleting user from gateway",
                        )
                        all_drifts.append(drift)
                        if not is_dry_run:
                            try:
                                self._gateway.delete_user(user_id=uid)
                            except RetryableError as e:
                                logger.warning(
                                    "grace_period_deletion_gateway_retryable_error",
                                    user_id=uid,
                                    error=str(e),
                                )
                                deletion_failures.append(
                                    DeletionFailure(
                                        user_id=uid,
                                        error=str(e),
                                        error_type=type(e).__name__,
                                    )
                                )
                                continue
                            except PermanentError as e:
                                if _is_user_already_absent(e):
                                    uow.accounts.delete(uid)
                                    uow.audit.append(
                                        AuditEvent(
                                            event_id=uuid4(),
                                            source_event_id=f"reconcile-expire-{uuid4()}",
                                            actor=f"identity-lifecycle/{source_name}",
                                            action="delete_user",
                                            target=uid,
                                            decision="grace_period_expired",
                                            reason="already_absent",
                                            timestamp=now,
                                        )
                                    )
                                    continue
                                logger.warning(
                                    "grace_period_deletion_gateway_permanent_error",
                                    user_id=uid,
                                    error=str(e),
                                )
                                uow.audit.append(
                                    AuditEvent(
                                        event_id=uuid4(),
                                        source_event_id=f"reconcile-expire-fail-{uuid4()}",
                                        actor=f"identity-lifecycle/{source_name}",
                                        action="delete_user_failed",
                                        target=uid,
                                        decision="grace_period_expired",
                                        reason=type(e).__name__,
                                        timestamp=now,
                                    )
                                )
                                deletion_failures.append(
                                    DeletionFailure(
                                        user_id=uid,
                                        error=str(e),
                                        error_type=type(e).__name__,
                                    )
                                )
                                continue
                            except Exception as e:
                                logger.error(
                                    "grace_period_deletion_gateway_unexpected_error",
                                    user_id=uid,
                                    error=str(e),
                                )
                                deletion_failures.append(
                                    DeletionFailure(
                                        user_id=uid,
                                        error=str(e),
                                        error_type=type(e).__name__,
                                    )
                                )
                                continue

                            uow.accounts.delete(uid)
                            uow.audit.append(
                                AuditEvent(
                                    event_id=uuid4(),
                                    source_event_id=f"reconcile-expire-{uuid4()}",
                                    actor=f"identity-lifecycle/{source_name}",
                                    action="delete_user",
                                    target=uid,
                                    decision="grace_period_expired",
                                    reason="grace_period_expired",
                                    timestamp=now,
                                )
                            )

                # 4. Apply changes or rollback if dry run
                if is_dry_run:
                    uow.rollback()
                else:
                    for i in range(0, len(all_events), self._batch_size):
                        batch = all_events[i : i + self._batch_size]
                        for ev in batch:
                            uow.outbox.enqueue(ev)
                    uow.commit()

        logger.info(
            "reconciliation_completed",
            drifts=len(all_drifts),
            events_emitted=len(all_events),
            misses_recorded=len(all_misses),
            dry_run=is_dry_run,
        )

        return ReconciliationResult(
            drifts=tuple(all_drifts),
            events_emitted=tuple(all_events),
            misses_recorded=tuple(all_misses),
            misses_cleared=tuple(all_cleared),
            dry_run=is_dry_run,
            deletion_failures=tuple(deletion_failures),
        )

    def _read_all_users(self, source: IdentitySource) -> dict[str, IdentityUser]:
        users: dict[str, IdentityUser] = {}
        cursor: str | None = None
        while True:
            page = source.list_users(cursor)
            for item in page.items:
                users[item.source_user_id] = item
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        return users

    def _read_all_group_members(self, source: IdentitySource) -> dict[str, set[str]]:
        memberships: dict[str, set[str]] = defaultdict(set)
        for mapping in self._group_mappings:
            if mapping.source != source.name():
                continue
            cursor: str | None = None
            while True:
                page = source.get_group_members(mapping.source_group_id, cursor)
                for member in page.items:
                    memberships[member.source_user_id].add(mapping.source_group_id)
                if page.next_cursor is None:
                    break
                cursor = page.next_cursor
        return dict(memberships)

    def _winning_group_id(self, source_name: str, group_ids: set[str]) -> str:
        candidates = [
            SourceGroup(source=source_name, source_group_id=gid, name="") for gid in group_ids
        ]
        decision = decide_access(
            self._group_mappings,
            candidates,
            frozenset(self._identity_sources.keys()),
        )
        if decision.outcome is DecisionOutcome.GRANTED and decision.selected is not None:
            return decision.selected.source_group_id
        return sorted(group_ids)[0]
