"""Durable, transaction-atomic Active Directory polling."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import structlog

from identity_lifecycle.adapters.ad.connector import ADIdentitySource
from identity_lifecycle.adapters.ad.cursor import format_cursor, parse_cursor
from identity_lifecycle.adapters.ad.mapping import map_user_entry
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.ports.unit_of_work import GroupMemberSnapshot, UnitOfWork

UnitOfWorkFactory = Callable[[str], AbstractContextManager[UnitOfWork]]

logger = structlog.get_logger(__name__)
FEED_SCOPE = "usn_poll"


class ADPoller:
    """Read Active Directory changes and atomically persist events, group snapshot, and cursor.

    The group object is read unconditionally every cycle. Membership additions
    and removals are detected by diffing against the persisted group snapshot. The cursor
    advances monotonically per DC as an integer USN.
    """

    def __init__(
        self,
        source: ADIdentitySource,
        unit_of_work: UnitOfWorkFactory,
        *,
        feed_scope: str = FEED_SCOPE,
    ) -> None:
        self._source = source
        self._unit_of_work = unit_of_work
        self._feed_scope = feed_scope

    def poll_once(self) -> int:
        """Poll and commit one cycle of AD changes; return count of enqueued events."""
        source_name = self._source.name()
        group_dn = self._source.group_dn

        with self._unit_of_work(source_name) as uow:
            token = uow.cursors.read(source_name, self._feed_scope)
            root_dse = self._source.client.read_root_dse()
            connected_dc = root_dse["invocationID"]
            now = self._source._clock.now()

            cursor_state, gap_reason = parse_cursor(token, connected_dc=connected_dc)

            # Reset condition: missing/corrupt cursor or DC invocationID changed
            if cursor_state is None:
                logger.warning(
                    "ad_cursor_reset",
                    source=source_name,
                    reason=gap_reason,
                    connected_dc=connected_dc,
                )
                enqueued = self._full_sync(uow, root_dse, now)
                uow.commit()
                return enqueued

            # Incremental cycle:
            # 1. Unconditional group read
            group, member_dns, group_usn, when_changed = self._source.read_group_entry()
            occurred_at = when_changed or now

            # 2. Group membership diff
            previous_snapshot = uow.group_members.read(source_name, group_dn)
            previous_user_ids = (
                set(previous_snapshot.source_user_ids) if previous_snapshot is not None else set()
            )

            current_users = self._source.resolve_members(member_dns)
            current_user_by_id = {u.source_user_id: u for u in current_users}
            current_user_ids = set(current_user_by_id.keys())

            enqueued = 0

            # Membership removals (F4)
            removed_ids = previous_user_ids - current_user_ids
            for user_id in sorted(removed_ids):
                # Try to re-read removed user for link hint if still in directory
                existing_user = self._source.get_user(user_id)
                emp_number = existing_user.employee_number if existing_user else None
                event = _membership_event(
                    source=source_name,
                    group_id=group_dn,
                    group_name=group.name,
                    user_id=user_id,
                    employee_number=emp_number,
                    event_type=EventType.GROUP_MEMBER_REMOVED,
                    usn=group_usn,
                    occurred_at=occurred_at,
                )
                uow.outbox.enqueue(event)
                enqueued += 1

            # Membership additions
            added_ids = current_user_ids - previous_user_ids
            for user_id in sorted(added_ids):
                user = current_user_by_id[user_id]
                event = _membership_event(
                    source=source_name,
                    group_id=group_dn,
                    group_name=group.name,
                    user_id=user_id,
                    employee_number=user.employee_number,
                    event_type=EventType.GROUP_MEMBER_ADDED,
                    usn=group_usn,
                    occurred_at=occurred_at,
                )
                uow.outbox.enqueue(event)
                enqueued += 1

            # 3. User delta
            delta_entries, max_delta_usn = self._source.read_user_delta(cursor_state.usn)
            for entry in delta_entries:
                try:
                    delta_user = map_user_entry(entry)
                    u_attrs = entry.get("attributes", {})
                    u_usn = int(u_attrs.get("uSNChanged", [cursor_state.usn])[0])
                    u_when = self._source._parse_when_changed(u_attrs.get("whenChanged"))

                    if not delta_user.enabled:
                        event = _user_event(
                            source=source_name,
                            user_id=delta_user.source_user_id,
                            employee_number=delta_user.employee_number,
                            event_type=EventType.USER_DISABLED,
                            usn=u_usn,
                            occurred_at=u_when,
                        )
                        uow.outbox.enqueue(event)
                        enqueued += 1
                    else:
                        event = _user_event(
                            source=source_name,
                            user_id=delta_user.source_user_id,
                            employee_number=delta_user.employee_number,
                            event_type=EventType.USER_UPDATED,
                            usn=u_usn,
                            occurred_at=u_when,
                        )
                        uow.outbox.enqueue(event)
                        enqueued += 1
                except Exception as error:
                    logger.warning("ad_delta_user_skip", dn=entry.get("dn"), error=str(error))

            # 4. Check for USN regression (e.g. DC restore from backup)
            observed_max = max(cursor_state.usn, group_usn, max_delta_usn)
            if observed_max < cursor_state.usn:
                logger.warning(
                    "ad_usn_moved_backwards",
                    source=source_name,
                    stored=cursor_state.usn,
                    observed=observed_max,
                )
                return self._full_sync(uow, root_dse, now)

            # 5. Persist group snapshot, advance cursor, and commit in same transaction
            uow.group_members.replace(
                GroupMemberSnapshot(
                    source=source_name,
                    source_group_id=group_dn,
                    source_user_ids=frozenset(current_user_ids),
                )
            )
            advanced_cursor = format_cursor(connected_dc, observed_max)
            uow.cursors.write(source_name, self._feed_scope, advanced_cursor)
            uow.commit()

            return enqueued

    def _full_sync(self, uow: UnitOfWork, root_dse: dict[str, Any], now: datetime) -> int:
        """Run full group sync, emit canonical events, replace snapshot, and re-seed cursor."""
        source_name = self._source.name()
        group_dn = self._source.group_dn
        connected_dc = root_dse["invocationID"]
        highest_usn = root_dse["highestCommittedUSN"]

        group, member_dns, group_usn, when_changed = self._source.read_group_entry()
        current_users = self._source.resolve_members(member_dns)
        current_user_by_id = {u.source_user_id: u for u in current_users}
        current_ids = set(current_user_by_id.keys())

        previous_snapshot = uow.group_members.read(source_name, group_dn)
        previous_ids = (
            set(previous_snapshot.source_user_ids) if previous_snapshot is not None else set()
        )

        enqueued = 0

        # Emit added members
        for user_id in sorted(current_ids - previous_ids):
            user = current_user_by_id[user_id]
            uow.outbox.enqueue(
                _membership_event(
                    source=source_name,
                    group_id=group_dn,
                    group_name=group.name,
                    user_id=user_id,
                    employee_number=user.employee_number,
                    event_type=EventType.GROUP_MEMBER_ADDED,
                    usn=group_usn,
                    occurred_at=now,
                )
            )
            enqueued += 1

        # Emit removed members
        for user_id in sorted(previous_ids - current_ids):
            removed_user = self._source.get_user(user_id)
            emp_number = removed_user.employee_number if removed_user else None
            uow.outbox.enqueue(
                _membership_event(
                    source=source_name,
                    group_id=group_dn,
                    group_name=group.name,
                    user_id=user_id,
                    employee_number=emp_number,
                    event_type=EventType.GROUP_MEMBER_REMOVED,
                    usn=group_usn,
                    occurred_at=now,
                )
            )
            enqueued += 1

        # Emit disabled status for current members whose accounts are disabled
        for user in current_users:
            if not user.enabled:
                uow.outbox.enqueue(
                    _user_event(
                        source=source_name,
                        user_id=user.source_user_id,
                        employee_number=user.employee_number,
                        event_type=EventType.USER_DISABLED,
                        usn=group_usn,
                        occurred_at=now,
                    )
                )
                enqueued += 1

        # Persist full group snapshot
        uow.group_members.replace(
            GroupMemberSnapshot(
                source=source_name,
                source_group_id=group_dn,
                source_user_ids=frozenset(current_ids),
            )
        )

        # Seed cursor to highest committed USN (or group USN)
        seed_usn = max(group_usn, highest_usn)
        uow.cursors.write(
            source_name,
            self._feed_scope,
            format_cursor(connected_dc, seed_usn),
        )

        return enqueued


def _membership_event(
    *,
    source: str,
    group_id: str,
    group_name: str,
    user_id: str,
    employee_number: str | None,
    event_type: EventType,
    usn: int,
    occurred_at: datetime,
) -> CanonicalEvent:
    direction = "added" if event_type == EventType.GROUP_MEMBER_ADDED else "removed"
    source_event_id = f"ad:{group_id}:{user_id}:{direction}:{usn}"
    return CanonicalEvent(
        event_id=uuid5(NAMESPACE_URL, f"identity-lifecycle:{source}:{source_event_id}"),
        source=source,
        source_event_id=source_event_id,
        type=event_type,
        occurred_at=occurred_at,
        person=EventPerson(source_user_id=user_id, employee_number=employee_number),
        group=EventGroup(source_group_id=group_id, name=group_name),
    )


def _user_event(
    *,
    source: str,
    user_id: str,
    employee_number: str | None,
    event_type: EventType,
    usn: int,
    occurred_at: datetime,
) -> CanonicalEvent:
    tag = "disabled" if event_type == EventType.USER_DISABLED else "updated"
    source_event_id = f"ad:{user_id}:{tag}:{usn}"
    return CanonicalEvent(
        event_id=uuid5(NAMESPACE_URL, f"identity-lifecycle:{source}:{source_event_id}"),
        source=source,
        source_event_id=source_event_id,
        type=event_type,
        occurred_at=occurred_at,
        person=EventPerson(source_user_id=user_id, employee_number=employee_number),
        group=None,
    )
