"""Durable, page-at-a-time Okta System Log polling."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

import structlog

from identity_lifecycle.adapters.okta.connector import OktaIdentitySource
from identity_lifecycle.adapters.okta.cursor import (
    SystemLogCursor,
    completed_cursor,
    page_cursor,
    seeded_cursor,
)
from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.ports.identity_source import EventCondition
from identity_lifecycle.ports.unit_of_work import GroupMemberSnapshot, UnitOfWork

UnitOfWorkFactory = Callable[[str], AbstractContextManager[UnitOfWork]]

logger = structlog.get_logger(__name__)
FEED_SCOPE = "system_log"


class OktaSystemLogPoller:
    """Read one System Log page and atomically persist its events and cursor.

        A call commits one page, so a process restart resumes from the `after` token.
        The page's events, group-member snapshot, and cursor share the same transaction
    . The in-memory drain start preserves ADR-008's first-response
        watermark during ordinary pagination; after a restart, using the resume
        response is conservative because the query still uses the original `since`
        and `after` values.
    """

    def __init__(
        self,
        source: OktaIdentitySource,
        unit_of_work: UnitOfWorkFactory,
        *,
        overlap_seconds: int,
        drain_start: datetime | None = None,
    ) -> None:
        self._source = source
        self._unit_of_work = unit_of_work
        self._overlap_seconds = overlap_seconds
        self._drain_start = drain_start

    @property
    def has_more_pages(self) -> bool:
        """Whether the current drain has another persisted System Log page to read."""
        return self._drain_start is not None

    def poll_once(self) -> int:
        """Poll and commit one page; return the number of canonical events enqueued."""
        source_name = self._source.name()
        with self._unit_of_work(source_name) as uow:
            token = uow.cursors.read(source_name, FEED_SCOPE)
            page = self._source._read_system_log_page(token)

            if page.gap is not None:
                enqueued = self._full_sync(uow, page.server_now)
                uow.cursors.write(
                    source_name,
                    FEED_SCOPE,
                    seeded_cursor(page.server_now, self._overlap_seconds),
                )
                uow.commit()
                self._drain_start = None
                logger.warning("okta_system_log_gap", source=source_name, reason=page.gap)
                return enqueued

            state = page.cursor
            if state is None:
                # A usable cursor is required for a non-gap response; the connector
                # treats every unusable token as a gap before returning items.
                raise PermanentError("Okta System Log page omitted its parsed cursor")

            drain_start = self._start_for_page(state, page.server_now)
            enqueued = 0
            member_ids = self._snapshot_members(uow)
            for item in page.items:
                if isinstance(item, EventCondition):
                    logger.warning(
                        "okta_system_log_condition",
                        source=source_name,
                        code=item.code,
                        detail=item.detail,
                    )
                    continue
                uow.outbox.enqueue(item)
                enqueued += 1
                self._apply_membership_event(member_ids, item)

            uow.group_members.replace(
                GroupMemberSnapshot(
                    source=source_name,
                    source_group_id=self._source.group_id,
                    source_user_ids=frozenset(member_ids),
                )
            )
            if page.next_after is None:
                new_token = completed_cursor(
                    state,
                    now=drain_start,
                    overlap_seconds=self._overlap_seconds,
                )
                self._drain_start = None
            else:
                new_token = page_cursor(state, after=page.next_after)
                self._drain_start = drain_start
            uow.cursors.write(source_name, FEED_SCOPE, new_token)
            uow.commit()
            return enqueued

    def _start_for_page(self, cursor: SystemLogCursor, response_time: datetime) -> datetime:
        if cursor.after is None:
            return response_time
        if self._drain_start is not None:
            return self._drain_start
        # This process resumed after a restart. The page cursor is still inside the
        # old `since` window, so finishing from this later watermark cannot skip it.
        return response_time

    def _snapshot_members(self, uow: UnitOfWork) -> set[str]:
        snapshot = uow.group_members.read(self._source.name(), self._source.group_id)
        return set() if snapshot is None else set(snapshot.source_user_ids)

    def _full_sync(self, uow: UnitOfWork, occurred_at: datetime) -> int:
        source_name = self._source.name()
        group_id = self._source.group_id
        current_users = self._source.group_members()
        groups = self._source.list_groups(None).items
        group_name = next(
            (group.name for group in groups if group.source_group_id == group_id), group_id
        )
        current_ids = {user.source_user_id for user in current_users}
        previous = uow.group_members.read(source_name, group_id)
        previous_ids = set() if previous is None else set(previous.source_user_ids)
        user_by_id = {user.source_user_id: user for user in current_users}
        enqueued = 0

        for source_user_id in sorted(current_ids - previous_ids):
            user = user_by_id[source_user_id]
            uow.outbox.enqueue(
                _membership_event(
                    source=source_name,
                    group_id=group_id,
                    group_name=group_name,
                    user_id=source_user_id,
                    employee_number=user.employee_number,
                    event_type=EventType.GROUP_MEMBER_ADDED,
                    occurred_at=occurred_at,
                )
            )
            enqueued += 1
        for source_user_id in sorted(previous_ids - current_ids):
            removed_user = self._source.get_user(source_user_id)
            uow.outbox.enqueue(
                _membership_event(
                    source=source_name,
                    group_id=group_id,
                    group_name=group_name,
                    user_id=source_user_id,
                    employee_number=(
                        None if removed_user is None else removed_user.employee_number
                    ),
                    event_type=EventType.GROUP_MEMBER_REMOVED,
                    occurred_at=occurred_at,
                )
            )
            enqueued += 1
        for user in current_users:
            if user.enabled:
                continue
            uow.outbox.enqueue(
                _disabled_event(
                    source=source_name,
                    group_id=group_id,
                    user_id=user.source_user_id,
                    employee_number=user.employee_number,
                    occurred_at=occurred_at,
                )
            )
            enqueued += 1
        uow.group_members.replace(
            GroupMemberSnapshot(
                source=source_name,
                source_group_id=group_id,
                source_user_ids=frozenset(current_ids),
            )
        )
        return enqueued

    @staticmethod
    def _apply_membership_event(member_ids: set[str], event: CanonicalEvent) -> None:
        if event.group is None or event.person is None:
            return
        if event.type == EventType.GROUP_MEMBER_ADDED:
            member_ids.add(event.person.source_user_id)
        elif event.type == EventType.GROUP_MEMBER_REMOVED:
            member_ids.discard(event.person.source_user_id)


def _membership_event(
    *,
    source: str,
    group_id: str,
    group_name: str,
    user_id: str,
    employee_number: str | None,
    event_type: EventType,
    occurred_at: datetime,
) -> CanonicalEvent:
    direction = "added" if event_type == EventType.GROUP_MEMBER_ADDED else "removed"
    source_event_id = f"full-sync:{group_id}:{user_id}:{direction}:{occurred_at.isoformat()}"
    return CanonicalEvent(
        event_id=uuid5(NAMESPACE_URL, f"identity-lifecycle:{source}:{source_event_id}"),
        source=source,
        source_event_id=source_event_id,
        type=event_type,
        occurred_at=occurred_at,
        person=EventPerson(source_user_id=user_id, employee_number=employee_number),
        group=EventGroup(source_group_id=group_id, name=group_name),
    )


def _disabled_event(
    *,
    source: str,
    group_id: str,
    user_id: str,
    employee_number: str | None,
    occurred_at: datetime,
) -> CanonicalEvent:
    source_event_id = f"full-sync:{group_id}:{user_id}:disabled:{occurred_at.isoformat()}"
    return CanonicalEvent(
        event_id=uuid5(NAMESPACE_URL, f"identity-lifecycle:{source}:{source_event_id}"),
        source=source,
        source_event_id=source_event_id,
        type=EventType.USER_DISABLED,
        occurred_at=occurred_at,
        person=EventPerson(source_user_id=user_id, employee_number=employee_number),
        group=None,
    )
