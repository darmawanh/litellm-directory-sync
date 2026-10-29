"""Test doubles for the four ports, plus an in-memory unit of work.

These are the fakes T-044 needs so the walking skeleton runs with no vendor and no
network. Each implements its port structurally; nothing here is imported by
production code, and the dependency test rejects a production import of ``tests``.

``FakeGateway`` records every write and serves every read from its own state. It
never echoes its arguments back: ADR-019 section 3 makes a non-confirming read a
``RetryableError``, so a fake that returned what it was told would let a broken
adapter pass the shared contract suite. ``FakeIdentitySource`` is read-only, like
the port it implements, and ``FakeClock`` moves time without sleeping.

The in-memory ``UnitOfWork`` lives in ``in_memory_unit_of_work.py`` and is
re-exported here, because the ticket names this module as the fakes' home and the
unit-of-work module is long enough to keep apart.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import LiteLLMAccount
from identity_lifecycle.domain.policy import BudgetPolicy
from identity_lifecycle.ports.identity_source import (
    Capabilities,
    EventCondition,
    IdentityGroup,
    IdentityUser,
    Page,
)

from .in_memory_unit_of_work import (
    InMemoryStore,
    InMemoryUnitOfWork,
    OutboxRow,
    event_rows,
    reap_expired,
)

__all__ = [
    "FakeClock",
    "FakeGateway",
    "FakeIdentitySource",
    "InMemoryStore",
    "InMemoryUnitOfWork",
    "OutboxRow",
    "event_rows",
    "reap_expired",
]


class FakeClock:
    """A ``Clock`` whose instant a test moves; production uses ``SystemClock``."""

    def __init__(self, now: datetime | None = None) -> None:
        self._now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC) if now is None else now

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


class FakeGateway:
    """The ``Gateway`` port over dictionaries, with programmable failures.

    ``team_id`` and team name are the same value: the port separates the two, and
    the fake needs no identifier allocator to prove the lifecycle path. A failure
    queued with :meth:`fail_next` is raised by the next mutating or reading call,
    before it touches state, so a retryable failure leaves no half-write behind.
    """

    def __init__(self) -> None:
        self.teams: dict[str, str] = {}
        self.accounts: dict[str, LiteLLMAccount] = {}
        self.blocked_keys: set[str] = set()
        self.calls: list[str] = []
        self.writes: list[str] = []
        self.failures: list[Exception] = []
        self.on_call: Callable[[str], None] | None = None
        self.closed = False

    # test control

    def fail_next(self, error: Exception) -> None:
        """Raise ``error`` on the next call, before that call changes anything."""
        self.failures.append(error)

    def user_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.accounts))

    def close(self) -> None:
        """Mirror the adapter's process cleanup hook for composition tests."""
        self.closed = True

    # the port

    def ensure_team(self, *, name: str, create_if_missing: bool) -> str:
        self._before("ensure_team")
        existing = self.teams.get(name)
        if existing is not None:
            return existing
        if not create_if_missing:
            raise PermanentError(f"team {name!r} does not exist and create_if_missing is false")
        self.teams[name] = name
        self.writes.append("ensure_team")
        return name

    def create_user(
        self,
        *,
        user_id: str,
        email: str,
        display_name: str,
        role: str,
        team_id: str,
        budget: BudgetPolicy,
    ) -> LiteLLMAccount:
        self._before("create_user")
        if user_id in self.accounts:
            raise PermanentError(f"gateway user {user_id!r} already exists")
        self.accounts[user_id] = LiteLLMAccount(
            user_id=user_id,
            status="active",
            role=role,
            team=team_id,
            budget=budget.max_budget,
            keys=(),
        )
        self.writes.append("create_user")
        return self._read(user_id)

    def update_user(
        self, *, user_id: str, role: str, team_id: str, budget: BudgetPolicy
    ) -> LiteLLMAccount:
        self._before("update_user")
        account = self._account(user_id)
        self.accounts[user_id] = replace(
            account, status="active", role=role, team=team_id, budget=budget.max_budget
        )
        self.writes.append("update_user")
        return self._read(user_id)

    def remove_from_team(self, *, user_id: str, team_id: str) -> LiteLLMAccount:
        self._before("remove_from_team")
        account = self._account(user_id)
        if account.team == team_id:
            self.accounts[user_id] = replace(account, team="")
            self.writes.append("remove_from_team")
        return self._read(user_id)

    def revoke_keys(self, *, user_id: str) -> LiteLLMAccount:
        self._before("revoke_keys")
        account = self._account(user_id)
        self.blocked_keys.update(account.keys)
        self.writes.append("revoke_keys")
        return self._read(user_id)

    def delete_user(self, *, user_id: str) -> None:
        self._before("delete_user")
        self._account(user_id)
        del self.accounts[user_id]
        self.writes.append("delete_user")

    def get_user(self, *, user_id: str) -> LiteLLMAccount | None:
        self._before("get_user")
        account = self.accounts.get(user_id)
        return None if account is None else replace(account)

    # internals

    def _before(self, name: str) -> None:
        """Record the call, run a test hook, then raise any queued failure."""
        self.calls.append(name)
        if self.on_call is not None:
            self.on_call(name)
        if self.failures:
            raise self.failures.pop(0)

    def _account(self, user_id: str) -> LiteLLMAccount:
        account = self.accounts.get(user_id)
        if account is None:
            raise PermanentError(f"gateway user {user_id!r} does not exist")
        return account

    def _read(self, user_id: str) -> LiteLLMAccount:
        """Build the returned account from state, never from the arguments."""
        return replace(self._account(user_id))


class FakeIdentitySource:
    """A read-only ``IdentitySource`` over two dictionaries."""

    def __init__(
        self,
        *,
        source: str = "corp-ad",
        users: Mapping[str, IdentityUser] | None = None,
        groups: Mapping[str, tuple[str, ...]] | None = None,
        group_members_page_size: int | None = None,
    ) -> None:
        self._source = source
        self.users: dict[str, IdentityUser] = dict(users or {})
        self.groups: dict[str, list[str]] = {
            group_id: list(members) for group_id, members in (groups or {}).items()
        }
        self.group_members_page_size = group_members_page_size
        self.calls: list[str] = []

    # test control

    def add_user(self, user: IdentityUser) -> None:
        self.users[user.source_user_id] = user

    def add_to_group(self, group_id: str, source_user_id: str) -> None:
        members = self.groups.setdefault(group_id, [])
        if source_user_id not in members:
            members.append(source_user_id)

    def remove_from_group(self, group_id: str, source_user_id: str) -> None:
        members = self.groups.get(group_id, [])
        if source_user_id in members:
            members.remove(source_user_id)

    def delete_user(self, source_user_id: str) -> None:
        self.users.pop(source_user_id, None)

    def disable_user(self, source_user_id: str) -> None:
        user = self.users[source_user_id]
        self.users[source_user_id] = replace(user, enabled=False)

    def enable_user(self, source_user_id: str) -> None:
        user = self.users[source_user_id]
        self.users[source_user_id] = replace(user, enabled=True)

    # the port

    def name(self) -> str:
        return self._source

    def capabilities(self) -> Capabilities:
        return Capabilities(incremental_changes=True, full_snapshot=True, group_membership=True)

    def list_users(self, cursor: str | None) -> Page[IdentityUser]:
        self.calls.append("list_users")
        return Page(items=tuple(self.users.values()), next_cursor=None)

    def get_user(self, source_user_id: str) -> IdentityUser | None:
        self.calls.append("get_user")
        return self.users.get(source_user_id)

    def list_groups(self, cursor: str | None) -> Page[IdentityGroup]:
        self.calls.append("list_groups")
        items = tuple(
            IdentityGroup(source_group_id=group_id, name=group_id) for group_id in self.groups
        )
        return Page(items=items, next_cursor=None)

    def get_group_members(self, group_id: str, cursor: str | None) -> Page[IdentityUser]:
        self.calls.append("get_group_members")
        members = [
            self.users[member] for member in self.groups.get(group_id, []) if member in self.users
        ]
        if self.group_members_page_size is not None and self.group_members_page_size > 0:
            offset = int(cursor) if cursor is not None else 0
            page_slice = members[offset : offset + self.group_members_page_size]
            next_offset = offset + len(page_slice)
            next_cursor = str(next_offset) if next_offset < len(members) else None
            return Page(items=tuple(page_slice), next_cursor=next_cursor)
        return Page(items=tuple(members), next_cursor=None)

    def poll_changes(self, cursor: str | None) -> Page[CanonicalEvent | EventCondition]:
        self.calls.append("poll_changes")
        return Page(items=(), next_cursor=None)

    def normalize(self, raw_event: Mapping[str, object]) -> CanonicalEvent | EventCondition:
        return EventCondition(
            code="not_supported",
            detail="the fake does not normalize vendor bodies; the adapter's mapping does",
        )
