"""Okta's read-only ``IdentitySource`` adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TypeVar, cast
from urllib.parse import quote

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from identity_lifecycle.adapters.okta.client import OktaClient, next_after
from identity_lifecycle.adapters.okta.cursor import (
    SystemLogCursor,
    gap_reason,
    initial_since,
    page_cursor,
    parse_cursor,
)
from identity_lifecycle.adapters.okta.mapping import (
    mapped_event_types,
    normalize,
    normalize_system_log_entry,
    user_group_id,
)
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.identity_source import (
    Capabilities,
    EventCondition,
    IdentityGroup,
    IdentityUser,
    Page,
)

logger = structlog.get_logger(__name__)
_ModelT = TypeVar("_ModelT", bound=BaseModel)
_USER_PAGE_SIZE = 200


class _OktaProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    employeeNumber: str | None = None
    email: str | None = None
    login: str | None = None
    firstName: str | None = None
    lastName: str | None = None
    displayName: str | None = None
    name: str | None = None


class _OktaUser(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    status: str
    profile: _OktaProfile


class _OktaGroupProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str


class _OktaGroup(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    profile: _OktaGroupProfile


@dataclass(frozen=True)
class OktaSystemLogPage:
    """One API page plus the server facts needed by the durable poller."""

    items: tuple[CanonicalEvent | EventCondition, ...]
    cursor: SystemLogCursor | None
    next_after: str | None
    server_now: datetime
    gap: str | None


class OktaIdentitySource:
    """Implement the synchronous, read-only source port for one configured group."""

    def __init__(
        self,
        *,
        source_name: str,
        group_id: str,
        client: OktaClient,
        clock: Clock,
        log_page_limit: int,
        log_overlap_seconds: int,
        log_retention_seconds: int,
    ) -> None:
        self._source_name = source_name
        self._group_id = group_id
        self._client = client
        self._clock = clock
        self._log_page_limit = log_page_limit
        self._log_overlap_seconds = log_overlap_seconds
        self._log_retention_seconds = log_retention_seconds

    def close(self) -> None:
        """Close the source's HTTP pool when the process stops."""
        self._client.close()

    def name(self) -> str:
        return self._source_name

    @property
    def group_id(self) -> str:
        """The one configured group this source scopes membership events to."""
        return self._group_id

    def capabilities(self) -> Capabilities:
        return Capabilities(incremental_changes=True, full_snapshot=True, group_membership=True)

    def list_users(self, cursor: str | None) -> Page[IdentityUser]:
        params: dict[str, str | int] = {"limit": _USER_PAGE_SIZE}
        if cursor is not None:
            params["after"] = cursor
        response = self._required_get("/api/v1/users", params=params)
        entries = _array(self._json(response, "user listing"), "user listing")
        users = tuple(_identity_user(_validate(_OktaUser, entry, "user")) for entry in entries)
        return Page(items=users, next_cursor=next_after(response.headers))

    def get_user(self, source_user_id: str) -> IdentityUser | None:
        path = f"/api/v1/users/{quote(source_user_id, safe='')}"
        response = self._client.get(path, allow_missing=True)
        if response is None:
            return None
        return _identity_user(_validate(_OktaUser, self._json(response, "user"), "user"))

    def list_groups(self, cursor: str | None) -> Page[IdentityGroup]:
        if cursor is not None:
            return Page(items=(), next_cursor=None)
        path = f"/api/v1/groups/{quote(self._group_id, safe='')}"
        response = self._required_get(path)
        group = _validate(_OktaGroup, self._json(response, "group"), "group")
        return Page(
            items=(IdentityGroup(source_group_id=group.id, name=group.profile.name),),
            next_cursor=None,
        )

    def get_group_members(self, group_id: str, cursor: str | None) -> Page[IdentityUser]:
        if group_id != self._group_id:
            raise PermanentError("Okta group is outside the configured source scope")
        params: dict[str, str | int] = {"limit": _USER_PAGE_SIZE}
        if cursor is not None:
            params["after"] = cursor
        path = f"/api/v1/groups/{quote(group_id, safe='')}/users"
        response = self._required_get(path, params=params)
        entries = _array(self._json(response, "group member listing"), "group member listing")
        users = tuple(
            _identity_user(_validate(_OktaUser, entry, "group member")) for entry in entries
        )
        return Page(items=users, next_cursor=next_after(response.headers))

    def poll_changes(self, cursor: str | None) -> Page[CanonicalEvent | EventCondition]:
        """Read one System Log page; durable cursor/outbox writes belong to the poller."""
        result = self._read_system_log_page(cursor)
        if result.gap is not None:
            return Page(
                items=(EventCondition("system_log_gap", result.gap),),
                next_cursor=None,
            )
        next_token = (
            None
            if result.cursor is None or result.next_after is None
            else page_cursor(result.cursor, after=result.next_after)
        )
        return Page(items=result.items, next_cursor=next_token)

    def normalize(self, raw_event: Mapping[str, object]) -> CanonicalEvent | EventCondition:
        return normalize(raw_event, source_name=self._source_name)

    def group_members(self) -> tuple[IdentityUser, ...]:
        """Read every configured group member, following only opaque page cursors."""
        members: list[IdentityUser] = []
        cursor: str | None = None
        while True:
            page = self.get_group_members(self._group_id, cursor)
            members.extend(page.items)
            if page.next_cursor is None:
                return tuple(members)
            cursor = page.next_cursor

    def _read_system_log_page(self, token: str | None) -> OktaSystemLogPage:
        state, parse_reason = parse_cursor(token)
        params: dict[str, str | int] = {
            "filter": _system_log_filter(),
            "limit": self._log_page_limit,
            "since": (
                initial_since(self._clock.now(), self._log_overlap_seconds)
                if state is None
                else _format_instant(state.since)
            ),
        }
        if state is not None and state.after is not None:
            params["after"] = state.after

        response = self._required_get("/api/v1/logs", params=params)
        server_now = _server_time(response.headers, self._clock)
        reason = gap_reason(
            state,
            now=server_now,
            overlap_seconds=self._log_overlap_seconds,
            retention_seconds=self._log_retention_seconds,
            parse_reason=parse_reason,
        )
        if reason is not None:
            return OktaSystemLogPage(
                items=(), cursor=state, next_after=None, server_now=server_now, gap=reason
            )

        entries = _array(self._json(response, "System Log"), "System Log")
        items: list[CanonicalEvent | EventCondition] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                items.append(
                    EventCondition("malformed_event", "Okta System Log entry is not an object")
                )
                continue
            event_type = entry.get("eventType")
            if (
                isinstance(event_type, str)
                and event_type in {"group.user_membership.add", "group.user_membership.remove"}
                and user_group_id(entry) != self._group_id
            ):
                continue
            result = normalize_system_log_entry(entry, source_name=self._source_name)
            items.append(result)
        return OktaSystemLogPage(
            items=tuple(items),
            cursor=state,
            next_after=next_after(response.headers),
            server_now=server_now,
            gap=None,
        )

    def _required_get(
        self,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
    ) -> httpx.Response:
        response = self._client.get(path, params=params)
        if response is None:
            raise PermanentError(f"Okta returned no response for {path}")
        return response

    @staticmethod
    def _json(response: httpx.Response, label: str) -> object:
        try:
            return cast(object, response.json())
        except ValueError:
            raise RetryableError(f"Okta returned invalid JSON for {label}") from None


def _system_log_filter() -> str:
    """Filter every mapped event type; the group is matched in memory."""
    return " or ".join(
        f'eventType eq "{event_type}"' for event_type in sorted(mapped_event_types())
    )


def _identity_user(user: _OktaUser) -> IdentityUser:
    profile = user.profile
    email = profile.email or profile.login
    name = profile.displayName or profile.name
    if not name:
        name = " ".join(part for part in (profile.firstName, profile.lastName) if part).strip()
    if not name:
        name = profile.login or email
    if not email or not name:
        raise PermanentError("Okta user profile has no readable email or display name")
    return IdentityUser(
        source_user_id=user.id,
        employee_number=profile.employeeNumber or None,
        email=email,
        display_name=name,
        enabled=user.status == "ACTIVE",
    )


def _validate(model: type[_ModelT], value: object, label: str) -> _ModelT:
    try:
        return model.model_validate(value)
    except ValidationError:
        raise PermanentError(f"Okta returned an invalid {label} response") from None


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise PermanentError(f"Okta returned an invalid {label} response")
    return value


def _server_time(headers: Mapping[str, str], clock: Clock) -> datetime:
    raw = headers.get("Date")
    if raw is None:
        logger.warning("okta_system_log_date_missing")
        return clock.now()
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        logger.warning("okta_system_log_date_invalid")
        return clock.now()
    if parsed.utcoffset() is None:
        logger.warning("okta_system_log_date_invalid")
        return clock.now()
    return parsed.astimezone(UTC)


def _format_instant(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.") + f"{normalized.microsecond // 1000:03d}Z"
