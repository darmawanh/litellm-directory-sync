"""Map Okta hook and System Log records into the canonical event vocabulary."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.ports.identity_source import EventCondition

_EVENT_TYPES: dict[str, EventType] = {
    "group.user_membership.add": EventType.GROUP_MEMBER_ADDED,
    "group.user_membership.remove": EventType.GROUP_MEMBER_REMOVED,
    "user.lifecycle.deactivate": EventType.USER_DISABLED,
}


def mapped_event_types() -> frozenset[str]:
    """Return the event-type vocabulary the System Log filter must cover."""
    return frozenset(_EVENT_TYPES)


def normalize(
    raw_event: Mapping[str, object], *, source_name: str
) -> CanonicalEvent | EventCondition:
    """Normalize a hook body; a missing employee number is a typed condition."""
    return _normalize(raw_event, source_name=source_name, missing_number_is_condition=True)


def normalize_system_log_entry(
    raw_event: Mapping[str, object], *, source_name: str
) -> CanonicalEvent | EventCondition:
    """Normalize a log entry, keeping a missing employee number as a null hint."""
    return _normalize(raw_event, source_name=source_name, missing_number_is_condition=False)


def user_group_id(raw_event: Mapping[str, object]) -> str | None:
    """Read the stable group id for in-memory scoping, never the display name."""
    group = _target(raw_event, "UserGroup")
    return _string(group.get("id")) if group is not None else None


def _normalize(
    raw_event: Mapping[str, object],
    *,
    source_name: str,
    missing_number_is_condition: bool,
) -> CanonicalEvent | EventCondition:
    if "verification" in raw_event:
        code = (
            "verification_challenge_is_not_an_event"
            if set(raw_event) == {"verification"}
            else "malformed_event"
        )
        return EventCondition(code, "verification payload is not an identity event")

    vendor_type = _string(raw_event.get("eventType"))
    event_type = None if vendor_type is None else _EVENT_TYPES.get(vendor_type)
    if event_type is None:
        code = "unsupported_event_type" if vendor_type is not None else "malformed_event"
        return EventCondition(code, "Okta event type has no canonical mapping")

    outcome = raw_event.get("outcome")
    if not isinstance(outcome, Mapping) or not isinstance(outcome.get("result"), str):
        return EventCondition("malformed_event", "Okta event outcome is missing or malformed")
    if outcome["result"] != "SUCCESS":
        return EventCondition("unsuccessful_outcome", "Okta event outcome was not successful")

    source_event_id = _string(raw_event.get("uuid"))
    published = _string(raw_event.get("published"))
    if source_event_id is None or published is None:
        return EventCondition("malformed_event", "Okta event id or published timestamp is missing")
    occurred_at = _instant(published)
    if occurred_at is None:
        return EventCondition("malformed_event", "Okta event published timestamp is invalid")

    user = _target(raw_event, "User")
    if user is None:
        return EventCondition("malformed_event", "Okta event has no User target id")
    source_user_id = _string(user.get("id"))
    if source_user_id is None:
        return EventCondition("malformed_event", "Okta event has no User target id")
    employee_number = _employee_number(user)
    if employee_number is None and missing_number_is_condition:
        return EventCondition("missing_employee_number", "Okta User target has no employeeNumber")

    group: EventGroup | None = None
    if event_type in {EventType.GROUP_MEMBER_ADDED, EventType.GROUP_MEMBER_REMOVED}:
        group_target = _target(raw_event, "UserGroup")
        if group_target is None:
            return EventCondition("malformed_event", "Okta membership event has no UserGroup id")
        group_id = _string(group_target.get("id"))
        if group_id is None:
            return EventCondition("malformed_event", "Okta membership event has no UserGroup id")
        group_name = _string(group_target.get("alternateId")) or _string(
            group_target.get("displayName")
        )
        group = EventGroup(source_group_id=group_id, name=group_name or group_id)

    return CanonicalEvent(
        event_id=uuid5(NAMESPACE_URL, f"identity-lifecycle:{source_name}:{source_event_id}"),
        source=source_name,
        source_event_id=source_event_id,
        type=event_type,
        occurred_at=occurred_at,
        person=EventPerson(source_user_id=source_user_id, employee_number=employee_number),
        group=group,
    )


def _target(raw_event: Mapping[str, object], target_type: str) -> Mapping[str, object] | None:
    targets = raw_event.get("target")
    if not isinstance(targets, list):
        return None
    for target in targets:
        if isinstance(target, Mapping) and target.get("type") == target_type:
            return target
    return None


def _employee_number(user_target: Mapping[str, object]) -> str | None:
    detail = user_target.get("detailEntry")
    if not isinstance(detail, Mapping):
        return None
    return _string(detail.get("employeeNumber"))


def _instant(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
