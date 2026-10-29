"""The canonical envelope as the outbox stores it.

``identity_event_outbox.payload`` is ``jsonb`` holding design 8's envelope,
including ``schema_version``. The envelope itself carries no
serializer — ``domain/events.py`` records that turning a value into JSON is the
outbox writer's job — so this module is the writer's half of it.

The document is written with the standard library's ``json`` and rebuilt through
``CanonicalEvent``, whose ``__post_init__`` validates every field. A row whose
payload cannot describe a legal event raises ``EventValidationError``, a
permanent failure: retrying the same bytes changes nothing.
``event_from_payload`` is total over the JSON the column can hold, including a
document that is not an object: it returns an envelope or raises one of the
failures the claim path dead-letters, never an arbitrary exception such as
``AttributeError``, which would stall the batch.

``person_key`` is computed here too, beside the envelope it comes from:
``source + ":" + person.source_user_id``, null exactly when the event names no
person. It is stored on the row, never inside the payload.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
    EventValidationError,
)


def event_to_payload(event: CanonicalEvent) -> dict[str, Any]:
    """Render the envelope as the JSON document the ``payload`` column holds."""
    return {
        "event_id": str(event.event_id),
        "source": event.source,
        "source_event_id": event.source_event_id,
        "type": event.type.value,
        "occurred_at": event.occurred_at.isoformat(),
        "schema_version": event.schema_version,
        "person": None if event.person is None else _person_to_payload(event.person),
        "group": None if event.group is None else _group_to_payload(event.group),
    }


def event_from_payload(payload: object) -> CanonicalEvent:
    """Rebuild the envelope from a stored payload, validating it on the way in.

        ``payload`` is annotated ``object`` because the column is bare ``jsonb``
     (migration 0003): the document can be a string, a list, a number, ``null``,
        or a boolean, not only an object. A non-object is rejected here with the
        same explicit check the members use, so the function is total: it returns
        an envelope or raises a failure the claim path dead-letters, never
        ``AttributeError`` from ``.get`` on a value that is not a mapping
    .

        ``schema_version`` is passed through unchanged rather than coerced: the
        envelope's own guard rejects a boolean or a string, and ``int (True)`` would
        turn that guard back into an annotation.
    """
    document = _require_mapping("payload", payload)
    person = document.get("person")
    group = document.get("group")
    return CanonicalEvent(
        event_id=UUID(str(document["event_id"])),
        source=str(document["source"]),
        source_event_id=str(document["source_event_id"]),
        type=EventType(str(document["type"])),
        occurred_at=_parse_timestamp(str(document["occurred_at"])),
        person=None if person is None else _person_from_payload(person),
        group=None if group is None else _group_from_payload(group),
        schema_version=cast(int, document["schema_version"]),
    )


def person_key(event: CanonicalEvent) -> str | None:
    """Return ADR-015 section 1's key, or ``None`` when the event names no person."""
    if event.person is None:
        return None
    return f"{event.source}:{event.person.source_user_id}"


def _person_to_payload(person: EventPerson) -> dict[str, Any]:
    return {
        "source_user_id": person.source_user_id,
        "employee_number": person.employee_number,
    }


def _group_to_payload(group: EventGroup) -> dict[str, Any]:
    return {"source_group_id": group.source_group_id, "name": group.name}


def _person_from_payload(value: object) -> EventPerson:
    mapping = _require_mapping("person", value)
    employee_number = mapping.get("employee_number")
    return EventPerson(
        source_user_id=str(mapping["source_user_id"]),
        employee_number=None if employee_number is None else str(employee_number),
    )


def _group_from_payload(value: object) -> EventGroup:
    mapping = _require_mapping("group", value)
    return EventGroup(
        source_group_id=str(mapping["source_group_id"]),
        name=str(mapping["name"]),
    )


def _require_mapping(field: str, value: object) -> Mapping[str, Any]:
    """Return ``value`` as a mapping, or reject it as an unreadable payload.

        Used for the stored document and for its ``person`` and ``group`` members.
        A bare ``cast`` let a string, a number, or a list reach ``.get`` and raise
        ``AttributeError``, which is not a ``DomainError``: the claim path would not
        dead-letter the row, and a caller that did not go through ``payload_of``
        would get an arbitrary exception instead of a typed permanent failure
    . The check is explicit rather than a
        caught ``AttributeError`` so the function has no other way to fail: it
        either returns a value or raises ``EventValidationError``.
    """
    if not isinstance(value, Mapping):
        raise EventValidationError(f"{field} must be an object; got {type(value).__name__}")
    return value


def _parse_timestamp(value: str) -> datetime:
    """Parse the ISO 8601 instant the writer stored.

    ``datetime.fromisoformat`` accepts the ``+00:00`` offset ``isoformat``
    emits and a trailing ``Z`` as of Python 3.11. A naive value is still
    rejected by the envelope, not repaired here.
    """
    return datetime.fromisoformat(value)
