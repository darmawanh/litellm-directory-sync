"""``event_from_payload`` is total over the JSON documents the column can hold.

The outbox's claim path catches `` (DomainError, KeyError, TypeError, ValueError)``
and dead-letters the row; anything else escapes before the claim commits and
stalls the whole batch. A payload whose ``person``
or ``group`` is a string, a number, or a list used to reach ``Mapping.get`` on a
value that is not a mapping and raise ``AttributeError`` — an exception the claim
path does not catch. The parser now type-checks both members and reports the
malformation as ``EventValidationError``, a ``DomainError``.

These are pure tests of the adapter's parse function: no database, no clock.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from identity_lifecycle.adapters.persistence.payload import (
    event_from_payload,
    event_to_payload,
)
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
    EventValidationError,
)


def _valid_payload() -> dict[str, Any]:
    return event_to_payload(
        CanonicalEvent(
            event_id=uuid4(),
            source="corp-ad",
            source_event_id="s-1",
            type=EventType.GROUP_MEMBER_ADDED,
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
            person=EventPerson(source_user_id="object-guid-1", employee_number="E-1"),
            group=EventGroup(source_group_id="group-1", name="AI-Platform-Users"),
        )
    )


def test_event_from_payload_round_trips_a_valid_payload() -> None:
    """The new type check must not reject a document the writer just produced."""
    payload = _valid_payload()

    assert event_to_payload(event_from_payload(payload)) == payload


@pytest.mark.parametrize(
    ("member", "value"),
    [
        pytest.param("person", "x", id="person-string"),
        pytest.param("person", 7, id="person-number"),
        pytest.param("person", [1, 2], id="person-list"),
        pytest.param("group", "x", id="group-string"),
    ],
)
def test_event_from_payload_rejects_a_non_mapping_person(member: str, value: object) -> None:
    """The ticket's four shapes; ``group`` shares the one guard with ``person``."""
    payload = _valid_payload()
    payload[member] = value

    with pytest.raises(EventValidationError, match=member):
        event_from_payload(payload)


@pytest.mark.parametrize("value", [7, [1, 2]])
def test_event_from_payload_rejects_a_non_mapping_group(value: object) -> None:
    """The remaining ``group`` shapes; ``{"group": "x"}`` is in the test above."""
    payload = _valid_payload()
    payload["group"] = value

    with pytest.raises(EventValidationError, match="group"):
        event_from_payload(payload)


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("x", id="string"),
        pytest.param([1, 2], id="list"),
        pytest.param(7, id="number"),
        pytest.param(None, id="null"),
        pytest.param(True, id="boolean"),
    ],
)
def test_event_from_payload_rejects_a_non_mapping_document(document: object) -> None:
    """The ``payload`` column is bare ``jsonb`` (migration 0003), so the document
    itself can be a string, a list, a number, ``null``, or a boolean. The parser
    must reject each as a permanent parse failure rather than raise ``AttributeError``
    from ``.get``."""
    with pytest.raises(EventValidationError, match="payload"):
        event_from_payload(document)


@pytest.mark.parametrize("member", ["person", "group"])
def test_event_from_payload_still_accepts_a_null_member(member: str) -> None:
    """A null member is legal, not a type error."""
    payload = _valid_payload()
    payload[member] = None

    rebuilt = event_from_payload(payload)

    assert getattr(rebuilt, member) is None
