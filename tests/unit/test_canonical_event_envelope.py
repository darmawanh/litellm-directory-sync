"""The canonical envelope and the seven event types are typed and closed.

``domain/events.py`` validates the shape of the envelope and nothing else: it
does not parse a vendor body, serialize, deduplicate, or compare clocks. These
tests pin the closed vocabulary, the ``schema_version`` rule, the UTC rule, the
subject rule, and the module's whole import set, so a later ticket that widens
one of them has to say which design sentence it came from.
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import (
    SCHEMA_VERSION,
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
    EventValidationError,
)

pytestmark = pytest.mark.unit

EVENTS_MODULE = (
    Path(__file__).resolve().parents[2] / "src" / "identity_lifecycle" / "domain" / "events.py"
)

EVENT_ID = UUID("0f8fad5b-d9cb-469f-a165-70867728950e")

#: Design section 7, the seven canonical types, as a literal. Deleting a member
#: from the enum cannot shrink the expected set along with it.
DESIGN_EVENT_TYPES = {
    "user.created",
    "user.updated",
    "user.disabled",
    "user.deleted",
    "group.member_added",
    "group.member_removed",
    "group.updated",
}

#: The module's whole import set: the standard library plus ``domain/errors``.
#: ``datetime.timedelta`` is used by the UTC check, not imported for show.
EXPECTED_IMPORTS = {
    "__future__.annotations",
    "dataclasses.dataclass",
    "datetime.datetime",
    "datetime.timedelta",
    "enum.StrEnum",
    "uuid.UUID",
    "identity_lifecycle.domain.errors.PermanentError",
}


def _import_targets(source: str) -> set[str]:
    """Return every absolute import target in ``source`` as ``module.name``."""
    targets: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "events.py uses absolute imports only"
            targets.update(f"{node.module}.{alias.name}" for alias in node.names)
    return targets


def _valid_event(**overrides: Any) -> CanonicalEvent:
    """A complete, valid envelope with one field replaced by ``overrides``."""
    fields: dict[str, Any] = {
        "event_id": EVENT_ID,
        "source": "okta",
        "source_event_id": "okta-event-id",
        "type": EventType.USER_UPDATED,
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
        "person": EventPerson(source_user_id="user-1", employee_number="E12345"),
        "group": None,
    }
    fields.update(overrides)
    return CanonicalEvent(**fields)


def test_the_seven_canonical_types_are_the_only_types() -> None:
    assert issubclass(EventType, StrEnum)
    assert {member.value for member in EventType} == DESIGN_EVENT_TYPES
    assert len(EventType) == len(DESIGN_EVENT_TYPES)
    # Closed, not documented: an eighth name cannot be built, and the standard
    # library's ValueError is the enforcement, so there is no bespoke check.
    with pytest.raises(ValueError):
        EventType("user.merged")


def test_the_envelope_defaults_to_schema_version_one() -> None:
    assert SCHEMA_VERSION == 1
    assert _valid_event().schema_version == SCHEMA_VERSION


def test_a_schema_version_other_than_one_is_a_permanent_error() -> None:
    with pytest.raises(EventValidationError) as raised:
        _valid_event(schema_version=2)

    error = raised.value
    assert isinstance(error, PermanentError)
    assert not isinstance(error, RetryableError)
    # A direct subclass, not a family cousin: the retry policy branches
    # on the family, so the base must be PermanentError itself.
    assert EventValidationError.__bases__ == (PermanentError,)
    assert f"schema_version must be {SCHEMA_VERSION}" in str(error)


def test_a_naive_or_non_utc_timestamp_is_rejected() -> None:
    with pytest.raises(EventValidationError):
        _valid_event(occurred_at=datetime(2026, 1, 1, 12, 0))
    with pytest.raises(EventValidationError):
        _valid_event(occurred_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=2))))


def test_an_aware_utc_timestamp_is_accepted() -> None:
    event = _valid_event(occurred_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC))

    assert event.occurred_at.utcoffset() == timedelta(0)


def test_an_event_must_name_at_least_one_subject() -> None:
    with pytest.raises(EventValidationError):
        _valid_event(person=None, group=None)

    person_only = _valid_event(
        person=EventPerson(source_user_id="user-1", employee_number=None), group=None
    )
    group_only = _valid_event(
        person=None, group=EventGroup(source_group_id="group-1", name="AI-Platform-Users")
    )

    assert person_only.person is not None and person_only.group is None
    assert group_only.group is not None and group_only.person is None


@pytest.mark.parametrize(
    ("field", "overrides"),
    [
        ("source", {"source": ""}),
        ("source_event_id", {"source_event_id": ""}),
        (
            "person.source_user_id",
            {"person": EventPerson(source_user_id="", employee_number=None)},
        ),
    ],
)
def test_empty_identifiers_are_rejected(field: str, overrides: dict[str, Any]) -> None:
    # A blank identifier names nothing: a blank source or source_user_id makes
    # `source + source_user_id` an empty ordering key, and a
    # blank source_event_id makes the vendor's id unusable in an audit record.
    with pytest.raises(EventValidationError) as raised:
        _valid_event(**overrides)

    assert field in str(raised.value)


def test_event_rejects_non_event_type() -> None:
    # An annotation is not a check: ``EventType`` is a ``StrEnum``, so
    # ``type="user.merged"`` is a plain string that used to construct.
    with pytest.raises(EventValidationError, match="type must be an EventType"):
        _valid_event(type="user.merged")

    with pytest.raises(EventValidationError, match="type must be an EventType"):
        _valid_event(type="user.updated")


def test_event_rejects_non_uuid_event_id() -> None:
    # Design 9.1 stores the id as ``event_id uuid``; a string would be rejected
    # by PostgreSQL after the envelope had already accepted it.
    with pytest.raises(EventValidationError, match="event_id must be a UUID"):
        _valid_event(event_id="0f8fad5b-d9cb-469f-a165-70867728950e")


def test_event_rejects_a_boolean_schema_version() -> None:
    # ``True == 1``, so the version comparison alone admits a bool. The
    # envelope has one integer version, never a boolean.
    with pytest.raises(EventValidationError, match="schema_version must be an int"):
        _valid_event(schema_version=True)


def test_event_rejects_an_empty_group_identifier() -> None:
    with pytest.raises(EventValidationError, match="group.source_group_id"):
        _valid_event(person=None, group=EventGroup(source_group_id="", name="AI-Platform-Users"))


def test_valid_envelope_still_constructs() -> None:
    # The guards are validation only: both legal subject shapes still build,
    # and the default version is still 1.
    assert _valid_event().schema_version == 1
    assert _valid_event(person=None, group=EventGroup(source_group_id="g", name="n")).group


def test_a_hint_only_employee_number_is_accepted() -> None:
    event = _valid_event(person=EventPerson(source_user_id="user-1", employee_number=None))

    assert event.person is not None
    assert event.person.source_user_id == "user-1"
    assert event.person.employee_number is None


def test_the_group_member_carries_its_source_identifier() -> None:
    group = EventGroup(source_group_id="group-1", name="AI-Platform-Users")
    event = _valid_event(person=None, group=group)

    assert event.group == group
    assert event.group.source_group_id == "group-1"
    assert event.group.name == "AI-Platform-Users"


def test_the_envelope_cannot_be_mutated_after_validation() -> None:
    event = _valid_event()
    person = event.person
    assert person is not None

    with pytest.raises(FrozenInstanceError):
        event.source = "corp-ad"  # type: ignore[misc]
    # Frozen must hold through the member too, or the envelope's invariants can
    # be broken by mutating the person it points at.
    with pytest.raises(FrozenInstanceError):
        person.source_user_id = ""  # type: ignore[misc]


def test_the_event_module_imports_only_the_standard_library_and_domain_errors() -> None:
    assert _import_targets(EVENTS_MODULE.read_text(encoding="utf-8")) == EXPECTED_IMPORTS


def test_the_import_scanner_sees_an_import_it_must_reject() -> None:
    # Negative control: a scanner that finds nothing would pass the test above
    # forever, including on a module that imports json.
    assert _import_targets("import json\nfrom datetime import timedelta\n") == {
        "json",
        "datetime.timedelta",
    }
