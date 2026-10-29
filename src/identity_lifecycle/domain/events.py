"""The canonical event envelope and the closed vocabulary of event types.

An event is a trigger, never the truth: a consumer re-reads the source before it
acts, so ``EventPerson.employee_number`` is a hint and
nothing downstream may key off it. This module
types and validates the envelope and does nothing else. Turning a vendor body
into one is ``adapters/*/mapping.py``'s job, which is why there is
no ``json`` import, no ``from_payload``, and no ``to_json``: the Phase 2 outbox
writer serializes.

Validation is shape validation of the envelope: ``type`` must be an ``EventType``,
``event_id`` must be a ``UUID``, ``schema_version`` must be the version this
module writes (and an ``int``, not a ``bool``), ``occurred_at`` must be an aware
UTC instant, ``source``, ``source_event_id``, a person's
``source_user_id`` and a group's ``source_group_id`` must be non-empty, and an
event must name at least one subject. Every failure is an
``EventValidationError``, a ``PermanentError``: a malformed event is not
retried.
Whitespace is not trimmed here; normalizing a vendor value is the adapter's job
.

The first four checks are the four guard holes Phase 1 recorded: an annotation
alone is not a check, so a string ``type``, a string ``event_id``,
``schema_version=True`` (which compares equal to ``1``), and an empty
``group.source_group_id`` all used to construct. They are validation only: no
field is added, removed, or retyped, and ``SCHEMA_VERSION`` stays ``1``
.

Three readings are recorded so a reviewer can check them instead of finding them
in a diff:

- ``event_id`` is a ``UUID`` and ``source_event_id`` is a ``str``. Design 8's
  envelope carries the canonical id as a UUID and design 9.1 stores it as
  ``event_id uuid``, while ``source_event_id`` is the vendor's opaque id, whose
  form this service does not own.
- The type vocabulary is closed by the enum. An eighth type cannot be named, and
  ``EventType ("user.merged")`` raises the standard library's ``ValueError``, so
  there is no bespoke membership check.
- ``person`` and ``group`` are individually optional and at least one is
  required. Design 7's list mixes ``user.*`` events, which name no group, with
  ``group.*`` events, so one universal presence rule would reject a legal
  ``user.deleted``. Which member each type requires is not stated by the design
  and is not decided here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from identity_lifecycle.domain.errors import PermanentError

#: Design 8 is the first version of the envelope. Changing it needs a migration
#: note and an ADR; this module never writes another value.
SCHEMA_VERSION = 1


class EventType(StrEnum):
    """The seven canonical types, and no eighth."""

    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DISABLED = "user.disabled"
    USER_DELETED = "user.deleted"
    GROUP_MEMBER_ADDED = "group.member_added"
    GROUP_MEMBER_REMOVED = "group.member_removed"
    GROUP_UPDATED = "group.updated"


class EventValidationError(PermanentError):
    """An event that cannot describe itself; retrying it changes nothing."""


@dataclass(frozen=True)
class EventPerson:
    """The person an event names.

    ``employee_number`` is a hint, never authoritative: a consumer resolves it by
    re-reading the source, and a missing value
    is a fallback, not an error. It is required-but-nullable,
    as ``Person.employee_number`` is in ``models.py``.

    Frozen like the envelope that holds it: a frozen envelope over a mutable
    person could still be made invalid after validation.
    """

    source_user_id: str
    employee_number: str | None


@dataclass(frozen=True)
class EventGroup:
    """The group an event names.

        ``source_group_id`` is the group's stable identity, never its display name
    ; ``name`` travels for the reader's benefit only.
    """

    source_group_id: str
    name: str


@dataclass(frozen=True)
class CanonicalEvent:
    """One canonical event, shaped as design 8's envelope defines it.

    The envelope is the unit of validation: a member record on its own is a
    value, and the invariants below are stated here, once, so no caller can hold
    a half-valid event. Frozen, because a mutable envelope could be made invalid
    after construction.
    """

    event_id: UUID
    source: str
    source_event_id: str
    type: EventType
    occurred_at: datetime
    person: EventPerson | None
    group: EventGroup | None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.type, EventType):
            raise EventValidationError(
                f"type must be an EventType; got {self.type!r}. The vocabulary is closed "
                "(design 7); a string is not a member"
            )
        if not isinstance(self.event_id, UUID):
            raise EventValidationError(
                f"event_id must be a UUID; got {self.event_id!r}. Design 9.1 stores it as "
                "event_id uuid"
            )
        # ``bool`` is an ``int`` subclass, so ``True == 1`` would pass the version
        # comparison. The envelope has one integer version, never a boolean.
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise EventValidationError(
                f"schema_version must be an int; got {self.schema_version!r}"
            )
        if self.schema_version != SCHEMA_VERSION:
            raise EventValidationError(
                f"schema_version must be {SCHEMA_VERSION}; got {self.schema_version!r}"
            )
        if not _is_utc(self.occurred_at):
            raise EventValidationError(
                f"occurred_at must be an aware UTC instant; got {self.occurred_at!r}"
            )
        _require_text("source", self.source)
        _require_text("source_event_id", self.source_event_id)
        if self.person is None and self.group is None:
            raise EventValidationError("an event must name at least one subject: person or group")
        if self.person is not None:
            _require_text("person.source_user_id", self.person.source_user_id)
        if self.group is not None:
            _require_text("group.source_group_id", self.group.source_group_id)


def _is_utc(moment: datetime) -> bool:
    """Return whether ``moment`` is an aware instant at offset zero from UTC.

    A naive datetime has ``utcoffset is None``, so the first test rejects it;
    a non-zero offset is an instant in another zone, and converting it is the
    adapter's job. Comparing against ``timedelta`` is
    the timestamp rule, not the out-of-scope clock-skew comparison
    """
    offset = moment.utcoffset()
    return offset is not None and offset == timedelta(0)


def _require_text(name: str, value: str) -> None:
    if not value:
        raise EventValidationError(f"{name} must be a non-empty string")
