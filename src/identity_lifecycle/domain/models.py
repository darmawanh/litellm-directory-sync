"""The six canonical entities of design section 8, as plain dataclasses.

These are records, not policy. Every field is a value the store or an adapter
supplies, and no model here decides anything: behaviour lives in ``policy.py``
, so there is no ``is_entitled``, no status transition, and no
validator. Pydantic is for config, HTTP payloads, and vendor responses only
.

Vendor spellings stop at the adapter boundary. A person
carries ``employee_number``, never ``employeeID`` or ``employeeNumber``; a
gateway account carries key identifiers, never a LiteLLM payload.

Every timestamp is an aware ``datetime`` in UTC. The
domain neither parses nor formats RFC 3339 strings; that is the adapter's and
the loader's business.

Identifiers are typed by the record that owns them: ``person_id``,
``source_user_id``, ``source_group_id`` and ``user_id`` are ``str``, because the
store and the adapters fix their textual form (``source_user_id`` is the
canonical lowercase UUID string of AD's ``objectGUID``, ADR-005 section 1), and
``event_id`` is a ``UUID`` because design 8's envelope carries the canonical
event id as a UUID and design 9.1 stores that id as ``event_id uuid``, so the
audit writer needs no cast at either end.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

#: Design 10.5 step 2 is the only place the design fixes this vocabulary: a
#: person is reactivated by reusing the same ``person_id``. A source account
#: that is disabled is a source-side fact (Phase 3/6), not a person
#: status, so there is no third value.
ACTIVE = "active"
INACTIVE = "inactive"


@dataclass
class Person:
    """One employee.

        ``employee_number`` is a nullable cross-system link, never an identity
    : a person with no employee number is a valid
        object, and a deleted-and-recreated account without one is a new person.
    """

    person_id: str
    employee_number: str | None
    email: str
    display_name: str
    status: str


@dataclass
class SourceIdentity:
    """The link from one source object to a person."""

    source: str
    source_user_id: str
    person_id: str


@dataclass
class SourceGroup:
    """The source group that grants access.

    ``source_group_id`` holds the AD group DN or the Okta group id, never the
    group's display name, which is not stable.
    """

    source: str
    source_group_id: str
    name: str


@dataclass
class Entitlement:
    """The access decision in force for a person.

    ``effective_to`` is ``None`` while the entitlement is open; a closed
    entitlement names the instant it ended. ``budget_policy`` names the policy
    that won resolution; the policy's values are not copied here.
    """

    person_id: str
    role: str
    team: str
    budget_policy: str
    source: str
    effective_from: datetime
    effective_to: datetime | None


@dataclass
class LiteLLMAccount:
    """The gateway state as last read back.

    ``keys`` holds key identifiers only, never a vendor payload: the full
    LiteLLM response stops at ``adapters/litellm``, and a key's
    secret is never stored here.
    """

    user_id: str
    status: str
    role: str
    team: str
    budget: float
    keys: tuple[str, ...]


@dataclass
class AuditEvent:
    """One record of an access decision.

    ``timestamp`` is the name design 8's table gives this field. The Phase 2
    ``audit_events`` column that stores it is ``occurred_at`` (plan 5.2); that
    is a storage name, not this field's name, and renaming the field to match
    the migration would put a database concern in the domain.
    """

    event_id: UUID
    source_event_id: str
    actor: str
    action: str
    target: str
    decision: str
    reason: str
    timestamp: datetime
