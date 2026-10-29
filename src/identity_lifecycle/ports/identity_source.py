"""The identity source contract: read-only, synchronous, pull-only.

Eight methods, and no ninth: the block is ADR-014 section 3's, restated rather
than invented. There is no write verb, no membership write, no push or stream
method, no ``async def``, and no vendor type. A source
is read by ``poll_changes`` or by a full enumeration; ingest that arrives from
outside is the hook route's HTTP request, which calls ``normalize``. The service
opens no subscription.

The four read methods speak in this module's own values, not a vendor payload:
``IdentityUser`` is the source's record, and ``Person`` is the canonical store's
record, created only after resolution. ``IdentityUser`` and
``IdentityGroup`` are therefore defined here rather than in ``domain/models.py``,
whose six entities are design section 8's table exactly; ADR-011 section 3 calls
these types dataclasses, which is the property that matters, not their module.

Three shapes are recorded so a reviewer can check them instead of inferring
them:

- ``Page.next_cursor`` is an opaque string or ``None``; ``None`` means the page
  is the last one. The cursor is opaque because one source's token may be a
  counter and another's a base64 page marker, with nothing in common (ADR-005
  section 8, ADR-008 section 1).
- ``get_user`` returns ``IdentityUser | None``. ADR-014 section 4 leaves the
  not-found shape to this ticket: a read that finds no such user is an outcome,
  not an error, and a deletion is exactly the case the worker must be able
  to see. A transport or authentication failure is still a typed error.
- ``normalize`` and ``poll_changes`` return ``CanonicalEvent | EventCondition``,
  never raise for a bad body: a verification challenge, an
  unsupported type, and an incomplete payload are outcomes the route
  acknowledges and the poller counts. ``EventCondition`` lives here, not in the
  domain, because the domain knows events and errors, not this service's
  acknowledgement vocabulary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from identity_lifecycle.domain.events import CanonicalEvent

T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of a read, with the token that asks for the next one.

    ``next_cursor`` is ``None`` on the last page. Frozen, so a page handed to
    another layer cannot be re-pointed at a different cursor afterwards; the
    cursor is the source's state and only the adapter may advance it.
    """

    items: tuple[T, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class Capabilities:
    """What a source can be read for, in three booleans and no vendor field.

    Each answers a question the core already asks: whether the poller has a
    change feed to advance, whether reconciliation can enumerate
    the group, and whether the worker can re-read one user by its
    source identifier. A capability that no caller
    branches on would be dead configuration, so the set is this small.
    """

    incremental_changes: bool
    full_snapshot: bool
    group_membership: bool


@dataclass(frozen=True)
class EventCondition:
    """An outcome that is not an event and must not be dropped.

    ``code`` is the acknowledgement vocabulary the route and the poller branch
    on; ``detail`` is for the operator. There is no ``permanent`` flag: a
    condition is an outcome, not a failure, so it is neither retried nor
    classified. A body that is malformed enough to be a server fault is
    still a condition, because the route answers it with a 4xx and the poller
    counts it.
    """

    code: str
    detail: str


@dataclass(frozen=True)
class IdentityUser:
    """One user as the source holds it.

    ``source_user_id`` is the source identity and never the cross-system link:
    the source's own immutable identifier. ``employee_number`` is the nullable
    link, used only when unambiguous. ``enabled`` carries
    the source-side disable fact, which ADR-005 section 6 requires because a
    disabled member is still listed and is not entitled.
    """

    source_user_id: str
    employee_number: str | None
    email: str
    display_name: str
    enabled: bool


@dataclass(frozen=True)
class IdentityGroup:
    """One group as the source holds it.

        ``source_group_id`` is the group's stable identifier, never its display name
    ; the name travels for the reader's benefit only.
    """

    source_group_id: str
    name: str


class IdentitySource(Protocol):
    """The read-only contract both adapters implement."""

    def name(self) -> str:
        """Return the configured ``source_name`` this instance reads.

        It is the value ``person_key`` and the mappings key on, so it is the
        configured name, not the vendor's product name.
        """
        ...

    def capabilities(self) -> Capabilities:
        """Return what this source can be read for."""
        ...

    def list_users(self, cursor: str | None) -> Page[IdentityUser]:
        """Return one page of every user in scope; ``None`` starts at the first.

        Full enumeration is reconciliation's input, and reconciliation is the
        truth when a change feed has missed something.
        """
        ...

    def get_user(self, source_user_id: str) -> IdentityUser | None:
        """Return one user as the source holds it now, or ``None``.

        This is the re-read the worker performs before it decides: the event is
        a trigger and this is the truth. ``None`` is the outcome "the source no
        longer has this object", which is what a deletion looks like.
        """
        ...

    def list_groups(self, cursor: str | None) -> Page[IdentityGroup]:
        """Return one page of every group in scope."""
        ...

    def get_group_members(self, group_id: str, cursor: str | None) -> Page[IdentityUser]:
        """Return one page of a group's members.

                ``group_id`` is the source group identifier, never the group's name
        . Membership is the entitlement signal, so an
                incomplete read of this method is a failure to retry, never an empty
                group.
        """
        ...

    def poll_changes(self, cursor: str | None) -> Page[CanonicalEvent | EventCondition]:
        """Return one page of changes after ``cursor``; ``None`` starts a full sync.

        The cursor is opaque: this module never parses it, and neither does the
        use case. A page mixes events and
        conditions so the poller counts a skipped entry instead of failing the
        page.
        """
        ...

    def normalize(self, raw_event: Mapping[str, object]) -> CanonicalEvent | EventCondition:
        """Map one already-parsed vendor body to an event or a typed condition.

        Both feeds call this one method, so the hook route and the log poller
        cannot drift. The body is a mapping, not a
        vendor model, and it is read, never mutated: converting it into the
        envelope is the adapter's job.
        """
        ...
