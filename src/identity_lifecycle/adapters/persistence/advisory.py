"""Per-person serialization: session-scoped advisory locks.

The lock is **session-scoped** (``pg_advisory_lock``), not transaction-scoped.
ADR-002 section 4 commits the claim before the vendor call, so a
``pg_advisory_xact_lock`` taken at claim is released at that commit — before the
work it was meant to exclude. A session lock outlives every transaction on the
connection and is released in a ``finally`` after settle, which is exactly the
use case's span.

Three keys, namespaced, taken in one fixed order and only when each exists:

1. ``identity:<person_key>`` — whenever the event names a person.
2. ``link:<employee_number>`` — when the link is present and unambiguous.
3. ``person:<person_id>`` — when the person is resolved.

The order is fixed so the at-most-three locks cannot deadlock. The key text is
hashed in SQL with ``hashtextextended (key)``: a hash collision over-serializes
and can never under-serialize, so it costs throughput and never correctness.

Nothing here reads a table. The keys come from the envelope and, for the link and
person keys, from reads the caller makes through the unit of work.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager

from sqlalchemy import text
from sqlalchemy.engine import Connection

#: The three namespaces, in acquisition order.
IDENTITY = "identity"
LINK = "link"
PERSON = "person"


def identity_key(person_key: str) -> str:
    """Return the key for one source identity, ``identity:<person_key>``."""
    return f"{IDENTITY}:{person_key}"


def link_key(employee_number: str) -> str:
    """Return the key for one unambiguous employee link, ``link:<number>``."""
    return f"{LINK}:{employee_number}"


def person_key_lock(person_id: str) -> str:
    """Return the key for one resolved person, ``person:<person_id>``."""
    return f"{PERSON}:{person_id}"


def lock_keys(
    *,
    person_key: str | None,
    employee_number: str | None = None,
    person_id: str | None = None,
) -> tuple[str, ...]:
    """Return the keys to take,'s fixed order.

    Each argument is included only when it exists: an event naming no person
    takes no lock, and a link that was ambiguous is not passed at all, because
    ``link:`` is the key two sources share only when the link is unambiguous.
    """
    keys: list[str] = []
    if person_key is not None:
        keys.append(identity_key(person_key))
    if employee_number is not None:
        keys.append(link_key(employee_number))
    if person_id is not None:
        keys.append(person_key_lock(person_id))
    return tuple(keys)


@contextmanager
def hold_locks(connection: Connection, keys: Sequence[str]) -> Iterator[None]:
    """Take every key in order, blocking, and release all of them on exit.

    ``pg_advisory_lock`` blocks until the key is free, so two events for one
    person run one after the other rather than both reading the same state. The
    release runs in ``finally``, so an exception between acquire and settle still
    frees the key; the connection's own close would release it too, but relying
    on that would hold the lock for as long as the connection lives.
    """
    acquired: list[str] = []
    try:
        for key in keys:
            connection.execute(
                text("select pg_advisory_lock(hashtextextended(:key, 0))"), {"key": key}
            )
            acquired.append(key)
        yield
    finally:
        for key in reversed(acquired):
            connection.execute(
                text("select pg_advisory_unlock(hashtextextended(:key, 0))"), {"key": key}
            )
