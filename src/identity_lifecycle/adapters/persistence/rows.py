"""Row to domain value, and the type checks that keep a ``Row`` from escaping.

Every function here takes a ``RowMapping`` and returns a ``domain.models``
dataclass. The column names are the migration's, the field names are the
domain's, and the two are translated once, in this module (design 15.2: vendor
and storage spellings stop at the boundary).

A value the column type does not allow raises ``StoreError`` rather than being
coerced. Coercion would hide schema drift — a ``text`` where a ``uuid`` belongs
is a migration bug, not a value to repair on read — and ``StoreError`` is
permanent, so a caller does not retry it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, cast
from uuid import UUID

from sqlalchemy.engine import RowMapping

from identity_lifecycle.adapters.persistence.errors import StoreError
from identity_lifecycle.domain.models import (
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceIdentity,
)


def person_from_row(row: RowMapping) -> Person:
    """Build a ``Person`` from one ``persons`` row."""
    return Person(
        person_id=_text(row, "person_id"),
        employee_number=_optional_text(row, "employee_number"),
        email=_text(row, "email"),
        display_name=_text(row, "display_name"),
        status=_text(row, "status"),
    )


def identity_from_row(row: RowMapping) -> SourceIdentity:
    """Build a ``SourceIdentity`` from one ``source_identities`` row."""
    return SourceIdentity(
        source=_text(row, "source"),
        source_user_id=_text(row, "source_user_id"),
        person_id=_text(row, "person_id"),
    )


def entitlement_from_row(row: RowMapping) -> Entitlement:
    """Build an ``Entitlement`` from one ``entitlements`` row.

    ``entitlement_id`` is a storage key the domain does not model, so it is not
    read: a row is identified by what it says, not by its surrogate key.
    """
    return Entitlement(
        person_id=_text(row, "person_id"),
        role=_text(row, "role"),
        team=_text(row, "team"),
        budget_policy=_text(row, "budget_policy"),
        source=_text(row, "source"),
        effective_from=_timestamp(row, "effective_from"),
        effective_to=_optional_timestamp(row, "effective_to"),
    )


def account_from_row(row: RowMapping) -> LiteLLMAccount:
    """Build a ``LiteLLMAccount`` from one ``litellm_accounts`` row.

       ``budget`` is ``numeric`` and arrives as ``Decimal``; the domain
       field is a ``float``, so the conversion happens here, once.
       ``delete_after`` is a gateway-side deadline the domain does not model
    (migration 0002), so it is not read.
    """
    budget = row["budget"]
    if not isinstance(budget, Decimal):
        raise StoreError(f"litellm_accounts.budget is {type(budget).__name__}, not numeric")
    return LiteLLMAccount(
        user_id=_text(row, "user_id"),
        status=_text(row, "status"),
        role=_text(row, "role"),
        team=_text(row, "team"),
        budget=float(budget),
        keys=_key_identifiers(row["keys"]),
    )


def member_ids(rows: Sequence[RowMapping]) -> frozenset[str]:
    """Collect the ``source_user_id`` values of a snapshot's rows."""
    return frozenset(_text(row, "source_user_id") for row in rows)


def payload_of(row: RowMapping) -> Mapping[str, Any]:
    """Return the ``jsonb`` payload of one outbox row as a mapping."""
    payload = row["payload"]
    if not isinstance(payload, dict):
        raise StoreError(f"identity_event_outbox.payload is {type(payload).__name__}, not jsonb")
    return cast(Mapping[str, Any], payload)


def row_id_of(row: RowMapping) -> UUID:
    """Return the surrogate primary key of one outbox row, ``id``.

    This is **not** the canonical ``event_id``: ``id`` is ``gen_random_uuid``
    per row, while ``event_id`` is the envelope's id and the column every
    ``where event_id =...`` clause matches. Naming the two apart is what keeps
    a dead-letter update from silently matching no row.
    """
    value = row["id"]
    if not isinstance(value, UUID):
        raise StoreError(f"identity_event_outbox.id is {type(value).__name__}, not uuid")
    return value


def event_id_of(row: RowMapping) -> UUID:
    """Return the canonical ``event_id`` of one outbox row.

    A caller that selects the row must ask for ``event_id`` explicitly; the
    claim query does, because ``settle`` and the poison dead-letter both match
    on it rather than on ``id``.
    """
    value = row["event_id"]
    if not isinstance(value, UUID):
        raise StoreError(f"identity_event_outbox.event_id is {type(value).__name__}, not uuid")
    return value


def _text(row: RowMapping, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        raise StoreError(f"{column} is {type(value).__name__}, not text")
    return value


def _optional_text(row: RowMapping, column: str) -> str | None:
    value = row[column]
    if value is None:
        return None
    if not isinstance(value, str):
        raise StoreError(f"{column} is {type(value).__name__}, not text")
    return value


def _timestamp(row: RowMapping, column: str) -> datetime:
    value = row[column]
    if not isinstance(value, datetime):
        raise StoreError(f"{column} is {type(value).__name__}, not timestamptz")
    return value


def _optional_timestamp(row: RowMapping, column: str) -> datetime | None:
    value = row[column]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise StoreError(f"{column} is {type(value).__name__}, not timestamptz")
    return value


def _key_identifiers(value: object) -> tuple[str, ...]:
    """Read ``litellm_accounts.keys``: key identifiers only, never a secret."""
    if not isinstance(value, list):
        raise StoreError(f"litellm_accounts.keys is {type(value).__name__}, not a json array")
    identifiers: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            raise StoreError("litellm_accounts.keys holds a non-string identifier")
        identifiers.append(item)
    return tuple(identifiers)
