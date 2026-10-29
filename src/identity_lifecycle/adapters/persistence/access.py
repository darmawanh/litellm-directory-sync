"""The ``entitlements``, ``litellm_accounts``, and ``audit_events`` repositories.

The three write-side records of one decision. Each keeps the
storage-only columns out of the domain value: ``entitlement_id`` is a surrogate
key, ``delete_after`` is a gateway-side deadline, and ``audit_events.source``
comes from the unit of work's source rather than the record (migration 0002's
docstring: "The writer supplies it from the canonical event").
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

from identity_lifecycle.adapters.persistence.rows import (
    account_from_row,
    entitlement_from_row,
)
from identity_lifecycle.domain.models import AuditEvent, Entitlement, LiteLLMAccount
from identity_lifecycle.ports.unit_of_work import AuditEntry, ReconciliationMiss


class EntitlementStore:
    """The ``entitlements`` rows: the access decision in force."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def current_for(self, person_id: str) -> Entitlement | None:
        """Return the open entitlement (``effective_to`` null), or ``None``.

        The order is newest first so a person with two open rows — which only a
        hand-written insert can produce — answers with the later decision.
        """
        row = (
            self._connection.execute(
                text(
                    "select person_id, role, team, budget_policy, source,"
                    " effective_from, effective_to from entitlements"
                    " where person_id = :person_id and effective_to is null"
                    " order by effective_from desc, entitlement_id"
                ),
                {"person_id": person_id},
            )
            .mappings()
            .first()
        )
        return None if row is None else entitlement_from_row(row)

    def save(self, entitlement: Entitlement) -> None:
        """Insert the new entitlement and close the one it replaces.

        Closing is scoped to the same person and to an **earlier** instant, and
        the insert is skipped when that instant is already stored. A repeated
        save therefore leaves one row, not two, and a replay of an older event
        cannot close the newer decision that already replaced it — the re-read
        converges on the current source state.
        """
        self._connection.execute(
            text(
                "update entitlements set effective_to = :effective_from"
                " where person_id = :person_id"
                " and effective_to is null"
                " and effective_from < :effective_from"
            ),
            {
                "person_id": entitlement.person_id,
                "effective_from": entitlement.effective_from,
            },
        )
        self._connection.execute(
            text(
                "insert into entitlements"
                " (person_id, role, team, budget_policy, source, effective_from, effective_to)"
                " select :person_id, :role, :team, :budget_policy, :source,"
                " :effective_from, :effective_to"
                " where not exists ("
                " select 1 from entitlements"
                " where person_id = :person_id and effective_from = :effective_from)"
            ),
            {
                "person_id": entitlement.person_id,
                "role": entitlement.role,
                "team": entitlement.team,
                "budget_policy": entitlement.budget_policy,
                "source": entitlement.source,
                "effective_from": entitlement.effective_from,
                "effective_to": entitlement.effective_to,
            },
        )


class AccountStore:
    """The ``litellm_accounts`` rows: the gateway state at the last read."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get(self, user_id: str) -> LiteLLMAccount | None:
        """Return the stored account for one gateway user id, or ``None``."""
        row = (
            self._connection.execute(
                text(
                    "select user_id, status, role, team, budget, keys"
                    " from litellm_accounts where user_id = :user_id"
                ),
                {"user_id": user_id},
            )
            .mappings()
            .first()
        )
        return None if row is None else account_from_row(row)

    def save(self, account: LiteLLMAccount, delete_after: datetime | None = None) -> None:
        """Record the account exactly as the gateway's read-back returned it."""
        self._connection.execute(
            text(
                "insert into litellm_accounts"
                " (user_id, status, role, team, budget, keys, delete_after)"
                " values (:user_id, :status, :role, :team, :budget,"
                " cast(:keys as jsonb), :delete_after)"
                " on conflict (user_id) do update set"
                " status = excluded.status,"
                " role = excluded.role,"
                " team = excluded.team,"
                " budget = excluded.budget,"
                " keys = excluded.keys,"
                " delete_after = excluded.delete_after"
            ),
            {
                "user_id": account.user_id,
                "status": account.status,
                "role": account.role,
                "team": account.team,
                "budget": account.budget,
                "keys": json.dumps(list(account.keys)),
                "delete_after": delete_after,
            },
        )

    def list_all(self) -> tuple[LiteLLMAccount, ...]:
        """Return every stored account."""
        rows = (
            self._connection.execute(
                text(
                    "select user_id, status, role, team, budget, keys"
                    " from litellm_accounts"
                    " order by user_id"
                )
            )
            .mappings()
            .all()
        )
        return tuple(account_from_row(row) for row in rows)

    def list_pending_deletions(self, before: datetime) -> tuple[str, ...]:
        """Return user_ids of accounts whose grace period has expired on or before ``before``."""
        rows = (
            self._connection.execute(
                text(
                    "select user_id from litellm_accounts"
                    " where delete_after is not null and delete_after <= :before"
                    " order by delete_after, user_id"
                ),
                {"before": before},
            )
            .scalars()
            .all()
        )
        return tuple(rows)

    def delete(self, user_id: str) -> None:
        """Remove an account record after gateway deletion."""
        self._connection.execute(
            text("delete from litellm_accounts where user_id = :user_id"),
            {"user_id": user_id},
        )

    def get_delete_after(self, user_id: str) -> datetime | None:
        """Return the scheduled deletion instant for an account, or ``None``."""
        return (
            self._connection.execute(
                text("select delete_after from litellm_accounts where user_id = :user_id"),
                {"user_id": user_id},
            )
            .scalars()
            .first()
        )


class AuditStore:
    """The ``audit_events`` rows: one per decision, append-only."""

    def __init__(self, connection: Connection, *, source: str) -> None:
        self._connection = connection
        self._source = source

    def append(self, record: AuditEvent) -> None:
        """Append the record; an audit row is never updated or deleted.

        ``source`` is the unit of work's source, not a field of ``AuditEvent``:
        design 8's table does not carry it, FR14 names it in the record, and
        migration 0002 records that the writer supplies it from the event.
        """
        self._connection.execute(
            text(
                "insert into audit_events"
                " (event_id, source_event_id, source, actor, action, target,"
                " decision, reason, occurred_at)"
                " values (:event_id, :source_event_id, :source, :actor, :action,"
                " :target, :decision, :reason, :occurred_at)"
            ),
            {
                "event_id": record.event_id,
                "source_event_id": record.source_event_id,
                "source": self._source,
                "actor": record.actor,
                "action": record.action,
                "target": record.target,
                "decision": record.decision,
                "reason": record.reason,
                "occurred_at": record.timestamp,
            },
        )

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        employee_number: str | None = None,
        source_user_id: str | None = None,
    ) -> tuple[AuditEntry, ...]:
        """Query audit events matching the criteria."""
        conditions: list[str] = []
        params: dict[str, Any] = {}

        if since is not None:
            conditions.append("a.occurred_at >= :since")
            params["since"] = since

        if until is not None:
            conditions.append("a.occurred_at <= :until")
            params["until"] = until

        if employee_number is not None:
            conditions.append(
                "(p.employee_number = :employee_number OR a.target = :employee_number)"
            )
            params["employee_number"] = employee_number

        if source_user_id is not None:
            conditions.append(
                "(a.target IN ("
                "SELECT person_id FROM source_identities WHERE source_user_id = :source_user_id"
                ") OR a.target = :source_user_id)"
            )
            params["source_user_id"] = source_user_id

        where_clause = ""
        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)

        stmt = text(
            "SELECT a.event_id, a.occurred_at, a.actor, a.action, a.source, "
            "a.target AS person_id, p.employee_number, p.email, a.reason, "
            "a.decision, a.source_event_id "
            "FROM audit_events a "
            "LEFT JOIN persons p ON a.target = p.person_id"
            f"{where_clause} "
            "ORDER BY a.occurred_at ASC, a.event_id ASC"
        )
        rows = self._connection.execute(stmt, params).mappings().all()
        results: list[AuditEntry] = []
        for row in rows:
            occurred_at = row["occurred_at"]
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=UTC)
            else:
                occurred_at = occurred_at.astimezone(UTC)
            results.append(
                AuditEntry(
                    event_id=row["event_id"],
                    occurred_at=occurred_at,
                    actor=row["actor"],
                    action=row["action"],
                    source=row["source"],
                    person_id=row["person_id"],
                    employee_number=row["employee_number"],
                    email=row["email"],
                    reason=row["reason"],
                    decision=row["decision"],
                    details=row["source_event_id"],
                )
            )
        return tuple(results)


class ReconciliationMissStore:
    """The ``reconciliation_misses`` rows (migration 0003)."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get(self, person_id: str, source: str) -> ReconciliationMiss | None:
        """Return the miss record for one person and source, or ``None``."""
        row = (
            self._connection.execute(
                text(
                    "select person_id, source, miss_count, last_seen_at"
                    " from reconciliation_misses"
                    " where person_id = :person_id and source = :source"
                ),
                {"person_id": person_id, "source": source},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        return ReconciliationMiss(
            person_id=str(row["person_id"]),
            source=str(row["source"]),
            miss_count=int(row["miss_count"]),
            last_seen_at=row["last_seen_at"],
        )

    def record_miss(self, person_id: str, source: str, seen_at: datetime) -> ReconciliationMiss:
        """Increment or insert the miss count for one person and source."""
        row = (
            self._connection.execute(
                text(
                    "insert into reconciliation_misses"
                    " (person_id, source, miss_count, last_seen_at)"
                    " values (:person_id, :source, 1, :seen_at)"
                    " on conflict (person_id, source) do update set"
                    " miss_count = reconciliation_misses.miss_count + 1,"
                    " last_seen_at = excluded.last_seen_at"
                    " returning person_id, source, miss_count, last_seen_at"
                ),
                {"person_id": person_id, "source": source, "seen_at": seen_at},
            )
            .mappings()
            .one()
        )
        return ReconciliationMiss(
            person_id=str(row["person_id"]),
            source=str(row["source"]),
            miss_count=int(row["miss_count"]),
            last_seen_at=row["last_seen_at"],
        )

    def clear(self, person_id: str, source: str) -> None:
        """Clear the miss record when the person is found in the source."""
        self._connection.execute(
            text(
                "delete from reconciliation_misses"
                " where person_id = :person_id and source = :source"
            ),
            {"person_id": person_id, "source": source},
        )

    def list_all(self) -> tuple[ReconciliationMiss, ...]:
        """Return every stored miss record."""
        rows = (
            self._connection.execute(
                text(
                    "select person_id, source, miss_count, last_seen_at"
                    " from reconciliation_misses"
                    " order by person_id, source"
                )
            )
            .mappings()
            .all()
        )
        return tuple(
            ReconciliationMiss(
                person_id=str(r["person_id"]),
                source=str(r["source"]),
                miss_count=int(r["miss_count"]),
                last_seen_at=r["last_seen_at"],
            )
            for r in rows
        )
