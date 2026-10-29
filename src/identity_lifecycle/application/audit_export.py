"""Audit export use case: export access decision records for compliance and audit.

Provides query and formatting of audit log events filtered by date range,
employee number, or source user identifier in RFC 4180 CSV or JSON formats.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import AuditEntry

EXPORT_COLUMNS = (
    "event_id",
    "timestamp",
    "actor",
    "action",
    "source",
    "person_id",
    "employee_number",
    "email",
    "reason",
    "outcome",
    "details",
)


class AuditExportError(PermanentError):
    """An invalid audit export query or parameter."""


def _entry_to_dict(entry: AuditEntry) -> dict[str, Any]:
    return {
        "event_id": str(entry.event_id),
        "timestamp": entry.occurred_at.isoformat(),
        "actor": entry.actor,
        "action": entry.action,
        "source": entry.source,
        "person_id": entry.person_id,
        "employee_number": entry.employee_number,
        "email": entry.email,
        "reason": entry.reason,
        "outcome": entry.decision,
        "details": entry.details,
    }


def _entry_to_csv_row(entry: AuditEntry) -> dict[str, str]:
    return {
        "event_id": str(entry.event_id),
        "timestamp": entry.occurred_at.isoformat(),
        "actor": entry.actor,
        "action": entry.action,
        "source": entry.source,
        "person_id": entry.person_id,
        "employee_number": entry.employee_number or "",
        "email": entry.email or "",
        "reason": entry.reason,
        "outcome": entry.decision,
        "details": entry.details,
    }


class AuditExport:
    """The audit export use case."""

    def __init__(self, unit_of_work: UnitOfWorkFactory, clock: Clock) -> None:
        self._unit_of_work = unit_of_work
        self._clock = clock

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        employee_number: str | None = None,
        source_user_id: str | None = None,
    ) -> tuple[AuditEntry, ...]:
        """Query audit entries matching the filters."""
        if employee_number is not None and source_user_id is not None:
            raise AuditExportError("Cannot filter by both employee_number and source_user_id")

        resolved_until = until if until is not None else self._clock.now()
        if since is not None and since > resolved_until:
            raise AuditExportError(
                f"Start date ({since.isoformat()}) must not be after "
                f"end date ({resolved_until.isoformat()})"
            )

        with self._unit_of_work("audit_export") as uow:
            return uow.audit.query(
                since=since,
                until=resolved_until,
                employee_number=employee_number,
                source_user_id=source_user_id,
            )

    @staticmethod
    def to_csv(entries: Sequence[AuditEntry]) -> str:
        """Format audit entries as RFC 4180 CSV with header row."""
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=list(EXPORT_COLUMNS),
            lineterminator="\r\n",
        )
        writer.writeheader()
        for entry in entries:
            writer.writerow(_entry_to_csv_row(entry))
        return output.getvalue()

    @staticmethod
    def to_json(entries: Sequence[AuditEntry], *, indent: int = 2) -> str:
        """Format audit entries as a JSON array."""
        data = [_entry_to_dict(entry) for entry in entries]
        return json.dumps(data, indent=indent) + "\n"

    @staticmethod
    def to_ndjson(entries: Sequence[AuditEntry]) -> str:
        """Format audit entries as newline-delimited JSON."""
        lines = [json.dumps(_entry_to_dict(entry)) for entry in entries]
        return "\n".join(lines) + ("\n" if lines else "")

    def export(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        employee_number: str | None = None,
        source_user_id: str | None = None,
        format: str = "csv",
        output: Path | None = None,
    ) -> str:
        """Query and export audit entries in the specified format."""
        entries = self.query(
            since=since,
            until=until,
            employee_number=employee_number,
            source_user_id=source_user_id,
        )

        normalized_format = format.lower()
        if normalized_format == "csv":
            formatted = self.to_csv(entries)
        elif normalized_format == "json":
            formatted = self.to_json(entries)
        elif normalized_format == "ndjson":
            formatted = self.to_ndjson(entries)
        else:
            raise AuditExportError(
                f"Unsupported export format: {format!r} (choose from csv, json, ndjson)"
            )

        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(formatted.encode("utf-8"))

        return formatted
