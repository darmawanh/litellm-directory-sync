"""Administrative HTTP API routes for manual sync, reconcile, and audit export.

Implements FR13, FR14, FR17, FR30, ADR-007, and ADR-021.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from identity_lifecycle.api.auth import AdminToken
from identity_lifecycle.application.audit_export import AuditExport, AuditExportError
from identity_lifecycle.application.manual_sync import (
    AmbiguousLinkError,
    ManualSync,
    NotFoundError,
)
from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.observability.metrics import record_admin_auth_rejected

logger = structlog.get_logger(__name__)


class SyncRequest(BaseModel):
    """Payload for operator-requested single identity synchronization."""

    employee: str | None = None
    user: str | None = None


def get_admin_auth(
    admin_token: AdminToken,
) -> Callable[[Request], None]:
    """Return a FastAPI dependency verifying the admin bearer token."""

    def _verify(request: Request) -> None:
        values = request.headers.getlist("authorization")
        result = admin_token.verify(values)
        if not result.accepted:
            record_admin_auth_rejected(result.value)
            raise HTTPException(status_code=401, detail="unauthorized")

    return _verify


def _parse_iso_timestamp(param_name: str, value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid ISO-8601 timestamp for {param_name}: {value!r}",
        ) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def create_admin_router(
    admin_token: AdminToken,
    *,
    audit_export: AuditExport | None = None,
    manual_sync: ManualSync | None = None,
    reconcile: Reconcile | None = None,
) -> APIRouter:
    """Build and configure the APIRouter for administrative endpoints."""
    router = APIRouter(
        prefix="/api/v1",
        dependencies=[Depends(get_admin_auth(admin_token))],
    )

    @router.get("/audit/export")
    def get_audit_export(
        from_: str | None = Query(None, alias="from"),
        to: str | None = Query(None),
        employee: str | None = Query(None),
        user: str | None = Query(None),
        format: str = Query("json"),
    ) -> Response:
        if audit_export is None:
            raise HTTPException(
                status_code=503,
                detail="audit_export_not_configured",
            )

        since = _parse_iso_timestamp("from", from_)
        until = _parse_iso_timestamp("to", to)

        try:
            payload = audit_export.export(
                since=since,
                until=until,
                employee_number=employee,
                source_user_id=user,
                format=format,
            )
        except AuditExportError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        normalized_format = format.lower()
        if normalized_format == "csv":
            media_type = "text/csv"
        elif normalized_format == "ndjson":
            media_type = "application/x-ndjson"
        else:
            media_type = "application/json"

        return Response(content=payload, media_type=media_type)

    @router.post("/sync")
    def post_sync(request: SyncRequest) -> dict[str, Any]:
        if (request.employee is None and request.user is None) or (
            request.employee is not None and request.user is not None
        ):
            raise HTTPException(
                status_code=400,
                detail="Provide exactly one of employee or user",
            )

        if manual_sync is None:
            raise HTTPException(
                status_code=503,
                detail="manual_sync_not_configured",
            )

        try:
            result = manual_sync.sync(
                employee_number=request.employee,
                source_user_id=request.user,
            )
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AmbiguousLinkError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        logger.info(
            "admin_manual_sync_completed",
            person_id=result.person_id,
            source=result.source,
            source_user_id=result.source_user_id,
            event_id=str(result.event_enqueued.event_id),
        )

        return {
            "status": "ok",
            "person_id": result.person_id,
            "source": result.source,
            "source_user_id": result.source_user_id,
            "employee_number": result.employee_number,
            "event_id": str(result.event_enqueued.event_id),
            "decision": {
                "outcome": result.decision.outcome.value,
                "reason": result.decision.reason,
            },
            "desired": {
                "action": result.desired.action.value,
                "role": result.desired.role,
                "team": result.desired.team,
            },
        }

    @router.post("/reconcile")
    def post_reconcile(dry_run: bool = Query(False)) -> dict[str, Any]:
        if reconcile is None:
            raise HTTPException(
                status_code=503,
                detail="reconcile_not_configured",
            )

        result = reconcile.reconcile(dry_run=dry_run)

        if not dry_run and result.deletion_failures:
            logger.warning(
                "admin_reconcile_deletion_failures",
                failures_count=len(result.deletion_failures),
                failures=[
                    {"user_id": f.user_id, "error": f.error, "error_type": f.error_type}
                    for f in result.deletion_failures
                ],
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "message": "reconcile_deletion_failures",
                    "failures": [
                        {"user_id": f.user_id, "error": f.error, "error_type": f.error_type}
                        for f in result.deletion_failures
                    ],
                },
            )

        logger.info(
            "admin_reconcile_completed",
            dry_run=result.dry_run,
            drifts_count=len(result.drifts),
            events_emitted_count=len(result.events_emitted),
            deletion_failures_count=len(result.deletion_failures),
        )

        return {
            "status": "ok",
            "dry_run": result.dry_run,
            "drifts_count": len(result.drifts),
            "events_emitted_count": len(result.events_emitted),
            "misses_recorded_count": len(result.misses_recorded),
            "misses_cleared_count": len(result.misses_cleared),
            "deletion_failures_count": len(result.deletion_failures),
            "drifts": [
                {
                    "kind": drift.kind,
                    "source": drift.source,
                    "user_id": drift.user_id,
                    "detail": drift.detail,
                }
                for drift in result.drifts
            ],
        }

    return router
