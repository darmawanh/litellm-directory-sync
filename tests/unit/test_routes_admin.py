"""Unit tests for administrative HTTP API endpoints."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from identity_lifecycle.api.app import create_app
from identity_lifecycle.application.manual_sync import (
    AmbiguousLinkError,
    ManualSync,
    ManualSyncResult,
    NotFoundError,
)
from identity_lifecycle.application.reconcile import (
    DeletionFailure,
    Reconcile,
    ReconciliationDrift,
    ReconciliationResult,
)
from identity_lifecycle.config import Config, load_config
from identity_lifecycle.domain.events import CanonicalEvent, EventPerson, EventType
from identity_lifecycle.domain.models import AuditEvent
from identity_lifecycle.domain.policy import (
    AccessAction,
    AccessDecision,
    DecisionOutcome,
    DesiredAccess,
)
from identity_lifecycle.observability.metrics import ADMIN_AUTH_REJECTED
from tests.fixtures.fakes import FakeClock
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.unit

MASTER_KEY = "test-master-key-xyz-123"
NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def base_environ() -> dict[str, str]:
    return {
        **ENV,
        "LIFECYCLE_MASTER_KEY": MASTER_KEY,
    }


@pytest.fixture
def app_config(tmp_path: Path, base_environ: dict[str, str]) -> Config:
    path = tmp_path / "config.yaml"
    path.write_text(_text(), encoding="utf-8")
    return load_config(path, base_environ)


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(NOW)


def make_uow_factory(store: InMemoryStore, clock: FakeClock):
    def uow_factory(source: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    return uow_factory


def _seed_audit_events(store: InMemoryStore) -> None:
    event_1 = AuditEvent(
        event_id=UUID("00000000-0000-0000-0000-000000000001"),
        source_event_id="src-1",
        actor="okta",
        action="create",
        target="p-100",
        decision="granted",
        reason="highest_precedence",
        timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC),
    )
    event_2 = AuditEvent(
        event_id=UUID("00000000-0000-0000-0000-000000000002"),
        source_event_id="src-2",
        actor="okta",
        action="revoke",
        target="p-200",
        decision="revoked",
        reason="no_mapped_group",
        timestamp=datetime(2026, 1, 15, 11, 0, 0, tzinfo=UTC),
    )
    store.audit.extend([event_1, event_2])
    store.audit_records.extend([(event_1, "okta"), (event_2, "okta")])


# Authentication Tests


def test_admin_routes_reject_missing_authorization(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    before = ADMIN_AUTH_REJECTED.labels(reason="missing")._value.get()
    response = client.get("/api/v1/audit/export")
    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}
    after = ADMIN_AUTH_REJECTED.labels(reason="missing")._value.get()
    assert after == before + 1


def test_admin_routes_reject_mismatched_bearer_token(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    before = ADMIN_AUTH_REJECTED.labels(reason="mismatch")._value.get()
    response = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": "Bearer wrong-token-value"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}
    after = ADMIN_AUTH_REJECTED.labels(reason="mismatch")._value.get()
    assert after == before + 1


def test_admin_routes_reject_wrong_scheme(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    before = ADMIN_AUTH_REJECTED.labels(reason="mismatch")._value.get()
    response = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": f"Basic {MASTER_KEY}"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}
    after = ADMIN_AUTH_REJECTED.labels(reason="mismatch")._value.get()
    assert after == before + 1


# Audit Export Endpoint Tests (GET /api/v1/audit/export)


def test_audit_export_default_json(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    _seed_audit_events(store)
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["event_id"] == "00000000-0000-0000-0000-000000000001"
    assert data[1]["event_id"] == "00000000-0000-0000-0000-000000000002"


def test_audit_export_csv_format(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    _seed_audit_events(store)
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get(
        "/api/v1/audit/export?format=csv",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    csv_text = response.text
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("event_id,timestamp,actor,action")
    assert len(lines) == 3  # Header + 2 rows


def test_audit_export_ndjson_format(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    _seed_audit_events(store)
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get(
        "/api/v1/audit/export?format=ndjson",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    lines = response.text.strip().splitlines()
    assert len(lines) == 2


def test_audit_export_date_filter_success(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    _seed_audit_events(store)
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get(
        "/api/v1/audit/export?from=2026-01-15T10:30:00Z&to=2026-01-15T11:30:00Z",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["event_id"] == "00000000-0000-0000-0000-000000000002"


def test_audit_export_invalid_date_format_returns_400(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get(
        "/api/v1/audit/export?from=not-a-date",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 400
    assert "Invalid ISO-8601 timestamp" in response.json()["detail"]


def test_audit_export_conflicting_filters_returns_400(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get(
        "/api/v1/audit/export?employee=E100&user=00u100",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 400
    assert "Cannot filter by both" in response.json()["detail"]


# Manual Sync Endpoint Tests (POST /api/v1/sync)


def test_sync_by_employee_number_success(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_sync = MagicMock(spec=ManualSync)
    event_id = uuid4()
    mock_event = CanonicalEvent(
        event_id=event_id,
        source_event_id="evt-1",
        occurred_at=NOW,
        source="okta",
        type=EventType.USER_CREATED,
        person=EventPerson(source_user_id="00u100", employee_number="E100"),
        group=None,
    )
    mock_sync.sync.return_value = ManualSyncResult(
        person_id="p-100",
        source="okta",
        source_user_id="00u100",
        employee_number="E100",
        event_enqueued=mock_event,
        decision=AccessDecision(
            outcome=DecisionOutcome.GRANTED,
            selected=None,
            role="developer",
            team="engineering",
            precedence=10,
            reason="highest_precedence",
            candidates=(),
        ),
        desired=DesiredAccess(
            action=AccessAction.CREATE,
            person_id="p-100",
            role="developer",
            team="engineering",
            reason="highest_precedence",
        ),
    )

    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        manual_sync=mock_sync,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"employee": "E100"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["person_id"] == "p-100"
    assert data["source"] == "okta"
    assert data["employee_number"] == "E100"
    assert data["event_id"] == str(event_id)
    assert data["decision"]["outcome"] == "granted"
    assert data["desired"]["action"] == "create"
    mock_sync.sync.assert_called_once_with(employee_number="E100", source_user_id=None)


def test_sync_by_source_user_id_success(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_sync = MagicMock(spec=ManualSync)
    event_id = uuid4()
    mock_event = CanonicalEvent(
        event_id=event_id,
        source_event_id="evt-2",
        occurred_at=NOW,
        source="ad",
        type=EventType.USER_UPDATED,
        person=EventPerson(source_user_id="guid-200", employee_number=None),
        group=None,
    )
    mock_sync.sync.return_value = ManualSyncResult(
        person_id="p-200",
        source="ad",
        source_user_id="guid-200",
        employee_number=None,
        event_enqueued=mock_event,
        decision=AccessDecision(
            outcome=DecisionOutcome.NOT_ENTITLED,
            selected=None,
            role=None,
            team=None,
            precedence=None,
            reason="no_mapped_group",
            candidates=(),
        ),
        desired=DesiredAccess(
            action=AccessAction.REVOKE,
            person_id="p-200",
            role=None,
            team=None,
            reason="no_mapped_group",
        ),
    )

    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        manual_sync=mock_sync,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"user": "guid-200"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["person_id"] == "p-200"
    assert data["decision"]["outcome"] == "not_entitled"
    assert data["desired"]["action"] == "revoke"
    mock_sync.sync.assert_called_once_with(employee_number=None, source_user_id="guid-200")


def test_sync_invalid_payload_returns_400(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_sync = MagicMock(spec=ManualSync)
    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        manual_sync=mock_sync,
    )
    client = TestClient(app)

    # Both provided
    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"employee": "E100", "user": "00u100"},
    )
    assert response.status_code == 400
    assert "Provide exactly one" in response.json()["detail"]

    # Neither provided
    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={},
    )
    assert response.status_code == 400
    assert "Provide exactly one" in response.json()["detail"]


def test_sync_user_not_found_returns_404(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_sync = MagicMock(spec=ManualSync)
    mock_sync.sync.side_effect = NotFoundError("User E999 not found")
    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        manual_sync=mock_sync,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"employee": "E999"},
    )
    assert response.status_code == 404
    assert "User E999 not found" in response.json()["detail"]


def test_sync_ambiguous_link_returns_409(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_sync = MagicMock(spec=ManualSync)
    mock_sync.sync.side_effect = AmbiguousLinkError("Ambiguous employee number E100")
    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        manual_sync=mock_sync,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"employee": "E100"},
    )
    assert response.status_code == 409
    assert "Ambiguous employee number" in response.json()["detail"]


def test_sync_not_configured_returns_503(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        manual_sync=None,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"employee": "E100"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "manual_sync_not_configured"


# Reconcile Endpoint Tests (POST /api/v1/reconcile)


def test_reconcile_endpoint_live_mode(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_reconcile = MagicMock(spec=Reconcile)
    drift = ReconciliationDrift(
        kind="unmapped_account",
        source="okta",
        user_id="p-100",
        detail="orphaned account",
    )
    mock_reconcile.reconcile.return_value = ReconciliationResult(
        drifts=(drift,),
        events_emitted=(),
        misses_recorded=(),
        misses_cleared=(),
        dry_run=False,
    )

    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        reconcile=mock_reconcile,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/reconcile",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["dry_run"] is False
    assert data["drifts_count"] == 1
    assert data["drifts"][0]["kind"] == "unmapped_account"
    mock_reconcile.reconcile.assert_called_once_with(dry_run=False)


def test_reconcile_endpoint_dry_run_mode(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_reconcile = MagicMock(spec=Reconcile)
    mock_reconcile.reconcile.return_value = ReconciliationResult(
        drifts=(),
        events_emitted=(),
        misses_recorded=(),
        misses_cleared=(),
        dry_run=True,
    )

    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        reconcile=mock_reconcile,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/reconcile?dry_run=true",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["dry_run"] is True
    mock_reconcile.reconcile.assert_called_once_with(dry_run=True)


def test_reconcile_not_configured_returns_503(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        reconcile=None,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/reconcile",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "reconcile_not_configured"


def test_reconcile_deletion_failures_returns_503(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    mock_reconcile = MagicMock(spec=Reconcile)
    mock_reconcile.reconcile.return_value = ReconciliationResult(
        drifts=(),
        events_emitted=(),
        misses_recorded=(),
        misses_cleared=(),
        dry_run=False,
        deletion_failures=(
            DeletionFailure(user_id="p-100", error="Gateway 503", error_type="RetryableError"),
        ),
    )

    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        reconcile=mock_reconcile,
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/reconcile",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
    )
    assert response.status_code == 503
    data = response.json()
    assert "reconcile_deletion_failures" in str(data)


def test_admin_routes_are_synchronous_threadpool_callables(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(app_config, make_uow_factory(store, clock), clock)
    admin_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1")
    ]
    assert len(admin_routes) >= 3
    for route in admin_routes:
        assert not asyncio.iscoroutinefunction(
            route.endpoint
        ), f"Route {route.path} endpoint {route.endpoint} must not be a coroutine (T-070)"


@pytest.mark.anyio
async def test_admin_slow_reconcile_does_not_block_healthz(
    app_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    reconcile_started = threading.Event()
    reconcile_can_finish = threading.Event()

    class SlowReconcile:
        def reconcile(self, dry_run: bool = False) -> ReconciliationResult:
            reconcile_started.set()
            reconcile_can_finish.wait(timeout=5.0)
            return ReconciliationResult(
                drifts=(),
                events_emitted=(),
                misses_recorded=(),
                misses_cleared=(),
                dry_run=dry_run,
            )

    app = create_app(
        app_config,
        make_uow_factory(store, clock),
        clock,
        reconcile=SlowReconcile(),  # type: ignore[arg-type]
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        reconcile_task = asyncio.create_task(
            client.post("/api/v1/reconcile", headers={"Authorization": f"Bearer {MASTER_KEY}"})
        )

        await asyncio.to_thread(reconcile_started.wait, 2.0)
        assert reconcile_started.is_set()

        # While reconcile is executing in threadpool, /healthz and /metrics respond immediately
        healthz_resp = await client.get("/healthz")
        assert healthz_resp.status_code == 200
        assert healthz_resp.json() == {"status": "ok"}

        metrics_resp = await client.get("/metrics")
        assert metrics_resp.status_code == 200

        reconcile_can_finish.set()
        reconcile_resp = await reconcile_task
        assert reconcile_resp.status_code == 200
        assert reconcile_resp.json()["status"] == "ok"
