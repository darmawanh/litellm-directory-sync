"""Integration tests for inbound HTTP API and Okta event hook ingress against PostgreSQL."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine
from starlette.testclient import TestClient

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.api.app import create_app
from identity_lifecycle.config import Config, load_config
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_client
from tests.fixtures.fakes import FakeClock, FakeGateway
from tests.fixtures.okta import event_hook_payloads
from tests.fixtures.okta_http import FakeOktaHTTP, user
from tests.unit.test_config_loader import ENV, _text, _with_event_hook

pytestmark = pytest.mark.integration

HOOK_SECRET = "test-okta-hook-secret"
PREV_HOOK_SECRET = "test-okta-prev-secret"
MASTER_KEY = "test-master-key"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


@pytest.fixture
def hook_config(tmp_path: Path) -> Config:
    environ = {
        **ENV,
        "OKTA_EVENT_HOOK_SECRET": HOOK_SECRET,
        "OKTA_EVENT_HOOK_SECRET_PREVIOUS": PREV_HOOK_SECRET,
        "LIFECYCLE_MASTER_KEY": MASTER_KEY,
    }
    text = _with_event_hook(_text())
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, environ)


def test_api_hook_ingress_durably_enqueues_into_postgres_outbox(
    engine: Engine,
    hook_config: Config,
) -> None:
    clock = FakeClock(NOW)

    def uow_factory(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    app = create_app(hook_config, uow_factory, clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    # 1. Verify readyz checks PostgreSQL
    ready_resp = client.get("/readyz")
    assert ready_resp.status_code == 200
    assert ready_resp.json() == {"status": "ready"}

    # 2. Ingest membership add event
    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}

    # 3. Assert durable row in identity_event_outbox
    with engine.connect() as connection:
        rows = list(
            connection.execute(
                sqlalchemy.text(
                    "select status, source, attempts, person_key from identity_event_outbox"
                )
            ).mappings()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row["status"] == "pending"
        assert row["source"] == "corp-okta"
        assert row["attempts"] == 0
        assert row["person_key"] is not None

    # 4. Duplicate event returns 200 duplicate and does not insert a second row
    dup_response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert dup_response.status_code == 200
    assert dup_response.json() == {"status": "duplicate"}

    with engine.connect() as connection:
        count = connection.scalar(sqlalchemy.text("select count(*) from identity_event_outbox"))
        assert count == 1


def test_event_hook_to_worker_to_gateway_e2e(
    engine: Engine,
    hook_config: Config,
) -> None:
    clock = FakeClock(NOW)

    def uow_factory(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    # 1. Mount API and post event hook request
    app = create_app(hook_config, uow_factory, clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()
    # Align group ID with configured corp-okta group_id
    payload["target"][1]["id"] = "00gEXAMPLE0000000000"

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}

    # 2. Verify durable pending row in PostgreSQL outbox
    with engine.connect() as connection:
        rows = list(
            connection.execute(
                sqlalchemy.text(
                    "select status, source, attempts, person_key from identity_event_outbox"
                )
            ).mappings()
        )
        assert len(rows) == 1
        assert rows[0]["status"] == "pending"
        assert rows[0]["source"] == "corp-okta"

    # 3. Build worker and drain the enqueued hook event
    gateway = FakeGateway()
    fake_okta = FakeOktaHTTP()
    fake_okta.group_id = "00gEXAMPLE0000000000"
    fake_okta.add_user(
        user(
            "00uPLACEHOLDERUSER01",
            employee_number="E10001",
            email="alice.adams@example.com",
            name="Alice Adams",
        ),
        member=True,
    )
    fake_ad = FakeADConnection()

    worker, sources = cli.build_worker(
        hook_config,
        gateway,
        uow_factory,
        lambda: 0,
        clock,
        ad_client_factory=lambda _ad: create_fake_ad_client(fake_ad),
        okta_client_factory=lambda _okta: fake_okta.oauth_client(),
    )
    try:
        events = worker._claim()
        assert len(events) == 1
        assert events[0].source == "corp-okta"
        worker._finish(events)

        # 4. Gateway received access creation write
        assert "create_user" in gateway.writes
        assert len(gateway.accounts) == 1
        account = next(iter(gateway.accounts.values()))
        assert account.role == "internal_user"
        assert account.team == "ai-platform"

        # 5. Outbox row is marked done
        with engine.connect() as connection:
            rows = list(
                connection.execute(
                    sqlalchemy.text("select status, attempts from identity_event_outbox")
                ).mappings()
            )
            assert len(rows) == 1
            assert rows[0]["status"] == "done"

        # 6. Audit event is durably recorded
        with engine.connect() as connection:
            audit_rows = list(
                connection.execute(
                    sqlalchemy.text("select source, decision, action from audit_events")
                ).mappings()
            )
            assert len(audit_rows) == 1
            assert audit_rows[0]["source"] == "corp-okta"
            assert audit_rows[0]["action"] == "create"
    finally:
        for s in sources:
            s.close()
