"""The configured Okta source reaches LiteLLM through the durable worker path."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.okta.cursor import parse_cursor, seeded_cursor
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.config import Config, load_config
from tests.fixtures.fakes import FakeClock, FakeGateway
from tests.fixtures.okta import event_hook_payloads
from tests.fixtures.okta_http import FakeOktaHTTP, user
from tests.unit.test_config_loader import ENV, EXAMPLE

pytestmark = pytest.mark.integration

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def test_worker_composes_okta_poller_source_outbox_and_gateway(
    engine: Engine,
    migrated_database: str,
) -> None:
    config: Config = load_config(EXAMPLE, ENV)
    config = config.model_copy(
        update={
            "identity_sources": [
                s.model_copy(update={"enabled": s.source_name == "corp-okta"})
                for s in config.identity_sources
            ]
        }
    )
    source_config = next(
        source for source in config.identity_sources if source.source_name == "corp-okta"
    )
    assert source_config.okta is not None

    server = FakeOktaHTTP()
    server.group_id = source_config.okta.group_id
    server.add_user(
        user(event_hook_payloads.ALICE_USER_ID, employee_number="E10001"),
        member=True,
    )
    event = event_hook_payloads.membership_add()
    group_target = next(target for target in event["target"] if target["type"] == "UserGroup")
    group_target["id"] = source_config.okta.group_id
    server.log_pages = {None: ([event], None)}
    clock = FakeClock(START)

    def unit_of_work(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        uow.cursors.write(
            "corp-okta", "system_log", seeded_cursor(START - timedelta(seconds=60), 60)
        )
        uow.commit()

    gateway = FakeGateway()
    worker_holder = []

    def stop_after_idle(_seconds: float) -> None:
        worker_holder[0].request_stop()

    worker, sources = cli.build_worker(
        config,
        gateway,
        unit_of_work,
        lambda: 0,
        clock,
        client_factory=lambda _okta_config: server.oauth_client(),
        sleep=stop_after_idle,
    )
    worker_holder.append(worker)
    try:
        worker.run()
    finally:
        for source in sources:
            source.close()

    with engine.connect() as connection:
        outbox = (
            connection.execute(
                sqlalchemy.text("select status, event_type from identity_event_outbox")
            )
            .mappings()
            .one()
        )
        audit = (
            connection.execute(sqlalchemy.text("select source, decision from audit_events"))
            .mappings()
            .one()
        )
        cursor = connection.execute(
            sqlalchemy.text(
                "select cursor from source_cursors where source = 'corp-okta' "
                "and feed_scope = 'system_log'"
            )
        ).scalar_one()

    assert (outbox["status"], outbox["event_type"]) == ("done", "group.member_added")
    assert (audit["source"], audit["decision"]) == ("corp-okta", "granted")
    assert gateway.writes == ["ensure_team", "create_user"]
    assert len(gateway.user_ids()) == 1
    assert parse_cursor(cursor)[0] is not None
    assert any(request.url.path == "/api/v1/logs" for request in server.requests)
    assert all(
        request.method == "GET" or request.url.path == "/oauth2/v1/token"
        for request in server.requests
    )
