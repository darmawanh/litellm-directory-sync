"""The configured Active Directory source reaches LiteLLM through the durable worker path."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.ad.cursor import parse_cursor
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.config import Config, load_config
from tests.fixtures.ad import ldap_responses
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_client
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


def test_worker_composes_ad_poller_source_outbox_and_gateway(
    engine: Engine,
    migrated_database: str,
) -> None:
    config: Config = load_config(EXAMPLE, ENV)
    config = config.model_copy(
        update={
            "identity_sources": [
                s.model_copy(update={"enabled": s.source_name == "corp-ad"})
                for s in config.identity_sources
            ]
        }
    )
    source_config = next(
        source for source in config.identity_sources if source.source_name == "corp-ad"
    )
    assert source_config.ad is not None

    alice_entry = ldap_responses.alice_entry()
    alice_dn = f"CN=Alice Doe,{source_config.ad.search_base}"
    alice_entry["dn"] = alice_dn

    group_entry = ldap_responses.search_res_entry(
        source_config.ad.group_dn,
        {
            "objectClass": [b"top", b"group"],
            "cn": [b"AI-Platform-Users"],
            "distinguishedName": [source_config.ad.group_dn.encode("utf-8")],
            "objectGUID": [ldap_responses.GROUP_GUID],
            "uSNChanged": [b"25000"],
            "whenChanged": [b"20260101120000.0Z"],
            "member": [alice_dn.encode("utf-8")],
        },
    )

    fake_conn = FakeADConnection(
        group_entry=group_entry,
        users=[alice_entry],
    )
    fake_conn.group_dn = source_config.ad.group_dn

    clock = FakeClock(START)

    def unit_of_work(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    gateway = FakeGateway()
    worker_holder: list[cli.OutboxWorker] = []

    def stop_after_idle(_seconds: float) -> None:
        worker_holder[0].request_stop()

    worker, sources = cli.build_worker(
        config,
        gateway,
        unit_of_work,
        lambda: 0,
        clock,
        ad_client_factory=lambda _ad_config: create_fake_ad_client(fake_conn),
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
            connection.execute(sqlalchemy.text("select source, decision, target from audit_events"))
            .mappings()
            .one()
        )
        cursor = connection.execute(
            sqlalchemy.text(
                "select cursor from source_cursors where source = 'corp-ad' "
                "and feed_scope = 'usn_poll'"
            )
        ).scalar_one()

    assert (outbox["status"], outbox["event_type"]) == ("done", "group.member_added")
    assert (audit["source"], audit["decision"]) == ("corp-ad", "granted")
    assert gateway.writes == ["ensure_team", "create_user"]
    assert len(gateway.user_ids()) == 1
    assert gateway.user_ids()[0] == audit["target"]
    parsed_cursor, reason = parse_cursor(cursor)
    assert reason is None and parsed_cursor is not None
    assert parsed_cursor.usn >= 25000


def test_worker_composes_both_ad_and_okta_sources(
    engine: Engine,
    migrated_database: str,
) -> None:
    config: Config = load_config(EXAMPLE, ENV)
    ad_source_config = next(s for s in config.identity_sources if s.source_name == "corp-ad")
    okta_source_config = next(s for s in config.identity_sources if s.source_name == "corp-okta")
    assert ad_source_config.ad is not None
    assert okta_source_config.okta is not None

    fake_ad = FakeADConnection()
    fake_ad.group_dn = ad_source_config.ad.group_dn

    fake_okta = FakeOktaHTTP()
    fake_okta.group_id = okta_source_config.okta.group_id
    fake_okta.add_user(
        user(event_hook_payloads.ALICE_USER_ID, employee_number="E10001"),
        member=True,
    )
    fake_okta.log_pages = {None: ([], None)}

    clock = FakeClock(START)

    def unit_of_work(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    gateway = FakeGateway()
    worker_holder: list[cli.OutboxWorker] = []

    def stop_after_idle(_seconds: float) -> None:
        worker_holder[0].request_stop()

    worker, sources = cli.build_worker(
        config,
        gateway,
        unit_of_work,
        lambda: 0,
        clock,
        ad_client_factory=lambda _ad_config: create_fake_ad_client(fake_ad),
        okta_client_factory=lambda _okta_config: fake_okta.oauth_client(),
        sleep=stop_after_idle,
    )
    worker_holder.append(worker)
    assert len(sources) == 2
    assert {s.name() for s in sources} == {"corp-ad", "corp-okta"}
    try:
        worker.run()
    finally:
        for source in sources:
            source.close()
