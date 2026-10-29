"""The store, against real PostgreSQL: one transaction, typed rows out.

Each test gets its own migrated database from ``fresh_database`` and reaches it
only through ``PostgresUnitOfWork``, so what is proven is the port's behavior,
not a helper's. A few tests read a column directly with SQL when the port has no
read for it (the closed entitlement's ``effective_to``, the audit row's
``source``): that is a test inspecting the schema, not production code reaching
around a repository.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine, Row, RowMapping

from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import (
    AuditEvent,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceIdentity,
)
from identity_lifecycle.ports.unit_of_work import GroupMemberSnapshot

from .persistence_support import START, engine_for, member_added

pytestmark = pytest.mark.integration

SOURCE = "corp-ad"


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    """One engine over this test's migrated database, disposed afterwards."""
    built = engine_for(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def _person(
    person_id: str = "p-1",
    employee_number: str | None = "E20002",
    display_name: str = "Ada Lovelace",
) -> Person:
    return Person(
        person_id=person_id,
        employee_number=employee_number,
        email=f"{person_id}@example.com",
        display_name=display_name,
        status="active",
    )


def _entitlement(
    person_id: str, effective_from: datetime, role: str = "internal_user"
) -> Entitlement:
    return Entitlement(
        person_id=person_id,
        role=role,
        team="ai-platform",
        budget_policy="standard",
        source=SOURCE,
        effective_from=effective_from,
        effective_to=None,
    )


def _scalar(engine: Engine, statement: str, **parameters: Any) -> Any:
    with engine.connect() as connection:
        return connection.execute(sqlalchemy.text(statement), parameters).scalar_one()


def _rows(engine: Engine, statement: str, **parameters: Any) -> list[RowMapping]:
    with engine.connect() as connection:
        return connection.execute(sqlalchemy.text(statement), parameters).mappings().all()


# persons and links


def test_person_round_trips_through_the_store(engine: Engine) -> None:
    person = _person()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(person)
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.persons.get(person.person_id) == person
        assert uow.persons.get("absent") is None


def test_saving_a_person_again_updates_one_row(engine: Engine) -> None:
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        uow.persons.save(_person(display_name="Ada King"))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        stored = uow.persons.get("p-1")

    assert stored is not None
    assert stored.display_name == "Ada King"
    assert _scalar(engine, "select count(*) from persons") == 1


def test_link_lookup_returns_every_match(engine: Engine) -> None:
    """ADR-018 section 1: the cardinality is the answer, never a first row.

    Two live persons share one ``employee_number`` — which ADR-017 section 1 and
    ``test_two_people_may_share_an_employee_number`` make legal — and the lookup
    returns both, ordered by ``person_id`` so the tuple is stable.
    """
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person("p-2", employee_number="E20002"))
        uow.persons.save(_person("p-1", employee_number="E20002"))
        uow.persons.save(_person("p-3", employee_number="E20003"))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        shared = uow.persons.find_all_by_employee_number("E20002")
        absent = uow.persons.find_all_by_employee_number("E99999")

    assert [person.person_id for person in shared] == ["p-1", "p-2"]
    assert absent == ()


# source identities


def test_source_identity_round_trips_and_updates_the_link(engine: Engine) -> None:
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person("p-1"))
        uow.persons.save(_person("p-2"))
        uow.identities.save(SourceIdentity(SOURCE, "object-guid-1", "p-1"))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.identities.find(SOURCE, "object-guid-1") == SourceIdentity(
            SOURCE, "object-guid-1", "p-1"
        )
        assert uow.identities.find(SOURCE, "absent") is None
        uow.identities.save(SourceIdentity(SOURCE, "object-guid-1", "p-2"))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        stored = uow.identities.find(SOURCE, "object-guid-1")

    assert stored is not None
    assert stored.person_id == "p-2"
    assert _scalar(engine, "select count(*) from source_identities") == 1


# entitlements


def test_entitlement_round_trip_closes_the_one_it_replaces(engine: Engine) -> None:
    first = datetime(2026, 1, 1, tzinfo=UTC)
    second = datetime(2026, 2, 1, tzinfo=UTC)

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        uow.entitlements.save(_entitlement("p-1", first))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.entitlements.current_for("p-1") == _entitlement("p-1", first)
        uow.entitlements.save(_entitlement("p-1", second, role="proxy_admin"))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        current = uow.entitlements.current_for("p-1")
        assert uow.entitlements.current_for("absent") is None

    assert current == _entitlement("p-1", second, role="proxy_admin")
    rows = _rows(
        engine,
        "select role, effective_to from entitlements order by effective_from",
    )
    assert [(row["role"], row["effective_to"]) for row in rows] == [
        ("internal_user", second),
        ("proxy_admin", None),
    ]


def test_resaving_the_current_entitlement_leaves_one_open_row(engine: Engine) -> None:
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        uow.entitlements.save(_entitlement("p-1", moment))
        uow.entitlements.save(_entitlement("p-1", moment))
        uow.commit()

    assert _scalar(engine, "select count(*) from entitlements") == 1
    assert _scalar(engine, "select count(*) from entitlements where effective_to is null") == 1


def test_an_older_entitlement_does_not_close_the_newer_one(engine: Engine) -> None:
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = datetime(2026, 3, 1, tzinfo=UTC)

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        uow.entitlements.save(_entitlement("p-1", newer, role="proxy_admin"))
        uow.entitlements.save(_entitlement("p-1", older))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        current = uow.entitlements.current_for("p-1")

    assert current is not None
    assert current.role == "proxy_admin"


# gateway accounts


def test_account_round_trips_with_a_numeric_budget_and_key_identifiers(engine: Engine) -> None:
    account = LiteLLMAccount(
        user_id="user-1",
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=50.0,
        keys=("key-1", "key-2"),
    )

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.accounts.save(account)
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.accounts.get("user-1") == account
        assert uow.accounts.get("absent") is None
        uow.accounts.save(
            LiteLLMAccount("user-1", "blocked", "internal_user", "ai-platform", 25.5, ())
        )
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        stored = uow.accounts.get("user-1")

    assert stored is not None
    assert (stored.status, stored.budget, stored.keys) == ("blocked", 25.5, ())
    assert _scalar(engine, "select count(*) from litellm_accounts") == 1


# audit


def test_audit_append_stores_the_event_source_and_the_decision(engine: Engine) -> None:
    record = AuditEvent(
        event_id=uuid4(),
        source_event_id="source-event-1",
        actor="corp-ad",
        action="group.member_added",
        target="p-1",
        decision="granted",
        reason="highest_precedence",
        timestamp=START,
    )

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.audit.append(record)
        uow.audit.append(record)
        uow.commit()

    rows = _rows(
        engine,
        "select event_id, source_event_id, source, actor, action, target, decision,"
        " reason, occurred_at from audit_events order by audit_id",
    )
    assert len(rows) == 2, "an append-only log keeps every record, including a repeat"
    first = rows[0]
    assert (first["event_id"], first["source_event_id"]) == (record.event_id, "source-event-1")
    assert (first["source"], first["actor"], first["action"]) == (SOURCE, "corp-ad", record.action)
    assert (first["target"], first["decision"], first["reason"]) == (
        "p-1",
        "granted",
        "highest_precedence",
    )
    assert first["occurred_at"] == START


# group membership snapshot


def test_group_member_snapshot_is_replaced_wholesale(engine: Engine) -> None:
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.group_members.replace(GroupMemberSnapshot(SOURCE, "group-1", frozenset({"u-1", "u-2"})))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.group_members.read(SOURCE, "group-1") == GroupMemberSnapshot(
            SOURCE, "group-1", frozenset({"u-1", "u-2"})
        )
        assert uow.group_members.read(SOURCE, "group-absent") is None
        uow.group_members.replace(GroupMemberSnapshot(SOURCE, "group-1", frozenset({"u-2", "u-3"})))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        replaced = uow.group_members.read(SOURCE, "group-1")

    assert replaced == GroupMemberSnapshot(SOURCE, "group-1", frozenset({"u-2", "u-3"}))
    assert _scalar(engine, "select count(*) from source_group_members") == 2


def test_read_returns_none_after_an_empty_replace(engine: Engine) -> None:
    """An empty snapshot stores no row, so the next read cannot tell it from never-read.

    The table stores member rows and nothing else (F2). The
    poll that observes an empty group calls ``replace`` with the empty set in the
    same transaction as its removals, so the removals are already emitted; the
    cost is one redundant full sync on the next poll.
    """
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.group_members.replace(GroupMemberSnapshot(SOURCE, "group-1", frozenset({"u-1"})))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.group_members.read(SOURCE, "group-1") is not None
        uow.group_members.replace(GroupMemberSnapshot(SOURCE, "group-1", frozenset()))
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.group_members.read(SOURCE, "group-1") is None
    assert _scalar(engine, "select count(*) from source_group_members") == 0


# idempotency and cursors


def test_processed_event_round_trip_is_idempotent(engine: Engine) -> None:
    event_id = uuid4()
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.processed_events.is_processed(event_id) is False
        uow.processed_events.mark_processed(event_id)
        uow.processed_events.mark_processed(event_id)
        assert uow.processed_events.is_processed(event_id) is True
        uow.commit()

    assert _scalar(engine, "select count(*) from processed_events") == 1


def test_cursor_round_trip_keeps_the_token_opaque(engine: Engine) -> None:
    token = '{"v":1,"dc":"invocation-1","usn":19055}'

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.cursors.read(SOURCE, "dc-1") is None
        uow.cursors.write(SOURCE, "dc-1", token)
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.cursors.read(SOURCE, "dc-1") == token
        assert uow.cursors.read(SOURCE, "dc-absent") is None
        uow.cursors.write(SOURCE, "dc-1", "advanced")
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.cursors.read(SOURCE, "dc-1") == "advanced"


# the transaction


def test_unit_of_work_commits_once(engine: Engine) -> None:
    """Two writes, one commit: the state change and the outbox row are atomic."""
    commits: list[str] = []
    sqlalchemy.event.listen(engine, "commit", lambda connection: commits.append("commit"))

    event = member_added()
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        assert uow.outbox.enqueue(event) == "inserted"
        uow.commit()

    assert commits == ["commit"], "one commit for the whole use case"
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.persons.get("p-1") == _person()
        assert uow.outbox.claim(10) == (event,)


def test_rollback_leaves_no_row(engine: Engine) -> None:
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        uow.outbox.enqueue(member_added())
        uow.rollback()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        assert uow.persons.get("p-1") is None
        assert uow.outbox.claim(10) == ()
    assert _scalar(engine, "select count(*) from persons") == 0
    assert _scalar(engine, "select count(*) from identity_event_outbox") == 0


def test_an_uncommitted_write_is_invisible_to_another_connection(engine: Engine) -> None:
    # ``str (engine.url)`` masks the password as ``***``, so the second engine
    # must be built from the URL rendered with it: a masked URL cannot log in.
    other = build_engine(engine.url.render_as_string(hide_password=False))
    try:
        with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
            uow.persons.save(_person())
            assert uow.persons.get("p-1") == _person(), "the writer sees its own write"
            with other.connect() as reader:
                visible = reader.execute(
                    sqlalchemy.text("select count(*) from persons")
                ).scalar_one()
            assert visible == 0, "no reader sees an uncommitted row"
            uow.commit()
            with other.connect() as reader:
                committed = reader.execute(
                    sqlalchemy.text("select count(*) from persons")
                ).scalar_one()
            assert committed == 1
    finally:
        other.dispose()


# the boundary


def test_repositories_return_domain_types(engine: Engine) -> None:
    """No ``Row``, ``RowMapping``, ``dict``, or cursor crosses a repository.

    Every read the nine repositories offer is exercised, and each answer is
    checked against the type the port declares. The forbidden types are named
    explicitly so a future implementation that returns one fails here rather
    than at a caller.
    """
    event = member_added()
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        uow.persons.save(_person())
        uow.identities.save(SourceIdentity(SOURCE, event.person.source_user_id, "p-1"))
        uow.entitlements.save(_entitlement("p-1", START))
        uow.accounts.save(LiteLLMAccount("user-1", "active", "internal_user", "ai", 1.0, ()))
        uow.audit.append(
            AuditEvent(uuid4(), "s-1", "actor", "action", "target", "granted", "reason", START)
        )
        uow.group_members.replace(GroupMemberSnapshot(SOURCE, "group-1", frozenset({"u-1"})))
        uow.processed_events.mark_processed(uuid4())
        uow.cursors.write(SOURCE, "dc-1", "token")
        uow.outbox.enqueue(event)
        uow.commit()

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        answers = {
            "person": uow.persons.get("p-1"),
            "persons": uow.persons.find_all_by_employee_number("E20002"),
            "identity": uow.identities.find(SOURCE, event.person.source_user_id),
            "entitlement": uow.entitlements.current_for("p-1"),
            "account": uow.accounts.get("user-1"),
            "snapshot": uow.group_members.read(SOURCE, "group-1"),
            "cursor": uow.cursors.read(SOURCE, "dc-1"),
            "processed": uow.processed_events.is_processed(uuid4()),
            "claimed": uow.outbox.claim(10),
        }

    expected = {
        "person": Person,
        "persons": tuple,
        "identity": SourceIdentity,
        "entitlement": Entitlement,
        "account": LiteLLMAccount,
        "snapshot": GroupMemberSnapshot,
        "cursor": str,
        "processed": bool,
        "claimed": tuple,
    }
    for name, value in answers.items():
        assert isinstance(value, expected[name]), f"{name} returned {type(value).__name__}"
        assert not isinstance(value, Row | RowMapping | dict), f"{name} leaked a row or mapping"
    assert isinstance(answers["claimed"][0], CanonicalEvent)
    assert isinstance(answers["persons"][0], Person)
