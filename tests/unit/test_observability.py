"""Unit tests for observability, Prometheus metrics, and SLA tracking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from identity_lifecycle.api.app import create_app
from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.config import load_config
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping
from identity_lifecycle.observability.metrics import (
    EQUAL_PRECEDENCE_FAILURES,
    EVENTS_PROCESSED,
    REVOCATION_SLA_VIOLATIONS,
    record_equal_precedence_failure,
    record_event_processed,
    record_revocation_sla,
)
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork
from tests.unit.test_config_loader import ENV, EXAMPLE

pytestmark = pytest.mark.unit

SOURCE = "corp-ad"
USERS_GROUP = "ai-platform-users"
ADMIN_GROUP = "ai-platform-admins"
TEAM = "ai-platform"

USER_MAPPING = GroupMapping(
    source=SOURCE,
    source_group_id=USERS_GROUP,
    role="internal_user",
    team=TEAM,
    precedence=10,
)
ADMIN_MAPPING = GroupMapping(
    source=SOURCE,
    source_group_id=ADMIN_GROUP,
    role="proxy_admin",
    team=TEAM,
    precedence=100,
)
TIED_ADMIN_MAPPING = GroupMapping(
    source=SOURCE,
    source_group_id=ADMIN_GROUP,
    role="proxy_admin",
    team=TEAM,
    precedence=10,  # Tied with USER_MAPPING
)
BUDGET = BudgetPolicy(max_budget=100.0, budget_duration="30d")


def _event(
    event_type: EventType,
    *,
    occurred_at: datetime | None = None,
    source_user_id: str = "u-obs-1",
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        source=SOURCE,
        source_event_id=f"src-{uuid4()}",
        type=event_type,
        occurred_at=occurred_at or datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
        person=EventPerson(source_user_id=source_user_id, employee_number="E10001"),
        group=EventGroup(source_group_id=USERS_GROUP, name=USERS_GROUP),
    )


class Harness:
    def __init__(
        self,
        *,
        group_mappings: list[GroupMapping] | None = None,
        clock_now: datetime | None = None,
    ) -> None:
        self.clock = FakeClock(now=clock_now or datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC))
        self.store = InMemoryStore()
        self.gateway = FakeGateway()
        self.source = FakeIdentitySource(
            source=SOURCE,
            users={
                "u-obs-1": IdentityUser(
                    source_user_id="u-obs-1",
                    employee_number="E10001",
                    email="uobs1@example.com",
                    display_name="User Obs",
                    enabled=True,
                )
            },
            groups={USERS_GROUP: ["u-obs-1"], ADMIN_GROUP: ["u-obs-1"]},
        )

        def uow_factory(src: str) -> InMemoryUnitOfWork:
            return InMemoryUnitOfWork(self.store, self.clock, source=src)

        self.uow_factory = uow_factory
        self.ingest = IngestEvent(uow_factory, enabled_sources=frozenset({SOURCE}))
        self.process = ProcessEvent(
            uow_factory,
            self.gateway,
            {SOURCE: self.source},
            group_mappings=group_mappings or [USER_MAPPING, ADMIN_MAPPING],
            team_create_if_missing={TEAM: True},
            budget_policies={"standard": BUDGET},
            group_budget_policies={(SOURCE, USERS_GROUP): "standard"},
            default_budget_policy="standard",
            enabled_sources=frozenset({SOURCE}),
            clock=self.clock,
            on_equal_precedence=record_equal_precedence_failure,
            on_revocation=record_revocation_sla,
            on_processed=record_event_processed,
        )

    def run(self, event: CanonicalEvent) -> Settlement:
        outcome = self.ingest.ingest(event)
        assert outcome is EnqueueOutcome.INSERTED
        return self.process.process(event)


def test_equal_precedence_increments_metric_counter() -> None:
    # Set up tied precedence: both mappings precedence = 10
    harness = Harness(group_mappings=[USER_MAPPING, TIED_ADMIN_MAPPING])
    before = EQUAL_PRECEDENCE_FAILURES.labels(source=SOURCE)._value.get()

    settlement = harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    assert settlement is Settlement.PERMANENT

    after = EQUAL_PRECEDENCE_FAILURES.labels(source=SOURCE)._value.get()
    assert after == before + 1


def test_revocation_within_sla_records_histogram_without_violation() -> None:
    occurred = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    now = occurred + timedelta(minutes=5)  # 5 minutes: within 15m SLA
    harness = Harness(clock_now=now)

    # Join first
    harness.run(_event(EventType.GROUP_MEMBER_ADDED, occurred_at=occurred))

    # Revocation
    harness.source.remove_from_group(USERS_GROUP, "u-obs-1")
    harness.source.remove_from_group(ADMIN_GROUP, "u-obs-1")

    violations_before = REVOCATION_SLA_VIOLATIONS.labels(source=SOURCE)._value.get()
    settlement = harness.run(_event(EventType.GROUP_MEMBER_REMOVED, occurred_at=occurred))
    assert settlement is Settlement.DONE

    violations_after = REVOCATION_SLA_VIOLATIONS.labels(source=SOURCE)._value.get()
    assert violations_after == violations_before


def test_revocation_exceeding_15_minutes_records_sla_violation() -> None:
    occurred = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    now = occurred + timedelta(minutes=16)  # 16 minutes: exceeds 15m SLA
    harness = Harness(clock_now=now)

    # Join
    harness.run(_event(EventType.GROUP_MEMBER_ADDED, occurred_at=occurred))

    # Revocation
    harness.source.remove_from_group(USERS_GROUP, "u-obs-1")
    harness.source.remove_from_group(ADMIN_GROUP, "u-obs-1")

    violations_before = REVOCATION_SLA_VIOLATIONS.labels(source=SOURCE)._value.get()
    settlement = harness.run(_event(EventType.GROUP_MEMBER_REMOVED, occurred_at=occurred))
    assert settlement is Settlement.DONE

    violations_after = REVOCATION_SLA_VIOLATIONS.labels(source=SOURCE)._value.get()
    assert violations_after == violations_before + 1


def test_events_processed_metric_records_completion() -> None:
    harness = Harness()
    before = EVENTS_PROCESSED.labels(source=SOURCE, action="create", outcome="done")._value.get()

    harness.run(_event(EventType.GROUP_MEMBER_ADDED))

    after = EVENTS_PROCESSED.labels(source=SOURCE, action="create", outcome="done")._value.get()
    assert after == before + 1


def test_api_metrics_endpoint_exposition() -> None:
    environ = {
        **ENV,
        "LIFECYCLE_MASTER_KEY": "test-master-key",
    }
    config = load_config(EXAMPLE, environ)
    store = InMemoryStore()
    clock = FakeClock()

    def uow_factory(s: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=s)

    app = create_app(config, uow_factory, clock)
    client = TestClient(app)

    # Trigger some metric recordings
    record_equal_precedence_failure("corp-test")
    record_revocation_sla("corp-test", 950.0)
    record_event_processed("corp-test", "revoke", "done", 0.05)

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]

    body = response.text
    assert "identity_lifecycle_equal_precedence_failures_total" in body
    assert "identity_lifecycle_revocation_duration_seconds" in body
    assert "identity_lifecycle_revocation_sla_violations_total" in body
    assert "identity_lifecycle_events_processed_total" in body
