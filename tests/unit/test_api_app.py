"""Unit tests for the inbound HTTP API application and Okta hook ingress."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from identity_lifecycle.api.app import create_app
from identity_lifecycle.config import Config, load_config
from tests.fixtures.fakes import FakeClock
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork
from tests.fixtures.okta import event_hook_payloads
from tests.unit.test_config_loader import ENV, EXAMPLE, _text, _with_event_hook

pytestmark = pytest.mark.unit

HOOK_SECRET = "test-okta-hook-secret"
PREV_HOOK_SECRET = "test-okta-prev-secret"
MASTER_KEY = "test-master-key"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def base_environ() -> dict[str, str]:
    return {
        **ENV,
        "OKTA_EVENT_HOOK_SECRET": HOOK_SECRET,
        "OKTA_EVENT_HOOK_SECRET_PREVIOUS": PREV_HOOK_SECRET,
        "LIFECYCLE_MASTER_KEY": MASTER_KEY,
    }


@pytest.fixture
def hook_config(tmp_path: Path, base_environ: dict[str, str]) -> Config:
    text = _with_event_hook(_text())
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, base_environ)


@pytest.fixture
def default_config(base_environ: dict[str, str]) -> Config:
    return load_config(EXAMPLE, base_environ)


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


# Health and Readiness Probes


def test_healthz_returns_ok_liveness(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_returns_ready_when_database_is_healthy(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readyz_returns_503_when_database_fails(hook_config: Config, clock: FakeClock) -> None:
    def failing_uow_factory(source: str):
        raise RuntimeError("PostgreSQL connection refused")

    app = create_app(hook_config, failing_uow_factory, clock)  # type: ignore[arg-type]
    client = TestClient(app)

    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


# Okta GET Handshake


def test_okta_get_handshake_returns_challenge_header(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    challenge = "test-challenge-xyz-12345"
    response = client.get(
        "/api/v1/hooks/okta",
        headers={"x-okta-verification-challenge": challenge},
    )
    assert response.status_code == 200
    assert response.json() == {"verification": challenge}


def test_okta_get_handshake_requires_challenge_header(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app)

    response = client.get("/api/v1/hooks/okta")
    assert response.status_code == 400
    assert "missing" in response.json()["detail"]


# Okta POST Authentication (Shared Secret, Rotation & Master Key)


def test_okta_post_missing_auth_header_is_401(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    response = client.post(
        "/api/v1/hooks/okta",
        json=event_hook_payloads.membership_add(),
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_okta_post_invalid_secret_is_401(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": "Bearer wrong-secret"},
        json=event_hook_payloads.membership_add(),
    )
    assert response.status_code == 401


def test_okta_post_authenticates_with_current_shared_secret(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}


def test_okta_post_authenticates_with_previous_shared_secret(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {PREV_HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}


def test_okta_post_rejects_master_key_alone(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json=payload,
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_unconfigured_hook_path_returns_404(
    default_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    # default_config has change_feed: system_log, no event_hook block
    app = create_app(default_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    res_get = client.get(
        "/api/v1/hooks/okta",
        headers={"x-okta-verification-challenge": "test"},
    )
    assert res_get.status_code == 404

    res_post = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=event_hook_payloads.membership_add(),
    )
    assert res_post.status_code == 404


def test_disabled_source_hook_path_returns_404(
    tmp_path: Path, base_environ: dict[str, str], store: InMemoryStore, clock: FakeClock
) -> None:
    text = _with_event_hook(_text())
    text = text.replace("enabled: true", "enabled: false")
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path, base_environ)

    app = create_app(config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    res_post = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=event_hook_payloads.membership_add(),
    )
    assert res_post.status_code == 404


def test_hook_rate_limit_exceeded_returns_429(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    from identity_lifecycle.observability.metrics import HOOK_RATE_LIMITED

    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    # hook_config has verification_requests_per_minute = 5
    for _ in range(5):
        resp = client.get(
            "/api/v1/hooks/okta",
            headers={"x-okta-verification-challenge": "test"},
        )
        assert resp.status_code == 200

    # 6th request should be rate limited
    initial_metric = HOOK_RATE_LIMITED.labels(source="corp-okta")._value.get()
    resp6 = client.get(
        "/api/v1/hooks/okta",
        headers={"x-okta-verification-challenge": "test"},
    )
    assert resp6.status_code == 429
    assert "Retry-After" in resp6.headers
    assert resp6.json() == {"detail": "rate_limit_exceeded"}
    new_metric = HOOK_RATE_LIMITED.labels(source="corp-okta")._value.get()
    assert new_metric == initial_metric + 1


# IP Allowlist & Trusted Proxies


def test_okta_post_rejects_non_allowlisted_ip(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    # 192.168.1.50 is not in 203.0.113.0/24 or 198.51.100.0/24
    client = TestClient(app, client=("192.168.1.50", 12345))

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json={"eventType": "dummy"},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "client_ip_not_allowlisted"}


def test_okta_post_resolves_trusted_proxy_hops(
    tmp_path: Path, base_environ: dict[str, str], store: InMemoryStore, clock: FakeClock
) -> None:
    text = _with_event_hook(_text())
    # Configure trusted proxy 10.0.0.1
    text = text.replace("trusted_proxies: []", "trusted_proxies:\n          - 10.0.0.1/32")
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path, base_environ)

    app = create_app(config, make_uow_factory(store, clock), clock)

    # Immediate peer is trusted proxy 10.0.0.1, header has allowlisted IP 203.0.113.5
    client = TestClient(app, client=("10.0.0.1", 12345))
    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={
            "Authorization": f"Bearer {HOOK_SECRET}",
            "X-Forwarded-For": "203.0.113.5, 10.0.0.1",
        },
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}


def test_okta_post_untrusted_peer_cannot_spoof_x_forwarded_for(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    # trusted_proxies is empty, so peer is evaluated directly
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("10.0.0.1", 12345))

    # Peer is 10.0.0.1 (not allowlisted); attempting to spoof 203.0.113.5 in header
    response = client.post(
        "/api/v1/hooks/okta",
        headers={
            "Authorization": f"Bearer {HOOK_SECRET}",
            "X-Forwarded-For": "203.0.113.5",
        },
        json={"eventType": "dummy"},
    )
    assert response.status_code == 403


# Timestamp Skew


def test_okta_post_rejects_stale_event_older_than_300s(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    # 301 seconds old
    payload["published"] = (NOW - timedelta(seconds=301)).isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "stale_event"}


def test_okta_post_rejects_future_dated_event_beyond_300s(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    # 301 seconds in the future
    payload["published"] = (NOW + timedelta(seconds=301)).isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "future_dated"}


# Normalization, Outbox Enqueue, Deduplication & Conditions


def test_okta_post_enqueues_event_into_outbox(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    assert len(store.outbox) == 1


def test_okta_post_duplicate_event_returns_200_duplicate(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    # First attempt inserts
    res1 = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert res1.status_code == 200
    assert res1.json() == {"status": "accepted"}
    assert len(store.outbox) == 1

    # Second attempt deduplicates
    res2 = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert res2.status_code == 200
    assert res2.json() == {"status": "duplicate"}
    assert len(store.outbox) == 1


def test_okta_post_missing_employee_number_enqueues_with_null_link(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add_without_employee_number()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    assert len(store.outbox) == 1

    row = next(iter(store.outbox.values()))
    assert row.event.person.employee_number is None
    assert row.event.person.source_user_id == event_hook_payloads.BOB_USER_ID


def test_okta_post_failed_outcome_is_ignored(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add_failed_outcome()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "ignored"}
    assert len(store.outbox) == 0


def test_okta_post_batched_events_wrapper(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    e1 = event_hook_payloads.membership_add()
    e1["published"] = NOW.isoformat()
    e2 = event_hook_payloads.user_deactivate()
    e2["published"] = NOW.isoformat()

    wrapper = {"data": {"events": [e1, e2]}}

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=wrapper,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    assert len(store.outbox) == 2


def test_okta_post_verification_challenge_body(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=event_hook_payloads.VERIFICATION_REQUEST,
    )
    assert response.status_code == 200
    assert response.json() == {"verification": event_hook_payloads.VERIFICATION_CHALLENGE}


def test_okta_post_returns_503_on_persistence_error(hook_config: Config, clock: FakeClock) -> None:
    def failing_uow_factory(source: str):
        mock_uow = MagicMock()
        mock_uow.__enter__.return_value = mock_uow
        mock_uow.outbox.enqueue.side_effect = RuntimeError("database disk full")
        return mock_uow

    app = create_app(hook_config, failing_uow_factory, clock)  # type: ignore[arg-type]
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        json=payload,
    )
    assert response.status_code == 503
    assert response.json() == {"status": "error", "detail": "enqueue_failed"}


def test_readyz_is_synchronous_threadpool_callable(
    default_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(default_config, make_uow_factory(store, clock), clock)
    readyz_route = next(
        route for route in app.routes if isinstance(route, APIRoute) and route.path == "/readyz"
    )
    assert not asyncio.iscoroutinefunction(readyz_route.endpoint)


def test_hook_post_rejects_content_length_exceeding_limit_with_413(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    # max_body_bytes in hook_config is 262144
    oversized_length = 262145
    response = client.post(
        "/api/v1/hooks/okta",
        headers={
            "Authorization": f"Bearer {HOOK_SECRET}",
            "Content-Length": str(oversized_length),
        },
        content=b"x" * 10,  # Content-Length is checked before body is fully read
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "payload_too_large"}


def test_hook_post_rejects_chunked_body_exceeding_limit_with_413(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    def chunk_generator():
        # Yield chunks that exceed 262144 bytes
        for _ in range(27):
            yield b"a" * 10000

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        content=chunk_generator(),
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "payload_too_large"}


def test_hook_post_empty_body_returns_400(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        content=b"",
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "malformed_json"}


def test_hook_post_body_at_limit_is_accepted(
    hook_config: Config, store: InMemoryStore, clock: FakeClock
) -> None:
    import json

    app = create_app(hook_config, make_uow_factory(store, clock), clock)
    client = TestClient(app, client=("203.0.113.10", 12345))

    payload = event_hook_payloads.membership_add()
    payload["published"] = NOW.isoformat()
    raw_json = json.dumps(payload).encode("utf-8")
    padding_len = 262144 - len(raw_json)
    assert padding_len > 0
    padded_json = raw_json[:-1] + (b" " * padding_len) + raw_json[-1:]
    assert len(padded_json) == 262144

    response = client.post(
        "/api/v1/hooks/okta",
        headers={"Authorization": f"Bearer {HOOK_SECRET}"},
        content=padded_json,
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
