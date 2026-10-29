"""FastAPI application factory for the inbound HTTP API."""

from __future__ import annotations

import hmac
import ipaddress
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from identity_lifecycle.adapters.okta.mapping import (
    normalize,
    normalize_system_log_entry,
)
from identity_lifecycle.adapters.rate_limiter import MovingWindowLimiter
from identity_lifecycle.api.auth import AdminAuthConfigurationError, AdminToken
from identity_lifecycle.api.routes_admin import create_admin_router
from identity_lifecycle.application.audit_export import AuditExport
from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.manual_sync import ManualSync
from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.config import Config, ConfigError
from identity_lifecycle.domain.events import CanonicalEvent, EventValidationError
from identity_lifecycle.observability.metrics import (
    generate_metrics_payload,
    record_hook_rate_limited,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome

logger = structlog.get_logger(__name__)

DEFAULT_HOOK_PATH = "/api/v1/hooks/okta"
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300
DEFAULT_MAX_BODY_BYTES = 262144


def resolve_client_ip(
    request: Request,
    *,
    trusted_proxies: Sequence[str],
    client_ip_header: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Resolve the client IP from transport peer or trusted proxy walk."""
    peer_host = request.client.host if request.client else None
    if not peer_host:
        return None

    try:
        peer_ip = ipaddress.ip_address(peer_host)
    except ValueError:
        return None

    if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.ipv4_mapped is not None:
        peer_ip = peer_ip.ipv4_mapped

    if not trusted_proxies:
        return peer_ip

    proxy_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for proxy in trusted_proxies:
        try:
            proxy_networks.append(ipaddress.ip_network(proxy, strict=False))
        except ValueError:
            continue

    is_peer_trusted = any(peer_ip in net for net in proxy_networks)
    if not is_peer_trusted:
        return peer_ip

    raw_header = request.headers.get(client_ip_header)
    if not raw_header:
        return None

    hops: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for hop_str in raw_header.split(","):
        cleaned = hop_str.strip().strip("[]")
        if not cleaned:
            continue
        try:
            hop_ip = ipaddress.ip_address(cleaned)
            if isinstance(hop_ip, ipaddress.IPv6Address) and hop_ip.ipv4_mapped is not None:
                hop_ip = hop_ip.ipv4_mapped
            hops.append(hop_ip)
        except ValueError:
            return None

    if not hops:
        return None

    # Rightmost hop that is not a trusted proxy wins
    for hop in reversed(hops):
        if not any(hop in net for net in proxy_networks):
            return hop

    return None


def is_ip_allowlisted(
    client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
    allowlist: Sequence[str],
) -> bool:
    """Check if the resolved client IP falls within the configured allowlist."""
    if client_ip is None:
        return False
    if not allowlist:
        return True
    for entry in allowlist:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if client_ip in net:
                return True
        except ValueError:
            continue
    return False


def verify_auth_header(
    request: Request,
    *,
    auth_header_name: str,
    auth_scheme: str,
    shared_secrets: Sequence[str],
) -> bool:
    """Verify authorization in constant time against hook shared secrets."""
    header_values = request.headers.getlist(auth_header_name)
    if len(header_values) != 1:
        return False
    received = header_values[0].encode("utf-8")

    scheme_prefix = f"{auth_scheme} " if auth_scheme else ""
    for secret in shared_secrets:
        if not secret:
            continue
        expected = (scheme_prefix + secret).encode("utf-8")
        if hmac.compare_digest(expected, received):
            return True

    return False


def verify_skew(
    published_str: str,
    now: datetime,
    max_skew_seconds: float,
) -> tuple[bool, str]:
    """Verify timestamp skew against current clock time."""
    try:
        published_dt = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
    except ValueError:
        return False, "unparseable_timestamp"

    if published_dt.utcoffset() is None:
        published_dt = published_dt.replace(tzinfo=UTC)

    diff = (now - published_dt).total_seconds()
    if diff > max_skew_seconds:
        return False, "stale_event"
    if diff < -max_skew_seconds:
        return False, "future_dated"
    return True, "ok"


def create_app(
    config: Config,
    uow_factory: UnitOfWorkFactory,
    clock: Clock,
    *,
    admin_token: AdminToken | None = None,
    manual_sync: ManualSync | None = None,
    reconcile: Reconcile | None = None,
    audit_export: AuditExport | None = None,
) -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(title="Identity Lifecycle API", version="0.1.0")

    # Mount administrative endpoints router
    try:
        resolved_admin_token = (
            admin_token
            if admin_token is not None
            else AdminToken(config.general_settings.master_key.get_secret_value())
        )
    except AdminAuthConfigurationError as error:
        raise ConfigError(
            key="general_settings.master_key",
            reason="invalid_value",
            detail=str(error),
        ) from error
    resolved_audit_export = (
        audit_export if audit_export is not None else AuditExport(uow_factory, clock)
    )
    admin_router = create_admin_router(
        admin_token=resolved_admin_token,
        audit_export=resolved_audit_export,
        manual_sync=manual_sync,
        reconcile=reconcile,
    )
    app.include_router(admin_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe reporting process health."""
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> Response:
        """Readiness probe checking database connectivity via UnitOfWork."""
        try:
            with uow_factory("probe") as uow:
                uow.cursors.read("__probe__", "__readyz__")
            return JSONResponse(status_code=200, content={"status": "ready"})
        except Exception as error:
            logger.warning("readiness_check_failed", error=str(error))
            return JSONResponse(status_code=503, content={"status": "not_ready"})

    @app.get("/metrics")
    async def metrics() -> Response:
        """Prometheus metrics exposition endpoint."""
        content, media_type = generate_metrics_payload()
        return Response(content=content, media_type=media_type)

    rate_limiter = MovingWindowLimiter()

    enabled_sources = frozenset(s.source_name for s in config.identity_sources if s.enabled)
    ingest_use_case = IngestEvent(uow_factory, enabled_sources=enabled_sources)

    # Mount hook routes only for sources with an event_hook block and enabled
    for source in config.identity_sources:
        if (
            source.source_type == "okta"
            and source.enabled
            and source.okta is not None
            and source.okta.event_hook is not None
        ):
            source_name = source.source_name
            event_hook = source.okta.event_hook
            hook_path = event_hook.path

            auth_header_name = event_hook.auth_header
            auth_scheme = event_hook.auth_scheme
            shared_secrets = [
                s
                for s in (
                    event_hook.shared_secret.get_secret_value(),
                    event_hook.shared_secret_previous.get_secret_value(),
                )
                if s
            ]

            ip_allowlist = event_hook.ip_allowlist
            trusted_proxies = event_hook.trusted_proxies
            client_ip_header = event_hook.client_ip_header
            max_skew_seconds = float(event_hook.max_clock_skew_seconds)
            max_body_bytes = event_hook.max_body_bytes
            rate_spec = f"{event_hook.verification_requests_per_minute}/minute"

            def mount_okta_hook(
                s_name: str,
                path: str,
                h_name: str,
                h_scheme: str,
                secrets: list[str],
                allowlist: Sequence[str],
                proxies: Sequence[str],
                ip_header: str,
                max_skew: float,
                max_bytes: int,
                r_spec: str,
            ) -> None:
                @app.get(path)
                async def okta_verification_get(request: Request) -> Response:
                    """Okta GET verification handshake."""
                    client_ip = resolve_client_ip(
                        request,
                        trusted_proxies=proxies,
                        client_ip_header=ip_header,
                    )

                    # Rate limit check for verification challenge
                    key = f"{s_name}:{client_ip}"
                    if not rate_limiter.hit(r_spec, key):
                        retry_after = rate_limiter.get_retry_after(
                            r_spec, key, clock.now().timestamp()
                        )
                        record_hook_rate_limited(s_name)
                        return JSONResponse(
                            status_code=429,
                            headers={"Retry-After": str(retry_after)},
                            content={"detail": "rate_limit_exceeded"},
                        )

                    challenge = request.headers.get("x-okta-verification-challenge")
                    if not challenge:
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "missing x-okta-verification-challenge header"},
                        )
                    return JSONResponse(status_code=200, content={"verification": challenge})

                @app.post(path)
                async def okta_hook_post(request: Request) -> Response:
                    """Okta Event Hook POST ingestion."""
                    # 1. Early Content-Length check before buffering
                    content_length_header = request.headers.get("content-length")
                    if content_length_header is not None:
                        try:
                            content_length = int(content_length_header)
                            if content_length > max_bytes:
                                return JSONResponse(
                                    status_code=413,
                                    content={"detail": "payload_too_large"},
                                )
                        except ValueError:
                            return JSONResponse(
                                status_code=400,
                                content={"detail": "invalid_content_length"},
                            )

                    # 2. Bounded streaming read up to configured limit
                    body_chunks: list[bytes] = []
                    total_bytes = 0
                    async for chunk in request.stream():
                        total_bytes += len(chunk)
                        if total_bytes > max_bytes:
                            return JSONResponse(
                                status_code=413,
                                content={"detail": "payload_too_large"},
                            )
                        body_chunks.append(chunk)

                    body_bytes = b"".join(body_chunks)

                    # 3. JSON parse check
                    try:
                        payload: Any = json.loads(body_bytes)
                    except Exception:
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "malformed_json"},
                        )

                    if not isinstance(payload, dict):
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "malformed_payload"},
                        )

                    # 3. IP allowlist check
                    client_ip = resolve_client_ip(
                        request,
                        trusted_proxies=proxies,
                        client_ip_header=ip_header,
                    )
                    if allowlist and (
                        client_ip is None or not is_ip_allowlisted(client_ip, allowlist)
                    ):
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "client_ip_not_allowlisted"},
                        )

                    # 4. Authentication check (shared secret only, no master key)
                    authenticated = verify_auth_header(
                        request,
                        auth_header_name=h_name,
                        auth_scheme=h_scheme,
                        shared_secrets=secrets,
                    )
                    if not authenticated:
                        return JSONResponse(
                            status_code=401,
                            content={"detail": "unauthorized"},
                        )

                    # 5. Rate limit check
                    key = f"{s_name}:{client_ip}"
                    if not rate_limiter.hit(r_spec, key):
                        retry_after = rate_limiter.get_retry_after(
                            r_spec, key, clock.now().timestamp()
                        )
                        record_hook_rate_limited(s_name)
                        return JSONResponse(
                            status_code=429,
                            headers={"Retry-After": str(retry_after)},
                            content={"detail": "rate_limit_exceeded"},
                        )

                    # 6. One-time verification challenge via POST body
                    if "verification" in payload:
                        if set(payload) == {"verification"}:
                            return JSONResponse(
                                status_code=200,
                                content={"verification": str(payload["verification"])},
                            )
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "malformed_challenge"},
                        )

                    # 7. Extract raw events
                    raw_events: list[dict[str, Any]]
                    if "data" in payload and isinstance(payload["data"], dict):
                        events_field = payload["data"].get("events")
                        if isinstance(events_field, list):
                            raw_events = [e for e in events_field if isinstance(e, dict)]
                        else:
                            return JSONResponse(
                                status_code=400,
                                content={"detail": "malformed_events_list"},
                            )
                    elif "eventType" in payload:
                        raw_events = [payload]
                    else:
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "missing_events"},
                        )

                    if not raw_events:
                        return JSONResponse(status_code=200, content={"status": "ignored"})

                    # 8. Validate skew and normalize events
                    events_to_enqueue: list[CanonicalEvent] = []
                    now = clock.now()

                    for raw_event in raw_events:
                        published = raw_event.get("published")
                        if not isinstance(published, str):
                            return JSONResponse(
                                status_code=400,
                                content={"detail": "malformed_published_timestamp"},
                            )

                        skew_ok, skew_reason = verify_skew(published, now, max_skew)
                        if not skew_ok:
                            return JSONResponse(
                                status_code=400,
                                content={"detail": skew_reason},
                            )

                        norm_result = normalize(raw_event, source_name=s_name)
                        if isinstance(norm_result, CanonicalEvent):
                            events_to_enqueue.append(norm_result)
                        elif norm_result.code == "missing_employee_number":
                            canonical = normalize_system_log_entry(raw_event, source_name=s_name)
                            if isinstance(canonical, CanonicalEvent):
                                events_to_enqueue.append(canonical)
                            else:
                                return JSONResponse(
                                    status_code=400,
                                    content={"detail": norm_result.detail},
                                )
                        elif norm_result.code in ("unsuccessful_outcome", "unsupported_event_type"):
                            continue
                        else:
                            return JSONResponse(
                                status_code=400,
                                content={"detail": norm_result.detail},
                            )

                    if not events_to_enqueue:
                        return JSONResponse(status_code=200, content={"status": "ignored"})

                    # 9. Persist events via IngestEvent in threadpool
                    def _persist_events() -> bool:
                        any_inserted = False
                        for event in events_to_enqueue:
                            outcome = ingest_use_case.ingest(event)
                            if outcome is EnqueueOutcome.INSERTED:
                                any_inserted = True
                        return any_inserted

                    try:
                        any_inserted = await run_in_threadpool(_persist_events)
                        if any_inserted:
                            return JSONResponse(status_code=200, content={"status": "accepted"})
                        return JSONResponse(status_code=200, content={"status": "duplicate"})
                    except EventValidationError as error:
                        logger.warning("hook_source_unconfigured", error=str(error))
                        return JSONResponse(status_code=404, content={"detail": "unknown_source"})
                    except Exception as error:
                        logger.error("outbox_enqueue_failed", error=str(error))
                        return JSONResponse(
                            status_code=503,
                            content={"status": "error", "detail": "enqueue_failed"},
                        )

            mount_okta_hook(
                source_name,
                hook_path,
                auth_header_name,
                auth_scheme,
                shared_secrets,
                ip_allowlist,
                trusted_proxies,
                client_ip_header,
                max_skew_seconds,
                max_body_bytes,
                rate_spec,
            )

    return app
