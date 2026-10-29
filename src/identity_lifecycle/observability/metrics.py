"""Prometheus metrics for identity lifecycle monitoring."""

from __future__ import annotations

import prometheus_client
from prometheus_client import Counter, Histogram

REVOCATION_SLA_SECONDS = 900.0  # 15 minutes

# Precedence failure counter
EQUAL_PRECEDENCE_FAILURES = Counter(
    "identity_lifecycle_equal_precedence_failures_total",
    "Number of events that failed due to equal-precedence group mappings",
    ["source"],
)

# Revocation SLA duration histogram
REVOCATION_DURATION_SECONDS = Histogram(
    "identity_lifecycle_revocation_duration_seconds",
    "Time in seconds from event occurrence to gateway key revocation",
    ["source"],
    buckets=(15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0, 1800.0, 3600.0),
)

# Revocation SLA violations counter (> 15 minutes)
REVOCATION_SLA_VIOLATIONS = Counter(
    "identity_lifecycle_revocation_sla_violations_total",
    "Number of revocations that exceeded the 15-minute SLA threshold",
    ["source"],
)

# Event processing total
EVENTS_PROCESSED = Counter(
    "identity_lifecycle_events_processed_total",
    "Total number of events processed by the worker",
    ["source", "action", "outcome"],
)

# Event processing duration histogram
EVENT_PROCESSING_DURATION_SECONDS = Histogram(
    "identity_lifecycle_event_processing_duration_seconds",
    "Duration in seconds spent processing one event",
    ["source", "action"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

# Admin API authentication rejected counter
ADMIN_AUTH_REJECTED = Counter(
    "identity_lifecycle_admin_auth_rejected_total",
    "Total number of rejected inbound admin API requests",
    ["reason"],
)

# Hook rate limited counter
HOOK_RATE_LIMITED = Counter(
    "identity_lifecycle_hook_rate_limited_total",
    "Total number of hook requests rejected due to rate limiting",
    ["source"],
)


def record_equal_precedence_failure(source: str) -> None:
    """Record an equal-precedence conflict failure."""
    EQUAL_PRECEDENCE_FAILURES.labels(source=source).inc()


def record_revocation_sla(source: str, duration_seconds: float) -> None:
    """Record revocation latency and track SLA violations."""
    safe_duration = max(0.0, duration_seconds)
    REVOCATION_DURATION_SECONDS.labels(source=source).observe(safe_duration)
    if safe_duration > REVOCATION_SLA_SECONDS:
        REVOCATION_SLA_VIOLATIONS.labels(source=source).inc()


def record_event_processed(
    source: str,
    action: str,
    outcome: str,
    duration_seconds: float,
) -> None:
    """Record completed event processing."""
    safe_duration = max(0.0, duration_seconds)
    EVENTS_PROCESSED.labels(source=source, action=action, outcome=outcome).inc()
    EVENT_PROCESSING_DURATION_SECONDS.labels(source=source, action=action).observe(safe_duration)


def record_admin_auth_rejected(reason: str) -> None:
    """Record a rejected admin API authentication attempt."""
    ADMIN_AUTH_REJECTED.labels(reason=reason).inc()


def record_hook_rate_limited(source: str) -> None:
    """Record a hook rate limit rejection."""
    HOOK_RATE_LIMITED.labels(source=source).inc()


def generate_metrics_payload() -> tuple[bytes, str]:
    """Return serialized Prometheus metrics bytes and media type string."""
    return (
        prometheus_client.generate_latest(),
        prometheus_client.CONTENT_TYPE_LATEST,
    )
