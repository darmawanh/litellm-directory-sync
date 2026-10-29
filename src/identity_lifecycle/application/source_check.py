"""Source check use case: verify connectivity and read permissions for identity sources.

Allows operators to perform diagnostic verification of directory connections,
TLS authentication, and target group readability without running poller loops,
modifying database state, or advancing cursors.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass

import structlog

from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.identity_source import IdentitySource

logger = structlog.get_logger(__name__)


class SourceNotFoundError(PermanentError):
    """The requested identity source was not found in configuration or is not enabled."""


@dataclass(frozen=True)
class SourceCheckResult:
    """The outcome of verifying one identity source connection and read permissions."""

    source_name: str
    status: str  # "ok" or "failed"
    group_name: str | None = None
    group_id: str | None = None
    member_count: int = 0
    duration_ms: float = 0.0
    error: str | None = None
    exception: Exception | None = None


class SourceCheck:
    """Diagnostic check for configured identity sources."""

    def __init__(
        self,
        sources: Mapping[str, IdentitySource],
        clock: Clock,
    ) -> None:
        self._sources = sources
        self._clock = clock

    def check(self, source_name: str | None = None) -> tuple[SourceCheckResult, ...]:
        """Check the specified source or all configured enabled sources."""
        if source_name is not None:
            if source_name not in self._sources:
                raise SourceNotFoundError(
                    f"Identity source {source_name!r} not found among enabled sources: "
                    f"{sorted(self._sources)}"
                )
            return (self._check_single(self._sources[source_name]),)

        results: list[SourceCheckResult] = []
        for name in sorted(self._sources):
            results.append(self._check_single(self._sources[name]))
        return tuple(results)

    def _check_single(self, source: IdentitySource) -> SourceCheckResult:
        name = source.name()
        start = time.monotonic()
        try:
            groups_page = source.list_groups(cursor=None)
            group_name: str | None = None
            group_id: str | None = None
            member_count = 0

            if groups_page.items:
                target_group = groups_page.items[0]
                group_name = target_group.name
                group_id = target_group.source_group_id
                members_page = source.get_group_members(target_group.source_group_id, cursor=None)
                member_count = len(members_page.items)

            duration_ms = (time.monotonic() - start) * 1000.0
            logger.info(
                "source_check_passed",
                source=name,
                group=group_name,
                members=member_count,
                duration_ms=round(duration_ms, 2),
            )
            return SourceCheckResult(
                source_name=name,
                status="ok",
                group_name=group_name,
                group_id=group_id,
                member_count=member_count,
                duration_ms=round(duration_ms, 2),
            )
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000.0
            logger.error(
                "source_check_failed",
                source=name,
                error=str(exc),
                duration_ms=round(duration_ms, 2),
            )
            return SourceCheckResult(
                source_name=name,
                status="failed",
                duration_ms=round(duration_ms, 2),
                error=str(exc),
                exception=exc,
            )
