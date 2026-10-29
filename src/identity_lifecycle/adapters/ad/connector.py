"""Active Directory read-only IdentitySource adapter."""

from __future__ import annotations

import base64
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import ldap3  # type: ignore[import-untyped]
import structlog

from identity_lifecycle.adapters.ad.client import ADClient, escape_ldap_filter
from identity_lifecycle.adapters.ad.cursor import format_cursor, parse_cursor
from identity_lifecycle.adapters.ad.mapping import (
    map_group_entry,
    map_user_entry,
    uuid_to_ldap_filter_value,
)
from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.identity_source import (
    Capabilities,
    EventCondition,
    IdentityGroup,
    IdentityUser,
    Page,
)

logger = structlog.get_logger(__name__)

USER_ATTRIBUTES = (
    "objectGUID",
    "uSNChanged",
    "whenChanged",
    "employeeID",
    "userAccountControl",
    "sAMAccountName",
    "displayName",
    "mail",
    "distinguishedName",
)

GROUP_ATTRIBUTES = (
    "objectGUID",
    "uSNChanged",
    "whenChanged",
    "cn",
    "distinguishedName",
    "member",
)


class ADIdentitySource:
    """Implement the synchronous, read-only IdentitySource port for Active Directory."""

    def __init__(
        self,
        *,
        source_name: str,
        group_dn: str,
        search_base: str,
        client: ADClient,
        clock: Clock,
        poll_interval_seconds: int = 60,
    ) -> None:
        self._source_name = source_name
        self._group_dn = group_dn
        self._search_base = search_base
        self._client = client
        self._clock = clock
        self._poll_interval_seconds = poll_interval_seconds

    @property
    def client(self) -> ADClient:
        """Return the underlying client."""
        return self._client

    @property
    def group_dn(self) -> str:
        """Return the configured group DN."""
        return self._group_dn

    def close(self) -> None:
        """Close connection pools at shutdown."""
        self._client.close()

    def name(self) -> str:
        """Return the configured source name."""
        return self._source_name

    def capabilities(self) -> Capabilities:
        """Return supported capabilities (incremental changes, snapshot, membership)."""
        return Capabilities(
            incremental_changes=True,
            full_snapshot=True,
            group_membership=True,
        )

    def list_users(self, cursor: str | None) -> Page[IdentityUser]:
        """Return one page of users under search_base; cursor is the LDAP paging cookie."""
        cookie: bytes | None = None
        if cursor is not None:
            try:
                cookie = base64.b64decode(cursor)
            except Exception:
                cookie = None

        entries, next_cookie = self._client.search(
            search_base=self._search_base,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            search_scope=ldap3.SUBTREE,
            attributes=USER_ATTRIBUTES,
            paged_size=200,
            paged_cookie=cookie,
        )

        users: list[IdentityUser] = []
        for entry in entries:
            try:
                users.append(map_user_entry(entry))
            except Exception as error:
                logger.warning(
                    "ad_user_mapping_failed",
                    dn=entry.get("dn"),
                    error=str(error),
                )

        next_cursor = base64.b64encode(next_cookie).decode("ascii") if next_cookie else None
        return Page(items=tuple(users), next_cursor=next_cursor)

    def get_user(self, source_user_id: str) -> IdentityUser | None:
        """Re-read one user by their canonical objectGUID UUID string."""
        try:
            guid = uuid.UUID(source_user_id)
        except (ValueError, TypeError, AttributeError):
            return None

        filter_val = uuid_to_ldap_filter_value(guid)
        entries, _ = self._client.search(
            search_base=self._search_base,
            search_filter=f"(objectGUID={filter_val})",
            search_scope=ldap3.SUBTREE,
            attributes=USER_ATTRIBUTES,
            paged_size=1,
        )
        if not entries:
            return None

        try:
            return map_user_entry(entries[0])
        except Exception as error:
            logger.warning(
                "ad_get_user_mapping_failed",
                source_user_id=source_user_id,
                error=str(error),
            )
            raise PermanentError(
                f"Active Directory user mapping failed for {source_user_id}: {error}"
            ) from error

    def list_groups(self, cursor: str | None) -> Page[IdentityGroup]:
        """Return one page of groups in scope (the configured group)."""
        entries, _ = self._client.search(
            search_base=self._group_dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=GROUP_ATTRIBUTES,
            paged_size=1,
        )
        if not entries:
            group = IdentityGroup(source_group_id=self._group_dn, name=self._group_dn)
            return Page(items=(group,), next_cursor=None)

        group, _ = map_group_entry(entries[0])
        return Page(items=(group,), next_cursor=None)

    def get_group_members(self, group_id: str, cursor: str | None) -> Page[IdentityUser]:
        """Return one page of a group's members by reading member DNs and resolving them."""
        if "=" in group_id:
            entries, _ = self._client.search(
                search_base=group_id,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=GROUP_ATTRIBUTES,
                paged_size=1,
            )
        else:
            try:
                guid = uuid.UUID(group_id)
                filter_val = uuid_to_ldap_filter_value(guid)
                entries, _ = self._client.search(
                    search_base=self._search_base,
                    search_filter=f"(&(objectClass=group)(objectGUID={filter_val}))",
                    search_scope=ldap3.SUBTREE,
                    attributes=GROUP_ATTRIBUTES,
                    paged_size=1,
                )
            except Exception:
                entries = ()

        if not entries:
            return Page(items=(), next_cursor=None)

        _, member_dns = map_group_entry(entries[0])
        if not member_dns:
            return Page(items=(), next_cursor=None)

        members = self.resolve_members(member_dns)
        return Page(items=members, next_cursor=None)

    def resolve_members(self, member_dns: Sequence[str]) -> tuple[IdentityUser, ...]:
        """Resolve member DNs to IdentityUser values in batches."""
        if not member_dns:
            return ()

        resolved: list[IdentityUser] = []
        batch_size = 50
        for i in range(0, len(member_dns), batch_size):
            batch = member_dns[i : i + batch_size]
            filter_clauses = [f"(distinguishedName={escape_ldap_filter(dn)})" for dn in batch if dn]
            if not filter_clauses:
                continue

            search_filter = f"(|{''.join(filter_clauses)})"
            entries, _ = self._client.search(
                search_base=self._search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=USER_ATTRIBUTES,
                paged_size=len(filter_clauses),
            )
            for entry in entries:
                try:
                    resolved.append(map_user_entry(entry))
                except Exception as error:
                    logger.warning(
                        "ad_member_resolution_failed",
                        dn=entry.get("dn"),
                        error=str(error),
                    )
                    raise PermanentError(
                        f"Active Directory member mapping failed for {entry.get('dn')}: {error}"
                    ) from error

            returned_dns = {
                e.get("dn", "").lower() for e in entries if isinstance(e, dict) and e.get("dn")
            }
            for dn in batch:
                if dn and dn.lower() not in returned_dns:
                    logger.warning("ad_member_dn_not_found", dn=dn)
                    raise PermanentError(f"Active Directory member DN not found: {dn}")

        return tuple(resolved)

    def read_group_entry(self) -> tuple[IdentityGroup, tuple[str, ...], int, datetime]:
        """Read the group entry unconditionally: group, members, USN, whenChanged."""
        entries, _ = self._client.search(
            search_base=self._group_dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=GROUP_ATTRIBUTES,
            paged_size=1,
        )
        if not entries:
            raise PermanentError(f"Active Directory group not found: {self._group_dn}")

        entry = entries[0]
        group, members = map_group_entry(entry)
        attrs = entry.get("attributes", {})

        usn_list = attrs.get("uSNChanged", [0])
        usn_val = usn_list[0] if usn_list else 0
        usn = int(usn_val)

        when_changed = self._parse_when_changed(attrs.get("whenChanged"))
        return group, members, usn, when_changed

    def read_user_delta(self, since_usn: int) -> tuple[tuple[dict[str, Any], ...], int]:
        """Query user delta for uSNChanged >= since_usn and return entries plus max USN."""
        search_filter = f"(&(objectCategory=person)(objectClass=user)(uSNChanged>={since_usn}))"
        cookie: bytes | None = None
        all_entries: list[dict[str, Any]] = []
        max_usn = since_usn

        while True:
            entries, cookie = self._client.search(
                search_base=self._search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=USER_ATTRIBUTES,
                paged_size=1000,
                paged_cookie=cookie,
            )
            all_entries.extend(entries)
            for entry in entries:
                u_list = entry.get("attributes", {}).get("uSNChanged", [])
                if u_list:
                    val = int(u_list[0])
                    if val > max_usn:
                        max_usn = val
            if cookie is None:
                break

        return tuple(all_entries), max_usn

    def poll_changes(self, cursor: str | None) -> Page[CanonicalEvent | EventCondition]:
        """Return one page of changes after cursor (IdentitySource port contract)."""
        root_dse = self._client.read_root_dse()
        connected_dc = root_dse["invocationID"]
        now = self._clock.now()

        parsed_cursor, reason = parse_cursor(cursor, connected_dc=connected_dc)
        group, members, group_usn, when_changed = self.read_group_entry()
        max_usn = max(group_usn, root_dse["highestCommittedUSN"])

        if parsed_cursor is None:
            events: list[CanonicalEvent | EventCondition] = []
            if members:
                users = self.resolve_members(members)
                for user in users:
                    iso = now.isoformat()
                    src_evt_id = f"poll:{self._group_dn}:{user.source_user_id}:add:{iso}"
                    envelope_id = uuid5(
                        NAMESPACE_URL, f"identity-lifecycle:{self._source_name}:{src_evt_id}"
                    )
                    events.append(
                        CanonicalEvent(
                            event_id=envelope_id,
                            source=self._source_name,
                            source_event_id=src_evt_id,
                            type=EventType.GROUP_MEMBER_ADDED,
                            occurred_at=now,
                            person=EventPerson(
                                source_user_id=user.source_user_id,
                                employee_number=user.employee_number,
                            ),
                            group=EventGroup(
                                source_group_id=self._group_dn,
                                name=group.name,
                            ),
                        )
                    )
                    if not user.enabled:
                        dis_str = f"poll:{user.source_user_id}:disabled:{iso}"
                        dis_id = uuid5(
                            NAMESPACE_URL,
                            f"identity-lifecycle:{self._source_name}:{dis_str}",
                        )
                        events.append(
                            CanonicalEvent(
                                event_id=dis_id,
                                source=self._source_name,
                                source_event_id=dis_str,
                                type=EventType.USER_DISABLED,
                                occurred_at=now,
                                person=EventPerson(
                                    source_user_id=user.source_user_id,
                                    employee_number=user.employee_number,
                                ),
                                group=None,
                            )
                        )
            next_token = format_cursor(connected_dc, max_usn)
            return Page(items=tuple(events), next_cursor=next_token)

        since_usn = parsed_cursor.usn
        user_entries, observed_max_usn = self.read_user_delta(since_usn)
        max_usn = max(max_usn, observed_max_usn)

        events_delta: list[CanonicalEvent | EventCondition] = []
        for entry in user_entries:
            try:
                user = map_user_entry(entry)
                entry_usn = int(entry.get("attributes", {}).get("uSNChanged", [since_usn])[0])
                if not user.enabled:
                    evt_type = EventType.USER_DISABLED
                    direction = "disabled"
                else:
                    evt_type = EventType.USER_UPDATED
                    direction = "updated"
                src_evt_id = f"ad:{user.source_user_id}:{direction}:{entry_usn}"
                events_delta.append(
                    CanonicalEvent(
                        event_id=uuid5(
                            NAMESPACE_URL, f"identity-lifecycle:{self._source_name}:{src_evt_id}"
                        ),
                        source=self._source_name,
                        source_event_id=src_evt_id,
                        type=evt_type,
                        occurred_at=now,
                        person=EventPerson(
                            source_user_id=user.source_user_id,
                            employee_number=user.employee_number,
                        ),
                        group=None,
                    )
                )
            except Exception as error:
                logger.warning(
                    "ad_delta_entry_mapping_failed",
                    dn=entry.get("dn"),
                    error=str(error),
                )

        next_token = format_cursor(connected_dc, max_usn)
        return Page(items=tuple(events_delta), next_cursor=next_token)

    def normalize(self, raw_event: Mapping[str, object]) -> CanonicalEvent | EventCondition:
        """Map raw event or condition; AD is pull-only and receives no push events."""
        return EventCondition(
            code="unsupported_source_event",
            detail="AD source does not receive push events; changes are polled via LDAPS",
        )

    def _parse_when_changed(self, raw: Any) -> datetime:
        """Parse AD generalized-time string to UTC datetime."""
        if not raw:
            return self._clock.now()
        val = raw[0] if isinstance(raw, list) else raw
        if isinstance(val, bytes):
            val = val.decode("utf-8")
        if isinstance(val, str):
            clean = val.rstrip("Z").split(".")[0]
            try:
                return datetime.strptime(clean, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
            except Exception:
                pass
        return self._clock.now()
