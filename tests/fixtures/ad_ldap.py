"""In-memory, contract-faithful Active Directory LDAP fixture."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from identity_lifecycle.adapters.ad.client import PAGED_RESULTS_CONTROL, ADClient
from identity_lifecycle.adapters.ad.connector import ADIdentitySource
from identity_lifecycle.ports.clock import Clock
from tests.fixtures.ad import ldap_responses

AD_SOURCE_NAME = "corp-ad"
AD_SERVER = "dc1.corp.example.com"
AD_SEARCH_BASE = ldap_responses.USERS_BASE
AD_GROUP_DN = ldap_responses.GROUP_DN


class FakeADConnection:
    """Mock ldap3.Connection for synchronous searches against fixture data."""

    def __init__(
        self,
        *,
        group_entry: dict[str, Any] | None = None,
        users: Sequence[dict[str, Any]] | None = None,
        root_dse: dict[str, Any] | None = None,
    ) -> None:
        self.group_dn = AD_GROUP_DN
        self.current_group_entry = group_entry or ldap_responses.group_entry()
        self.users: list[dict[str, Any]] = (
            list(users)
            if users is not None
            else [
                ldap_responses.alice_entry(),
                ldap_responses.bob_entry(),
                ldap_responses.carol_entry(),
                ldap_responses.dave_entry(),
            ]
        )
        self.root_dse = root_dse or ldap_responses.root_dse_entry()

        self.bound: bool = True
        self.bind_error_code: int | None = None
        self.raise_error: Exception | None = None
        self.status_override: tuple[int, str] | None = None
        self.override_response: list[dict[str, Any]] | None = None

        self.searches: list[dict[str, Any]] = []
        self.response: list[dict[str, Any]] = []
        self.result: dict[str, Any] = ldap_responses.search_res_done()

    def bind(self) -> bool:
        if self.bind_error_code is not None:
            self.bound = False
            self.result = ldap_responses.search_res_done(
                result=self.bind_error_code,
                description="bind failed",
            )
            return False
        self.bound = True
        self.result = ldap_responses.search_res_done(result=0, description="success")
        return True

    def unbind(self) -> None:
        self.bound = False

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: Any = None,
        attributes: Sequence[str] | None = None,
        paged_size: int | None = None,
        paged_cookie: bytes | None = None,
    ) -> bool:
        self.searches.append(
            {
                "base": search_base,
                "filter": search_filter,
                "scope": search_scope,
                "attributes": attributes,
                "paged_size": paged_size,
                "paged_cookie": paged_cookie,
            }
        )

        if self.raise_error is not None:
            raise self.raise_error

        if self.status_override is not None:
            code, desc = self.status_override
            self.result = ldap_responses.search_res_done(result=code, description=desc)
            self.response = []
            return False

        if self.override_response is not None:
            self.response = list(self.override_response)
            self.result = ldap_responses.search_res_done()
            return True

        # 1. RootDSE query
        if search_base == "":
            self.response = [self.root_dse]
            self.result = ldap_responses.search_res_done()
            return True

        # 2. Group query
        if search_base.lower() == self.group_dn.lower():
            self.response = [self.current_group_entry]
            self.result = ldap_responses.search_res_done()
            return True

        # Base DN match on known entries
        for entry in self.users:
            if entry.get("dn", "").lower() == search_base.lower():
                self.response = [entry]
                self.result = ldap_responses.search_res_done()
                return True

        # 3. Member resolution by distinguishedName
        if "distinguishedName=" in search_filter:
            dns_requested = re.findall(r"\(distinguishedName=([^)]+)\)", search_filter)
            matching: list[dict[str, Any]] = []
            for dn in dns_requested:
                clean_dn = dn.replace(r"\,", ",").strip().lower()
                for user_entry in self.users:
                    if user_entry["dn"].lower() == clean_dn:
                        matching.append(user_entry)
            self.response = matching
            self.result = ldap_responses.search_res_done()
            return True

        # 4. User lookup by objectGUID
        if "objectGUID=" in search_filter:
            match = re.search(r"\(objectGUID=([^)]+)\)", search_filter)
            if match:
                raw_hex = match.group(1).replace("\\", "")
                try:
                    target_bytes = bytes.fromhex(raw_hex)
                    matching_users = [
                        u
                        for u in self.users
                        if u.get("raw_attributes", {}).get("objectGUID", [b""])[0] == target_bytes
                    ]
                    self.response = matching_users
                    self.result = ldap_responses.search_res_done()
                    return True
                except ValueError:
                    pass

        # 5. User delta by uSNChanged
        usn_match = re.search(r"uSNChanged>=(\d+)", search_filter)
        if usn_match:
            min_usn = int(usn_match.group(1))
            matched_users = []
            for u in self.users:
                u_attrs = u.get("attributes", {})
                usn_list = u_attrs.get("uSNChanged", [])
                if usn_list and int(usn_list[0]) >= min_usn:
                    matched_users.append(u)
            self.response = matched_users
            self.result = ldap_responses.search_res_done()
            return True

        # 6. Full user listing
        if "objectClass=user" in search_filter or "objectCategory=person" in search_filter:
            all_users = list(self.users)
            if paged_size and len(all_users) > paged_size:
                if paged_cookie is None:
                    self.response = all_users[:paged_size]
                    cookie_control = {
                        PAGED_RESULTS_CONTROL: {"value": {"cookie": b"page-cookie-2"}}
                    }
                    self.result = ldap_responses.search_res_done(controls=cookie_control)
                    return True
                else:
                    self.response = all_users[paged_size:]
                    self.result = ldap_responses.search_res_done()
                    return True

            self.response = all_users
            self.result = ldap_responses.search_res_done()
            return True

        # Default: empty search result
        self.response = []
        self.result = ldap_responses.search_res_done()
        return True


def create_fake_ad_client(fake_conn: FakeADConnection) -> ADClient:
    """Build an ADClient using the in-memory FakeADConnection."""
    return ADClient(
        server=AD_SERVER,
        bind_dn="CN=read-only,OU=Service Accounts,DC=corp,DC=example,DC=com",
        bind_password="synthetic-password",
        ca_cert_path="config/synthetic-ca.pem",
        connection=fake_conn,
    )


def create_fake_ad_source(
    fake_conn: FakeADConnection,
    clock: Clock,
    *,
    source_name: str = AD_SOURCE_NAME,
) -> ADIdentitySource:
    """Build an ADIdentitySource using FakeADConnection."""
    client = create_fake_ad_client(fake_conn)
    return ADIdentitySource(
        source_name=source_name,
        group_dn=AD_GROUP_DN,
        search_base=AD_SEARCH_BASE,
        client=client,
        clock=clock,
        poll_interval_seconds=60,
    )
