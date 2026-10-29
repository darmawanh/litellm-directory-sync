"""Read-only LDAPS client for Active Directory."""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

import ldap3  # type: ignore[import-untyped]
from ldap3.core.exceptions import (  # type: ignore[import-untyped]
    LDAPCommunicationError,
    LDAPConfigurationError,
    LDAPInsufficientAccessRightsResult,
    LDAPInvalidCredentialsResult,
    LDAPSessionTerminatedByServerError,
    LDAPSocketOpenError,
    LDAPSSLConfigurationError,
)
from ldap3.utils.conv import escape_filter_chars  # type: ignore[import-untyped]

from identity_lifecycle.adapters.ad.mapping import objectguid_to_uuid
from identity_lifecycle.domain.errors import PermanentError, RetryableError

PAGED_RESULTS_CONTROL = "1.2.840.113556.1.4.319"


def escape_ldap_filter(value: str) -> str:
    """Escape arbitrary user or directory data for safe inclusion in an LDAP filter (RFC 4515)."""
    return str(escape_filter_chars(value))


class ADClient:
    """Read-only client for Active Directory over LDAPS on port 636.

    Enforces TLS certificate verification against the provided CA bundle, pins
    the domain controller address resolved once at startup, and provides read-only
    search methods. Write, add, modify, and delete operations are completely absent.
    """

    def __init__(
        self,
        *,
        server: str,
        bind_dn: str,
        bind_password: str,
        ca_cert_path: str,
        port: int = 636,
        timeout_seconds: float = 10.0,
        connection: Any | None = None,
    ) -> None:
        if not server:
            raise PermanentError("Active Directory server host is empty")
        if not bind_dn:
            raise PermanentError("Active Directory bind DN is empty")
        if not bind_password:
            raise PermanentError("Active Directory bind password is empty")
        if not ca_cert_path:
            raise PermanentError("Active Directory CA cert path is empty")
        if port != 636:
            raise PermanentError(f"Active Directory connection must use port 636, got {port}")

        # Ensure server hostname does not contain embedded credentials or non-LDAPS schemes
        clean_server = server
        if "://" in server:
            parts = urlsplit(server)
            if parts.scheme.lower() != "ldaps":
                raise PermanentError(f"LDAPS required, unsupported scheme: {parts.scheme}")
            if parts.username or parts.password:
                raise PermanentError("Active Directory server URL must not contain credentials")
            clean_server = parts.hostname or ""
            if not clean_server:
                raise PermanentError("Active Directory server URL has no hostname")

        self._server = clean_server
        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._ca_cert_path = ca_cert_path
        self._port = port
        self._timeout_seconds = timeout_seconds

        if connection is not None:
            self._connection = connection
            self._owns_connection = False
        else:
            self._owns_connection = True
            self._connection = self._create_connection()

    def _create_connection(self) -> ldap3.Connection:
        """Resolve DC hostname once, pin address, and create read-only LDAPS connection."""
        if not os.path.isfile(self._ca_cert_path):
            raise PermanentError(f"CA certificate file not found: {self._ca_cert_path}")

        try:
            addr_info = socket.getaddrinfo(
                self._server,
                self._port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            if not addr_info:
                raise RetryableError(f"Could not resolve Active Directory host: {self._server}")
            pinned_ip = addr_info[0][4][0]
        except (socket.gaierror, socket.herror, TimeoutError) as error:
            raise RetryableError(
                f"DNS resolution failed for Active Directory host {self._server}: {error}"
            ) from error

        try:
            tls = ldap3.Tls(
                validate=ssl.CERT_REQUIRED,
                ca_certs_file=self._ca_cert_path,
                valid_names=[self._server],
                sni=self._server,
            )
            server_obj = ldap3.Server(
                host=pinned_ip,
                port=self._port,
                use_ssl=True,
                tls=tls,
                connect_timeout=self._timeout_seconds,
                get_info=ldap3.NONE,
            )
            conn = ldap3.Connection(
                server_obj,
                user=self._bind_dn,
                password=self._bind_password,
                read_only=True,
                client_strategy=ldap3.SYNC,
                check_names=False,
                raise_exceptions=False,
            )
            return conn
        except (LDAPSSLConfigurationError, LDAPConfigurationError) as error:
            raise PermanentError(f"LDAPS configuration error: {error}") from error
        except (LDAPSocketOpenError, LDAPCommunicationError) as error:
            raise RetryableError(f"LDAPS connection failed: {error}") from error

    def _ensure_bound(self) -> None:
        """Bind with dedicated read-only credentials if not already bound."""
        if getattr(self._connection, "bound", False):
            return

        try:
            bound = self._connection.bind()
        except (LDAPSocketOpenError, LDAPCommunicationError) as error:
            raise RetryableError(f"Active Directory bind failed: {error}") from error
        except (LDAPInvalidCredentialsResult, LDAPInsufficientAccessRightsResult) as error:
            raise PermanentError(f"Active Directory bind rejected: {error}") from error

        if not bound:
            result = getattr(self._connection, "result", {})
            code = result.get("result", 0) if isinstance(result, dict) else 0
            desc = result.get("description", "bind failure") if isinstance(result, dict) else ""
            if code == 49:
                raise PermanentError(f"Active Directory bind failed (invalid credentials): {desc}")
            if code in (51, 52, 81):
                raise RetryableError(f"Active Directory bind failed (server unavailable): {desc}")
            raise PermanentError(f"Active Directory bind failed ({code}): {desc}")

    def read_root_dse(self) -> dict[str, Any]:
        """Read RootDSE to identify the DC (invocationID) and highestCommittedUSN."""
        entries, _ = self.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=[
                "dnsHostName",
                "invocationID",
                "invocationId",
                "dsServiceName",
                "highestCommittedUSN",
                "supportedControl",
            ],
            paged_size=1,
        )
        if not entries:
            raise PermanentError("Failed to read RootDSE from Active Directory")

        entry = entries[0]
        raw_attrs: dict[str, Any] = entry.get("raw_attributes", {})
        attrs: dict[str, Any] = entry.get("attributes", {})

        dns_host_name_list = attrs.get("dnsHostName", [""])
        dns_host_name = str(dns_host_name_list[0]) if dns_host_name_list else ""

        inv_id_raw = (raw_attrs.get("invocationID") or raw_attrs.get("invocationId") or [None])[0]
        if inv_id_raw is None:
            ds_service_list = attrs.get("dsServiceName", [])
            if ds_service_list and ds_service_list[0]:
                ds_entries, _ = self.search(
                    search_base=str(ds_service_list[0]),
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["invocationId", "objectGUID"],
                    paged_size=1,
                )
                if ds_entries:
                    inv_id_raw = (
                        ds_entries[0].get("raw_attributes", {}).get("invocationId") or [None]
                    )[0]

        if inv_id_raw is not None:
            invocation_id = str(objectguid_to_uuid(inv_id_raw)).lower()
        else:
            inv_attr = (attrs.get("invocationID") or attrs.get("invocationId") or [""])[0]
            if isinstance(inv_attr, bytes):
                invocation_id = str(objectguid_to_uuid(inv_attr)).lower()
            else:
                invocation_id = str(inv_attr).strip()

        usn_raw = (attrs.get("highestCommittedUSN") or [0])[0]
        usn_int = int(usn_raw.decode("utf-8")) if isinstance(usn_raw, bytes) else int(usn_raw)

        return {
            "dnsHostName": dns_host_name,
            "invocationID": invocation_id,
            "highestCommittedUSN": usn_int,
        }

    def search(
        self,
        search_base: str,
        search_filter: str,
        *,
        search_scope: Any = ldap3.SUBTREE,
        attributes: Sequence[str] | None = None,
        paged_size: int = 1000,
        paged_cookie: bytes | None = None,
    ) -> tuple[tuple[dict[str, Any], ...], bytes | None]:
        """Execute a paged LDAP search and return entries with next page cookie."""
        self._ensure_bound()

        attr_list = list(attributes) if attributes is not None else None
        try:
            self._connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attr_list,
                paged_size=paged_size,
                paged_cookie=paged_cookie,
            )
        except (
            LDAPSocketOpenError,
            LDAPCommunicationError,
            LDAPSessionTerminatedByServerError,
        ) as error:
            raise RetryableError(f"Active Directory search failed ({error})") from error
        except (LDAPConfigurationError, LDAPSSLConfigurationError) as error:
            raise PermanentError(f"Active Directory search configuration error: {error}") from error

        result = getattr(self._connection, "result", {})
        if isinstance(result, dict):
            code = result.get("result", 0)
            if code != 0:
                desc = result.get("description", "search error")
                if code in (51, 52, 81):  # busy, unavailable, serverDown
                    raise RetryableError(f"Active Directory search failed ({code}: {desc})")
                raise PermanentError(f"Active Directory search failed ({code}: {desc})")

        response = getattr(self._connection, "response", [])
        entries = [
            e
            for e in response
            if isinstance(e, dict) and e.get("type") in ("searchResEntry", None) and "dn" in e
        ]

        next_cookie: bytes | None = None
        if isinstance(result, dict) and "controls" in result:
            controls = result["controls"]
            if PAGED_RESULTS_CONTROL in controls:
                cookie_val = controls[PAGED_RESULTS_CONTROL].get("value", {}).get("cookie")
                if cookie_val:
                    next_cookie = cookie_val

        return tuple(entries), next_cookie

    def close(self) -> None:
        """Unbind and close the owned connection."""
        if self._owns_connection:
            with contextlib.suppress(Exception):
                self._connection.unbind()
