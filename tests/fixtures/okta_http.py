"""In-memory, contract-faithful Okta HTTP fixture."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from identity_lifecycle.adapters.okta.client import OktaClient
from tests.fixtures.okta.event_hook_payloads import GROUP_ID, GROUP_NAME

ORG_URL = "https://example.okta.com"
SOURCE_NAME = "corp-okta"
SERVER_DATE = "Thu, 01 Jan 2026 12:00:00 GMT"


def user(
    source_user_id: str,
    *,
    employee_number: str | None = "E10001",
    email: str = "ada@example.com",
    name: str = "Ada Lovelace",
    status: str = "ACTIVE",
) -> dict[str, object]:
    """Build one documented Okta Users API user response with synthetic values."""
    return {
        "id": source_user_id,
        "status": status,
        "profile": {
            "employeeNumber": employee_number,
            "email": email,
            "login": email,
            "displayName": name,
        },
    }


class FakeOktaHTTP:
    """Stateful HTTP handler for users, groups, System Log, and OAuth token exchange."""

    def __init__(self) -> None:
        self.group_id = GROUP_ID
        self.group_name = GROUP_NAME
        self.users: dict[str, dict[str, object]] = {}
        self.members: list[str] = []
        self.user_page_size = 1
        self.member_page_size = 1
        self.log_pages: dict[str | None, tuple[list[object], str | None]] = {None: ([], None)}
        self.status_overrides: dict[str, int] = {}
        self.requests: list[httpx.Request] = []
        self.token_requests: list[Mapping[str, list[str]]] = []

    def add_user(self, value: dict[str, object], *, member: bool = False) -> None:
        source_user_id = value["id"]
        assert isinstance(source_user_id, str)
        self.users[source_user_id] = value
        if member and source_user_id not in self.members:
            self.members.append(source_user_id)

    def httpx_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=ORG_URL,
            transport=httpx.MockTransport(self.handle),
        )

    def oauth_client(self) -> OktaClient:
        """Build a client with a throwaway RSA key that exists only in a temp folder."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "temporary-test-key.pem"
            key_path.write_bytes(private_pem)
            return OktaClient(
                org_url=ORG_URL,
                oauth_client_id="synthetic-client-id",
                oauth_key_id="synthetic-key-id",
                private_key_path=str(key_path),
                client=self.httpx_client(),
            )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "POST" and request.url.path == "/oauth2/v1/token":
            from urllib.parse import parse_qs

            self.token_requests.append(parse_qs(request.content.decode("ascii")))
            return self._response(
                request,
                {"access_token": "test-access-token", "expires_in": 3600, "token_type": "Bearer"},
            )
        if request.method != "GET":
            return self._response(request, {"error": "method not allowed"}, status=405)

        path = request.url.path
        if path in self.status_overrides:
            return self._response(
                request,
                {"error": "synthetic status"},
                status=self.status_overrides[path],
            )
        if path == "/api/v1/users":
            return self._list_users(request)
        if path.startswith("/api/v1/users/"):
            source_user_id = path.rsplit("/", 1)[-1]
            value = self.users.get(source_user_id)
            if value is None:
                return self._response(request, {"error": "not found"}, status=404)
            return self._response(request, value)
        if path == f"/api/v1/groups/{self.group_id}":
            return self._response(
                request,
                {"id": self.group_id, "profile": {"name": self.group_name}},
            )
        if path == f"/api/v1/groups/{self.group_id}/users":
            return self._list_members(request)
        if path == "/api/v1/logs":
            return self._system_log_page(request)
        return self._response(request, {"error": "not found"}, status=404)

    def _list_users(self, request: httpx.Request) -> httpx.Response:
        values = list(self.users.values())
        page, next_after = self._page(
            values,
            request.url.params.get("after"),
            self.user_page_size,
            "users",
        )
        headers = self._link_header(next_after)
        return self._response(request, page, headers=headers)

    def _list_members(self, request: httpx.Request) -> httpx.Response:
        values = [self.users[user_id] for user_id in self.members if user_id in self.users]
        page, next_after = self._page(
            values,
            request.url.params.get("after"),
            self.member_page_size,
            "members",
        )
        return self._response(request, page, headers=self._link_header(next_after))

    def _system_log_page(self, request: httpx.Request) -> httpx.Response:
        after = request.url.params.get("after")
        body, next_after = self.log_pages.get(after, ([], None))
        return self._response(request, body, headers=self._link_header(next_after))

    @staticmethod
    def _page(
        values: list[dict[str, object]],
        after: str | None,
        page_size: int,
        cursor_prefix: str,
    ) -> tuple[list[dict[str, object]], str | None]:
        offset = 0 if after is None else int(after.rsplit("-", 1)[-1])
        page = values[offset : offset + page_size]
        next_offset = offset + page_size
        next_after = f"{cursor_prefix}-{next_offset}" if next_offset < len(values) else None
        return page, next_after

    @staticmethod
    def _link_header(after: str | None) -> dict[str, str]:
        if after is None:
            return {}
        target = f"{ORG_URL}/api/v1/logs?{urlencode({'limit': 200, 'after': after})}"
        return {"Link": f'<{target}>; rel="next"'}

    @staticmethod
    def _response(
        request: httpx.Request,
        body: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        return httpx.Response(
            status,
            json=body,
            headers={"Date": SERVER_DATE, **(headers or {})},
            request=request,
        )
