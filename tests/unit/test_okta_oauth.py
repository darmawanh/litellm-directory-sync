"""Okta service-app JWT uses only the configured read scopes."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from identity_lifecycle.adapters.okta.oauth import OKTA_READ_SCOPES, OktaOAuth


@pytest.mark.unit
def test_oauth_assertion_is_rs256_scoped_and_access_token_is_cached(tmp_path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "okta-test-private-key.pem"
    key_path.write_bytes(private_pem)
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"access_token": "test-access-token", "expires_in": 3600, "token_type": "Bearer"},
            request=request,
        )

    client = httpx.Client(
        base_url="https://example.okta.com", transport=httpx.MockTransport(handle)
    )
    oauth = OktaOAuth(
        org_url="https://example.okta.com",
        client_id="synthetic-client-id",
        key_id="synthetic-key-id",
        private_key_path=str(key_path),
        client=client,
        epoch=lambda: datetime(2026, 1, 1, 12, 0, tzinfo=UTC).timestamp(),
        monotonic=lambda: 10.0,
    )

    assert oauth.access_token() == "test-access-token"
    assert oauth.access_token() == "test-access-token"

    assert len(requests) == 1
    form = parse_qs(requests[0].content.decode("ascii"))
    assert form["scope"] == [OKTA_READ_SCOPES]
    assert form["grant_type"] == ["client_credentials"]
    assertion = form["client_assertion"][0]
    decoded = jwt.decode(
        assertion,
        private_key.public_key(),
        algorithms=["RS256"],
        audience="https://example.okta.com/oauth2/v1/token",
        options={"verify_exp": False},
    )
    assert decoded["iss"] == "synthetic-client-id"
    assert decoded["sub"] == "synthetic-client-id"
    assert requests[0].url.path == "/oauth2/v1/token"
    client.close()
