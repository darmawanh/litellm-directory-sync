"""Private-key JWT OAuth client for the Okta read-only service app."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
from pydantic import BaseModel, ConfigDict, ValidationError

from identity_lifecycle.domain.errors import PermanentError, RetryableError

OKTA_READ_SCOPES = "okta.users.read okta.groups.read okta.logs.read"
_ASSERTION_LIFETIME_SECONDS = 300
_TOKEN_REFRESH_MARGIN_SECONDS = 30
_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class _TokenResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    access_token: str
    expires_in: int
    token_type: str


class OktaOAuth:
    """Mint and cache an OAuth access token with the fixed read-only scopes."""

    def __init__(
        self,
        *,
        org_url: str,
        client_id: str,
        key_id: str,
        private_key_path: str,
        client: httpx.Client,
        epoch: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client_id = client_id
        self._key_id = key_id
        self._token_url = f"{org_url.rstrip('/')}/oauth2/v1/token"
        self._client = client
        self._epoch = epoch
        self._monotonic = monotonic
        self._access_token: str | None = None
        self._expires_at = 0.0
        try:
            self._private_key = Path(private_key_path).read_text(encoding="utf-8")
        except OSError:
            raise PermanentError("Okta OAuth signing key could not be read") from None

    def access_token(self) -> str:
        """Return a cached token or mint one without exposing it in errors or logs."""
        now = self._monotonic()
        if (
            self._access_token is not None
            and self._expires_at - _TOKEN_REFRESH_MARGIN_SECONDS > now
        ):
            return self._access_token

        issued_at = int(self._epoch())
        try:
            assertion = jwt.encode(
                {
                    "iss": self._client_id,
                    "sub": self._client_id,
                    "aud": self._token_url,
                    "iat": issued_at,
                    "exp": issued_at + _ASSERTION_LIFETIME_SECONDS,
                    "jti": str(uuid4()),
                },
                self._private_key,
                algorithm="RS256",
                headers={"kid": self._key_id},
            )
        except jwt.PyJWTError:
            raise PermanentError("Okta OAuth signing key is invalid") from None
        try:
            response = self._client.post(
                "/oauth2/v1/token",
                data={
                    "grant_type": "client_credentials",
                    "scope": OKTA_READ_SCOPES,
                    "client_assertion_type": _CLIENT_ASSERTION_TYPE,
                    "client_assertion": assertion,
                },
                headers={"Accept": "application/json"},
            )
        except (httpx.TimeoutException, httpx.TransportError) as error:
            raise RetryableError(f"Okta token request failed ({type(error).__name__})") from None

        if response.status_code == 429 or response.status_code >= 500:
            raise RetryableError(f"Okta token endpoint returned HTTP {response.status_code}")
        if not response.is_success:
            raise PermanentError(f"Okta token endpoint returned HTTP {response.status_code}")
        try:
            token = _TokenResponse.model_validate(response.json())
        except (ValidationError, ValueError):
            raise PermanentError("Okta token endpoint returned an invalid response") from None
        if token.token_type.casefold() != "bearer" or token.expires_in < 1:
            raise PermanentError("Okta token endpoint returned an invalid token lifetime")

        self._access_token = token.access_token
        self._expires_at = self._monotonic() + token.expires_in
        return token.access_token
