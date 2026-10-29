"""HTTP boundary for read-only Okta Users, Groups, and System Log calls."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import parse_qs, urlsplit

import httpx

from identity_lifecycle.adapters.okta.oauth import OktaOAuth
from identity_lifecycle.domain.errors import PermanentError, RetryableError


class OktaClient:
    """Issue GETs against the configured org; POST is confined to token minting."""

    def __init__(
        self,
        *,
        org_url: str,
        oauth_client_id: str,
        oauth_key_id: str,
        private_key_path: str,
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not org_url:
            raise PermanentError("Okta org URL is empty")
        origin = urlsplit(org_url)
        if (
            origin.scheme != "https"
            or not origin.netloc
            or origin.username is not None
            or origin.password is not None
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
        ):
            raise PermanentError(
                "Okta org URL must be an HTTPS origin without embedded credentials"
            )
        if not oauth_client_id or not oauth_key_id or not private_key_path:
            raise PermanentError("Okta OAuth service-app credentials are incomplete")
        self._client = client or httpx.Client(
            base_url=org_url.rstrip("/"),
            timeout=timeout_seconds,
        )
        self._owns_client = client is None
        self._oauth = OktaOAuth(
            org_url=org_url,
            client_id=oauth_client_id,
            key_id=oauth_key_id,
            private_key_path=private_key_path,
            client=self._client,
        )

    def close(self) -> None:
        """Close the owned HTTP pool at process shutdown."""
        if self._owns_client:
            self._client.close()

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
        allow_missing: bool = False,
    ) -> httpx.Response | None:
        """Make one read request and map transport/status errors to typed failures."""
        try:
            response = self._client.get(
                path,
                params=params,
                headers={"Authorization": self._authorization(), "Accept": "application/json"},
            )
        except (httpx.TimeoutException, httpx.TransportError) as error:
            raise RetryableError(
                f"Okta request failed ({type(error).__name__}) for {path}"
            ) from None

        if response.status_code == 404 and allow_missing:
            return None
        if response.status_code == 429 or response.status_code >= 500:
            raise RetryableError(f"Okta returned HTTP {response.status_code} for {path}")
        if not response.is_success:
            raise PermanentError(f"Okta returned HTTP {response.status_code} for {path}")
        return response

    def _authorization(self) -> str:
        return f"Bearer {self._oauth.access_token()}"


def next_after(headers: Mapping[str, str]) -> str | None:
    """Extract only the opaque ``after`` parameter from the next Link relation.

    The returned URL is never fetched. Rebuilding requests prevents a Link value
    from dropping the configured System Log filter or changing the target host.
    """
    link = headers.get("Link")
    if link is None:
        return None
    for relation in link.split(","):
        part = relation.strip()
        if 'rel="next"' not in part:
            continue
        target = part.split(";", 1)[0].strip().strip("<>")
        query = parse_qs(urlsplit(target).query, keep_blank_values=True)
        values = query.get("after")
        if values and values[0]:
            return values[0]
    return None
