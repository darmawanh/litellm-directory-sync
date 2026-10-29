"""Synchronous LiteLLM management client.

The management API is the only write boundary in this service. Vendor
payloads are parsed here and never leave the adapter. Every mutation is followed
by the ADR-019 read-back; a 2xx response alone is never treated as success.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import TypeVar, cast

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.models import LiteLLMAccount
from identity_lifecycle.domain.policy import BudgetPolicy

_PAGE_SIZE = 100
_MONEY_QUANTUM = Decimal("0.01")
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _UserInfo(BaseModel):
    """The fields of ``GET /user/info`` used by the domain."""

    model_config = ConfigDict(extra="ignore")

    user_id: str
    user_role: str
    teams: list[str] | None = None
    team_id: str | None = None
    max_budget: int | float | None = None


class _TeamInfo(BaseModel):
    """One team from LiteLLM's ``GET /team/list`` response."""

    model_config = ConfigDict(extra="ignore")

    team_id: str
    team_alias: str


class _KeyPage(BaseModel):
    """One page of key references; v1.105.0 returns an identifier, not a secret."""

    model_config = ConfigDict(extra="ignore")

    keys: list[str]
    total_pages: int


class _KeyInfo(BaseModel):
    """The key state returned by ``GET /key/info``."""

    model_config = ConfigDict(extra="ignore")

    blocked: bool | None = False


class LiteLLMGateway:
    """Implement the domain ``Gateway`` using the measured v1.105.0 API surface."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not base_url:
            raise PermanentError("LiteLLM base URL is empty")
        if not api_key:
            raise PermanentError("LiteLLM management key is empty")
        self._api_key = api_key
        self._client = client or httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
        )
        self._owns_client = client is None

    def close(self) -> None:
        """Release the HTTP connection pool when the process stops."""
        if self._owns_client:
            self._client.close()

    def ensure_team(self, *, name: str, create_if_missing: bool) -> str:
        teams = self._list_teams()
        existing = self._teams_named(teams, name)
        if len(existing) > 1:
            raise PermanentError("LiteLLM has multiple teams with the configured alias")
        if existing:
            return existing[0].team_id
        if not create_if_missing:
            raise PermanentError("the configured LiteLLM team does not exist")

        response = self._request_json("POST", "/team/new", json={"team_alias": name})
        returned_id = _string_field(response, "team_id", "team creation response")
        verified = self._teams_named(self._list_teams(), name)
        if len(verified) != 1 or verified[0].team_id != returned_id:
            raise RetryableError("LiteLLM team creation was not confirmed by read-back")
        return verified[0].team_id

    def create_user(
        self,
        *,
        user_id: str,
        email: str,
        display_name: str,
        role: str,
        team_id: str,
        budget: BudgetPolicy,
    ) -> LiteLLMAccount:
        self._request_json(
            "POST",
            "/user/new",
            json={
                "user_id": user_id,
                "user_email": email,
                "user_alias": display_name,
                "user_role": role,
                "teams": [team_id],
                "max_budget": budget.max_budget,
                "budget_duration": budget.budget_duration,
            },
        )
        account = self._read_account(user_id)
        if account is None:
            raise RetryableError("LiteLLM user creation was not confirmed by read-back")
        self._assert_access(account, role=role, team_id=team_id, budget=budget)
        return account

    def update_user(
        self, *, user_id: str, role: str, team_id: str, budget: BudgetPolicy
    ) -> LiteLLMAccount:
        current = self._read_account(user_id)
        if current is None:
            raise PermanentError("LiteLLM user does not exist")

        if current.team != team_id:
            if current.team:
                self._request_json(
                    "POST",
                    "/team/member_delete",
                    json={"team_id": current.team, "user_id": user_id},
                )
                removed = self._read_account(user_id)
                if removed is None or removed.team == current.team:
                    raise RetryableError("LiteLLM team removal was not confirmed by read-back")

            self._request_json(
                "POST",
                "/team/member_add",
                json={
                    "team_id": team_id,
                    "member": [{"user_id": user_id, "role": "user"}],
                },
            )
            added = self._read_account(user_id)
            if added is None or added.team != team_id:
                raise RetryableError("LiteLLM team addition was not confirmed by read-back")

        self._request_json(
            "POST",
            "/user/update",
            json={
                "user_id": user_id,
                "user_role": role,
                "max_budget": budget.max_budget,
                "budget_duration": budget.budget_duration,
            },
        )
        account = self._read_account(user_id)
        if account is None:
            raise RetryableError("LiteLLM user update was not confirmed by read-back")
        self._assert_access(account, role=role, team_id=team_id, budget=budget)
        return account

    def remove_from_team(self, *, user_id: str, team_id: str) -> LiteLLMAccount:
        current = self._read_account(user_id)
        if current is None:
            raise PermanentError("LiteLLM user does not exist")
        if current.team == team_id:
            self._request_json(
                "POST",
                "/team/member_delete",
                json={"team_id": team_id, "user_id": user_id},
            )
            account = self._read_account(user_id)
        else:
            account = current
        if account is None or account.team == team_id:
            raise RetryableError("LiteLLM team removal was not confirmed by read-back")
        return account

    def revoke_keys(self, *, user_id: str) -> LiteLLMAccount:
        before = self._read_account(user_id)
        if before is None:
            raise PermanentError("LiteLLM user does not exist")
        for key_id in before.keys:
            state = self._key_info(key_id, allow_missing=True)
            if state is None or state.blocked:
                continue
            self._request_json("POST", "/key/block", json={"key": key_id})
            state = self._key_info(key_id, allow_missing=True)
            if state is not None and not state.blocked:
                raise RetryableError("LiteLLM key revocation was not confirmed by read-back")

        account = self._read_account(user_id)
        if account is None:
            raise RetryableError("LiteLLM user disappeared during key revocation")
        for key_id in account.keys:
            state = self._key_info(key_id, allow_missing=True)
            if state is None or not state.blocked:
                raise RetryableError("LiteLLM key revocation was not confirmed by read-back")
        return account

    def delete_user(self, *, user_id: str) -> None:
        self._request_json("POST", "/user/delete", json={"user_ids": [user_id]})
        if self._read_account(user_id) is not None:
            raise PermanentError("LiteLLM user deletion was not confirmed by read-back")

    def get_user(self, *, user_id: str) -> LiteLLMAccount | None:
        return self._read_account(user_id)

    def _read_account(self, user_id: str) -> LiteLLMAccount | None:
        body = self._request_json(
            "GET", "/user/info", params={"user_id": user_id}, allow_missing=True
        )
        if body is None:
            return None
        info = _validate(_UserInfo, _unwrap(body, ("user_info", "user")), "user info")
        if info.user_id != user_id:
            raise PermanentError("LiteLLM returned a different user than requested")
        team_ids = info.teams or ([] if not info.team_id else [info.team_id])
        if info.team_id and info.team_id not in team_ids:
            team_ids = [*team_ids, info.team_id]
        if len(set(team_ids)) > 1:
            raise PermanentError("LiteLLM user belongs to multiple teams; the domain stores one")
        if info.max_budget is None:
            raise PermanentError("LiteLLM user has no readable budget")
        key_ids = self._list_key_ids(user_id)
        return LiteLLMAccount(
            user_id=info.user_id,
            status="active",
            role=info.user_role,
            team=team_ids[0] if team_ids else "",
            budget=float(info.max_budget),
            keys=key_ids,
        )

    def _list_teams(self) -> tuple[_TeamInfo, ...]:
        body = self._request_json("GET", "/team/list")
        entries: object = body
        if isinstance(body, Mapping) and "teams" in body:
            entries = body["teams"]
        if not isinstance(entries, list):
            raise PermanentError("LiteLLM team listing has an unexpected shape")
        return tuple(_validate(_TeamInfo, entry, "team listing") for entry in entries)

    def _list_key_ids(self, user_id: str) -> tuple[str, ...]:
        identifiers: list[str] = []
        page = 1
        total_pages: int | None = None
        while total_pages is None or page <= total_pages:
            body = self._request_json(
                "GET",
                "/key/list",
                params={"user_id": user_id, "page": page, "size": _PAGE_SIZE},
            )
            result = _validate(_KeyPage, _unwrap(body, "data"), "key listing")
            if result.total_pages < 0:
                raise PermanentError("LiteLLM key listing returned an invalid page count")
            total_pages = result.total_pages
            for item in result.keys:
                identifier = _key_identifier(item)
                if identifier not in identifiers:
                    identifiers.append(identifier)
            page += 1
        return tuple(sorted(identifiers))

    def _key_info(self, key_id: str, *, allow_missing: bool) -> _KeyInfo | None:
        body = self._request_json(
            "GET", "/key/info", params={"key": key_id}, allow_missing=allow_missing
        )
        if body is None:
            return None
        return _validate(_KeyInfo, _unwrap(body, ("info", "key")), "key info")

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json: Mapping[str, object] | None = None,
        allow_missing: bool = False,
    ) -> object | None:
        try:
            response = self._client.request(
                method,
                path,
                params=params,
                json=json,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        except (httpx.TimeoutException, httpx.TransportError) as error:
            raise RetryableError(
                f"LiteLLM request failed ({type(error).__name__}) for {path}"
            ) from None

        if response.status_code == 404 and allow_missing:
            return None
        if response.status_code == 429 or response.status_code >= 500:
            raise RetryableError(f"LiteLLM returned HTTP {response.status_code} for {path}")
        if response.status_code in {400, 401, 403, 404, 409} or not response.is_success:
            raise PermanentError(f"LiteLLM returned HTTP {response.status_code} for {path}")
        try:
            return cast(object, response.json())
        except ValueError:
            raise RetryableError(f"LiteLLM returned invalid JSON for {path}") from None

    @staticmethod
    def _teams_named(teams: tuple[_TeamInfo, ...], name: str) -> tuple[_TeamInfo, ...]:
        return tuple(team for team in teams if team.team_alias == name)

    @staticmethod
    def _assert_access(
        account: LiteLLMAccount,
        *,
        role: str,
        team_id: str,
        budget: BudgetPolicy,
    ) -> None:
        if (
            account.role != role
            or account.team != team_id
            or not _same_budget(account.budget, budget.max_budget)
        ):
            raise RetryableError("LiteLLM access change was not confirmed by read-back")


def _unwrap(body: object, key: str | tuple[str, ...]) -> object:
    """Accept the documented bare response or its one-field envelope."""
    if isinstance(body, Mapping):
        keys = (key,) if isinstance(key, str) else key
        for k in keys:
            if k in body and isinstance(body[k], Mapping):
                return body[k]
        for k in keys:
            if k in body:
                return body[k]
    return body


def _validate(model: type[_ModelT], value: object, label: str) -> _ModelT:
    try:
        return model.model_validate(value)
    except ValidationError:
        raise PermanentError(f"LiteLLM returned an invalid {label} response") from None


def _string_field(body: object, key: str, label: str) -> str:
    if not isinstance(body, Mapping):
        raise PermanentError(f"LiteLLM returned an invalid {label}")
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise PermanentError(f"LiteLLM returned an invalid {label}")
    return value


def _key_identifier(candidate: str) -> str:
    """Return only the measured non-secret key reference."""
    if len(candidate) != 64 or candidate.startswith("sk-"):
        raise PermanentError("LiteLLM key listing did not contain a safe key identifier")
    return candidate


def _same_budget(actual: float, expected: float) -> bool:
    try:
        return Decimal(str(actual)).quantize(_MONEY_QUANTUM) == Decimal(str(expected)).quantize(
            _MONEY_QUANTUM
        )
    except InvalidOperation:
        return False
