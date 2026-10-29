"""Contract-faithful LiteLLM HTTP test double for ADR-004 and ADR-019."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import httpx


@dataclass
class FakeLiteLLMHTTP:
    """A small in-memory server for the measured LiteLLM management endpoints."""

    teams: dict[str, str] = field(default_factory=dict)
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    keys: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    queries: list[dict[str, str]] = field(default_factory=list)
    user_info_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    post_response_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)

    def client(self) -> httpx.Client:
        return httpx.Client(
            base_url="https://litellm.example.invalid",
            transport=httpx.MockTransport(self.handle),
        )

    def seed_keys(self, user_id: str, count: int = 2) -> tuple[str, ...]:
        identifiers: list[str] = []
        for index in range(count):
            identifier = hashlib.sha256(f"{user_id}:{index}".encode()).hexdigest()
            self.keys[identifier] = {"user_id": user_id, "blocked": False}
            identifiers.append(identifier)
        return tuple(identifiers)

    def keys_are_blocked(self, user_id: str) -> bool:
        return all(key["blocked"] for key in self.keys.values() if key["user_id"] == user_id)

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        params = dict(request.url.params)
        self.calls.append((request.method, request.url.path, body))
        self.queries.append(params)
        if request.headers.get("Authorization") != "Bearer test-management-key":
            return httpx.Response(401, json={"error": "unauthorized"})

        path = request.url.path
        if path == "/team/list" and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {"team_id": team_id, "team_alias": alias}
                    for team_id, alias in self.teams.items()
                ],
            )
        if path == "/team/new" and request.method == "POST":
            team_id = str(uuid4())
            self.teams[team_id] = str(body["team_alias"])
            return httpx.Response(200, json={"team_id": team_id})
        if path == "/user/new" and request.method == "POST":
            user_id = str(body["user_id"])
            if user_id in self.users:
                return httpx.Response(409, json={"error": "exists"})
            self.users[user_id] = {
                "user_id": user_id,
                "user_email": body["user_email"],
                "user_alias": body["user_alias"],
                "user_role": body["user_role"],
                "teams": list(body["teams"]),
                "max_budget": body["max_budget"],
                "budget_duration": body["budget_duration"],
            }
            self.seed_keys(user_id, count=1)
            if path in self.post_response_overrides:
                return httpx.Response(200, json=self.post_response_overrides[path])
            # This secret-shaped value models the API response; the adapter must
            # ignore it and return only the identifier from /key/list.
            return httpx.Response(200, json={"key": "sk-test-secret-never-returned"})
        if path == "/user/info" and request.method == "GET":
            user = self.users.get(params.get("user_id", ""))
            if user is None:
                return httpx.Response(404, json={"error": "not found"})
            response_user = self.user_info_overrides.get(user["user_id"], user)
            return httpx.Response(
                200,
                json={**response_user, "team_id": (response_user["teams"] or [None])[0]},
            )
        if path == "/key/list" and request.method == "GET":
            user_id = params.get("user_id", "")
            keys = [token for token, value in self.keys.items() if value["user_id"] == user_id]
            page = int(params.get("page", "1"))
            size = int(params.get("size", "10"))
            total_count = len(keys)
            total_pages = (len(keys) + size - 1) // size
            keys = keys[(page - 1) * size : page * size]
            return httpx.Response(
                200,
                json={
                    "keys": keys,
                    "current_page": int(params.get("page", "1")),
                    "total_count": total_count,
                    "total_pages": total_pages,
                },
            )
        if path == "/key/info" and request.method == "GET":
            key = self.keys.get(params.get("key", ""))
            return (
                httpx.Response(404, json={"error": "not found"})
                if key is None
                else httpx.Response(200, json={"blocked": key["blocked"]})
            )
        if path == "/key/block" and request.method == "POST":
            key = self.keys.get(str(body.get("key", "")))
            if key is None:
                return httpx.Response(404, json={"error": "not found"})
            key["blocked"] = True
            return httpx.Response(200, json={"status": "success"})
        if path == "/team/member_delete" and request.method == "POST":
            user = self.users.get(str(body.get("user_id", "")))
            if user is None:
                return httpx.Response(404, json={"error": "not found"})
            user["teams"] = [team for team in user["teams"] if team != body.get("team_id")]
            return httpx.Response(200, json={"status": "success"})
        if path == "/team/member_add" and request.method == "POST":
            user = self.users.get(str(body["member"][0]["user_id"]))
            if user is None:
                return httpx.Response(404, json={"error": "not found"})
            team_id = str(body["team_id"])
            if team_id not in user["teams"]:
                user["teams"].append(team_id)
            return httpx.Response(200, json={"status": "success"})
        if path == "/user/update" and request.method == "POST":
            user = self.users.get(str(body.get("user_id", "")))
            if user is None:
                return httpx.Response(404, json={"error": "not found"})
            user["user_role"] = body["user_role"]
            user["max_budget"] = body["max_budget"]
            user["budget_duration"] = body["budget_duration"]
            return httpx.Response(200, json={"status": "success"})
        if path == "/user/delete" and request.method == "POST":
            for user_id in body["user_ids"]:
                self.users.pop(user_id, None)
                for key, value in tuple(self.keys.items()):
                    if value["user_id"] == user_id:
                        del self.keys[key]
            return httpx.Response(200, json={"status": "success"})
        return httpx.Response(404, json={"error": "unknown endpoint"})
