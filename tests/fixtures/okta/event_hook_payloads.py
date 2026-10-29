"""Hand-built Okta Event Hook bodies for the T-008 spike.

Written from Okta's documented Event Hook shape, **not captured from a live org**.
No org exists here, no request is sent, and this module is data only.

``membership_add`` / ``membership_remove`` are the membership signals FR8 needs;
``user_deactivate`` is FR25's disable signal and has no group target;
``VERIFICATION_REQUEST`` is the one-time registration exchange from design 9.3, a
different request shape and not an event;
``membership_add_without_employee_number`` is the case the design does not settle,
because a real user target usually has ``detailEntry: null``, leaving only the
immutable Okta ``id``; and ``membership_add_failed_outcome`` carries
``outcome.result: DENY``, which means the change did not happen and must not be
mapped as an applied event.

Every id is synthetic, every host is ``example.com``, and ``VERIFICATION_SECRET``
is a literal placeholder that exists only to make the HMAC vector reproducible.
"""

from __future__ import annotations

from typing import Any

ALICE_USER_ID = "00uPLACEHOLDERUSER01"
BOB_USER_ID = "00uPLACEHOLDERUSER02"
DAVE_USER_ID = "00uPLACEHOLDERUSER04"
GROUP_ID = "00gPLACEHOLDERGRP01"
GROUP_NAME = "AI-Platform-Users"

# Deterministic event ids so a replay produces the same canonical ``event_id``.
ADD_EVENT_UUID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
REMOVE_EVENT_UUID = "1a2b3c4d-5e6f-4a7b-9c8d-0e1f2a3b4c5d"
DEACTIVATE_EVENT_UUID = "2a3b4c5d-6e7f-4a8b-8d9e-0f1a2b3c4d5e"
NO_EMPLOYEE_NUMBER_EVENT_UUID = "3a4b5c6d-7e8f-4a9b-9c0d-1e2f3a4b5c6d"
FAILED_EVENT_UUID = "4a5b6c7d-8e9f-4a0b-8c1d-2e3f4a5b6c7d"

VERIFICATION_CHALLENGE = "cGxhY2Vob2xkZXItY2hhbGxlbmdl"
VERIFICATION_SECRET = "placeholder-shared-secret-not-a-credential"
VERIFICATION_REQUEST: dict[str, Any] = {"verification": VERIFICATION_CHALLENGE}

# The read-only header set a live registration would carry, so the fixture shows
# the difference between "authenticated request" and "payload signature".
HOOK_REQUEST_HEADERS: dict[str, str] = {
    "Content-Type": "application/json",
    "Authorization": "Bearer placeholder-shared-secret-not-a-credential",
    "User-Agent": "Okta-EventHook/1.0",
}


def _target(target_type: str, target_id: str, alternate_id: str, **detail: Any) -> dict[str, Any]:
    return {
        "id": target_id,
        "type": target_type,
        "alternateId": alternate_id,
        "displayName": alternate_id,
        "detailEntry": detail or None,
    }


def user_target(user_id: str, email: str, employee_number: str | None) -> dict[str, Any]:
    """A ``User`` target; ``employeeNumber`` lives in ``detailEntry`` when present."""
    detail = {"employeeNumber": employee_number} if employee_number else {}
    return _target("User", user_id, email, **detail)


def group_target() -> dict[str, Any]:
    """A ``UserGroup`` target, matched by id because the name is not stable."""
    return _target("UserGroup", GROUP_ID, GROUP_NAME)


def _event(
    event_type: str,
    uuid: str,
    published: str,
    targets: list[dict[str, Any]],
    outcome: str = "SUCCESS",
) -> dict[str, Any]:
    return {
        "eventType": event_type,
        "version": "0",
        "severity": "INFO",
        "displayMessage": "Placeholder display message",
        "actor": {"id": "00uPLACEHOLDERADMIN1", "type": "User", "detailEntry": None},
        "client": {"ipAddress": "203.0.113.10", "geographicalContext": None},
        "outcome": {"result": outcome, "reason": None if outcome == "SUCCESS" else "POLICY"},
        "published": published,
        "target": targets,
        "uuid": uuid,
    }


ALICE = user_target(ALICE_USER_ID, "alice.adams@example.com", "E10001")
DAVE = user_target(DAVE_USER_ID, "dave.davis@example.com", "E20002")
BOB_NO_EMPLOYEE_NUMBER = user_target(BOB_USER_ID, "bob.brown@example.com", None)


def membership_add() -> dict[str, Any]:
    """``group.user_membership.add`` for Alice, who has an ``employeeNumber``."""
    return _event(
        "group.user_membership.add",
        ADD_EVENT_UUID,
        "2026-01-01T12:00:00.000Z",
        [ALICE, group_target()],
    )


def membership_remove() -> dict[str, Any]:
    """``group.user_membership.remove`` for Alice."""
    return _event(
        "group.user_membership.remove",
        REMOVE_EVENT_UUID,
        "2026-01-01T12:05:00.000Z",
        [ALICE, group_target()],
    )


def user_deactivate() -> dict[str, Any]:
    """``user.lifecycle.deactivate`` for Dave: a user event with no group target."""
    return _event(
        "user.lifecycle.deactivate", DEACTIVATE_EVENT_UUID, "2026-01-01T12:10:00.000Z", [DAVE]
    )


def membership_add_without_employee_number() -> dict[str, Any]:
    """``group.user_membership.add`` for Bob, whose target has no ``employeeNumber``."""
    return _event(
        "group.user_membership.add",
        NO_EMPLOYEE_NUMBER_EVENT_UUID,
        "2026-01-01T12:15:00.000Z",
        [BOB_NO_EMPLOYEE_NUMBER, group_target()],
    )


def membership_add_failed_outcome() -> dict[str, Any]:
    """The same add for Alice with ``outcome.result: DENY``: the change did not happen.

    A mapping that reads only ``eventType`` and ``target`` would emit
    ``group.member_added`` for a denied action and provision access that Okta
    refused.
    """
    return _event(
        "group.user_membership.add",
        FAILED_EVENT_UUID,
        "2026-01-01T12:20:00.000Z",
        [ALICE, group_target()],
        outcome="DENY",
    )


# The bodies the mapping test walks, in order.
EVENT_PAYLOADS: tuple[dict[str, Any], ...] = (
    membership_add(),
    membership_remove(),
    user_deactivate(),
)
