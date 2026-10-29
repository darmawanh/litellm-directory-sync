"""Reference normalizer for Okta payloads.

**This is a reference, not the adapter.** Phase 5 must reimplement it in
``src/identity_lifecycle/adapters/okta/mapping.py`` and cover it with the adapter
contract suite. Nothing under ``src/`` may import this module.

It turns a hand-built Event Hook body into the design-section-8 envelope. It does
**not** decide the security posture: authentication, the allowlist, and replay
storage are D-011, decided by the reviewer and recorded.

These bodies return a typed condition instead of an event: the verification
challenge (a registration exchange, not an event); a body carrying ``verification``
with any other key (a 400, not an event); an absent or malformed
``outcome`` (a malformed body, a 400); an event whose present
``outcome.result`` is not ``SUCCESS`` (acknowledged and ignored); an unsupported
type; a missing ``uuid``, ``published``, or User target; and a real event whose
user target carries no ``employeeNumber``.

The missing-link case is deliberately **not** a copy's rule. Okta's
``id`` is immutable and is the source identity, much as AD's ``objectGUID`` is;
Okta's ``employeeNumber`` is an editable profile attribute, much as AD's
``employeeID`` is. The mechanics differ where it matters: AD returns a directory
object, so a missing ``employeeID`` is a fact about the object; an Okta hook
carries a ``target`` list whose user entry commonly has ``detailEntry: null``, so
a missing ``employeeNumber`` is a fact about **the payload**. The worker re-reads
the source, so the key may well exist on the user record.

This module returns a typed condition **for the event** rather than a silent
``employee_number: null``. ADR-006 §7 retains that code as the in-process signal
and maps it at the route to "accepted, enqueue with a null link"; the fixture's
job is only to make the condition visible and named.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from dataclasses import dataclass
from typing import Any, Final

SCHEMA_VERSION: Final = 1
SOURCE_NAME: Final = "okta"

# The only vendor event types this reference maps. An unsupported type is a typed
# condition, never a guess.
EVENT_TYPE_MAP: Final[dict[str, str]] = {
    "group.user_membership.add": "group.member_added",
    "group.user_membership.remove": "group.member_removed",
    "user.lifecycle.deactivate": "user.disabled",
}

CODE_VERIFICATION_CHALLENGE: Final = "verification_challenge_is_not_an_event"
CODE_MALFORMED_CHALLENGE: Final = "malformed_verification_challenge"
CODE_MISSING_EMPLOYEE_NUMBER: Final = "missing_employee_number"
CODE_UNSUPPORTED_EVENT_TYPE: Final = "unsupported_event_type"
CODE_UNSUCCESSFUL_OUTCOME: Final = "unsuccessful_outcome"
CODE_MALFORMED_EVENT: Final = "malformed_event"


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    """The design-section-8 envelope, with no vendor field name anywhere."""

    event_id: str
    source: str
    source_event_id: str
    type: str
    occurred_at: str
    schema_version: int
    person_source_user_id: str
    person_employee_number: str | None
    group_source_group_id: str | None
    group_name: str | None

    def as_dict(self) -> dict[str, Any]:
        """Return the envelope in the wire shape the outbox stores."""
        group = None
        if self.group_source_group_id is not None:
            group = {"source_group_id": self.group_source_group_id, "name": self.group_name}
        return {
            "event_id": self.event_id,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "type": self.type,
            "occurred_at": self.occurred_at,
            "schema_version": self.schema_version,
            "person": {
                "source_user_id": self.person_source_user_id,
                "employee_number": self.person_employee_number,
            },
            "group": group,
        }


@dataclass(frozen=True, slots=True)
class PermanentCondition:
    """A typed outcome that is not an event and must not be silently dropped.

    ``permanent`` is in the type so a caller cannot mistake this for a retryable
    failure. Phase 5 decides what each ``code`` means operationally.
    """

    code: str
    detail: str
    permanent: bool = True


NormalizationResult = CanonicalEvent | PermanentCondition
VerificationResult = str | PermanentCondition


def is_verification_request(raw: dict[str, Any]) -> bool:
    """True only for a body whose sole key is ``verification``.

    ADR-006 §3: the body must have exactly that key. Anything else is a 400, not
    a challenge, so an extra key must not be quietly accepted.
    """
    return set(raw) == {"verification"}


def verification_response(challenge: object, secret: str) -> VerificationResult:
    """Answer the one-time registration challenge.

    The documented answer is ``base64 (HMAC-SHA256(secret, challenge))`` over the
    challenge exactly as received. Whether the HMAC input is the received base64
    text or its decoded bytes is **unverified** and is an ADR-006 item.

    ``challenge`` is typed ``object`` because the body is attacker-controlled: a
    non-``str`` value (an integer, ``null``, a list) passes
    ``is_verification_request`` and must still be a typed 400 condition rather
    than an ``AttributeError`` surfacing as a 500 on a public endpoint. A
    ``str`` that is not ASCII is the same class of malformed challenge: it cannot
    be the base64 text the documented exchange sends.
    """
    if not isinstance(challenge, str):
        return PermanentCondition(
            CODE_MALFORMED_CHALLENGE,
            f"the verification challenge is {type(challenge).__name__}, not a string; "
            "the documented exchange sends base64 text",
        )
    if not challenge.isascii():
        return PermanentCondition(
            CODE_MALFORMED_CHALLENGE,
            "the verification challenge is not ASCII; the documented exchange sends "
            "base64 text, so this body is malformed",
        )
    digest = hmac.new(secret.encode(), challenge.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def verify_shared_secret(received_header: str, expected_secret: str) -> bool:
    """Constant-time comparison of a hook header against the configured secret.

    ``hmac.compare_digest`` is required by design 9.3; ``==`` leaks length and
    prefix timing.
    """
    return hmac.compare_digest(received_header.encode(), f"Bearer {expected_secret}".encode())


def canonical_event_id(source: str, source_event_id: str) -> str:
    """Derive a deterministic ``event_id`` so a replay is detectable."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"identity-lifecycle:{source}:{source_event_id}"))


def _first_target(raw: dict[str, Any], target_type: str) -> dict[str, Any] | None:
    targets = raw.get("target")
    if not isinstance(targets, list):
        return None
    return next(
        (
            target
            for target in targets
            if isinstance(target, dict) and target.get("type") == target_type
        ),
        None,
    )


def _employee_number(user_target: dict[str, Any]) -> str | None:
    detail = user_target.get("detailEntry")
    if not isinstance(detail, dict):
        return None
    value = detail.get("employeeNumber")
    return value if isinstance(value, str) and value else None


def _verification_key_condition(raw: dict[str, Any]) -> PermanentCondition | None:
    """Classify a body carrying a ``verification`` key before the event path.

    ADR-006 §3: exactly ``{"verification"}`` is the one-time challenge; a body
    that carries the key with anything else is a 400, and "a later body
    containing ``verification`` is not an event". Returning a condition here
    keeps such a body out of :func:`normalize_event`'s event path.
    """
    if is_verification_request(raw):
        return PermanentCondition(
            CODE_VERIFICATION_CHALLENGE,
            "the body carries a verification challenge and no eventType; it is answered "
            "once at registration and is not per-event authentication",
        )
    if "verification" in raw:
        return PermanentCondition(
            CODE_MALFORMED_EVENT,
            "the body carries a verification key with other keys; ADR-006 §3 requires "
            'exactly {"verification"} for a challenge, so this is not an event',
        )
    return None


def _outcome_condition(raw: dict[str, Any]) -> PermanentCondition | None:
    """Reject an absent or malformed ``outcome`` before judging its value.

    ADR-006 §4 acknowledges a present non-``SUCCESS`` outcome with 200
    ``{"status":"ignored"}`` but a malformed body with 400. An absent or
    non-string ``outcome.result`` is therefore ``malformed_event``; only a
    present, well-formed result that is not ``SUCCESS`` is an outcome. The shape
    check stays ahead of the value check so the two cannot swap.
    """
    outcome = raw.get("outcome")
    if not isinstance(outcome, dict):
        return PermanentCondition(
            CODE_MALFORMED_EVENT,
            f"the body has no outcome object; outcome is {type(outcome).__name__}",
        )
    result = outcome.get("result")
    if not isinstance(result, str):
        return PermanentCondition(
            CODE_MALFORMED_EVENT,
            f"the body has no string outcome.result; result is {type(result).__name__}",
        )
    if result != "SUCCESS":
        return PermanentCondition(
            CODE_UNSUCCESSFUL_OUTCOME,
            f"outcome.result is {result!r}; only SUCCESS is an applied change",
        )
    return None


def normalize_event(raw: dict[str, Any]) -> NormalizationResult:
    """Map one hand-built Event Hook body to the canonical envelope.

    Returns a :class:`CanonicalEvent`, or a :class:`PermanentCondition` for a
    verification challenge, a body carrying ``verification`` with another key, a
    malformed body (absent or malformed ``outcome``, missing ``uuid`` or
    ``published``, no User target), an unsupported type, an event whose present
    ``outcome.result`` is not ``SUCCESS``, or a real event whose user target has
    no ``employeeNumber``.
    """
    verification = _verification_key_condition(raw)
    if verification is not None:
        return verification

    vendor_type = raw.get("eventType")
    canonical_type = EVENT_TYPE_MAP.get(vendor_type) if isinstance(vendor_type, str) else None
    if canonical_type is None:
        code = CODE_UNSUPPORTED_EVENT_TYPE if vendor_type else CODE_MALFORMED_EVENT
        return PermanentCondition(code, f"event type {vendor_type!r} has no canonical mapping")

    # The outcome's shape decides whether this is a malformed body or a
    # present business outcome (200 ignored); a non-SUCCESS result means the
    # change did not happen, so mapping it would grant or revoke access on the
    # strength of an action that failed (F13).
    outcome = _outcome_condition(raw)
    if outcome is not None:
        return outcome

    source_event_id, occurred_at = raw.get("uuid"), raw.get("published")
    if not isinstance(source_event_id, str) or not source_event_id:
        return PermanentCondition(CODE_MALFORMED_EVENT, "the body has no uuid")
    if not isinstance(occurred_at, str) or not occurred_at:
        return PermanentCondition(CODE_MALFORMED_EVENT, "the body has no published")

    user_target = _first_target(raw, "User")
    if user_target is None or not isinstance(user_target.get("id"), str):
        return PermanentCondition(CODE_MALFORMED_EVENT, "the body has no User target with an id")

    employee_number = _employee_number(user_target)
    if employee_number is None:
        return PermanentCondition(
            CODE_MISSING_EMPLOYEE_NUMBER,
            f"User target {user_target['id']} has no employeeNumber in the payload; the "
            "source identity is present but the cross-system link is not",
        )

    group_target = _first_target(raw, "UserGroup") or {}
    group_id = group_target.get("id") if isinstance(group_target.get("id"), str) else None
    group_name = group_target.get("alternateId") or group_target.get("displayName")

    return CanonicalEvent(
        event_id=canonical_event_id(SOURCE_NAME, source_event_id),
        source=SOURCE_NAME,
        source_event_id=source_event_id,
        type=canonical_type,
        occurred_at=occurred_at,
        schema_version=SCHEMA_VERSION,
        person_source_user_id=user_target["id"],
        person_employee_number=employee_number,
        group_source_group_id=group_id,
        group_name=group_name if isinstance(group_name, str) else None,
    )


def normalize_system_log_entry(raw: dict[str, Any]) -> NormalizationResult:
    """Map a System Log entry through the same normalizer.

    An entry has the same ``eventType``/``target``/``uuid``/``published`` fields
    as a hook body, so the fallback feed shares one mapping and the two cannot
    drift.
    """
    return normalize_event(raw)
