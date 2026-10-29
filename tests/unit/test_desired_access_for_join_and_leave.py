"""A join creates, a leave revokes, and a tie changes nothing.

``desired_access`` distinguishes the two outcomes that say "nothing is
entitled": a tie blocks the new change and leaves existing access alone
, while a no-match after a complete read
revokes an existing account. These tests pin
that difference, the leave with nothing to revoke, and the two structural
rules: a ``CREATE`` allocates no id, and the module imports no randomness.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import pytest

from identity_lifecycle.domain.models import (
    ACTIVE,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceGroup,
)
from identity_lifecycle.domain.policy import (
    AccessAction,
    AccessDecision,
    DecisionOutcome,
    DesiredAccess,
    GroupMapping,
    decide_access,
    desired_access,
)

pytestmark = pytest.mark.unit

POLICY_MODULE = (
    Path(__file__).resolve().parents[2] / "src" / "identity_lifecycle" / "domain" / "policy.py"
)

ADMIN = GroupMapping(
    source="corp-ad",
    source_group_id="group-admins",
    role="proxy_admin",
    team="ai-platform",
    precedence=100,
)
ADMIN_OKTA = GroupMapping(
    source="corp-okta",
    source_group_id="group-okta-admins",
    role="proxy_admin",
    team="ai-platform",
    precedence=100,
)
USER = GroupMapping(
    source="corp-ad",
    source_group_id="group-users",
    role="internal_user",
    team="ai-platform",
    precedence=10,
)
ENABLED_SOURCES = frozenset({"corp-ad", "corp-okta"})

PERSON = Person(
    person_id="person-1",
    employee_number="E10001",
    email="ada@example.com",
    display_name="Ada Lovelace",
    status=ACTIVE,
)


def _member(mapping: GroupMapping) -> SourceGroup:
    """The membership a person holds when they are in ``mapping``'s group."""
    return SourceGroup(
        source=mapping.source,
        source_group_id=mapping.source_group_id,
        name="membership",
    )


def _grant() -> AccessDecision:
    """The decision for a person who is in the mapped user group."""
    return decide_access([USER], [_member(USER)], ENABLED_SOURCES)


def _no_match() -> AccessDecision:
    """A complete read with no mapped group: the leave case."""
    return decide_access([USER], [], ENABLED_SOURCES)


def _tie() -> AccessDecision:
    """Two mappings share the highest precedence: the failure case."""
    return decide_access(
        mappings=[ADMIN, ADMIN_OKTA],
        memberships=[_member(ADMIN), _member(ADMIN_OKTA)],
        enabled_sources=ENABLED_SOURCES,
    )


def _account() -> LiteLLMAccount:
    """The gateway state as last read back."""
    return LiteLLMAccount(
        user_id="user-1",
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=50.0,
        keys=("key-1",),
    )


def _entitlement() -> Entitlement:
    """The entitlement in force, which the caller audits as the old access."""
    return Entitlement(
        person_id=PERSON.person_id,
        role="internal_user",
        team="ai-platform",
        budget_policy="standard",
        source="corp-ad",
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
    )


def _import_targets(source: str) -> set[str]:
    """Return every absolute import target in ``source`` as ``module.name``."""
    targets: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "policy.py uses absolute imports only"
            targets.update(f"{node.module}.{alias.name}" for alias in node.names)
    return targets


def test_a_first_join_creates_the_account() -> None:
    decision = _grant()

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=None,
        previous=None,
    )

    assert result.action is AccessAction.CREATE
    assert result.role == "internal_user"
    assert result.team == "ai-platform"
    assert result.reason == "highest_precedence"


def test_a_create_returns_no_person_id_for_the_caller_to_allocate() -> None:
    # Allocation is Phase 2's store: a uuid4 here would be global randomness
    # inside a pure function, and a rehire test could not avoid patching it.
    decision = _grant()

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=None,
        previous=_entitlement(),
    )

    assert result.action is AccessAction.CREATE
    assert result.person_id is None


def test_a_leave_revokes_the_account() -> None:
    decision = _no_match()

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=_account(),
        previous=_entitlement(),
    )

    assert decision.outcome is DecisionOutcome.NOT_ENTITLED
    assert result.action is AccessAction.REVOKE
    assert result.role is None
    assert result.team is None
    assert result.person_id == PERSON.person_id
    assert result.reason == "no_mapped_group"


def test_a_leave_for_a_person_with_no_account_is_no_change() -> None:
    decision = _no_match()

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=None,
        previous=_entitlement(),
    )

    assert result.action is AccessAction.NO_CHANGE
    assert result.role is None
    assert result.team is None
    assert result.person_id == PERSON.person_id


def test_a_tie_leaves_existing_access_unchanged() -> None:
    # a tie blocks the new change, not the current account.
    decision = _tie()

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=_account(),
        previous=_entitlement(),
    )

    assert decision.outcome is DecisionOutcome.FAILED
    assert result.action is AccessAction.NO_CHANGE
    assert result.role is None
    assert result.team is None
    assert result.reason == "equal_precedence"


def test_a_tie_grants_no_new_access() -> None:
    # "New access is not granted", so this is not a CREATE.
    decision = _tie()

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=None,
        previous=None,
    )

    assert result.action is AccessAction.NO_CHANGE
    assert result.person_id == PERSON.person_id
    assert result.role is None
    assert result.team is None


def test_the_five_actions_are_the_only_actions() -> None:
    assert issubclass(AccessAction, StrEnum)
    assert {action.value for action in AccessAction} == {
        "create",
        "update",
        "reactivate",
        "revoke",
        "no_change",
    }
    # The value is the audit vocabulary, so a StrEnum comparison needs no.value.
    assert AccessAction.NO_CHANGE == "no_change"
    with pytest.raises(ValueError):
        # Open decision 1: no distinct BLOCKED action exists for a tie.
        AccessAction("blocked")


def test_the_instruction_carries_exactly_the_five_fields_and_cannot_change() -> None:
    assert dataclasses.is_dataclass(DesiredAccess)
    # `is_dataclass` is inherited by an undecorated subclass, so require the
    # decorator's own namespace as well.
    assert "__dataclass_fields__" in vars(DesiredAccess)
    assert DesiredAccess.__dataclass_params__.frozen
    assert {field.name for field in dataclasses.fields(DesiredAccess)} == {
        "action",
        "person_id",
        "role",
        "team",
        "reason",
    }

    result = desired_access(
        decision=_grant(),
        person=PERSON,
        account=_account(),
        previous=_entitlement(),
    )
    with pytest.raises(FrozenInstanceError):
        result.action = AccessAction.REVOKE  # type: ignore[misc]


def test_the_function_takes_four_keyword_only_values_and_no_event() -> None:
    # P-002: the event is a trigger, not the truth, so there is no parameter
    # for a caller to read a payload from. Keyword-only, so the three state
    # values cannot be transposed.
    signature = inspect.signature(desired_access)

    assert list(signature.parameters) == ["decision", "person", "account", "previous"]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert all(
        parameter.default is inspect.Parameter.empty for parameter in signature.parameters.values()
    )


def test_the_module_imports_no_randomness() -> None:
    targets = _import_targets(POLICY_MODULE.read_text(encoding="utf-8"))
    forbidden = {target for target in targets if target.split(".")[0] in {"uuid", "random"}}

    assert forbidden == set()


def test_the_randomness_scan_sees_an_import_it_must_reject() -> None:
    # Negative control: a scan that finds nothing passes the test above forever.
    source = "import uuid\nfrom random import random\n"

    assert _import_targets(source) == {"uuid", "random.random"}
