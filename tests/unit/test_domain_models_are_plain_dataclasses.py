"""The six entities of design section 8 are plain dataclasses, not policy.

``domain/models.py`` holds records: fields only, no method that decides
anything, no Pydantic, and no vendor spelling. These tests pin the field sets
against the design's table row for row, so a later ticket that adds a field to
a model has to say which design sentence it came from.
"""

from __future__ import annotations

import ast
import dataclasses
from datetime import UTC, datetime
from pathlib import Path
from typing import get_type_hints

import pydantic
import pytest

from identity_lifecycle.domain import models
from identity_lifecycle.domain.models import (
    ACTIVE,
    INACTIVE,
    Entitlement,
    LiteLLMAccount,
    Person,
)

pytestmark = pytest.mark.unit

MODELS_MODULE = (
    Path(__file__).resolve().parents[2] / "src" / "identity_lifecycle" / "domain" / "models.py"
)

#: The six names of design section 8's data-model table, in table order.
MODEL_NAMES = (
    "Person",
    "SourceIdentity",
    "SourceGroup",
    "Entitlement",
    "LiteLLMAccount",
    "AuditEvent",
)

#: Design section 8, row for row. A literal, so deleting a field from the
#: module cannot shrink the expected set along with it.
DESIGN_FIELDS: dict[str, set[str]] = {
    "Person": {"person_id", "employee_number", "email", "display_name", "status"},
    "SourceIdentity": {"source", "source_user_id", "person_id"},
    "SourceGroup": {"source", "source_group_id", "name"},
    "Entitlement": {
        "person_id",
        "role",
        "team",
        "budget_policy",
        "source",
        "effective_from",
        "effective_to",
    },
    "LiteLLMAccount": {"user_id", "status", "role", "team", "budget", "keys"},
    "AuditEvent": {
        "event_id",
        "source_event_id",
        "actor",
        "action",
        "target",
        "decision",
        "reason",
        "timestamp",
    },
}

#: Vendor spellings that must stop at the adapter boundary.
#: Compared exactly and case-sensitively: ``employee_number`` is a domain
#: field and does not match ``employeeNumber``.
VENDOR_FIELD_NAMES = (
    "objectGUID",
    "objectguid",
    "employeeID",
    "employeeNumber",
    "userAccountControl",
    "displayName",
    "mail",
    "whenChanged",
    "uSNChanged",
    "group_id",
)

#: The module's whole import set: the standard library, nothing else.
EXPECTED_IMPORTS = {
    "__future__.annotations",
    "dataclasses.dataclass",
    "datetime.datetime",
    "uuid.UUID",
}


def _import_targets(source: str) -> set[str]:
    """Return every absolute import target in ``source`` as ``module.name``."""
    targets: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "models.py uses absolute imports only"
            targets.update(f"{node.module}.{alias.name}" for alias in node.names)
    return targets


def _field_names(model: type) -> set[str]:
    return {field.name for field in dataclasses.fields(model)}


def _vendor_names(field_names: set[str]) -> list[str]:
    return sorted(name for name in field_names if name in VENDOR_FIELD_NAMES)


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_every_domain_model_is_a_dataclass(name: str) -> None:
    model = getattr(models, name)

    assert isinstance(model, type), f"{name} must be a class"
    assert dataclasses.is_dataclass(model), f"{name} must be a @dataclass"
    # ``is_dataclass`` is also true for an undecorated subclass of a dataclass,
    # so the decorator ran on this class only if the fields are in its own
    # namespace (not the predicate).
    assert "__dataclass_fields__" in vars(model), f"{name} must carry @dataclass itself"


def test_the_dataclass_check_rejects_an_undecorated_subclass() -> None:
    # Negative control for the assertion above: on this class ``is_dataclass``
    # is true while the decorator never ran, which is exactly the gap.
    class UndecoratedSubclass(Person):
        pass

    assert dataclasses.is_dataclass(UndecoratedSubclass)
    assert "__dataclass_fields__" not in vars(UndecoratedSubclass)


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_no_domain_model_is_a_pydantic_model(name: str) -> None:
    model = getattr(models, name)

    assert not issubclass(model, pydantic.BaseModel), f"{name} must not be a Pydantic model"
    assert "pydantic" not in {
        target.split(".", 1)[0] for target in _import_targets(MODELS_MODULE.read_text("utf-8"))
    }, "models.py must not import pydantic; ER5 keeps it at the config and vendor boundary"


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_each_model_has_the_fields_the_design_names(name: str) -> None:
    assert _field_names(getattr(models, name)) == DESIGN_FIELDS[name]


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_no_model_carries_a_vendor_field_name(name: str) -> None:
    assert _vendor_names(_field_names(getattr(models, name))) == []


def test_the_vendor_name_scan_matches_exactly_and_case_sensitively() -> None:
    # Negative control: the scan must see a vendor spelling when one exists,
    # and must not see one in the domain's own snake_case field.
    assert _vendor_names({"employeeNumber", "displayName"}) == ["displayName", "employeeNumber"]
    assert _vendor_names({"employee_number", "display_name", "source_group_id"}) == []


def test_a_person_with_no_employee_number_is_valid() -> None:
    person = Person(
        person_id="person-1",
        employee_number=None,
        email="ada@example.com",
        display_name="Ada Lovelace",
        status=ACTIVE,
    )

    assert person.employee_number is None
    assert person.status == ACTIVE


def test_the_person_status_vocabulary_is_active_and_inactive() -> None:
    # Design 10.5 step 2 is the only place the design fixes this vocabulary;
    # a disabled source account is a source fact, not a third person status.
    assert ACTIVE == "active"
    assert INACTIVE == "inactive"


def test_an_entitlement_records_an_optional_effective_end() -> None:
    open_entitlement = Entitlement(
        person_id="person-1",
        role="internal_user",
        team="ai-platform",
        budget_policy="standard",
        source="corp-ad",
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
    )
    closed_entitlement = dataclasses.replace(
        open_entitlement, effective_to=datetime(2026, 6, 1, tzinfo=UTC)
    )

    assert open_entitlement.effective_to is None
    assert closed_entitlement.effective_to == datetime(2026, 6, 1, tzinfo=UTC)
    assert closed_entitlement.person_id == open_entitlement.person_id


def test_a_litellm_account_holds_keys_as_plain_identifiers() -> None:
    account = LiteLLMAccount(
        user_id="user-1",
        # A gateway account's status is a LiteLLM fact ("active"/"blocked"),
        # not the person vocabulary, so it is a plain value here.
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=50.0,
        keys=("key-1", "key-2"),
    )

    assert get_type_hints(LiteLLMAccount)["keys"] == tuple[str, ...]
    assert account.keys == ("key-1", "key-2")
    assert all(isinstance(key, str) for key in account.keys)


def test_the_module_imports_only_the_standard_library() -> None:
    assert _import_targets(MODELS_MODULE.read_text("utf-8")) == EXPECTED_IMPORTS


def test_the_module_defines_exactly_the_six_entities() -> None:
    # GroupMapping, BudgetPolicy, and the other policy types are T-019..T-021.
    public_classes = {
        name
        for name, value in vars(models).items()
        if isinstance(value, type) and value.__module__ == models.__name__
    }

    assert public_classes == set(MODEL_NAMES)


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_the_models_carry_no_behaviour(name: str) -> None:
    model = getattr(models, name)
    public_callables = {
        attribute
        for attribute, value in vars(model).items()
        if not attribute.startswith("_") and callable(value)
    }

    assert public_callables == set(), f"{name} must carry fields only; policy is T-019..T-021"
