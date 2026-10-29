"""The four port modules are interfaces only, and vendor-free.

A port is a contract: no implementation, no vendor spelling, and no import outside
the standard library and ``identity_lifecycle.domain``. These
tests read the modules as text and as AST, so they fail on a change that a future
adapter or use case would silently inherit.

One reading is recorded because it looks like an exception and is not: the only
vendor-bearing spellings in the package are ``LiteLLMAccount``, which design 8
names as the canonical store's entity, and ``litellm_accounts``, the table that
stores it. The port may return the entity and may not define it, so the test
asserts both — they are the only such names, the entity is imported from
``identity_lifecycle.domain.models``, and no other ``litellm`` text survives.
``okta`` and ``ldap`` have no such excuse and are rejected wherever they appear,
in prose or in code.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
from pathlib import Path
from typing import get_origin, get_type_hints

import pytest

from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import LiteLLMAccount, Person
from identity_lifecycle.ports.identity_source import (
    Capabilities,
    EventCondition,
    IdentityGroup,
    IdentitySource,
    IdentityUser,
    Page,
)
from identity_lifecycle.ports.unit_of_work import (
    AccountRepository,
    AuditRepository,
    CursorRepository,
    EntitlementRepository,
    GroupMemberRepository,
    GroupMemberSnapshot,
    OutboxRepository,
    PersonRepository,
    ProcessedEventRepository,
    ReconciliationMissRepository,
    SourceIdentityRepository,
    UnitOfWork,
)

from .dependency_rules import check_package

pytestmark = pytest.mark.unit

PORTS_ROOT = Path(__file__).resolve().parents[2] / "src" / "identity_lifecycle" / "ports"

PORT_MODULES = ("__init__.py", "clock.py", "gateway.py", "identity_source.py", "unit_of_work.py")

#: ADR-014 section 3, method for method and in declaration order.
ADR_014_METHODS = (
    "name",
    "capabilities",
    "list_users",
    "get_user",
    "list_groups",
    "get_group_members",
    "poll_changes",
    "normalize",
)

#: The nine repositories ``UnitOfWork`` exposes, in the design 9.1/10.6 order.
UOW_ATTRIBUTES = (
    "persons",
    "identities",
    "entitlements",
    "accounts",
    "audit",
    "group_members",
    "processed_events",
    "cursors",
    "outbox",
    "misses",
)

REPOSITORY_PROTOCOLS = {
    "PersonRepository": PersonRepository,
    "SourceIdentityRepository": SourceIdentityRepository,
    "EntitlementRepository": EntitlementRepository,
    "AccountRepository": AccountRepository,
    "AuditRepository": AuditRepository,
    "GroupMemberRepository": GroupMemberRepository,
    "ProcessedEventRepository": ProcessedEventRepository,
    "CursorRepository": CursorRepository,
    "OutboxRepository": OutboxRepository,
    "ReconciliationMissRepository": ReconciliationMissRepository,
}

#: A method whose name carries one of these words writes, subscribes, or streams.
FORBIDDEN_METHOD_PARTS = frozenset(
    {
        "add",
        "assign",
        "block",
        "create",
        "delete",
        "disable",
        "drop",
        "enable",
        "patch",
        "push",
        "put",
        "remove",
        "revoke",
        "set",
        "stream",
        "subscribe",
        "update",
        "upsert",
        "write",
    }
)

#: A return type naming one of these hands the caller a live feed, not a page.
FORBIDDEN_RETURN_NAMES = (
    "AsyncGenerator",
    "AsyncIterator",
    "Coroutine",
    "Generator",
    "Iterable",
    "Iterator",
    "Stream",
)

VENDOR_TOKENS = ("litellm", "okta", "ldap")


def _source(module: str) -> str:
    return (PORTS_ROOT / module).read_text(encoding="utf-8")


def _tree(module: str) -> ast.Module:
    return ast.parse(_source(module), filename=str(PORTS_ROOT / module))


def _classes(tree: ast.Module) -> dict[str, ast.ClassDef]:
    return {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}


def _methods(class_node: ast.ClassDef) -> list[str]:
    return [
        child.name
        for child in class_node.body
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def _functions(class_node: ast.ClassDef) -> list[ast.FunctionDef]:
    return [child for child in class_node.body if isinstance(child, ast.FunctionDef)]


def _argument_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = function.args
    names = {
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }
    for extra in (arguments.vararg, arguments.kwarg):
        if extra is not None:
            names.add(extra.arg)
    return names


def _absolute_imports(tree: ast.Module) -> list[str]:
    """Return every absolute import target's module, asserting none is relative."""
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "the ports package imports absolutely"
            assert node.module is not None
            modules.append(node.module)
    return modules


def _names(tree: ast.Module) -> set[str]:
    """Every identifier the module mentions: declarations, parameters, and references."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            found.add(node.name)
        elif isinstance(node, ast.arg):
            found.add(node.arg)
        elif isinstance(node, ast.Name | ast.Attribute):
            found.add(node.attr if isinstance(node, ast.Attribute) else node.id)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            found.add(node.arg)
    return found


def _definitions(tree: ast.Module) -> set[str]:
    """The names this module itself declares, as opposed to refers to."""
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }


@pytest.mark.parametrize("module", PORT_MODULES)
def test_ports_import_only_stdlib_and_domain(module: str) -> None:
    for name in _absolute_imports(_tree(module)):
        top_level = name.split(".", 1)[0]
        assert (
            top_level in sys.stdlib_module_names or top_level == "identity_lifecycle"
        ), f"{module} imports {name}; a port takes the standard library and the project"
        if top_level == "identity_lifecycle":
            assert name == "identity_lifecycle.domain" or name.startswith(
                ("identity_lifecycle.domain.", "identity_lifecycle.ports.")
            ), f"{module} imports {name}; ports reach domain and ports only (ADR-011 section 2)"


def test_the_layer_policy_accepts_the_real_ports_package() -> None:
    # The ticket's wording: the layer-policy engine covers ``ports``. It scans the
    # whole package, so an import the test above missed still fails here.
    assert check_package() == []


def test_gateway_port_has_no_blocked_user_operation() -> None:
    # ADR-004 section 1 measured a 400 on ``blocked``: it is not a user field, so
    # the port cannot expose a user-level block. Revocation is key-scoped.
    gateway = _classes(_tree("gateway.py"))["Gateway"]
    methods = _methods(gateway)

    assert "revoke_keys" in methods, "the key-scoped revocation method must exist"
    assert "block_user" not in methods
    for name in methods:
        assert not set(name.split("_")) & {"block", "blocked", "blocked_user"}, name

    arguments = set().union(*(_argument_names(function) for function in _functions(gateway)))
    assert "blocked" not in arguments

    assert "blocked" not in {field.name for field in dataclasses.fields(LiteLLMAccount)}


def test_unit_of_work_exposes_one_commit() -> None:
    tree = _tree("unit_of_work.py")
    classes = _classes(tree)

    commits = {
        name: methods.count("commit")
        for name, methods in ((name, _methods(node)) for name, node in classes.items())
        if "commit" in methods
    }
    assert commits == {"UnitOfWork": 1}, "exactly one commit, on the unit of work (ER6)"

    for name, node in classes.items():
        methods = _methods(node)
        if name != "UnitOfWork":
            assert (
                "commit" not in methods
            ), f"{name} must not commit; ER6 forbids a partial use case"
            assert "rollback" not in methods, f"{name} must not roll back on its own"

    assert _methods(classes["UnitOfWork"]) == ["commit", "rollback"]


def test_unit_of_work_exposes_the_nine_repositories() -> None:
    # The attribute set is the design 9.1/10.6 need, and the annotation is the
    # protocol type: a use case cannot reach a table that no protocol describes.
    # ``group_members`` is the membership snapshot the poller writes in the same
    # transaction as the outbox rows and the cursor.
    hints = get_type_hints(UnitOfWork, localns=dict(REPOSITORY_PROTOCOLS))
    assert tuple(hints) == UOW_ATTRIBUTES
    for attribute in UOW_ATTRIBUTES:
        assert hints[attribute] is not None


def test_ports_declare_no_vendor_name() -> None:
    # The two spellings the package may carry, named here so the test states its
    # own exception: design 8's entity ``LiteLLMAccount`` and its table
    # ``litellm_accounts``. Nothing else may mention a vendor, in code or prose.
    permitted_litellm_spellings = ("LiteLLMAccount", "litellm_accounts")

    for module in PORT_MODULES:
        lowered = _source(module).lower()
        for token in ("okta", "ldap"):
            assert (
                token not in lowered
            ), f"{module} names {token!r}; vendor spelling stops at the adapter"

        remainder = _source(module)
        for permitted in permitted_litellm_spellings:
            remainder = remainder.replace(permitted, "")
        assert (
            "litellm" not in remainder.lower()
        ), f"{module} names litellm outside {permitted_litellm_spellings}"

    mentioned = {
        name
        for module in PORT_MODULES
        for name in _names(_tree(module))
        if any(token in name.lower() for token in VENDOR_TOKENS)
    }
    assert mentioned == {"LiteLLMAccount"}, mentioned

    defined = {name for module in PORT_MODULES for name in _definitions(_tree(module))}
    assert not any(
        token in name.lower() for token in VENDOR_TOKENS for name in defined
    ), "the ports package may refer to a domain entity but may not declare a vendor type"

    imported = {
        f"{node.module}.{alias.name}"
        for node in ast.walk(_tree("gateway.py"))
        if isinstance(node, ast.ImportFrom) and node.module is not None
        for alias in node.names
    }
    assert "identity_lifecycle.domain.models.LiteLLMAccount" in imported


def test_identity_source_has_exactly_eight_methods() -> None:
    methods = _methods(_classes(_tree("identity_source.py"))["IdentitySource"])

    assert tuple(methods) == ADR_014_METHODS


def test_identity_source_declares_no_write_or_push_method() -> None:
    tree = _tree("identity_source.py")
    assert not [
        node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)
    ], "ER4: no method is async"
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Await)], "ER4: no await"

    functions = _functions(_classes(tree)["IdentitySource"])
    for function in functions:
        parts = set(function.name.split("_"))
        assert not parts & FORBIDDEN_METHOD_PARTS, f"{function.name} is a write or push verb"
        assert not [
            node for node in ast.walk(function) if isinstance(node, ast.Yield | ast.YieldFrom)
        ], f"{function.name} must return a page, not a generator"

        assert function.returns is not None, f"{function.name} must declare its return type"
        rendered = ast.unparse(function.returns)
        for forbidden in FORBIDDEN_RETURN_NAMES:
            assert forbidden not in rendered, f"{function.name} returns {rendered}"

    assert "subscribe" not in _source("identity_source.py").lower()


def test_page_carries_cursor() -> None:
    page = Page(items=("a", "b"), next_cursor="after-1")

    assert [field.name for field in dataclasses.fields(Page)] == ["items", "next_cursor"]
    assert page.items == ("a", "b")
    assert page.next_cursor == "after-1"
    assert Page(items=(), next_cursor=None).next_cursor is None
    # Generic in the item type, so one Page serves users, groups, and events.
    assert get_origin(Page[int]) is Page
    assert get_type_hints(Page)["next_cursor"] == str | None
    with pytest.raises(dataclasses.FrozenInstanceError):
        page.next_cursor = None  # type: ignore[misc]


def test_capabilities_has_no_vendor_field() -> None:
    fields = dataclasses.fields(Capabilities)
    hints = get_type_hints(Capabilities)

    assert [field.name for field in fields] == [
        "incremental_changes",
        "full_snapshot",
        "group_membership",
    ]
    assert all(hints[field.name] is bool for field in fields)
    for field in fields:
        assert not any(token in field.name for token in VENDOR_TOKENS), field.name
    with pytest.raises(dataclasses.FrozenInstanceError):
        Capabilities(
            incremental_changes=True, full_snapshot=True, group_membership=True
        ).full_snapshot = False  # type: ignore[misc]


def test_event_condition_lives_in_the_port_and_is_not_an_error() -> None:
    # an outcome, not an exception, and not a domain type.
    condition = EventCondition(code="unsupported_event_type", detail="no mapping")

    assert condition.code == "unsupported_event_type"
    assert EventCondition.__module__ == "identity_lifecycle.ports.identity_source"
    assert not issubclass(EventCondition, Exception)
    with pytest.raises(dataclasses.FrozenInstanceError):
        condition.code = "other"  # type: ignore[misc]


def test_group_member_snapshot_distinguishes_never_read_from_empty() -> None:
    # ADR-005 section 6-7: ``None`` forces a full sync; an empty set is a real
    # answer that removes every member the previous snapshot held.
    empty = GroupMemberSnapshot(
        source="corp-ad", source_group_id="g-1", source_user_ids=frozenset()
    )
    assert empty.source_user_ids == frozenset()
    assert get_type_hints(GroupMemberRepository.read)["return"] == GroupMemberSnapshot | None
    with pytest.raises(dataclasses.FrozenInstanceError):
        empty.source = "other"  # type: ignore[misc]


def test_find_all_by_employee_number_returns_every_match() -> None:
    # the link is not a key, so the lookup's answer is a set, not one
    # person. An empty tuple is "nobody carries it"; two entries are ambiguous.
    assert (
        get_type_hints(PersonRepository.find_all_by_employee_number)["return"] == tuple[Person, ...]
    )


def _return_type(method: str) -> object:
    """The declared return type of one ``IdentitySource`` method."""
    return get_type_hints(getattr(IdentitySource, method))["return"]


def test_identity_source_speaks_in_domain_values() -> None:
    # The four read methods' return types name this module's own records, and the
    # two feed methods name the envelope. No vendor payload crosses the port.
    assert _return_type("list_users") == Page[IdentityUser]
    assert _return_type("get_user") == IdentityUser | None
    assert _return_type("list_groups") == Page[IdentityGroup]
    assert _return_type("get_group_members") == Page[IdentityUser]
    assert _return_type("poll_changes") == Page[CanonicalEvent | EventCondition]
    assert _return_type("normalize") == CanonicalEvent | EventCondition
