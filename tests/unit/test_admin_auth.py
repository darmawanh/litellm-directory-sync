"""The admin bearer-token primitive sections 5-7."""

from __future__ import annotations

import ast
import inspect
import re
import subprocess
import sys
from pathlib import Path

import pytest

import identity_lifecycle.api.auth as auth

pytestmark = pytest.mark.unit

AUTH_PATH = Path(auth.__file__)
INIT_PATH = AUTH_PATH.parent / "__init__.py"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"auth.py defines no class {name!r}")


def _method(tree: ast.Module, owner: str, name: str) -> ast.FunctionDef:
    for node in _class(tree, owner).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{owner} defines no method {name!r}")


def _values_subscript(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "values"
    )


def _mentions_values(node: ast.AST) -> bool:
    return any(_values_subscript(child) for child in ast.walk(node))


def test_api_package_init_is_empty() -> None:
    tree = _tree(INIT_PATH)
    body = tree.body
    if not body:
        return
    assert len(body) == 1, "__init__.py may hold one docstring and nothing else"
    only = body[0]
    assert isinstance(only, ast.Expr) and isinstance(
        only.value, ast.Constant
    ), "__init__.py must not import or re-export anything"
    assert isinstance(only.value.value, str)


def test_auth_module_imports_only_the_standard_library() -> None:
    permitted = {"__future__", "collections", "enum", "hmac", "typing"}
    for node in ast.walk(_tree(AUTH_PATH)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError("auth.py must use absolute imports only")
            assert node.module is not None
            names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
        else:
            continue
        for name in names:
            root = name.split(".", 1)[0]
            assert root in sys.stdlib_module_names, f"auth.py imports third-party {name!r}"
            assert not name.startswith("identity_lifecycle"), name
            assert root in permitted, f"auth.py imports unexpected module {name!r}"


def test_importing_auth_does_not_import_a_framework() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import identity_lifecycle.api.auth, sys; print('fastapi' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        check=True,
    )
    assert completed.stdout == "False\n"


def test_admin_auth_result_has_exactly_four_reasons() -> None:
    assert {member.name: member.value for member in auth.AdminAuthResult} == {
        "ACCEPTED": "accepted",
        "MISSING": "missing",
        "DUPLICATED": "duplicated",
        "MISMATCH": "mismatch",
    }
    accepted = {member for member in auth.AdminAuthResult if member.accepted}
    assert accepted == {auth.AdminAuthResult.ACCEPTED}


@pytest.mark.parametrize(
    "secret",
    ["", "   ", " token", "token ", "\ttoken\n"],
)
def test_missing_token_fails_at_construction(secret: str) -> None:
    with pytest.raises(auth.AdminAuthConfigurationError):
        auth.AdminToken(secret)


def test_short_token_has_no_length_rule() -> None:
    assert auth.AdminToken("x").verify(["Bearer x"]) is auth.AdminAuthResult.ACCEPTED


def test_from_environment_requires_the_variable() -> None:
    with pytest.raises(auth.AdminAuthConfigurationError):
        auth.AdminToken.from_environment({})
    with pytest.raises(auth.AdminAuthConfigurationError):
        auth.AdminToken.from_environment({"LIFECYCLE_MASTER_KEY": ""})

    token = auth.AdminToken.from_environment({"LIFECYCLE_MASTER_KEY": "s3cret"})
    assert token.verify(["Bearer s3cret"]) is auth.AdminAuthResult.ACCEPTED
    assert token.verify(["Bearer other"]) is auth.AdminAuthResult.MISMATCH


def test_correct_token_is_accepted() -> None:
    assert auth.AdminToken("s3cret").verify(["Bearer s3cret"]) is auth.AdminAuthResult.ACCEPTED


def test_missing_header_is_rejected_as_missing() -> None:
    assert auth.AdminToken("s3cret").verify([]) is auth.AdminAuthResult.MISSING


def test_duplicate_authorization_header_is_rejected() -> None:
    result = auth.AdminToken("s3cret").verify(["Bearer s3cret", "Bearer s3cret"])
    assert result is auth.AdminAuthResult.DUPLICATED


@pytest.mark.parametrize(
    "values",
    [
        ["Bearer wrong"],
        ["Bearer "],
        ["Bearer " + "x" * 4096],
        ["Bearer " + "x" * len("s3cret")],
        ["bearer s3cret"],
        ["BEARER s3cret"],
        ["Basic s3cret"],
    ],
)
def test_wrong_token_is_rejected(values: list[str]) -> None:
    assert auth.AdminToken("s3cret").verify(values) is auth.AdminAuthResult.MISMATCH


def test_comparison_is_constant_time_by_construction() -> None:
    """Guard against an accidental ``==`` on the header value in ``verify``.

    This is a *reduction*, not a proof of constant time and not an airtight
    AST policy: it keys on the ``values[...]`` spelling, so a rewrite that
    moved the comparison behind a helper (``values[0].strip ==...``) or
    added an early accept ahead of the untouched ``hmac.compare_digest`` would
    pass. It catches every value-level rewrite the ticket's mutation table
    lists, which is its purpose; the constant-time property itself rests on
    reading ``verify``.
    """
    verify = _method(_tree(AUTH_PATH), "AdminToken", "verify")

    compare_calls = [
        node
        for node in ast.walk(verify)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "compare_digest"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hmac"
    ]
    assert len(compare_calls) == 1, "verify compares exactly once, with hmac.compare_digest"
    expected, supplied = compare_calls[0].args
    assert isinstance(expected, ast.Attribute) and isinstance(
        expected.value, ast.Name
    ), "the first argument is the precomputed value on self"
    assert expected.value.id == "self"
    assert isinstance(supplied, ast.Call) and isinstance(
        supplied.func, ast.Attribute
    ), "the second argument is values[0].encode(...)"
    assert supplied.func.attr == "encode"
    assert _values_subscript(supplied.func.value), "encode is called on values[0] directly"

    for node in ast.walk(verify):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for operand in operands:
                assert not _values_subscript(
                    operand
                ), "a header value is never compared with ==, !=, in, or not in"

    for node in ast.walk(verify):
        if isinstance(node, ast.BinOp | ast.JoinedStr):
            text = ast.get_source_segment(AUTH_PATH.read_text(encoding="utf-8"), node) or ""
            if '"Bearer "' in text or "'Bearer '" in text:
                assert not _mentions_values(
                    node
                ), "the scheme literal is never concatenated with a header value"


def test_token_has_no_default_and_one_reader() -> None:
    parameters = inspect.signature(auth.AdminToken).parameters
    assert parameters["secret"].default is inspect.Parameter.empty

    readers = [
        name
        for name, member in inspect.getmembers(auth.AdminToken, predicate=inspect.ismethod)
        if "environ" in inspect.signature(member).parameters
    ]
    assert readers == ["from_environment"]

    for node in ast.walk(_tree(AUTH_PATH)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert (
                re.fullmatch(r"[0-9a-f]{64}", node.value) is None
            ), "auth.py must carry no 64-hex secret literal"


def test_no_second_token_entry_point() -> None:
    assert not hasattr(auth, "token_is_valid")

    defined = {
        name
        for name, value in vars(auth).items()
        if isinstance(value, type) and value.__module__ == auth.__name__
    }
    assert defined == {"AdminAuthResult", "AdminAuthConfigurationError", "AdminToken"}

    if hasattr(auth, "__all__"):
        assert isinstance(auth.__all__, list)
