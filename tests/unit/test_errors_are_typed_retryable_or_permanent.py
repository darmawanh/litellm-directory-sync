"""A failure is retryable or permanent, and the two are siblings.

``domain/errors.py`` defines types and catches nothing. These tests pin the
hierarchy the retry policy will branch on, and the absence of any ``except``
clause, so a permanent failure can never be retried by an ``isinstance`` test.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from identity_lifecycle.domain import errors
from identity_lifecycle.domain.errors import DomainError, PermanentError, RetryableError

pytestmark = pytest.mark.unit

ERRORS_MODULE = (
    Path(__file__).resolve().parents[2] / "src" / "identity_lifecycle" / "domain" / "errors.py"
)


def _except_handlers(source: str) -> list[ast.ExceptHandler]:
    return [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ExceptHandler)]


def test_the_error_module_has_no_bare_except() -> None:
    handlers = _except_handlers(ERRORS_MODULE.read_text(encoding="utf-8"))

    assert [
        handler for handler in handlers if handler.type is None
    ] == [], "a bare except would swallow the failure the caller must classify"
    assert handlers == [], "errors.py defines types; it must not catch anything"


def test_the_except_scanner_detects_a_bare_except() -> None:
    # Negative control: a scanner that finds nothing would pass the test above
    # forever, including on a module that does catch.
    handlers = _except_handlers("try:\n    pass\nexcept:\n    pass\n")

    assert [handler.type for handler in handlers] == [None]


def test_a_retryable_error_is_not_a_permanent_error() -> None:
    error = RetryableError("throttled by the gateway")

    assert isinstance(error, RetryableError)
    assert not isinstance(error, PermanentError)


def test_a_permanent_error_is_not_a_retryable_error() -> None:
    error = PermanentError("the group does not exist")

    assert isinstance(error, PermanentError)
    assert not isinstance(error, RetryableError)


def test_both_error_families_share_one_base_error() -> None:
    assert issubclass(RetryableError, DomainError)
    assert issubclass(PermanentError, DomainError)

    unclassified = DomainError("no family assigned yet")
    assert not isinstance(unclassified, RetryableError)
    assert not isinstance(unclassified, PermanentError)


def test_each_error_family_subclasses_domain_error_directly() -> None:
    assert RetryableError.__bases__ == (DomainError,)
    assert PermanentError.__bases__ == (DomainError,)


def test_the_error_module_defines_exactly_three_public_classes() -> None:
    public_classes = {
        name
        for name, value in vars(errors).items()
        if not name.startswith("_") and isinstance(value, type)
    }

    assert public_classes == {"DomainError", "RetryableError", "PermanentError"}
