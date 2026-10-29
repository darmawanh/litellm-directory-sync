"""The dependency direction holds for every module in the package.

The rule is::

    api and workers -> application -> domain
    adapters -> ports
    application -> ports
    domain -> nothing

``domain`` is an allowlist: the standard library — minus the database and
socket/HTTP names ADR-012 denies — and ``identity_lifecycle.domain`` are
importable, so an unlisted third-party package is rejected rather than
silently admitted. The engine lives in ``dependency_rules`` so neither file
exceeds design 15.3's size guidance.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from .dependency_rules import (
    DOMAIN_ALLOWED_PROJECT_PREFIXES,
    DOMAIN_DENIED_STDLIB,
    LAYER_POLICIES,
    PACKAGE_NAME,
    PACKAGE_ROOT,
    RECOGNIZED_LAYERS,
    STDLIB_MODULES,
    UnrecognizedLayer,
    Violation,
    check_package,
)

pytestmark = pytest.mark.unit

#: Literal list from T-004. A name here proves nothing unless the allowlist
#: rejects it, which is what the test asserts.
THIRD_PARTY_MODULES = (
    # Installed transitively in Phase 0 and missed by the round-2 denylist.
    "anyio", "click", "docker", "dotenv", "greenlet",
    "h11", "httpcore", "mako", "requests", "urllib3",
    # Design 14 stack.
    "fastapi", "sqlalchemy", "alembic", "psycopg", "ldap3", "httpx",
    "pydantic", "pydantic_settings", "tenacity", "limits", "pybreaker",
    "structlog", "prometheus_client", "litellm", "uvicorn", "starlette",
    "pydantic_core", "jwt", "jose",
    # Test-only libraries, the fakes, and the undecided parsers.
    "pytest", "respx", "testcontainers", "tests", "yaml", "ruamel",
)  # fmt: skip

OTHER_PROJECT_LAYERS = (
    "identity_lifecycle.ports.gateway",
    "identity_lifecycle.application.process_event",
    "identity_lifecycle.adapters.okta.connector",
    "identity_lifecycle.api.routes_hooks",
    "identity_lifecycle.workers.outbox_worker",
    "identity_lifecycle.observability.metrics",
)

#: The layers outside the ``ports``/``application`` core, derived from the
#: policy table rather than restated: a layer is outward
#: exactly when its policy lets it depend on ``identity_lifecycle.adapters``.
OUTWARD_LAYERS = tuple(
    layer
    for layer in RECOGNIZED_LAYERS
    if LAYER_POLICIES[layer].allows_project("identity_lifecycle.adapters")
)

#: The layers ``adapters`` may not import, likewise derived: its policy row
#: names every project prefix it may reach, so the complement is the cycle set
#:.
ADAPTER_EXCLUDED_LAYERS = tuple(
    layer
    for layer in RECOGNIZED_LAYERS
    if not LAYER_POLICIES["adapters"].allows_project(f"identity_lifecycle.{layer}")
)

#: ADR-012 section 2, written as a literal so deleting a name from the engine
#: cannot shrink the proof.
DOMAIN_DENIED_STDLIB_EXPECTED = (
    "dbm",
    "http",
    "shelve",
    "socket",
    "sqlite3",
    "urllib",
    "_dbm",
    "_gdbm",
    "_socket",
    "_sqlite3",
)


def _package(tmp_path: Path, files: dict[str, str], directory: str = "pkg") -> Path:
    root = tmp_path / directory / PACKAGE_NAME
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return root


def _violations(
    tmp_path: Path, relative: str, source: str, directory: str = "pkg"
) -> list[Violation]:
    return check_package(_package(tmp_path, {relative: source}, directory))


def _rules(tmp_path: Path, relative: str, source: str, directory: str = "pkg") -> list[str]:
    return [violation.rule for violation in _violations(tmp_path, relative, source, directory)]


def test_domain_allowlist_constants_are_exactly_as_specified() -> None:
    assert DOMAIN_ALLOWED_PROJECT_PREFIXES == ("identity_lifecycle.domain",)
    assert frozenset(sys.stdlib_module_names) == STDLIB_MODULES
    # Operands swapped from ADR-012's wording: ruff SIM300 reads the uppercase
    # constant as the Yoda side. The claim is the same equality.
    assert LAYER_POLICIES["domain"].denied_stdlib == DOMAIN_DENIED_STDLIB


@pytest.mark.parametrize("module", DOMAIN_DENIED_STDLIB_EXPECTED)
def test_domain_rejects_a_stdlib_database_or_network_module(module: str, tmp_path: Path) -> None:
    found = [
        (violation.rule, violation.imported)
        for violation in _violations(tmp_path, "domain/leak.py", f"import {module}\n")
    ]
    assert found == [("domain-allowlist", module)]


def test_the_domain_reason_distinguishes_a_stdlib_name_from_a_third_party_package(
    tmp_path: Path,
) -> None:
    # a denied stdlib name is not third-party, and the
    # reason an operator reads must say so. The rule name stays domain-allowlist.
    denied = _violations(tmp_path, "domain/leak.py", "import socket\n")
    assert [violation.rule for violation in denied] == ["domain-allowlist"]
    assert "standard-library socket" in denied[0].reason
    assert "third-party" not in denied[0].reason

    unlisted = _violations(tmp_path, "domain/leak.py", "import sqlalchemy\n")
    assert "third-party sqlalchemy" in unlisted[0].reason


@pytest.mark.parametrize(
    ("module", "source"),
    [
        ("ast", "import ast\n"),
        ("dataclasses", "from dataclasses import dataclass\n"),
        ("enum", "from enum import Enum\n"),
        ("typing", "from typing import Any\n"),
        ("uuid", "import uuid\n"),
        ("__future__", "from __future__ import annotations\n"),
    ],
)
def test_domain_allows_stdlib_imports(module: str, source: str, tmp_path: Path) -> None:
    assert check_package() == []
    assert _rules(tmp_path, "domain/person.py", source) == [], f"allow stdlib {module}"


@pytest.mark.parametrize(
    "source",
    [
        "from identity_lifecycle.domain.models import Person\n",
        "from .models import Person\n",
        "from identity_lifecycle import domain\n",
        "import identity_lifecycle.domain\n",
    ],
)
def test_domain_allows_its_own_subpackage(source: str, tmp_path: Path) -> None:
    assert _rules(tmp_path, "domain/person.py", source) == [], f"allow own layer: {source!r}"


@pytest.mark.parametrize(
    "source", ["import identity_lifecycle\n", "import identity_lifecycle as il\n"]
)
def test_domain_rejects_a_bare_package_import(source: str, tmp_path: Path) -> None:
    assert _rules(tmp_path, "domain/person.py", source) == ["domain-outside"], f"bare {source!r}"


@pytest.mark.parametrize("module", THIRD_PARTY_MODULES)
def test_domain_rejects_any_non_stdlib_import(module: str, tmp_path: Path) -> None:
    violations = _violations(tmp_path, "domain/leak.py", f"import {module}\n")
    allowlist = [v for v in violations if v.rule == "domain-allowlist"]
    assert allowlist, f"the domain allowlist must reject {module}; got {violations}"
    assert (allowlist[0].line, allowlist[0].imported) == (1, module)


def test_domain_rejects_an_unlisted_third_party_module(tmp_path: Path) -> None:
    # Not in any list: the rule must fail closed rather than enumerate.
    violations = _violations(tmp_path, "domain/leak.py", "import totally_unknown_sdk\n")
    found = [(v.rule, v.imported) for v in violations]
    assert found == [("domain-allowlist", "totally_unknown_sdk")]


@pytest.mark.parametrize("module", OTHER_PROJECT_LAYERS)
def test_domain_rejects_other_project_subpackages(module: str, tmp_path: Path) -> None:
    source = f"from {module} import Thing\n"
    assert _rules(tmp_path, "domain/leak.py", source) == ["domain-outside"], module


@pytest.mark.parametrize("source", ["import docker as d\n", "from docker import from_env as x\n"])
def test_domain_rejects_an_aliased_import(source: str, tmp_path: Path) -> None:
    assert _rules(tmp_path, "domain/leak.py", source) == ["domain-allowlist"], source


@pytest.mark.parametrize("module", ["pytest", "respx", "testcontainers"])
def test_test_only_libraries_are_forbidden_in_domain(module: str, tmp_path: Path) -> None:
    # Covered by construction (third-party), named explicitly so the intent
    # survives a future rewrite of the allowlist.
    assert _rules(tmp_path, "domain/leak.py", f"import {module}\n") == ["domain-allowlist"]


@pytest.mark.parametrize("layer", OUTWARD_LAYERS)
def test_ports_import_no_adapter_api_or_worker(layer: str, tmp_path: Path) -> None:
    source = f"from identity_lifecycle.{layer}.thing import T\n"
    assert _rules(tmp_path, "ports/leak.py", source) == ["ports-layer"], layer


@pytest.mark.parametrize("layer", OUTWARD_LAYERS)
def test_application_imports_no_adapter_or_entry_point(layer: str, tmp_path: Path) -> None:
    source = f"from identity_lifecycle.{layer}.thing import T\n"
    assert _rules(tmp_path, "application/leak.py", source) == ["application-layer"], layer


def test_the_outward_layer_derivation_is_the_three_layers_outside_the_core() -> None:
    # Guards the derivation above: a policy edit that shrank the tuple would
    # otherwise drop parametrized cases instead of failing a test.
    assert OUTWARD_LAYERS == ("adapters", "api", "workers")


def test_the_adapter_cycle_derivation_is_application_and_the_entry_points() -> None:
    assert ADAPTER_EXCLUDED_LAYERS == ("application", "api", "workers")


@pytest.mark.parametrize("layer", ADAPTER_EXCLUDED_LAYERS)
def test_adapters_do_not_import_entry_points_or_application(layer: str, tmp_path: Path) -> None:
    # adapters -> ports. Reaching an entry point would close a cycle.
    source = f"from identity_lifecycle.{layer}.thing import T\n"
    assert _rules(tmp_path, "adapters/okta/leak.py", source, "bad") == ["adapters-layer"], layer
    allowed = "from identity_lifecycle.ports.gateway import G\n"
    assert _rules(tmp_path, "adapters/okta/c.py", allowed, "ok") == [], "ports stay allowed"


@pytest.mark.parametrize(
    ("relative", "source"),
    [
        ("__init__.py", "import tests\n"),
        ("domain/leak.py", "from tests.fixtures import fake_gateway\n"),
        ("application/leak.py", "def helper() -> None:\n    import tests\n"),
        (
            "api/leak.py",
            "from typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    import tests\n",
        ),
    ],
)
def test_production_code_does_not_import_tests(relative: str, source: str, tmp_path: Path) -> None:
    assert "tests-import" in _rules(tmp_path, relative, source), relative


def test_root_modules_are_checked_for_tests_imports(tmp_path: Path) -> None:
    root = _package(
        tmp_path, {"main.py": "import tests\n", "config.py": "import identity_lifecycle.adapters\n"}
    )
    violations = check_package(root)
    found = [(violation.rule, violation.path.name) for violation in violations]
    # root carries an allowlist now, so `tests` is both an
    # unlisted third-party name and a production->tests import. `config.py` is
    # wiring and may import any project module.
    assert found == [
        ("root-allowlist", "main.py"),
        ("tests-import", "main.py"),
    ], f"root modules are wiring; got {found}"


def test_unrecognized_subdirectory_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(UnrecognizedLayer, match="domian"):
        check_package(_package(tmp_path, {"domian/leak.py": "import fastapi\n"}))


def test_checker_reports_file_and_line(tmp_path: Path) -> None:
    root = _package(tmp_path, {"domain/bad.py": '"""Bad."""\n\nimport fastapi\n'})
    violations = check_package(root)
    assert [(v.path, v.line) for v in violations] == [(root / "domain" / "bad.py", 3)]
    assert f"{root / 'domain' / 'bad.py'}:3" in str(violations[0])


def test_checker_detects_a_known_violation(tmp_path: Path) -> None:
    violations = check_package(_package(tmp_path, {"domain/bad.py": "import sqlalchemy\n"}))
    assert [(v.rule, v.imported) for v in violations] == [("domain-allowlist", "sqlalchemy")]


def test_checker_ignores_relative_imports_within_the_same_layer(tmp_path: Path) -> None:
    root = _package(
        tmp_path,
        {
            "domain/models.py": "class Person:\n    pass\n",
            "domain/person.py": (
                "from .models import Person\nfrom . import models\n"
                "from identity_lifecycle.domain.models import Person as P\n"
            ),
        },
    )
    assert check_package(root) == []


def test_checker_fails_loudly_when_the_package_root_is_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="pass vacuously"):
        check_package(tmp_path / "moved" / PACKAGE_NAME)


def test_phase_zero_skeleton_is_scanned_not_skipped() -> None:
    # Only a real, existing tree may pass; a moved src/ raises instead.
    assert PACKAGE_ROOT.is_dir()
    assert (PACKAGE_ROOT / "__init__.py").is_file()
    assert check_package() == []
