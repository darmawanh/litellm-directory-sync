"""Each layer's import allowlist, proven fail-closed.

The three sets the ticket pins (``PORTS_ALLOWED_MODULES``,
``APPLICATION_ALLOWED_MODULES``, ``ADAPTERS_ALLOWED_MODULES``) are compared to
literal expected values, so widening an allowlist fails a test. Every rejection
case is parametrized from a literal tuple, not from the guarded set, so deleting
a name from the engine cannot shrink the proof.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from . import dependency_rules as rules
from .dependency_rules import (
    ADAPTERS_ALLOWED_MODULES,
    APPLICATION_ALLOWED_MODULES,
    LAYER_POLICIES,
    PACKAGE_NAME,
    PORTS_ALLOWED_MODULES,
    Violation,
    check_package,
)

pytestmark = pytest.mark.unit

#: ADR-011 section 2, row for row: project prefixes and third-party names.
ADR_LAYER_TABLE: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {
    "domain": (("identity_lifecycle.domain",), frozenset()),
    "ports": (
        ("identity_lifecycle.domain", "identity_lifecycle.ports"),
        frozenset(),
    ),
    "application": (
        (
            "identity_lifecycle.domain",
            "identity_lifecycle.ports",
            "identity_lifecycle.application",
        ),
        frozenset({"structlog"}),
    ),
    "adapters": (
        (
            "identity_lifecycle.domain",
            "identity_lifecycle.ports",
            "identity_lifecycle.adapters",
            "identity_lifecycle.observability",
        ),
        frozenset(
            {
                "alembic",
                "httpx",
                "jwt",
                "ldap3",
                "limits",
                "psycopg",
                "pybreaker",
                "pydantic",
                "sqlalchemy",
                "structlog",
                "tenacity",
            }
        ),
    ),
    "api": (
        (
            "identity_lifecycle.domain",
            "identity_lifecycle.ports",
            "identity_lifecycle.application",
            "identity_lifecycle.adapters",
            "identity_lifecycle.api",
            "identity_lifecycle.config",
            "identity_lifecycle.observability",
        ),
        frozenset({"fastapi", "pydantic", "starlette", "structlog"}),
    ),
    "workers": (
        (
            "identity_lifecycle.domain",
            "identity_lifecycle.ports",
            "identity_lifecycle.application",
            "identity_lifecycle.adapters",
            "identity_lifecycle.workers",
            "identity_lifecycle.config",
            "identity_lifecycle.observability",
        ),
        frozenset({"structlog"}),
    ),
    "observability": (
        ("identity_lifecycle.domain", "identity_lifecycle.observability"),
        frozenset({"prometheus_client", "structlog"}),
    ),
    "root": (
        ("identity_lifecycle",),
        frozenset({"pydantic", "pydantic_settings", "structlog", "uvicorn", "yaml"}),
    ),
}

STDLIB = frozenset(sys.stdlib_module_names)

PORTS_EXPECTED = STDLIB | frozenset({"identity_lifecycle.domain", "identity_lifecycle.ports"})

APPLICATION_EXPECTED = (
    STDLIB
    | frozenset(
        {
            "identity_lifecycle.domain",
            "identity_lifecycle.ports",
            "identity_lifecycle.application",
        }
    )
    | {"structlog"}
)

ADAPTERS_EXPECTED = (
    STDLIB
    | frozenset(
        {
            "identity_lifecycle.domain",
            "identity_lifecycle.ports",
            "identity_lifecycle.adapters",
            "identity_lifecycle.observability",
        }
    )
    | frozenset(
        {
            "alembic",
            "httpx",
            "jwt",
            "ldap3",
            "limits",
            "psycopg",
            "pybreaker",
            "pydantic",
            "sqlalchemy",
            "structlog",
            "tenacity",
        }
    )
)

#: Every framework D-012 forbids in ``ports``, plus ``fastapi`` from the stack.
FRAMEWORKS_FORBIDDEN_IN_PORTS = (
    "fastapi",
    "jose",
    "jwt",
    "prometheus_client",
    "pydantic",
    "starlette",
    "structlog",
    "tenacity",
    "uvicorn",
)

#: Every vendor SDK D-012 forbids in ``ports``.
VENDOR_SDKS_FORBIDDEN_IN_PORTS = (
    "alembic",
    "docker",
    "httpx",
    "ldap3",
    "litellm",
    "psycopg",
    "requests",
    "sqlalchemy",
)

#: The ticket's literal list, plus ``pydantic``.
VENDOR_SDKS_FORBIDDEN_IN_APPLICATION = (
    "docker",
    "httpx",
    "ldap3",
    "litellm",
    "psycopg",
    "pydantic",
    "requests",
    "sqlalchemy",
)

#: Names absent from the ``adapters`` allowlist; ``litellm`` is ADR-001 section 10.
OUTSIDE_ADAPTERS_ALLOWLIST = (
    "docker",
    "fastapi",
    "jose",
    "litellm",
    "requests",
    "ruamel",
    "uvicorn",
    "yaml",
)

ADAPTERS_THIRD_PARTY = (
    "alembic",
    "httpx",
    "jwt",
    "ldap3",
    "limits",
    "psycopg",
    "pybreaker",
    "pydantic",
    "sqlalchemy",
    "structlog",
    "tenacity",
)

#: ``yaml`` is placed at the root layer only.
NON_ROOT_LAYERS = ("domain", "ports", "application", "adapters", "api", "workers", "observability")
ALL_LAYERS = (*NON_ROOT_LAYERS, "root")

LEGAL_IMPORT_PER_LAYER = {
    "domain/models.py": "import dataclasses\n",
    "ports/gateway.py": "from identity_lifecycle.domain.models import Person\n",
    "application/process_event.py": (
        "import structlog\nfrom identity_lifecycle.ports.gateway import Gateway\n"
    ),
    "adapters/okta/client.py": (
        "import httpx\nfrom identity_lifecycle.ports.gateway import Gateway\n"
    ),
    "api/routes.py": (
        "from fastapi import FastAPI\n"
        "from identity_lifecycle.application.process_event import ProcessEvent\n"
    ),
    "workers/outbox.py": (
        "import structlog\n"
        "from identity_lifecycle.application.process_event import ProcessEvent\n"
    ),
    "observability/metrics.py": (
        "import prometheus_client\nfrom identity_lifecycle.domain.models import Person\n"
    ),
    "config.py": "import yaml\nimport identity_lifecycle.adapters.okta.client\n",
}


def _package(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "pkg" / PACKAGE_NAME
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return root


def _violations(tmp_path: Path, relative: str, source: str) -> list[Violation]:
    return check_package(_package(tmp_path, {relative: source}))


def _rules(tmp_path: Path, relative: str, source: str) -> list[str]:
    return [violation.rule for violation in _violations(tmp_path, relative, source)]


def _detail(violations: list[Violation]) -> str:
    """Render each violation as ``path:line: reason``, never a dataclass repr."""
    return "; ".join(str(violation) for violation in violations) or "no violation"


def test_ports_allowlist_matches_d012() -> None:
    # The three sets are literal copies of D-012 / ADR-011 section 2. A future
    # widening, even of one name, fails here before it can pass silently.
    assert PORTS_ALLOWED_MODULES == PORTS_EXPECTED
    assert APPLICATION_ALLOWED_MODULES == APPLICATION_EXPECTED
    assert ADAPTERS_ALLOWED_MODULES == ADAPTERS_EXPECTED


def test_each_layer_policy_matches_the_adr_table() -> None:
    assert set(LAYER_POLICIES) == set(ADR_LAYER_TABLE)
    for layer, (prefixes, third_party) in ADR_LAYER_TABLE.items():
        policy = LAYER_POLICIES[layer]
        assert policy.project_prefixes == prefixes, layer
        assert policy.third_party == third_party, layer


def test_only_the_domain_layer_denies_a_stdlib_module() -> None:
    # the narrowing is domain-only; every other layer keeps the total
    # set. A later silent narrowing of ``ports`` fails here.
    expected = frozenset(
        {
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
        }
    )
    for layer, policy in LAYER_POLICIES.items():
        assert policy.denied_stdlib == (expected if layer == "domain" else frozenset()), layer


def test_the_two_denylists_are_gone() -> None:
    # ADR-011 section 5 and section 7 remove these rather than keep them.
    assert not hasattr(rules, "UNDECIDED_MODULES")
    assert not hasattr(rules, "VENDOR_SDK_MODULES")


@pytest.mark.parametrize("module", FRAMEWORKS_FORBIDDEN_IN_PORTS)
def test_ports_rejects_a_framework_import(module: str, tmp_path: Path) -> None:
    violations = _violations(tmp_path, "ports/gateway.py", f"import {module}\n")
    assert [violation.rule for violation in violations] == [
        "ports-allowlist"
    ], f"{module} must be rejected in ports; got {_detail(violations)}"


@pytest.mark.parametrize("module", VENDOR_SDKS_FORBIDDEN_IN_PORTS)
def test_ports_rejects_a_vendor_sdk_import(module: str, tmp_path: Path) -> None:
    violations = _violations(tmp_path, "ports/gateway.py", f"import {module}\n")
    assert [violation.rule for violation in violations] == [
        "ports-allowlist"
    ], f"{module} must be rejected in ports; got {_detail(violations)}"


@pytest.mark.parametrize("module", VENDOR_SDKS_FORBIDDEN_IN_APPLICATION)
def test_application_rejects_a_vendor_sdk_import(module: str, tmp_path: Path) -> None:
    violations = _violations(tmp_path, "application/leak.py", f"import {module}\n")
    assert [violation.rule for violation in violations] == [
        "application-allowlist"
    ], f"{module} must be rejected in application; got {_detail(violations)}"


#: ``adapters`` may import domain, ports, its own layer,
#: observability, and the eleven libraries below. Entry points and application
#: would close a cycle; ``litellm`` is absent.
ADAPTERS_IMPORT_CASES = (
    pytest.param(
        "from identity_lifecycle.api.routes import router\n", ("adapters-layer",), id="reject-api"
    ),
    pytest.param(
        "from identity_lifecycle.workers.outbox import run\n",
        ("adapters-layer",),
        id="reject-workers",
    ),
    pytest.param(
        "from identity_lifecycle.application.process_event import ProcessEvent\n",
        ("adapters-layer",),
        id="reject-application",
    ),
    *(
        pytest.param(f"import {module}\n", ("adapters-allowlist",), id=f"reject-{module}")
        for module in OUTSIDE_ADAPTERS_ALLOWLIST
    ),
    *(
        pytest.param(f"import {module}\n", (), id=f"allow-{module}")
        for module in ADAPTERS_THIRD_PARTY
    ),
    pytest.param("from identity_lifecycle.ports.gateway import Gateway\n", (), id="allow-ports"),
    pytest.param("from identity_lifecycle.domain.models import Person\n", (), id="allow-domain"),
    pytest.param(
        "from identity_lifecycle.observability.metrics import counter\n",
        (),
        id="allow-observability",
    ),
)


@pytest.mark.parametrize(("source", "expected"), ADAPTERS_IMPORT_CASES)
def test_adapters_import_only_ports_domain_and_permitted_libraries(
    source: str, expected: tuple[str, ...], tmp_path: Path
) -> None:
    violations = _violations(tmp_path, "adapters/okta/client.py", source)
    assert (
        tuple(violation.rule for violation in violations) == expected
    ), f"{source!r}: {_detail(violations)}"


@pytest.mark.parametrize("layer", ALL_LAYERS)
def test_an_unlisted_third_party_module_is_rejected_in_every_layer(
    layer: str, tmp_path: Path
) -> None:
    # All eight layers, root included: measured, every one rejects an unlisted
    # third-party name, so the name states the parametrization.
    relative = "config.py" if layer == "root" else f"{layer}/leak.py"
    violations = _violations(tmp_path, relative, "import totally_unknown_sdk\n")
    assert [violation.rule for violation in violations] == [
        f"{layer}-allowlist"
    ], f"{layer} must fail closed; got {_detail(violations)}"


def test_yaml_is_allowed_at_the_root_layer(tmp_path: Path) -> None:
    assert _rules(tmp_path, "config.py", "import yaml\n") == []


@pytest.mark.parametrize("layer", NON_ROOT_LAYERS)
def test_yaml_is_rejected_in_every_other_layer(layer: str, tmp_path: Path) -> None:
    violations = _violations(tmp_path, f"{layer}/loader.py", "import yaml\n")
    assert [violation.rule for violation in violations] == [
        f"{layer}-allowlist"
    ], f"yaml must be rejected in {layer}; got {_detail(violations)}"


@pytest.mark.parametrize("layer", ALL_LAYERS)
def test_ruamel_is_rejected_in_every_layer(layer: str, tmp_path: Path) -> None:
    relative = "config.py" if layer == "root" else f"{layer}/loader.py"
    violations = _violations(tmp_path, relative, "import ruamel\n")
    assert [violation.rule for violation in violations] == [
        f"{layer}-allowlist"
    ], f"ruamel must be rejected in {layer}; got {_detail(violations)}"


def test_a_legal_import_in_every_layer_passes(tmp_path: Path) -> None:
    violations = check_package(_package(tmp_path, LEGAL_IMPORT_PER_LAYER))
    assert violations == [], _detail(violations)
