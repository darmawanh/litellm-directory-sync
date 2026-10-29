"""The `application` layer's imports, proven against the real modules.

`tests/unit/dependency_rules.py` already rejects an adapter import from a
synthetic `application/` module, and `test_layer_policy.py` pins the allowlist
itself. This test adds the one thing those two cannot say: the *actual* modules
this ticket added — `ingest_event`, `process_event`, `event_effects`,
`unit_of_work_factory` — pass the same engine, and `application` names no vendor
even in prose.

No allowlist is widened for it. `application` may import `domain`, `ports`, its
own layer, the standard library, and `structlog`; that is exactly the set
ADR-011 section 2 gives it, and a vendor import here would be a design change,
not a test change.
"""

from __future__ import annotations

import ast

import pytest

from .dependency_rules import PACKAGE_ROOT, check_package

pytestmark = pytest.mark.unit

APPLICATION_ROOT = PACKAGE_ROOT / "application"

#: The vendor names D-012 forbids in this layer, as text as well as code: a
#: docstring that names a vendor is the boundary leaking into the layer that must
#: not know which adapter it holds.
VENDOR_TOKENS = ("litellm", "okta", "ldap", "sqlalchemy", "httpx", "psycopg", "alembic")

MODULES = (
    "audit_export.py",
    "event_effects.py",
    "ingest_event.py",
    "manual_sync.py",
    "outbox_replay.py",
    "process_event.py",
    "reconcile.py",
    "source_check.py",
    "source_poll.py",
    "unit_of_work_factory.py",
)


def test_the_application_modules_exist() -> None:
    # A typo in a module name would make the scans below vacuous.
    assert sorted(path.name for path in APPLICATION_ROOT.glob("*.py")) == [
        "__init__.py",
        "audit_export.py",
        "event_effects.py",
        "ingest_event.py",
        "manual_sync.py",
        "outbox_replay.py",
        "process_event.py",
        "reconcile.py",
        "source_check.py",
        "source_poll.py",
        "unit_of_work_factory.py",
    ]


def test_the_real_package_passes_the_layer_engine() -> None:
    violations = check_package()
    assert violations == [], "; ".join(str(violation) for violation in violations)


@pytest.mark.parametrize("module", MODULES)
def test_an_application_module_imports_no_adapter(module: str) -> None:
    tree = ast.parse((APPLICATION_ROOT / module).read_text(encoding="utf-8"), filename=module)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.append(node.module)
    offending = [
        name
        for name in imported
        if name.startswith("identity_lifecycle.adapters")
        or name.startswith(("identity_lifecycle.api", "identity_lifecycle.workers"))
    ]
    assert offending == [], f"{module} reaches out of the layer: {offending}"


@pytest.mark.parametrize("module", MODULES)
def test_an_application_module_names_no_vendor(module: str) -> None:
    # LiteLLMAccount is the canonical domain model name from domain.models (see test_ports.py).
    text = (
        (APPLICATION_ROOT / module)
        .read_text(encoding="utf-8")
        .replace("LiteLLMAccount", "")
        .lower()
    )
    found = [token for token in VENDOR_TOKENS if token in text]
    assert found == [], f"{module} names {found}; a vendor spelling stops at the adapter"


def test_the_vendor_scan_detects_a_vendor_name() -> None:
    # Negative control: a scan that finds nothing would pass the tests above on a
    # module that had grown a vendor name.
    sample = "import httpx\n"
    assert [token for token in VENDOR_TOKENS if token in sample.lower()] == ["httpx"]
