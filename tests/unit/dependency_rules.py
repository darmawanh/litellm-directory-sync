"""Dependency-rule engine for design 15.1.

Every module under ``src/identity_lifecycle`` is parsed with :mod:`ast`; the
code under test is never imported. A tree with no modules passes, so the check
starts enforcing as Phase 1+ adds modules. This is the enforcement mechanism
for P-004.

Each module belongs to exactly one layer. Every layer has a fail-closed
allowlist: the project prefixes it may import, the third-party top-level names
it may import, and the standard library. An import outside those sets is a
violation, so an unlisted package is rejected until this file is edited. The
tables are copied from ADR-011 section 2; widening one needs a new decision
. ADR-012 narrows the standard-library dimension of ``domain`` by a
literal deny-set, subtracted from the total set; every other layer keeps the
total set.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

PACKAGE_NAME = "identity_lifecycle"
PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / PACKAGE_NAME

#: Every layer admits the standard library of the running interpreter.
STDLIB_MODULES = frozenset(sys.stdlib_module_names)

RECOGNIZED_LAYERS = (
    "domain",
    "ports",
    "application",
    "adapters",
    "api",
    "workers",
    "observability",
)

#: A module directly under the package root is wiring, not a layer.
ROOT_LAYER = "root"

# the eight layer allowlists

DOMAIN_ALLOWED_PROJECT_PREFIXES = ("identity_lifecycle.domain",)
DOMAIN_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset()

#: standard-library names ``domain`` may not import. The
#: total set stays ``STDLIB_MODULES``; this is subtracted for ``domain`` only.
DOMAIN_DENIED_STDLIB: frozenset[str] = frozenset(
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

PORTS_ALLOWED_PROJECT_PREFIXES = ("identity_lifecycle.domain", "identity_lifecycle.ports")
PORTS_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset()

APPLICATION_ALLOWED_PROJECT_PREFIXES = (
    "identity_lifecycle.domain",
    "identity_lifecycle.ports",
    "identity_lifecycle.application",
)
APPLICATION_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"structlog"})

ADAPTERS_ALLOWED_PROJECT_PREFIXES = (
    "identity_lifecycle.domain",
    "identity_lifecycle.ports",
    "identity_lifecycle.adapters",
    "identity_lifecycle.observability",
)
ADAPTERS_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset(
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

API_ALLOWED_PROJECT_PREFIXES = (
    "identity_lifecycle.domain",
    "identity_lifecycle.ports",
    "identity_lifecycle.application",
    "identity_lifecycle.adapters",
    "identity_lifecycle.api",
    "identity_lifecycle.config",
    "identity_lifecycle.observability",
)
API_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset(
    {"fastapi", "pydantic", "starlette", "structlog"}
)

WORKERS_ALLOWED_PROJECT_PREFIXES = (
    "identity_lifecycle.domain",
    "identity_lifecycle.ports",
    "identity_lifecycle.application",
    "identity_lifecycle.adapters",
    "identity_lifecycle.workers",
    "identity_lifecycle.config",
    "identity_lifecycle.observability",
)
WORKERS_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"structlog"})

OBSERVABILITY_ALLOWED_PROJECT_PREFIXES = (
    "identity_lifecycle.domain",
    "identity_lifecycle.observability",
)
OBSERVABILITY_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"prometheus_client", "structlog"})

ROOT_ALLOWED_PROJECT_PREFIXES = ("identity_lifecycle",)
ROOT_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset(
    {"pydantic", "pydantic_settings", "structlog", "uvicorn", "yaml"}
)

#: The three sets T-011 pins. Each is the standard library plus the literal
#: project prefixes and third-party names above.
PORTS_ALLOWED_MODULES = (
    STDLIB_MODULES | frozenset(PORTS_ALLOWED_PROJECT_PREFIXES) | PORTS_ALLOWED_THIRD_PARTY
)
APPLICATION_ALLOWED_MODULES = (
    STDLIB_MODULES
    | frozenset(APPLICATION_ALLOWED_PROJECT_PREFIXES)
    | APPLICATION_ALLOWED_THIRD_PARTY
)
ADAPTERS_ALLOWED_MODULES = (
    STDLIB_MODULES | frozenset(ADAPTERS_ALLOWED_PROJECT_PREFIXES) | ADAPTERS_ALLOWED_THIRD_PARTY
)


@dataclass(frozen=True)
class LayerPolicy:
    """The allowlists of one layer; the standard library is implicit.

        ``denied_stdlib`` subtracts names from the total standard-library set
    . It is empty for every layer but ``domain``.
    """

    project_prefixes: tuple[str, ...]
    third_party: frozenset[str]
    denied_stdlib: frozenset[str] = frozenset()

    def allows_project(self, name: str) -> bool:
        return any(
            name == prefix or name.startswith(f"{prefix}.") for prefix in self.project_prefixes
        )

    def allows_third_party(self, top_level: str) -> bool:
        if top_level in self.denied_stdlib:
            return False
        return top_level in STDLIB_MODULES or top_level in self.third_party


#: One entry per recognized layer plus the root layer.
LAYER_POLICIES: Mapping[str, LayerPolicy] = {
    "domain": LayerPolicy(
        DOMAIN_ALLOWED_PROJECT_PREFIXES, DOMAIN_ALLOWED_THIRD_PARTY, DOMAIN_DENIED_STDLIB
    ),
    "ports": LayerPolicy(PORTS_ALLOWED_PROJECT_PREFIXES, PORTS_ALLOWED_THIRD_PARTY),
    "application": LayerPolicy(
        APPLICATION_ALLOWED_PROJECT_PREFIXES, APPLICATION_ALLOWED_THIRD_PARTY
    ),
    "adapters": LayerPolicy(ADAPTERS_ALLOWED_PROJECT_PREFIXES, ADAPTERS_ALLOWED_THIRD_PARTY),
    "api": LayerPolicy(API_ALLOWED_PROJECT_PREFIXES, API_ALLOWED_THIRD_PARTY),
    "workers": LayerPolicy(WORKERS_ALLOWED_PROJECT_PREFIXES, WORKERS_ALLOWED_THIRD_PARTY),
    "observability": LayerPolicy(
        OBSERVABILITY_ALLOWED_PROJECT_PREFIXES, OBSERVABILITY_ALLOWED_THIRD_PARTY
    ),
    ROOT_LAYER: LayerPolicy(ROOT_ALLOWED_PROJECT_PREFIXES, ROOT_ALLOWED_THIRD_PARTY),
}


class UnrecognizedLayer(ValueError):
    """A module lives in a subdirectory that is not a layer"""

    def __init__(self, directory: str, path: Path) -> None:
        self.directory = directory
        super().__init__(
            f"{path}: {directory!r} is not a layer of design 15.1; "
            f"expected one of {RECOGNIZED_LAYERS} or a root-level module"
        )


@dataclass(frozen=True)
class Violation:
    """One broken import, reported with its file and line."""

    rule: str
    path: Path
    line: int
    imported: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.reason} (rule {self.rule})"


def check_package(package_root: Path = PACKAGE_ROOT) -> list[Violation]:
    """Return every dependency-rule violation in ``package_root``, sorted by file."""
    if not package_root.is_dir():
        raise FileNotFoundError(
            f"package root {package_root} does not exist; the dependency check would "
            "pass vacuously"
        )
    violations: list[Violation] = []
    for path in sorted(package_root.rglob("*.py")):
        if "__pycache__" not in path.parts:
            violations.extend(_check_module(path, package_root))
    return violations


def _check_module(path: Path, package_root: Path) -> list[Violation]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    layer = _layer_of(path, package_root)
    violations: list[Violation] = []
    for node, names in _iter_imports(tree, path, package_root):
        for name in dict.fromkeys(names):
            violations.extend(_violations_for_import(layer, path, node.lineno, name))
    return violations


def _layer_of(path: Path, package_root: Path) -> str:
    """Return the layer of ``path``; raise rather than let a typo evade every rule."""
    parts = path.relative_to(package_root).parts
    if len(parts) == 1:
        return ROOT_LAYER
    if parts[0] in RECOGNIZED_LAYERS:
        return parts[0]
    raise UnrecognizedLayer(parts[0], path)


def _iter_imports(
    tree: ast.Module, path: Path, package_root: Path
) -> Iterator[tuple[ast.stmt, list[str]]]:
    """Yield every import node with the absolute names it targets.

    ``ast.walk`` descends into function bodies and ``if TYPE_CHECKING:`` blocks,
    exactly where a forbidden import could otherwise hide.
    """
    package_parts = path.relative_to(package_root).parent.parts
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield node, [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            yield node, _imported_names(node, package_parts)


def _imported_names(node: ast.ImportFrom, package_parts: tuple[str, ...]) -> list[str]:
    """Resolve ``from... import...`` to the absolute names it binds.

    Only the imported names are targets, not the base module: ``from
    identity_lifecycle import domain`` targets ``identity_lifecycle.domain``.
    """
    if node.level == 0:
        if not node.module:
            return []
        return [f"{node.module}.{alias.name}" for alias in node.names]
    trim = node.level - 1
    if trim > len(package_parts):
        return []
    anchor = (PACKAGE_NAME, *package_parts[: len(package_parts) - trim])
    if node.module:
        anchor = (*anchor, *node.module.split("."))
    return [".".join((*anchor, alias.name)) for alias in node.names]


def _violation(rule: str, path: Path, line: int, name: str, reason: str) -> Violation:
    return Violation(rule=rule, path=path, line=line, imported=name, reason=reason)


def _project_rule(layer: str) -> str:
    """Keep T-004's rule names for the project dimension it already tested."""
    if layer == "domain":
        return "domain-outside"
    return f"{layer}-layer"


def _violations_for_import(layer: str, path: Path, line: int, name: str) -> list[Violation]:
    top_level = name.split(".", 1)[0]
    policy = LAYER_POLICIES[layer]
    violations: list[Violation] = []

    if _is_project(name):
        if not policy.allows_project(name):
            allowed = ", ".join(policy.project_prefixes)
            violations.append(
                _violation(
                    _project_rule(layer),
                    path,
                    line,
                    name,
                    f"{layer} may not import {name}; allowed project prefixes are {allowed}",
                )
            )
    elif not policy.allows_third_party(top_level):
        # A denied stdlib name is not third-party; name the actual defect
        # while the rule name stays ``{layer}-allowlist``.
        kind = "standard-library" if top_level in STDLIB_MODULES else "third-party"
        violations.append(
            _violation(
                f"{layer}-allowlist",
                path,
                line,
                name,
                f"{layer} may not import {kind} {top_level}; it is not on the "
                f"{layer} allowlist",
            )
        )

    if top_level == "tests":
        violations.append(
            _violation("tests-import", path, line, name, f"production code may not import {name}")
        )

    return violations


def _is_project(name: str) -> bool:
    return name == PACKAGE_NAME or name.startswith(f"{PACKAGE_NAME}.")
