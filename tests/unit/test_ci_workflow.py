"""The CI workflow runs the four gates and nothing the ticket did not ask for.

The file is read as text on purpose. PyYAML reaches the virtual environment
only through pre-commit's dev group, so a parser-based test would prove a
dependency the manifest does not declare. Text assertions also keep
this test independent of the YAML library's shape, and the workflow is small
enough that line-oriented checks are exact.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"

#: The gates, in the order ER8 and the ticket require.
GATES = (
    "ruff check .",
    "ruff format --check .",
    "mypy src",
    "pytest",
)

#: Every gate runs on the environment `uv sync --locked` installed.
GATE_COMMANDS = tuple(f"uv run --no-sync {gate}" for gate in GATES)

#: Paths owned by T-004, which runs in parallel with this ticket.
PARALLEL_TICKET_PATHS = (
    "test_dependency_direction",
    "dependency_rules",
    "T-004",
)


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _run_commands(text: str) -> list[str]:
    """The shell command of each step, in file order."""
    commands = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("- run:", "run:")):
            commands.append(stripped.split("run:", 1)[1].strip())
    return commands


def test_workflow_declares_the_four_gates() -> None:
    commands = _run_commands(_workflow())

    for gate, command in zip(GATES, GATE_COMMANDS, strict=True):
        assert commands.count(command) == 1, f"{gate!r} must be exactly one step; got {commands}"

    positions = [commands.index(command) for command in GATE_COMMANDS]
    assert positions == sorted(positions), f"gates run out of order: {commands}"


def test_workflow_has_no_repository_secrets() -> None:
    text = _workflow()

    assert "secrets." not in text, "CI must pass with no repository secrets"
    assert "secrets[" not in text, "CI must pass with no repository secrets"
    assert "services:" not in text, "a dependency container is not this repository's infrastructure"


def test_workflow_pins_python_312() -> None:
    text = _workflow()
    pinned = (WORKFLOW.parents[2] / ".python-version").read_text(encoding="utf-8").strip()

    assert pinned == "3.12"
    assert '"3.12"' in text, "the workflow must request the version in .python-version"
    assert "uv sync --locked" in _run_commands(text), "install the environment from uv.lock"


def test_workflow_pins_uv_and_caches_on_the_lockfile() -> None:
    text = _workflow()

    assert "astral-sh/setup-uv@v5" in text
    assert re.search(r'^\s+version: "\d+\.\d+\.\d+"$', text, re.MULTILINE), "uv is not pinned"
    assert 'cache-dependency-glob: "uv.lock"' in text, "the cache must be keyed on uv.lock"


def test_workflow_does_not_depend_on_a_parallel_ticket() -> None:
    text = _workflow()

    for owned_path in PARALLEL_TICKET_PATHS:
        assert owned_path not in text, f"T-005 must not name {owned_path!r} from T-004"


def test_workflow_triggers_on_pull_request_and_push_to_main() -> None:
    text = _workflow()

    assert re.search(r"^on:$", text, re.MULTILINE), "the workflow has no trigger block"
    assert re.search(r"^  pull_request:$", text, re.MULTILINE), "pull requests must run CI"
    assert re.search(r"^    branches: \[main\]$", text, re.MULTILINE), "main pushes must run CI"


def test_workflow_cancels_superseded_runs_on_the_same_ref() -> None:
    text = _workflow()

    assert re.search(r"^concurrency:$", text, re.MULTILINE), "no concurrency group"
    assert "cancel-in-progress: true" in text
    assert "github.ref" in text, "the group must be keyed on the ref, not on the branch name"


def test_workflow_collects_the_unit_suite() -> None:
    commands = _run_commands(_workflow())

    assert "uv run --no-sync pytest --collect-only -q tests/unit" in commands


def test_workflow_pins_actions_to_major_tags() -> None:
    uses = re.findall(r"uses:\s*(\S+)", _workflow())

    assert uses, "the workflow uses no actions"
    for action in uses:
        assert re.fullmatch(r"[^@\s]+@v\d+(?:\.\d+)*", action), f"{action!r} is not pinned to a tag"


def test_workflow_does_not_tolerate_a_failing_gate() -> None:
    text = _workflow()

    assert "continue-on-error: true" not in text
    assert "|| true" not in text
