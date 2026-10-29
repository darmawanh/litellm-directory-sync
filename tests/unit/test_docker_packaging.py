"""Unit tests for Docker packaging and.dockerignore rules.

Proves:
- Dockerfile syntax, multi-stage structure (builder + runtime), and non-root execution.
-.dockerignore exclusions for secrets, credentials, VCS, caches, and test suites.
-.dockerignore preservation of essential build artifacts and source code.
md §3, §10, and Ticket T-055.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"
DOCKERIGNORE_PATH = REPO_ROOT / ".dockerignore"


def _load_dockerignore_patterns(path: Path) -> list[str]:
    """Parse non-empty, non-comment lines from.dockerignore."""
    patterns: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _matches_dockerignore(rel_path: str, patterns: list[str]) -> bool:
    """Check if a relative path (using forward slashes) matches any dockerignore pattern."""
    normalized = rel_path.strip("/")
    parts = normalized.split("/")

    for pattern in patterns:
        clean_pat = pattern.strip("/")
        # Direct pattern match on full path
        if fnmatch.fnmatch(normalized, clean_pat) or fnmatch.fnmatch(normalized, f"{clean_pat}/*"):
            return True
        # Directory prefix match
        if any(fnmatch.fnmatch(part, clean_pat) for part in parts):
            return True
        # Filename match (e.g. *.key or *.pem)
        if fnmatch.fnmatch(parts[-1], clean_pat):
            return True
    return False


def test_dockerfile_exists_and_readable() -> None:
    assert DOCKERFILE_PATH.is_file(), "Dockerfile must exist at repository root"
    content = DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert len(content) > 0


def test_dockerfile_multi_stage_structure() -> None:
    content = DOCKERFILE_PATH.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines()]

    from_lines = [line for line in lines if line.startswith("FROM ")]
    assert len(from_lines) >= 2, "Dockerfile must define at least two stages (builder and runtime)"

    # Builder stage validation
    assert any("AS builder" in line for line in from_lines), "Builder stage must be named 'builder'"
    assert any(
        "python:3.12-slim" in line for line in from_lines
    ), "Base image must use python:3.12-slim"

    # Runtime stage validation
    assert any(
        "AS runtime" in line or line == "FROM python:3.12-slim" for line in from_lines
    ), "Runtime stage must derive from python:3.12-slim"

    # Builder uv sync assertions
    assert any(
        "uv sync" in line and "--locked" in line for line in lines
    ), "Builder stage must use uv sync --locked"
    assert any(
        "uv sync" in line and "--no-dev" in line for line in lines
    ), "Builder stage must exclude development dependencies (--no-dev)"


def test_dockerfile_security_and_runtime_configuration() -> None:
    content = DOCKERFILE_PATH.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines()]

    # Unprivileged non-root user creation and declaration
    assert any(
        "groupadd" in line and "10001" in line for line in lines
    ), "Dockerfile must create non-root group with GID 10001"
    assert any(
        "useradd" in line and "10001" in line and "appuser" in line for line in lines
    ), "Dockerfile must create unprivileged user appuser with UID 10001"
    assert any(
        line == "USER appuser" for line in lines
    ), "Dockerfile must switch to USER appuser before entrypoint"

    # Port and Entrypoint
    assert any("EXPOSE 8000" in line for line in lines), "Dockerfile must expose port 8000"
    assert any(
        'ENTRYPOINT ["identity-lifecycle"]' in line for line in lines
    ), 'Dockerfile must declare ENTRYPOINT ["identity-lifecycle"]'
    assert any(
        'CMD ["--help"]' in line for line in lines
    ), 'Dockerfile must declare default CMD ["--help"]'

    # Isolated virtual environment copying
    assert any(
        "COPY --from=builder" in line and "/app/.venv" in line for line in lines
    ), "Dockerfile must copy isolated virtual environment from builder stage"

    # PATH inclusion
    assert any(
        'PATH="/app/.venv/bin:$PATH"' in line or "/app/.venv/bin" in line for line in lines
    ), "Dockerfile must prepend virtualenv bin directory to PATH"


def test_dockerignore_exists_and_readable() -> None:
    assert DOCKERIGNORE_PATH.is_file(), ".dockerignore must exist at repository root"
    content = DOCKERIGNORE_PATH.read_text(encoding="utf-8")
    assert len(content) > 0


def test_dockerignore_excludes_vcs_and_virtualenvs() -> None:
    patterns = _load_dockerignore_patterns(DOCKERIGNORE_PATH)

    vcs_and_venv_paths = [
        ".git",
        ".git/HEAD",
        ".git/objects/abc",
        ".gitignore",
        ".venv",
        ".venv/bin/python",
        ".venv/lib/site-packages",
        "venv/bin/activate",
        "env/bin/activate",
    ]

    for path in vcs_and_venv_paths:
        assert _matches_dockerignore(path, patterns), f"{path} must be excluded by .dockerignore"


def test_dockerignore_excludes_caches_and_bytecode() -> None:
    patterns = _load_dockerignore_patterns(DOCKERIGNORE_PATH)

    cache_paths = [
        "__pycache__",
        "src/__pycache__",
        "src/identity_lifecycle/__pycache__/main.cpython-312.pyc",
        "module.pyc",
        "module.pyo",
        "module.so",
        ".pytest_cache",
        ".pytest_cache/v/cache/nodeids",
        ".mypy_cache",
        ".ruff_cache",
        ".coverage",
        "htmlcov/index.html",
    ]

    for path in cache_paths:
        assert _matches_dockerignore(path, patterns), f"{path} must be excluded by .dockerignore"


def test_dockerignore_excludes_secrets_and_credentials() -> None:
    patterns = _load_dockerignore_patterns(DOCKERIGNORE_PATH)

    secret_paths = [
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa.pem",
        "private.key",
        "server.cert",
        "server.crt",
        "keystore.pfx",
        "bundle.p12",
        "config/config.yaml",
    ]

    for path in secret_paths:
        assert _matches_dockerignore(
            path, patterns
        ), f"Potential secret path {path} must be excluded by .dockerignore (AGENTS.md §10)"


def test_dockerignore_excludes_development_and_test_tooling() -> None:
    patterns = _load_dockerignore_patterns(DOCKERIGNORE_PATH)

    dev_paths = [
        "tests",
        "tests/unit/test_policy.py",
        "ops",
        "ops/gates.sh",
        "ops/tickets/T-055.md",
        "docs",
        "docs/adr/ADR-001.md",
        ".idea/workspace.xml",
        ".vscode/settings.json",
        ".system_generated/tasks/task-1.log",
        ".gemini/config.json",
        "temp.tmp",
    ]

    for path in dev_paths:
        assert _matches_dockerignore(path, patterns), f"{path} must be excluded by .dockerignore"


def test_dockerignore_retains_essential_application_files() -> None:
    patterns = _load_dockerignore_patterns(DOCKERIGNORE_PATH)

    essential_paths = [
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "alembic.ini",
        "src/identity_lifecycle/main.py",
        "src/identity_lifecycle/domain/models.py",
        "migrations/env.py",
        "migrations/versions/0001_initial.py",
        "config/config.example.yaml",
    ]

    for path in essential_paths:
        assert not _matches_dockerignore(
            path, patterns
        ), f"Essential build file {path} must NOT be excluded by .dockerignore"
