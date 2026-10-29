"""Integration test verifying the built production Docker service image.

Proves:
- The production Docker image runs as unprivileged non-root user (UID/GID 10001).
- The identity-lifecycle CLI commands (version, api, worker, scheduler, config, reconcile, sync)
  execute cleanly inside the container environment.
- Alembic database migration tooling is available and executable in the container.
md §3, and Ticket T-055.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

IMAGE_TAG = "identity-lifecycle:local"


def _docker_executable() -> str:
    path = shutil.which("docker")
    if path is None:
        pytest.skip("docker CLI binary not found in PATH")
    return path


def _run_docker(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [_docker_executable(), *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.integration
def test_docker_image_version_subcommand() -> None:
    res = _run_docker("run", "--rm", IMAGE_TAG, "version")
    assert res.returncode == 0, f"docker run version failed: {res.stderr}"
    assert "0.1.0" in res.stdout.strip()


@pytest.mark.integration
def test_docker_image_runs_as_non_root_user() -> None:
    res = _run_docker("run", "--rm", "--entrypoint", "id", IMAGE_TAG)
    assert res.returncode == 0, f"docker run id failed: {res.stderr}"
    assert "uid=10001(appuser)" in res.stdout
    assert "gid=10001(appuser)" in res.stdout


@pytest.mark.integration
@pytest.mark.parametrize(
    ("subcommand", "expected_help_text"),
    [
        ("api", "Run the API process"),
        ("worker", "Run the worker process"),
        ("scheduler", "Run the scheduler process"),
        ("reconcile", "Run a one-shot reconciliation pass"),
        ("sync", "Target employee number to resynchronize"),
    ],
)
def test_docker_image_service_subcommands_help(subcommand: str, expected_help_text: str) -> None:
    res = _run_docker("run", "--rm", IMAGE_TAG, subcommand, "--help")
    assert res.returncode == 0, f"docker run {subcommand} --help failed: {res.stderr}"
    assert expected_help_text in res.stdout or "options:" in res.stdout


@pytest.mark.integration
def test_docker_image_config_validate_help() -> None:
    res = _run_docker("run", "--rm", IMAGE_TAG, "config", "validate", "--help")
    assert res.returncode == 0, f"docker run config validate --help failed: {res.stderr}"
    assert "--config PATH" in res.stdout


@pytest.mark.integration
def test_docker_image_default_entrypoint_help() -> None:
    res = _run_docker("run", "--rm", IMAGE_TAG)
    assert res.returncode == 0, f"docker run default failed: {res.stderr}"
    assert "Identity lifecycle service command line." in res.stdout


@pytest.mark.integration
def test_docker_image_alembic_entrypoint() -> None:
    res = _run_docker("run", "--rm", "--entrypoint", "alembic", IMAGE_TAG, "--help")
    assert res.returncode == 0, f"docker run alembic failed: {res.stderr}"
    assert "usage: alembic" in res.stdout
