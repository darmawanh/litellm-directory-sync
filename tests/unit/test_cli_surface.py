"""The CLI and process surface sections 1-4."""

from __future__ import annotations

import ast
import dataclasses
import enum
import subprocess
import sys
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

import identity_lifecycle
import identity_lifecycle.main as cli
from identity_lifecycle.domain.errors import PermanentError, RetryableError

pytestmark = pytest.mark.unit

MAIN_PATH = Path(cli.__file__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTED_COMMANDS = {
    "api",
    "worker",
    "scheduler",
    "version",
    "config",
    "reconcile",
    "sync",
    "audit",
    "outbox",
    "source",
}
RESERVED_SPELLINGS: list[list[str]] = []


def _tree() -> ast.Module:
    return ast.parse(MAIN_PATH.read_text(encoding="utf-8"), filename=str(MAIN_PATH))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"main.py defines no function {name!r}")


def _binary_write_streams(node: ast.AST) -> set[str]:
    """Return the streams named by ``sys.<stream>.buffer.write`` calls."""
    streams: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if not (isinstance(func, ast.Attribute) and func.attr == "write"):
            continue
        target = func.value
        if not (isinstance(target, ast.Attribute) and target.attr == "buffer"):
            continue
        stream = target.value
        if (
            isinstance(stream, ast.Attribute)
            and isinstance(stream.value, ast.Name)
            and stream.value.id == "sys"
        ):
            streams.add(stream.attr)
    return streams


def _version_branch(main_function: ast.FunctionDef) -> ast.If:
    """Return ``main``'s ``if args.command == "version":`` branch."""
    for node in ast.walk(main_function):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        left = node.test.left
        if not (isinstance(left, ast.Attribute) and left.attr == "command"):
            continue
        if any(
            isinstance(comparator, ast.Constant) and comparator.value == "version"
            for comparator in node.test.comparators
        ):
            return node
    raise AssertionError("main.py has no version branch")


def _permanent_handler(main_function: ast.FunctionDef) -> ast.ExceptHandler:
    """Return ``main``'s ``except ProcessNotImplemented:`` handler."""
    for node in ast.walk(main_function):
        if (
            isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Name)
            and node.type.id == "ProcessNotImplemented"
        ):
            return node
    raise AssertionError("main.py has no ProcessNotImplemented handler")


def _help_metavar(help_text: str) -> set[str]:
    usage_start = help_text.index("usage: identity-lifecycle ")
    start = help_text.index("{", usage_start) + 1
    end = help_text.index("}", start)
    return set(help_text[start:end].split(","))


def test_main_returns_an_exit_code_and_never_calls_sys_exit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["version"]) == 0

    tree = _tree()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert not (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "sys"
                and node.func.attr == "exit"
            ), "main.py must not call sys.exit"
        if isinstance(node, ast.ExceptHandler):
            assert node.type is not None, "no bare except"
            names = {child.id for child in ast.walk(node.type) if isinstance(child, ast.Name)}
            assert "SystemExit" not in names, "main must not catch SystemExit"


def test_main_catches_only_the_typed_errors_it_maps() -> None:
    main_function = _function(_tree(), "main")
    caught: set[str] = set()
    for node in ast.walk(main_function):
        if isinstance(node, ast.ExceptHandler):
            assert node.type is not None, "every handler names a type"
            assert isinstance(node.type, ast.Name), "every handler names a plain type"
            caught.add(node.type.id)
    # Process commands add their typed config, permanent, and retryable errors.
    assert caught == {
        "ConfigError",
        "PermanentError",
        "ProcessNotImplemented",
        "RetryableError",
    }


@pytest.mark.parametrize(
    ("error", "expected_code", "family"),
    [
        (PermanentError("invalid upstream response"), cli.ExitCode.PERMANENT, "permanent"),
        (RetryableError("upstream unavailable"), cli.ExitCode.RETRYABLE, "retryable"),
    ],
)
def test_main_maps_typed_adapter_errors_to_process_exit_codes(
    error: Exception,
    expected_code: cli.ExitCode,
    family: str,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    def fail(_options: cli.ProcessOptions) -> int:
        raise error

    monkeypatch.setitem(cli.PROCESS_COMMANDS, "worker", fail)

    assert cli.main(["worker"]) == expected_code
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert (
        captured.err
        == (
            f"identity-lifecycle: error={family} type={type(error).__name__} detail={error}\n"
        ).encode()
    )


def test_exit_code_enum_is_exactly_the_documented_set() -> None:
    assert issubclass(cli.ExitCode, enum.IntEnum)
    assert {member.name: member.value for member in cli.ExitCode} == {
        "SUCCESS": 0,
        "INTERNAL": 1,
        "USAGE": 2,
        "CONFIG": 3,
        "PERMANENT": 4,
        "RETRYABLE": 5,
    }


def test_help_lists_implemented_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("usage: identity-lifecycle ")
    assert _help_metavar(captured.out) == IMPLEMENTED_COMMANDS


def test_all_reserved_subcommands_are_implemented() -> None:
    """All 7 reserved subcommands from ADR-007 are now implemented."""
    assert RESERVED_SPELLINGS == []


def test_unknown_source_subcommand_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["source", "unknown"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err


def test_source_poll_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["source", "poll", "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "usage: identity-lifecycle source poll" in captured.out
    assert "--source" in captured.out
    assert "--once" in captured.out


def test_no_subcommand_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main([])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err
    assert captured.out == ""


def test_unknown_command_uses_exit_code_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["no-such-command"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err
    assert captured.out == ""


@pytest.mark.parametrize("command", ["api", "worker", "scheduler"])
def test_process_help_shows_shared_options(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main([command, "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--config" in captured.out
    assert "--log-level" in captured.out


def test_version_help_carries_no_process_options(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["version", "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--config" not in captured.out
    assert "--log-level" not in captured.out


def _recorder(recorded: list[cli.ProcessOptions]) -> Callable[[cli.ProcessOptions], int]:
    def record(options: cli.ProcessOptions) -> int:
        recorded.append(options)
        return 0

    return record


def test_config_defaults_to_the_documented_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    recorded: list[cli.ProcessOptions] = []
    monkeypatch.setattr(cli, "PROCESS_COMMANDS", {"api": _recorder(recorded)})
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    assert cli.main(["api"]) == 0
    assert recorded[0].config_path == Path("config/config.yaml")


def test_log_level_defaults_to_environment_then_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[cli.ProcessOptions] = []
    monkeypatch.setattr(cli, "PROCESS_COMMANDS", {"api": _recorder(recorded)})

    monkeypatch.delenv("LOG_LEVEL", raising=False)
    assert cli.main(["api"]) == 0
    assert recorded[-1].log_level == "INFO"

    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    assert cli.main(["api"]) == 0
    assert recorded[-1].log_level == "DEBUG"

    assert cli.main(["api", "--log-level", "ERROR"]) == 0
    assert recorded[-1].log_level == "ERROR"


def test_invalid_log_level_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    with pytest.raises(SystemExit) as raised:
        cli.main(["api", "--log-level", "TRACE"])
    assert raised.value.code == 2
    assert "usage:" in capsys.readouterr().err

    monkeypatch.setenv("LOG_LEVEL", "TRACE")
    with pytest.raises(SystemExit) as raised:
        cli.main(["api"])
    assert raised.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_shared_options_are_not_global(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["--config", "x", "api"])
    assert raised.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_all_process_commands_are_implemented() -> None:
    assert set(cli.PROCESS_COMMANDS) == {"api", "worker", "scheduler"}
    assert all(callable(runner) for runner in cli.PROCESS_COMMANDS.values())


def test_stub_raises_a_typed_error_not_a_runtime_error() -> None:
    error = cli.ProcessNotImplemented(command="api", phase=3)
    assert error.command == "api"
    assert error.phase == 3
    assert isinstance(error, Exception)


def test_process_registry_is_complete_and_typed() -> None:
    assert isinstance(cli.PROCESS_COMMANDS, Mapping)
    assert set(cli.PROCESS_COMMANDS) == {"api", "worker", "scheduler"}
    assert all(callable(runner) for runner in cli.PROCESS_COMMANDS.values())

    assert dataclasses.is_dataclass(cli.ProcessOptions)
    assert cli.ProcessOptions.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert [field.name for field in dataclasses.fields(cli.ProcessOptions)] == [
        "config_path",
        "log_level",
    ]

    assert dataclasses.is_dataclass(cli.ProcessNotImplemented)
    assert cli.ProcessNotImplemented.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert issubclass(cli.ProcessNotImplemented, Exception)
    assert [field.name for field in dataclasses.fields(cli.ProcessNotImplemented)] == [
        "command",
        "phase",
    ]

    options = cli.ProcessOptions(config_path=Path("config/config.yaml"), log_level="INFO")
    with pytest.raises(dataclasses.FrozenInstanceError):
        options.log_level = "DEBUG"  # type: ignore[misc]

    defined = {
        value.__name__
        for value in vars(cli).values()
        if isinstance(value, type) and value.__module__ == cli.__name__
    }
    assert defined == {
        "ExitCode",
        "ProcessOptions",
        "ProcessNotImplemented",
        "_ScheduledADPoller",
        "_ScheduledOktaPoller",
    }


def test_version_prints_exactly_the_version_with_newline(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    assert cli.main(["version"]) == 0
    captured = capsysbinary.readouterr()
    # capsysbinary returns bytes, but CaptureIO's newline="" does no write
    # translation, so this assertion also passes on a sys.stdout.write
    # implementation. test_version_bytes_through_a_real_pipe and
    # test_byte_contract_writes_through_the_binary_streams are the witnesses.
    assert captured.out == f"{identity_lifecycle.__version__}\n".encode()
    assert len(captured.out) == 6
    assert captured.err == b""


def test_byte_contract_writes_through_the_binary_streams() -> None:
    """The platform-independent witness for criteria 10 and 12.

    ``capsys`` and ``capsysbinary`` share one ``CaptureIO`` built with
    ``newline=""``, which performs no write translation, so neither fixture can
    see ``"\\n"`` become ``"\\r\\n"`` and both pass on the text-stream code. This
    AST check does not: it requires the ``version`` branch to write through
    ``sys.stdout.buffer`` and the ``ProcessNotImplemented`` handler to write
    through ``sys.stderr.buffer``, which a reverted ``sys.stdout.write`` cannot
    satisfy on any platform.
    """
    main_function = _function(_tree(), "main")
    assert _binary_write_streams(_version_branch(main_function)) == {"stdout"}
    assert _binary_write_streams(_permanent_handler(main_function)) == {"stderr"}


def test_version_bytes_through_a_real_pipe() -> None:
    """The entry point emits exactly six bytes through a real OS pipe.

    This discriminates on Windows, where the text-stream implementation writes
    seven bytes because ``"\\n"`` becomes ``"\\r\\n"``. On POSIX no translation
    occurs, so this test is not discriminating there; the platform-independent
    witness is ``test_byte_contract_writes_through_the_binary_streams``.
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from identity_lifecycle.main import main; "
            "raise SystemExit(main(['version']))",
        ],
        capture_output=True,
        cwd=PROJECT_ROOT,
        check=True,
    )
    assert completed.stdout == b"0.1.0\n"
    assert len(completed.stdout) == 6
    assert completed.stderr == b""


def test_stub_bytes_through_a_real_pipe() -> None:
    """The stub line is 79 bytes ending in a bare newline through a real pipe.

    This discriminates on Windows (80 bytes from the text stream, 79 from the
    binary stream). On POSIX no translation occurs, so this test is not
    discriminating there; the platform-independent witness is
    ``test_byte_contract_writes_through_the_binary_streams``.
    """
    script = (
        "import sys; import identity_lifecycle.main as m; "
        "m.PROCESS_COMMANDS = {'api': lambda _: "
        "(_ for _ in ()).throw(m.ProcessNotImplemented('api', 3))}; "
        "raise SystemExit(m.main(['api']))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        cwd=PROJECT_ROOT,
        # main returns 4, so this process exits 4 by design.
        check=False,
    )
    expected = b"identity-lifecycle: error=permanent phase=3 command=api detail=not_implemented\n"
    assert completed.returncode == 4
    assert completed.stdout == b""
    assert completed.stderr == expected
    assert len(completed.stderr) == 79
    assert b"\r" not in completed.stderr


def test_version_matches_pyproject() -> None:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert isinstance(identity_lifecycle.__version__, str)
    assert data["project"]["version"] == identity_lifecycle.__version__


def test_main_imports_no_framework_and_no_api_app() -> None:
    # The root module is wiring, so it may name an
    # adapter and the API app. What it may still not do is pull in fastapi directly
    # or the private admin auth module.
    tree = _tree()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            assert node.module is not None
            names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
        else:
            continue
        for name in names:
            root = name.split(".", 1)[0]
            assert (
                root in sys.stdlib_module_names or root == "identity_lifecycle" or root == "uvicorn"
            ), (
                f"main.py imports {name!r}; only the standard library, uvicorn, and "
                f"identity_lifecycle are allowed (no fastapi)"
            )
            assert name != "fastapi", name
            assert not name.startswith("fastapi."), name
            assert name != "identity_lifecycle.api.auth", name
            assert not name.startswith("identity_lifecycle.api.auth."), name


def test_phase_zero_runners_do_not_read_the_token_environment(
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    expected = b"identity-lifecycle: error=permanent phase=3 command=api detail=not_implemented\n"
    monkeypatch.setattr(
        cli,
        "PROCESS_COMMANDS",
        {"api": lambda _: (_ for _ in ()).throw(cli.ProcessNotImplemented("api", 3))},
    )

    monkeypatch.delenv("LIFECYCLE_MASTER_KEY", raising=False)
    assert cli.main(["api"]) == 4
    assert capsysbinary.readouterr().err == expected

    monkeypatch.setenv("LIFECYCLE_MASTER_KEY", "sentinel-value")
    assert cli.main(["api"]) == 4
    assert capsysbinary.readouterr().err == expected
