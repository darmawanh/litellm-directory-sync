"""Evidence tests for the T-007 AD spike: ``objectGUID`` and fixture hygiene.

These tests use only hand-built fixtures. They never open a socket, never bind
to a directory, and never write anywhere.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.ad import ldap_responses
from tests.fixtures.ad.objectguid import MalformedObjectGuid, objectguid_to_uuid
from tests.fixtures.ad.objectguid_samples import SAMPLES, ObjectGuidSample

SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
FIXTURES_MODULE = "tests.fixtures"


def _attributes(entry: dict[str, Any]) -> dict[str, list[Any]]:
    attributes = entry["attributes"]
    assert isinstance(attributes, dict)
    return attributes


def _raw(entry: dict[str, Any]) -> dict[str, list[bytes]]:
    raw = entry["raw_attributes"]
    assert isinstance(raw, dict)
    return raw


def _entries(response: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in response if entry["type"] == "searchResEntry"]


def _is_fixtures_module(module: str) -> bool:
    return module == FIXTURES_MODULE or module.startswith(f"{FIXTURES_MODULE}.")


def _tests_fixture_imports(path: Path) -> list[tuple[Path, int]]:
    """Return every ``tests.fixtures`` import in one module, with line numbers."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[Path, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            _is_fixtures_module(alias.name) for alias in node.names
        ):
            hits.append((path, node.lineno))
        if (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and _is_fixtures_module(node.module)
        ):
            hits.append((path, node.lineno))
    return hits


@pytest.mark.unit
@pytest.mark.parametrize("sample", SAMPLES, ids=[sample.name for sample in SAMPLES])
def test_binary_objectguid_converts_to_canonical_uuid(sample: ObjectGuidSample) -> None:
    assert str(objectguid_to_uuid(sample.raw)) == sample.expected


@pytest.mark.unit
def test_binary_objectguid_conversion_matches_the_bytes_le_layout() -> None:
    # Guard against a converter that happens to agree on one sample: the first
    # three fields must be byte-swapped relative to a big-endian reading.
    raw = bytes.fromhex("4a3b2c1d5e6f47a8b9c0d1e2f3a4b5c6")

    assert str(objectguid_to_uuid(raw)) == "1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6"
    assert str(objectguid_to_uuid(raw)) != "4a3b2c1d-5e6f-47a8-b9c0-d1e2f3a4b5c6"


@pytest.mark.unit
@pytest.mark.parametrize("length", [0, 15, 17], ids=["empty", "short", "long"])
def test_short_or_malformed_objectguid_raises_malformed_object_guid(length: int) -> None:
    with pytest.raises(MalformedObjectGuid) as excinfo:
        objectguid_to_uuid(b"\x00" * length)

    assert str(length) in str(excinfo.value)


@pytest.mark.unit
def test_non_bytes_objectguid_raises_malformed_object_guid() -> None:
    with pytest.raises(MalformedObjectGuid):
        objectguid_to_uuid("4a3b2c1d5e6f47a8b9c0d1e2f3a4b5c6")  # type: ignore[arg-type]


@pytest.mark.unit
def test_fixtures_are_not_importable_from_src() -> None:
    modules = sorted(SRC_ROOT.rglob("*.py"))

    assert modules, f"expected production modules under {SRC_ROOT}"

    violations = [hit for module in modules for hit in _tests_fixture_imports(module)]

    assert not violations, "src/ imports test fixtures at " + ", ".join(
        f"{path}:{line}" for path, line in violations
    )


@pytest.mark.unit
def test_fixture_import_check_detects_a_known_violation(tmp_path: Path) -> None:
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from tests.fixtures.ad.objectguid import objectguid_to_uuid\n",
        encoding="utf-8",
    )

    assert _tests_fixture_imports(planted) == [(planted, 1)]


@pytest.mark.unit
def test_fixture_import_check_ignores_unrelated_imports(tmp_path: Path) -> None:
    planted = tmp_path / "clean.py"
    planted.write_text(
        "import uuid\nfrom identity_lifecycle import __version__\n",
        encoding="utf-8",
    )

    assert _tests_fixture_imports(planted) == []


@pytest.mark.unit
def test_group_fixture_keeps_objectguid_binary_and_member_dns() -> None:
    group = ldap_responses.group_entry()
    attributes = _attributes(group)

    assert group["type"] == "searchResEntry"
    assert isinstance(_raw(group)["objectGUID"][0], bytes)
    assert attributes["objectGUID"] == [ldap_responses.GROUP_GUID]
    assert all(
        isinstance(member, str) and member.startswith("CN=") for member in attributes["member"]
    )
    assert ldap_responses.ALICE_DN in attributes["member"]


@pytest.mark.unit
def test_usn_fixture_carries_the_attributes_the_cursor_needs() -> None:
    entries = _entries(ldap_responses.usn_search_response())

    assert entries
    assert entries[0]["dn"] == ldap_responses.GROUP_DN
    for entry in entries:
        assert _attributes(entry)["uSNChanged"]
        assert _attributes(entry)["whenChanged"]
        assert isinstance(_raw(entry)["objectGUID"][0], bytes)
    users = [entry for entry in entries if entry["dn"] != ldap_responses.GROUP_DN]
    assert users
    for entry in users:
        assert _attributes(entry)["userAccountControl"]


@pytest.mark.unit
def test_usn_changed_must_be_parsed_as_an_integer() -> None:
    # uSNChanged is a counter, not a string: "9999" > "10000" lexicographically
    # would move the cursor backwards and silently skip every later change.
    before = ldap_responses.USN_BEFORE.decode()
    after = ldap_responses.USN_AFTER.decode()

    assert before > after, "the fixture must demonstrate the lexicographic trap"
    assert int(before) < int(after), "as integers the cursor moves forward"


@pytest.mark.unit
def test_membership_removal_changes_the_group_entry_not_the_user_entry() -> None:
    before = ldap_responses.group_entry()
    after = ldap_responses.group_entry_after_removal()
    bob = ldap_responses.bob_entry()

    assert ldap_responses.BOB_DN in _attributes(before)["member"]
    assert ldap_responses.BOB_DN not in _attributes(after)["member"]
    assert int(_attributes(after)["uSNChanged"][0]) > int(_attributes(before)["uSNChanged"][0])
    assert _raw(after)["uSNChanged"] != _raw(bob)["uSNChanged"]
    assert _raw(bob)["uSNChanged"] == [b"19035"]


@pytest.mark.unit
def test_usn_poll_after_removal_returns_only_the_group_entry() -> None:
    entries = _entries(ldap_responses.usn_search_response_after_removal())

    assert [entry["dn"] for entry in entries] == [ldap_responses.GROUP_DN]


@pytest.mark.unit
def test_identity_fixture_shows_missing_and_duplicated_employee_id() -> None:
    entries = _entries(ldap_responses.member_search_response())
    employee_ids = [
        _attributes(entry)["employeeID"][0]
        for entry in entries
        if "employeeID" in _attributes(entry)
    ]

    assert len(employee_ids) != len(entries), "fixture must include a missing employeeID"
    assert len(employee_ids) != len(set(employee_ids)), "fixture must include a duplicate"


@pytest.mark.unit
def test_disabled_account_fixture_uses_accountdisable_bit() -> None:
    disabled = _attributes(ldap_responses.dave_entry())["userAccountControl"][0]

    assert int(disabled) & 0x0002, "ACCOUNTDISABLE (0x0002) must be set for the disabled sample"


@pytest.mark.unit
def test_paged_fixture_exposes_a_paging_cookie() -> None:
    response = ldap_responses.paged_search_response()
    done = response[-1]

    assert done["type"] == "searchResDone"
    assert "1.2.840.113556.1.4.319" in done["controls"]


@pytest.mark.unit
def test_fixtures_are_data_only_and_never_open_a_connection() -> None:
    fixture_root = Path(ldap_responses.__file__).resolve().parent
    forbidden = {"ldap3", "socket", "ssl", "http", "httpx", "requests", "urllib"}

    offenders: list[str] = []
    for module in sorted(fixture_root.glob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                names = [node.module.split(".")[0]]
            offenders.extend(
                f"{module.name}:{node.lineno} imports {name}" for name in names if name in forbidden
            )

    assert not offenders, "fixtures must not import a transport: " + "; ".join(offenders)
