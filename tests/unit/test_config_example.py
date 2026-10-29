"""The example configuration exists, is readable, and carries no secret or company identity.

No YAML parser is declared in Phase 0, so these tests read the file as
plain text. ADR-010 limits Phase 0 to claims a line scan proves totally: existence and UTF-8,
the required section labels, credential and connection references, and the absence of named
retired labels. Structure -- how many source items there are, which block sits under which
parent, which keys a block carries -- is not visible in a line's text and is deliberately not
claimed here. Those claims belong to the Phase 2/3 loader's tests, which use the parser that
reads the file.

`test_yaml_uses_only_bare_keys_and_sequence_scalars` is the precondition that makes the other
claims total: every non-blank, non-comment line is a bare-key line or a bare sequence scalar,
and every value the scan reads is visible on that one line. A construct the scan cannot see --
a quoted key, a block scalar, a flow collection, an alias, a tag, a document marker -- is
refused rather than guessed at, because a construct the scan skips is a construct a loader
honours.

The precondition has two predicates, and neither alone is sufficient. First, a
credential-named key must carry a non-empty value on its own line. Second, a valued line -- a
key line with a non-empty value, or a sequence item with a scalar -- must not be followed by a
more-indented significant line, because a YAML plain scalar continues onto one. The first
misses `bind_password: os.environ/X` followed by `- sk-live-SECRET`; the second misses a bare
`master_key:` with an indented child.

The credential match is case-insensitive: `_is_credential_key` folds the key to lower case
before both the `CREDENTIAL_KEYS` membership test and the `CREDENTIAL_NAME_PARTS` parts test,
and the `NON_SECRET_KEYS` exclusion is folded the same way. A YAML key's case is not a security
property -- a loader does not care whether the example spells `api_token` or `API_TOKEN` -- so a
case-sensitive matcher would reopen the round-8 hole with one capital letter (`API_TOKEN:
hunter2` under a real `api_token` was green before this fold).

Residual: predicate 2 rejects a *more*-indented continuation only, so it covers every unquoted
plain value, whether it hangs off a key or a sequence item, except a continuation at the value's
own column. Two shapes are therefore outside the predicate. First, a double-quoted scalar may
continue at the key's own indent; the closing quote is part of the forged construct, so a
document can hold `schedule: "0 * * * *` followed by `dry_run: true"` even though the shipped
file spells `dry_run: true` unquoted. Second, an unquoted scalar followed by a same-column `- `
line is not rejected by the shape test either; a loader rejects that document (`- ` lands in a
mapping), so no literal reaches a loader as the key's value and the credential claim is
unaffected. The credential and connection claims stay total for both shapes because a value that
begins with a quote, or a key whose same-column child does not parse, cannot present a literal to
a loader as the credential value. What the shape test does not make total is the one-line claim
over *non-credential* values in these two shapes, and that is stated here rather than implied.
"""

from __future__ import annotations

import re
from itertools import pairwise
from pathlib import Path

import pytest

EXAMPLE_PATH = Path(__file__).resolve().parents[2] / "config" / "config.example.yaml"

REQUIRED_SECTIONS = (
    "general_settings",
    "identity_sources",
    "group_mappings",
    "teams",
    "budget_policies",
    "budget_mappings",
    "gateway",
    "event_bus",
    "reconciliation",
    "rate_limits",
)

# Keys ADR-006 replaces. Named once so the assertion and its message cannot drift.
RETIRED_OKTA_KEYS = frozenset({"fallback_poll_seconds"})

# Every one of these must be an `os.environ/VAR` reference in the example.
CREDENTIAL_KEYS = (
    "bind_password",
    "api_key",
    "key_id",
    "private_key_path",
)

# Labels needed by the currently shipped System Log config and accepted config examples,
# checked for presence anywhere. Placement stays the loader's claim.
ADR_NAMED_LABELS = (
    "system_log",
    "retention_seconds",
    "queries_per_second",
    "concurrency",
)

# A credential is recognised by any of these name parts, not only by a suffix:
# `shared_secret_previous` is a credential whose name does not end in `_secret`. The match is
# case-insensitive (`_is_credential_key` folds first): `API_TOKEN` and `SHARED_SECRET` are the
# same credential to a loader, so the matcher must not depend on the example's capitalisation.
CREDENTIAL_NAME_PARTS = ("password", "secret", "token", "key")
# Keys whose names contain a credential part but are not credentials. Also folded, so the
# exclusion cannot be bypassed by case.
NON_SECRET_KEYS = frozenset({"cross_system_key"})

# Connection details that must never carry a real host or tenant.
CONNECTION_KEYS = ("org_url", "server", "base_url", "bind_dn")

# A bare-key line: `key:` or `key: value`, optionally the first field of a sequence item
# (`- key: value`). The colon must be followed by whitespace or end the line; `key:value` is
# a plain scalar to a loader, not a key, so it does not match and is rejected as such. The
# key charset includes `-` because `teams` uses hyphenated names. A quoted key does not
# match this pattern, which is what makes it visible to the line-shape test.
KEY_LINE = re.compile(
    r"^(?P<indent>[ ]*)(?P<dash>-\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<rest>(?:\s.*)?)$"
)
# A trailing comment is introduced by whitespace then `#`. `abc#def` is a literal in YAML,
# so the whitespace is part of the pattern.
TRAILING_COMMENT = re.compile(r"[ \t]+#.*$")
# A bare sequence scalar: `- mail`, `- 203.0.113.0/24`. `indent` is the dash's column, which
# is the item's column: a sibling `- ` starts there, and a deeper line continues the scalar.
BARE_SEQUENCE_SCALAR = re.compile(r"^(?P<indent>[ ]*)-[ ]+(?P<scalar>\S.*)$")
# A quoted key: a quote in key position followed by the mapping colon.
QUOTED_KEY = re.compile(r"""^[ ]*(?:-\s+)?["'][^"']*["']\s*:""")
# A YAML document marker, which separates documents rather than adding a value.
DOCUMENT_MARKER = re.compile(r"^(?:---|\.\.\.)(?:\s|$)")
ENV_REFERENCE = re.compile(r"^os\.environ/[A-Z][A-Z0-9_]*$")

# A value that begins with one of these is a block scalar, a flow collection, an anchor, an
# alias, or a tag. None of them is visible on the key line, so the scan cannot verify it.
FORBIDDEN_VALUE_PREFIXES = ("|", ">", "{", "[", "&", "*", "!")


def _text() -> str:
    return EXAMPLE_PATH.read_text(encoding="utf-8")


def _value(raw: str) -> str:
    """Strip a whitespace-preceded trailing comment, then surrounding whitespace."""
    return TRAILING_COMMENT.sub("", raw).strip()


def _assignments() -> list[tuple[str, str]]:
    """Return (key, value) for every `key: value` line, in file order."""
    pairs: list[tuple[str, str]] = []
    for line in _text().splitlines():
        match = KEY_LINE.match(line)
        if match is not None:
            pairs.append((match.group("key"), _value(match.group("rest"))))
    return pairs


def _is_credential_key(key: str) -> bool:
    """True when the key names a credential, whatever its capitalisation.

    The fold is deliberate: a YAML key's case is not a security property, and a case-sensitive
    matcher lets `API_TOKEN: hunter2` sit beside the real `api_token` while the scan stays
    green, which is the round-8 fail-open with one capital letter.
    """
    lowered = key.lower()
    if lowered in NON_SECRET_KEYS:
        return False
    return lowered in CREDENTIAL_KEYS or any(part in lowered for part in CREDENTIAL_NAME_PARTS)


def _significant_lines() -> list[tuple[int, int]]:
    """Return (lineno, indent) for every non-blank, non-comment line."""
    lines: list[tuple[int, int]] = []
    for lineno, line in enumerate(_text().splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        lines.append((lineno, len(line) - len(line.lstrip())))
    return lines


def _top_level_labels() -> set[str]:
    """Return keys that sit at indent zero and are not a sequence item's first field."""
    labels: set[str] = set()
    for line in _text().splitlines():
        match = KEY_LINE.match(line)
        if match is None:
            continue
        if match.group("indent") or match.group("dash"):
            continue
        labels.add(match.group("key"))
    return labels


def _continuation_offender(
    lineno: int,
    column: int,
    following: int | None,
    subject: str,
) -> str | None:
    """Return a message when `following` is indented past `column`, so `subject` continues.

       A YAML plain scalar continues onto any line more indented than the value's own column, so
       the value on `subject` would not be the value the scan read. `column` is the key's column
    (its indent) for a mapping value and the dash's column for a sequence item. A line
       *exactly* at that column is not a deeper continuation, so this predicate does not fire: for
       a scalar item it starts a sibling, and for a valued key a same-column `- ` line is a
       document a loader rejects rather than a value it reads (both measured with a loader).
    """
    if following is None or following <= column:
        return None
    return (
        f"line {lineno}: {subject} carries a value and the next significant line is indented "
        f"{following}, deeper than its column {column}; a plain scalar would continue onto it"
    )


@pytest.mark.unit
def test_example_config_exists() -> None:
    assert EXAMPLE_PATH.is_file(), f"missing example configuration: {EXAMPLE_PATH}"
    # existence and UTF-8 are the two file-level claims. Reading with an explicit
    # encoding makes a non-UTF-8 file a failure here rather than a later decode error.
    _text()


@pytest.mark.unit
def test_yaml_uses_only_bare_keys_and_sequence_scalars() -> None:
    """Refuse any line whose value the scan cannot read from that line.

    Every other test in this module reasons about a line scan, so the scan must be total over
    the file. A construct it skips is a construct a loader honours and the guard does not:
    `okta: |` makes `okta` a string, `"okta": {...}` is a second key that overrides the first,
    `!!seq` changes the node's type, and a continuation line appends to the value the scan
    just approved.

    The rules: every non-blank, non-comment line is a bare-key line (optionally `- `
    prefixed) or a bare sequence scalar; a value may not begin with `|`, `>`, `{`, `[`,
    `&`, `*`, or `!`; a sequence scalar may not contain `{`, `[`, or `: `; there are no
    quoted keys, no `---`/`...` markers, and no tab indentation.

    Two further predicates close the two holes a line scan has for an unquoted value, and
    neither alone is sufficient:

    1. A credential-named key must carry a non-empty value on its own line. A bare
       `master_key:` plus an indented `value: hunter2` child is a literal secret the
       credential scan never sees, because it records the key with an empty value.
       `shared_secret_previous` is not exempt: the example is documentation of the
       recommended shape and always ships a reference. ADR-006 §3's blank-previous-secret
       rotation state is a schema concern for the Phase 2/3 loader, not a Phase 0 text
       claim; restoring an empty-value exemption reopens this hole.
    2. A line that carries an unquoted scalar value must not be followed by a significant
       line deeper than that value's column. The column is the key's (the indent, plus two
       when the line starts with `- `) for a mapping value, and the sequence's column for a
       `- ` scalar item. A YAML plain scalar continues onto any more-indented line, so
       `bind_password: os.environ/AD_BIND_PASSWORD` followed by `- sk-live-SECRET` makes one
       string that still passes predicate 1, and `- 203.0.113.0/24` followed by a deeper
       `- sk-live-SECRET` does the same to a `ip_allowlist` item. This predicate is
       independent of the key's name: a continuation is a property of the value. A sibling
       at the same column is a new node, not a continuation, so an ordinary list or the
       `identity_sources` sequence stays green.

    Residual, stated rather than implied: predicate 2 rejects a *more*-indented continuation
    only. A quoted scalar opened on a value line may continue at the key's own indent, and an
    unquoted scalar followed by a same-column `- ` line is also not rejected -- but a loader
    rejects the second document (`- ` lands in a mapping), so it cannot carry a credential
    value to a loader. The credential and connection scans stay total because `ENV_REFERENCE`
    is anchored and neither shape presents a matching value to a loader.

    `[]` is permitted only for `trusted_proxies`: ADR-006 §6 pins that value, and an empty
    flow sequence carries no hidden structure. For any other key `[]` empties a block the
    scan cannot see (`event_bus: []` removes the outbox; `ip_allowlist: []` is a startup
    failure), so it is an offender.
    """
    offenders: list[str] = []

    significant = _significant_lines()
    next_significant: dict[int, int] = {
        lineno: following_indent for (lineno, _), (_, following_indent) in pairwise(significant)
    }

    for lineno, line in enumerate(_text().splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        leading = line[: len(line) - len(line.lstrip())]
        if "\t" in leading:
            offenders.append(f"line {lineno}: tab indentation is outside the subset")
            continue

        stripped = line.strip()
        if DOCUMENT_MARKER.match(stripped):
            offenders.append(f"line {lineno}: document marker {stripped!r} is not allowed")
            continue

        match = KEY_LINE.match(line)
        if match is not None:
            key = match.group("key")
            value = _value(match.group("rest"))
            if (
                value
                and not (value == "[]" and key == "trusted_proxies")
                and value.startswith(FORBIDDEN_VALUE_PREFIXES)
            ):
                offenders.append(
                    f"line {lineno}: `{key}:` carries {value!r}, whose first "
                    f"character hides a block scalar, flow collection, anchor, alias, or tag"
                )
            if _is_credential_key(key) and not value:
                offenders.append(
                    f"line {lineno}: credential key `{key}` carries no value on its line; a "
                    f"child or a later line could hold a literal the scan never sees"
                )
            if value:
                effective = len(match.group("indent")) + (2 if match.group("dash") else 0)
                message = _continuation_offender(
                    lineno, effective, next_significant.get(lineno), f"`{key}:`"
                )
                if message is not None:
                    offenders.append(message)
            continue

        if QUOTED_KEY.match(line):
            offenders.append(
                f"line {lineno}: quoted key {stripped!r} is invisible to the scan and would "
                f"override the bare key it duplicates"
            )
            continue

        scalar_match = BARE_SEQUENCE_SCALAR.match(line)
        if scalar_match is not None:
            scalar = _value(scalar_match.group("scalar"))
            if scalar.startswith(FORBIDDEN_VALUE_PREFIXES):
                offenders.append(
                    f"line {lineno}: sequence scalar {scalar!r} begins with a block or flow "
                    f"indicator"
                )
            elif "{" in scalar or "[" in scalar or ": " in scalar:
                offenders.append(
                    f"line {lineno}: sequence scalar {scalar!r} contains `{{`, `[`, or `: ` "
                    f"and may be a collection or a mapping"
                )
            message = _continuation_offender(
                lineno,
                len(scalar_match.group("indent")),
                next_significant.get(lineno),
                f"sequence scalar {scalar!r}",
            )
            if message is not None:
                offenders.append(message)
            continue

        offenders.append(
            f"line {lineno}: {stripped!r} is neither a bare-key line nor a bare sequence " f"scalar"
        )

    assert offenders == [], "the example uses YAML this scan cannot verify:\n" + "\n".join(
        offenders
    )


@pytest.mark.unit
def test_required_sections_present() -> None:
    """The ten required section labels appear at top level; the ADR-named labels appear.

       Top level means indent zero and not a sequence item. A label nested under another key,
       or a key inside `- ` item, is not the section: `teams:` moved under a new `meta:` key
       still leaves the label text in the file, but no longer names a top-level section. This
       enforces ADR-010 §1's existing "top-level labels" wording from the line text; it adds no
       structural claim.

       The ADR-named labels are a separate presence claim, anywhere in the file, because
       `event_hook`, `retention_seconds`, and `queries_per_second` live
       inside blocks. Presence is what makes those keys mutation-provable in Phase 0; their
       placement stays a Phase 2/3 loader claim.

       This is a label claim, not a structural one. It does not prove uniqueness: a second
       `event_bus:` is two well-formed key lines and is indistinguishable to a line scan
    ("What a text scan can and cannot prove").
    """
    top_level = _top_level_labels()
    missing = sorted(set(REQUIRED_SECTIONS) - top_level)

    assert missing == [], f"required top-level section labels are missing: {missing}"

    labels = {key for key, _ in _assignments()}
    absent = sorted(set(ADR_NAMED_LABELS) - labels)

    assert absent == [], f"labels an accepted ADR names are missing: {absent}"


@pytest.mark.unit
def test_retired_okta_keys_absent() -> None:
    labels = {key for key, _ in _assignments()}
    retired = sorted(RETIRED_OKTA_KEYS & labels)

    assert retired == [], f"keys ADR-006 replaces are still present: {retired}"


@pytest.mark.unit
def test_system_log_budget_has_no_second_home() -> None:
    """The retired rate-limit labels are absent; nothing more is claimed here.

    ADR-009 §1 gives the System Log budget one home, `okta.system_log`. Only the negative
    label claim is made: `okta_system_log` and `system_log_requests_per_second` do not appear.
    The positive claim -- that `requests_per_second: 2` and `burst: 4` sit under
    `okta.system_log` -- is placement, which a line scan cannot prove; ADR-010 §3 moves it
    and the other pinned values to the Phase 2/3 loader tests.
    """
    labels = {key for key, _ in _assignments()}

    for retired in ("okta_system_log", "system_log_requests_per_second"):
        assert retired not in labels, (
            f"`{retired}` is retired by ADR-009; the System Log budget is "
            f"`okta.system_log.requests_per_second` and `.burst`"
        )


@pytest.mark.unit
def test_secret_keys_are_references_not_values() -> None:
    """Each credential key is an exact `os.environ/VAR` reference.

    The pattern is anchored: `.startswith ("os.environ/")` accepts a reference followed by
    attacker-controlled text, which a loader reads as one literal string. A quoted value does
    not match the anchored pattern either, so a quote cannot smuggle a continuation.
    """
    values = dict(_assignments())

    for key in CREDENTIAL_KEYS:
        assert key in values, f"{key} is not set in the example"
        assert ENV_REFERENCE.match(
            values[key]
        ), f"{key} must be an os.environ/VAR reference, found {values[key]!r}"


@pytest.mark.unit
def test_no_literal_secret_values() -> None:
    """No credential-named key carries a value that is not an `os.environ/VAR` reference.

    An empty value is skipped here because the line-shape precondition already rejects it
    for a credential key: the blank-rotation allowance for `shared_secret_previous` is a
    schema concern, not a property of the example, which always ships a
    reference. Do not restore an empty-value exemption in this test; that reopens the
    round-8 hole where a bare `master_key:` plus an indented child read as a literal.
    """
    offenders = [
        (key, value)
        for key, value in _assignments()
        if _is_credential_key(key) and value and not ENV_REFERENCE.match(value)
    ]

    assert offenders == [], f"literal credential values in the example: {offenders}"


@pytest.mark.unit
def test_no_default_hosts_or_tenants() -> None:
    present = {key for key, _ in _assignments()}
    absent = [key for key in CONNECTION_KEYS if key not in present]

    # A scan over keys that are not there proves nothing. Fail instead of passing empty.
    assert (
        absent == []
    ), f"connection keys missing from the example, so the scan is vacuous: {absent}"

    offenders = [
        (key, value)
        for key, value in _assignments()
        if key in CONNECTION_KEYS and not ENV_REFERENCE.match(value)
    ]

    assert offenders == [], f"connection details must be os.environ/VAR references: {offenders}"
