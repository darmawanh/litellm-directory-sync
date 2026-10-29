"""Group to role, team, and precedence: the access decision

``decide_access`` is a pure function. It takes the ``group_mappings`` entries and
the memberships the caller read, and returns an ``AccessDecision``. It calls no
port, writes nothing, and imports no framework.

Two structural rules are part of the signature:

- **There is no event parameter.** The candidate set is computed from the
  memberships the caller read, never from an event payload (ADR-003 section 1,
  P-002). A duplicate or out-of-order event cannot change the outcome because
  the event is not an input.
- **There is no ``read_complete`` flag.** An incomplete or failed read never
  reaches this function: ADR-003 section 4 makes a failed read a retry, never a
  "no match", and that precondition belongs to the caller (Phase 3). A flag here
  would only let the policy trust a value it cannot check.

A tie returns a ``FAILED`` decision; it does not raise. ADR-003 section 3 makes
the failure a decision result so the caller can write the audit row (decision
``failed``, reason ``equal_precedence``) before it raises ``EqualPrecedenceError``
and makes no gateway call. The raise path needs a gateway and is Phase 3's.

The decision's ``role``, ``team`` and ``precedence`` are the selected result:
they are ``None`` unless the outcome is ``GRANTED``. A failed or not-entitled
decision carries its audit material in ``candidates`` and ``reason``, where each
candidate keeps its own precedence; ``EqualPrecedenceError`` names the shared
precedence of a tie from those candidates.

Readings recorded so a reviewer can check them:

- A candidate must match on `` (source, source_group_id)``, not on the group id
  alone: AD and Okta can use the same string for different groups.
- ``reason`` is a string, not an enum, because design 8's ``AuditEvent.reason``
  is a string and ADR-003 section 5 fixes the two failure values. The grant
  value ``highest_precedence`` is this ticket's choice (its open decision 1).
- Candidates are ordered by descending precedence, then ``source`` and
  ``source_group_id``, so the audit order is stable and the winner is first; no
  input-order tie-break exists.
- ``DecisionOutcome`` values are the audit vocabulary: ADR-003 section 3 writes
  the decision as ``failed``, and section 4 audits a no-match as a decision.

Budget resolution is this module's second half.
``resolve_budget`` takes the four candidates the caller already looked up and
returns the first that exists, in the design's order: the person override, the
group override, the ``budget_mappings`` rule, and the default. The order is
positional, not numeric — the first level present wins whatever its amount — and
the resolution carries that level's own value as its audit ``reason`` (FR7,
FR33).

Two readings recorded so a reviewer can check them:

- ``resolve_budget`` does no lookup: the override table is read through a port
  in Phase 2 and the mapping rule is selected by the config loader, so the
  function receives four resolved candidates and stays pure.
- It takes no ``AccessDecision``, and the decision above carries no ``budget``
  field: a group is an access decision, not a budget value (ADR-003 section 6,
  P-009). ``BudgetPolicy`` does not parse ``budget_duration`` either; the window
  is the gateway's.

Desired access is the module's third part.
``desired_access`` turns a decision plus the person's current state into an
instruction for the gateway: create, update, reactivate, revoke, or leave
alone. It is a pure function over four values the caller already read; it calls
no port, allocates no identifier, and takes no event.

Readings recorded so a reviewer can check them:

- Role and team always come from ``decision``, which carries the selected
  mapping. The old account's values are never
  copied, so a rehire cannot resurrect a stale role.
- ``FAILED`` maps to ``NO_CHANGE``, not ``REVOKE``: a tie blocks the new change
  and leaves existing access alone.
  ``NOT_ENTITLED`` with an existing account maps to ``REVOKE`` (ADR-003
  section 4, design 10.3).
- ``CREATE`` names no ``person_id``: the caller allocates one, so this module
  cannot invent an identity. The other four actions echo the ``person_id`` they
  act on, and a rehire is the proof: ``REACTIVATE`` carries the same id the
  person already had.
- ``REVOKE`` carries ``role=None`` and ``team=None``: the values being revoked
  stay on the ``previous`` argument the caller holds, which is what design
  10.2 step 5 audits as the old access. ``previous`` also names the person
  when the store no longer has the record.
- ``reason`` is ``decision.reason`` on every action, so the audit row's reason
  is the one the decision already fixed; the action
  value is the second half of the vocabulary.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.models import (
    INACTIVE,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceGroup,
)

#: ADR-003 section 5 fixes the two failure reasons. The grant reason is this
#: ticket's choice (its open decision 1); it is an audit-query contract.
REASON_HIGHEST_PRECEDENCE = "highest_precedence"
REASON_EQUAL_PRECEDENCE = "equal_precedence"
REASON_NO_MAPPED_GROUP = "no_mapped_group"


@dataclass(frozen=True)
class GroupMapping:
    """One ``group_mappings`` entry.

    ``source_group_id`` is the AD group DN or the Okta group id, the same value
    ``SourceGroup.source_group_id`` carries. The config spells the two
    sources' keys differently (``group`` and ``group_id``); the Phase 2 loader
    normalizes them, so this type has one spelling.
    """

    source: str
    source_group_id: str
    role: str
    team: str
    precedence: int
    enabled: bool = True


@dataclass(frozen=True)
class Candidate:
    """One mapping the person currently matches, and whether it won.

    Frozen, and holding a frozen ``GroupMapping``, so an audit record cannot be
    changed after the decision was made.
    """

    mapping: GroupMapping
    selected: bool


class DecisionOutcome(StrEnum):
    """The three answers design 10.9 allows, and no fourth."""

    GRANTED = "granted"
    NOT_ENTITLED = "not_entitled"
    FAILED = "failed"


@dataclass(frozen=True)
class AccessDecision:
    """One access decision, with the audit detail ADR-003 section 5 requires.

    ``candidates`` lists every mapping the person currently matches, not only
    the winner: a record that lists only the winner cannot explain a
    denial or a surprise grant. ``decide_access`` orders the tuple
    deterministically, so equal inputs give an equal decision (ADR-003
    Consequences).
    """

    outcome: DecisionOutcome
    selected: GroupMapping | None
    role: str | None
    team: str | None
    precedence: int | None
    reason: str
    candidates: tuple[Candidate, ...]


class EqualPrecedenceError(PermanentError):
    """Two or more mappings share the highest precedence.

    Permanent, not retryable: the configuration will not change between
    attempts. Construct it from the ``FAILED`` decision
    ``decide_access`` returned, which carries the tied candidates; the message
    names the tied precedence so an operator sees it without reading the
    decision.
    """

    def __init__(self, decision: AccessDecision) -> None:
        self.decision = decision
        tied = _tied_precedence(decision)
        detail = f"equal precedence {tied}" if tied is not None else "equal precedence"
        super().__init__(
            f"{detail} at the highest level; the event fails rather than guessing "
            "(ADR-003 section 3)"
        )


def decide_access(
    mappings: Sequence[GroupMapping],
    memberships: Sequence[SourceGroup],
    enabled_sources: frozenset[str],
) -> AccessDecision:
    """Return the access decision for one person's current memberships.

    ``enabled_sources`` is the caller's set of enabled source names: a
    mapping from a source outside it is not a candidate. ``memberships`` is the
    complete, successfully read membership set; an incomplete read is the
    caller's error to retry, never this function's input.
    """
    held = {(group.source, group.source_group_id) for group in memberships}
    candidates = sorted(
        (
            mapping
            for mapping in mappings
            if mapping.enabled
            and mapping.source in enabled_sources
            and (mapping.source, mapping.source_group_id) in held
        ),
        key=_candidate_order,
    )
    if not candidates:
        return _not_entitled()
    highest = max(mapping.precedence for mapping in candidates)
    winners = [mapping for mapping in candidates if mapping.precedence == highest]
    if len(winners) > 1:
        return _failed(candidates)
    return _granted(winners[0], candidates)


def _candidate_order(mapping: GroupMapping) -> tuple[int, str, str]:
    """Sort key: highest precedence first, then the stable source/group pair.

    A deterministic order is what makes the decision independent of input
    order; it is not a tie-break, because a tie never selects anything.
    """
    return (-mapping.precedence, mapping.source, mapping.source_group_id)


def _not_entitled() -> AccessDecision:
    """A complete read with no mapped group: a decision, not an error."""
    return AccessDecision(
        outcome=DecisionOutcome.NOT_ENTITLED,
        selected=None,
        role=None,
        team=None,
        precedence=None,
        reason=REASON_NO_MAPPED_GROUP,
        candidates=(),
    )


def _failed(candidates: list[GroupMapping]) -> AccessDecision:
    """A tie at the highest precedence: every candidate is listed, none selected."""
    return AccessDecision(
        outcome=DecisionOutcome.FAILED,
        selected=None,
        role=None,
        team=None,
        precedence=None,
        reason=REASON_EQUAL_PRECEDENCE,
        candidates=tuple(Candidate(mapping=mapping, selected=False) for mapping in candidates),
    )


def _granted(winner: GroupMapping, candidates: list[GroupMapping]) -> AccessDecision:
    """The highest precedence is unique: apply its role, team, and precedence."""
    return AccessDecision(
        outcome=DecisionOutcome.GRANTED,
        selected=winner,
        role=winner.role,
        team=winner.team,
        precedence=winner.precedence,
        reason=REASON_HIGHEST_PRECEDENCE,
        candidates=tuple(
            Candidate(mapping=mapping, selected=mapping is winner) for mapping in candidates
        ),
    )


def _tied_precedence(decision: AccessDecision) -> int | None:
    """The precedence every tied candidate shares, or ``None`` if there is none.

    ``max`` over an empty sequence raises ``ValueError``, and an error
    constructor that raised an untyped error would break ER7: every failure this
    service raises is a ``DomainError``. The only legal argument is the
    ``FAILED`` decision from ``decide_access``, which always has candidates; a
    decision without any still yields a typed message rather than a ``ValueError``.
    """
    if not decision.candidates:
        return None
    return max(candidate.mapping.precedence for candidate in decision.candidates)


class BudgetSource(StrEnum):
    """The four levels design 10.7 resolves in order, and no fifth.

    The value is the audit vocabulary: it is what ``BudgetResolution.reason``
    carries, so the record names the level that won without a second spelling.
    """

    PERSON_OVERRIDE = "person_override"
    GROUP_OVERRIDE = "group_override"
    CONFIG_MAPPING = "config_mapping"
    DEFAULT = "default"


@dataclass(frozen=True)
class BudgetPolicy:
    """One ``budget_policies`` entry.

        The two fields are the requirement's: ``max_budget`` and
        ``budget_duration``. ``budget_duration`` is stored as written (the example
        spells ``30d``) and never parsed here: the window is the gateway's
    . No validator runs, because the config loader owns the
        startup checks and this dataclass is the type.
    """

    max_budget: float
    budget_duration: str


@dataclass(frozen=True)
class BudgetResolution:
    """The policy that applies, the level it came from, and the audit reason.

    ``reason`` is ``source``'s own value, so the audit row stores the level
    without translating a second name.
    """

    policy: BudgetPolicy
    source: BudgetSource
    reason: str


def resolve_budget(
    *,
    person_override: BudgetPolicy | None,
    group_override: BudgetPolicy | None,
    config_mapping: BudgetPolicy | None,
    default: BudgetPolicy,
) -> BudgetResolution:
    """Return the budget policy design 10.7 selects, in its fixed order.

    The order is positional, not numeric: the person override, then the group
    override, then the ``budget_mappings`` rule, then the default. The first
    level present wins whatever its ``max_budget`` is, so a larger default
    never displaces a smaller mapping. The arguments are keyword-only so the
    two overrides cannot be transposed.

    The caller has already looked the candidates up: the override table is read
    through a port in Phase 2 and the mapping rule is selected by the config
    loader, so this function does no lookup and holds no state. ``default`` is
    required, because a missing default is a startup configuration error, not a
    runtime branch.
    """
    if person_override is not None:
        return _resolved(BudgetSource.PERSON_OVERRIDE, person_override)
    if group_override is not None:
        return _resolved(BudgetSource.GROUP_OVERRIDE, group_override)
    if config_mapping is not None:
        return _resolved(BudgetSource.CONFIG_MAPPING, config_mapping)
    return _resolved(BudgetSource.DEFAULT, default)


def _resolved(source: BudgetSource, policy: BudgetPolicy) -> BudgetResolution:
    """The one shape a resolution takes: the level's own value is its reason."""
    return BudgetResolution(policy=policy, source=source, reason=source.value)


class AccessAction(StrEnum):
    """The five instructions the gateway can receive.

    The value is the audit vocabulary: a Phase 3 row stores it beside the
    decision's ``reason``, so a record says both what was done and why.
    """

    CREATE = "create"
    UPDATE = "update"
    REACTIVATE = "reactivate"
    REVOKE = "revoke"
    NO_CHANGE = "no_change"


@dataclass(frozen=True)
class DesiredAccess:
    """What the gateway should hold after one decision.

    ``role`` and ``team`` are ``None`` unless the action writes them, so a
    ``REVOKE`` or a ``NO_CHANGE`` can never be applied as an update by mistake.
    """

    action: AccessAction
    person_id: str | None
    role: str | None
    team: str | None
    reason: str


def desired_access(
    *,
    decision: AccessDecision,
    person: Person | None,
    account: LiteLLMAccount | None,
    previous: Entitlement | None,
) -> DesiredAccess:
    """Return the gateway instruction one decision implies.

    ``person`` and ``account`` are the caller's fresh reads; ``previous`` is the
    entitlement in force, which the caller audits as the old access. Every
    argument is keyword-only so the three state values cannot be transposed, and
    there is no ``event`` parameter.

    A tie is not a revocation and a leave is not an error: the two outcomes that
    say "nothing is entitled" differ in what they do to an account that already
    exists. A rehire is a grant for an inactive person
    whose account exists, and it reuses that person's ``person_id`` (design
    10.5 step 2).
    """
    if decision.outcome is DecisionOutcome.FAILED:
        return _unchanged(person, previous, decision.reason)
    if decision.outcome is DecisionOutcome.NOT_ENTITLED:
        if account is None:
            return _unchanged(person, previous, decision.reason)
        return _instruction(
            AccessAction.REVOKE,
            _person_id(person, previous),
            None,
            None,
            decision.reason,
        )
    if account is None:
        # The caller allocates the id: this module never invents one.
        return _instruction(
            AccessAction.CREATE,
            None,
            decision.role,
            decision.team,
            decision.reason,
        )
    if person is not None and person.status == INACTIVE:
        return _instruction(
            AccessAction.REACTIVATE,
            person.person_id,
            decision.role,
            decision.team,
            decision.reason,
        )
    if (account.role, account.team) == (decision.role, decision.team):
        return _unchanged(person, previous, decision.reason)
    return _instruction(
        AccessAction.UPDATE,
        _person_id(person, previous),
        decision.role,
        decision.team,
        decision.reason,
    )


def _instruction(
    action: AccessAction,
    person_id: str | None,
    role: str | None,
    team: str | None,
    reason: str,
) -> DesiredAccess:
    """The one shape an instruction takes, so no branch can set a field twice."""
    return DesiredAccess(
        action=action,
        person_id=person_id,
        role=role,
        team=team,
        reason=reason,
    )


def _unchanged(person: Person | None, previous: Entitlement | None, reason: str) -> DesiredAccess:
    """Nothing is written: no role, no team, and the person is still named."""
    return _instruction(AccessAction.NO_CHANGE, _person_id(person, previous), None, None, reason)


def _person_id(person: Person | None, previous: Entitlement | None) -> str | None:
    """The person this instruction is about, from the record or the entitlement.

    A leave can arrive after the person row is gone, and the entitlement in
    force still names who is being revoked.
    """
    if person is not None:
        return person.person_id
    if previous is not None:
        return previous.person_id
    return None
