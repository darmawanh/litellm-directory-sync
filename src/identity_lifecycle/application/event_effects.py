"""How one access decision becomes a gateway call and an audit row.

The second half of ``process_event``: given values the use case has already read
and a decision ``domain/policy.py`` already made, apply the instruction through
the ``Gateway`` and build the records the transaction writes. Nothing here opens
a unit of work, reads a repository, or knows which adapter it holds — the split
is "resolve and decide" (the use case) versus "apply and record" (this module),
so neither file grows past design 15.3's size guidance.

Two rules are carried in the code rather than in a comment beside it:

- **The returned account is the gateway's read-back.** ``apply_access`` returns
  what the port returned and never the arguments it was given (ADR-004 section 3,
  ADR-019 section 3, P-013). A caller that stored its own arguments would record
  a change the gateway did not make.
- **Role and team come from the decision, never from the old account.** A rehire
  cannot resurrect a stale role.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import AuditEvent, LiteLLMAccount, Person
from identity_lifecycle.domain.policy import (
    AccessAction,
    AccessDecision,
    BudgetPolicy,
    DesiredAccess,
    resolve_budget,
)
from identity_lifecycle.ports.gateway import Gateway

#: The audit ``decision`` value for ADR-018 section 1's ambiguity. It is not one
#: of the three ``DecisionOutcome`` values: the decision itself may be a grant,
#: and the ambiguity is a second fact recorded beside it.
DECISION_AMBIGUOUS_LINK = "ambiguous_link"
REASON_AMBIGUOUS_LINK = "employee_link_ambiguous"


def apply_access(
    *,
    gateway: Gateway,
    desired: DesiredAccess,
    person: Person,
    account: LiteLLMAccount | None,
    budget: BudgetPolicy,
    team_create_if_missing: Mapping[str, bool],
) -> LiteLLMAccount | None:
    """Apply one instruction and return the account the gateway read back.

    ``NO_CHANGE`` makes no call and returns the account the caller already read,
    so a decision that changes nothing cannot be recorded as a write. A
    ``REVOKE`` removes the membership first, then blocks every key: design 10.8
    step 5's order, and blocking is the revocation mechanism.
    """
    if desired.action is AccessAction.NO_CHANGE:
        return account
    if desired.action is AccessAction.CREATE:
        return gateway.create_user(
            user_id=person.person_id,
            email=person.email,
            display_name=person.display_name,
            role=required(desired.role, "role", desired),
            team_id=_team(gateway, required(desired.team, "team", desired), team_create_if_missing),
            budget=budget,
        )
    if desired.action in (AccessAction.UPDATE, AccessAction.REACTIVATE):
        return gateway.update_user(
            user_id=person.person_id,
            role=required(desired.role, "role", desired),
            team_id=_team(gateway, required(desired.team, "team", desired), team_create_if_missing),
            budget=budget,
        )
    if account is not None and account.team:
        gateway.remove_from_team(user_id=person.person_id, team_id=account.team)
    return gateway.revoke_keys(user_id=person.person_id)


def budget_for(
    decision: AccessDecision,
    *,
    group_budget_policies: Mapping[tuple[str, str], str],
    budget_policies: Mapping[str, BudgetPolicy],
    default_policy_name: str,
) -> BudgetPolicy:
    """Resolve the policy's order, as far as this phase reads it.

    The person and group override tables are a later phase, so both overrides are
    ``None`` here; the group's ``budget_mappings`` rule and the default are read.
    """
    return resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=_mapped_policy(decision, group_budget_policies, budget_policies),
        default=budget_policies[default_policy_name],
    ).policy


def policy_name(
    decision: AccessDecision,
    *,
    group_budget_policies: Mapping[tuple[str, str], str],
    default_policy_name: str,
) -> str:
    """The ``budget_policies`` key the entitlement records."""
    if decision.selected is not None:
        name = group_budget_policies.get(
            (decision.selected.source, decision.selected.source_group_id)
        )
        if name is not None:
            return name
    return default_policy_name


def audit_record(
    event: CanonicalEvent,
    *,
    target: str,
    desired: DesiredAccess,
    decision: AccessDecision,
    now: datetime,
) -> AuditEvent:
    """The decision's audit row: what was done, for whom, and why.

    ``actor`` is the source, because the source's change is the cause; ``reason``
    is the vocabulary D-114 and D-115 fixed, and ``decision`` is the outcome the
    policy returned.
    """
    return AuditEvent(
        event_id=event.event_id,
        source_event_id=event.source_event_id,
        actor=event.source,
        action=desired.action.value,
        target=target,
        decision=decision.outcome.value,
        reason=desired.reason,
        timestamp=now,
    )


def ambiguous_record(event: CanonicalEvent, *, target: str, now: datetime) -> AuditEvent:
    """ADR-018 section 1's ambiguity row: a fact beside the decision, not a failure.

    ``AuditEvent`` has one free-text ``reason``, and the decision's ``reason``
    belongs to the decision, so the ambiguity is its own row rather than a
    suffix on a fixed vocabulary.
    """
    return AuditEvent(
        event_id=event.event_id,
        source_event_id=event.source_event_id,
        actor=event.source,
        action=AccessAction.NO_CHANGE.value,
        target=target,
        decision=DECISION_AMBIGUOUS_LINK,
        reason=REASON_AMBIGUOUS_LINK,
        timestamp=now,
    )


def required(value: str | None, field: str, desired: DesiredAccess) -> str:
    """Return a field the policy guarantees, or fail loudly if it did not.

    ``desired_access`` names ``role`` and ``team`` for the three actions that
    write them, so a ``None`` here is a policy defect: retrying the event reads
    the same decision and fails the same way.
    """
    if value is None:
        raise PermanentError(
            f"{desired.action.value} names no {field}; " "desired_access must set it (design 10.8)"
        )
    return value


def _team(gateway: Gateway, name: str, team_create_if_missing: Mapping[str, bool]) -> str:
    """Return the team identifier, creating the team only when config allows."""
    return gateway.ensure_team(
        name=name,
        create_if_missing=team_create_if_missing.get(name, False),
    )


def _mapped_policy(
    decision: AccessDecision,
    group_budget_policies: Mapping[tuple[str, str], str],
    budget_policies: Mapping[str, BudgetPolicy],
) -> BudgetPolicy | None:
    """The ``budget_mappings`` rule the selected group names, if it names one."""
    if decision.selected is None:
        return None
    name = group_budget_policies.get((decision.selected.source, decision.selected.source_group_id))
    return None if name is None else budget_policies[name]
