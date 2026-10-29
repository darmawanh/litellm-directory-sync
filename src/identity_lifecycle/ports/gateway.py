"""The gateway contract: the account operations the lifecycle core needs.

The gateway is the only system this service writes to. Every method
speaks in domain terms — ``LiteLLMAccount``, ``BudgetPolicy`` — and no method
takes or returns a vendor payload, a response body, or an HTTP status (design
15.2).

Three constraints from ADR-004 are part of the shape, not a note beside it:

- **There is no user-level block.** The gateway has no blocked user field to
  write, so no method here takes a
  ``blocked`` flag and none changes a user's block state. Revocation is
  key-scoped: ``revoke_keys`` blocks every key the user holds, and a user with no
  keys is already unable to spend. The method is named for what it
  changes, a key, because FR25 makes the blocked key the revocation mechanism and
  not the user record; ADR-004 section 1's ``block_user`` names the same
  key-scoped work.
- **Membership is set through the user.** There is no ``add_member`` that trusts
  a team write response; ``create_user`` and ``update_user`` carry the team, and
  a move removes the old membership with ``remove_from_team`` before the new one
  is set.
- **Every write is read back.** Each mutating method returns the account the
  adapter read from the gateway after the write, so a caller treats a change as
  applied only from that value. ``delete_user``
  returns nothing: its read-back is the account's absence, which the adapter
  confirms and raises on if the account is still there.

The port gains no method without an ADR: it is a public contract implemented by
the adapter and by the test double.
"""

from __future__ import annotations

from typing import Protocol

from identity_lifecycle.domain.models import LiteLLMAccount
from identity_lifecycle.domain.policy import BudgetPolicy


class Gateway(Protocol):
    """The account operations one lifecycle decision can require."""

    def ensure_team(self, *, name: str, create_if_missing: bool) -> str:
        """Return the team's identifier, creating the team only when allowed.

        ``create_if_missing`` is the mapping's flag: when it is false and the team
        does not exist, the adapter raises a permanent error rather than
        inventing a team. The returned identifier is what the caller
        stores and what every other method takes as ``team_id``; the name is
        configuration and the identifier is data.
        """
        ...

    def create_user(
        self,
        *,
        user_id: str,
        email: str,
        display_name: str,
        role: str,
        team_id: str,
        budget: BudgetPolicy,
    ) -> LiteLLMAccount:
        """Create the account and return it read back.

        ``user_id`` is the identifier the caller allocated: ``DesiredAccess``
        names none for a create, so this port never invents one. ``team_id`` is
        the value :meth:`ensure_team` returned. Membership is part of the create,
        not a second call.
        """
        ...

    def update_user(
        self, *, user_id: str, role: str, team_id: str, budget: BudgetPolicy
    ) -> LiteLLMAccount:
        """Apply a move and return the account read back.

        Role, team, and budget travel together because design 10.2 step 4 applies
        them as one change; a caller that wanted to change one field passes the
        other two unchanged.
        """
        ...

    def remove_from_team(self, *, user_id: str, team_id: str) -> LiteLLMAccount:
        """Remove the membership and return the account read back.

                A move removes the old membership before the new one is set (ADR-004
                section 2). A leave removes the membership as part of revocation
        .
        """
        ...

    def revoke_keys(self, *, user_id: str) -> LiteLLMAccount:
        """Block every key the user holds and return the account read back.

        This is the revocation mechanism, and it is key-scoped (ADR-004 section
        1). The read-back is what makes "the call returned 200" insufficient: the
        Phase D acceptance test proves the key then returns 401.
        """
        ...

    def delete_user(self, *, user_id: str) -> None:
        """Delete the account after the grace period.

        There is no value to return, so the read-back is the absence: the adapter
        reads the account after the delete and raises a permanent error if it is
        still present.
        """
        ...

    def get_user(self, *, user_id: str) -> LiteLLMAccount | None:
        """Return the account as the gateway holds it, or ``None``.

        A read that finds no such account is an outcome, not an exception,
        and it is what ``delete_user``'s read-back asserts.
        """
        ...
