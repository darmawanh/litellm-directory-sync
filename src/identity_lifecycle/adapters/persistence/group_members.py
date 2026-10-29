"""The ``source_group_members`` snapshot, one member set per group.

The snapshot is the diff input for the poller: it reads the group object, compares
the source's member list against this set, and emits ``group.member_added`` and
``group.member_removed`` from the difference.

One limit of this schema is recorded here rather than hidden. The table stores
member rows and nothing else — there is no row that says "this group was read" —
so an empty set and a never-read group are both "no rows". ``read`` therefore
answers ``None`` for both, which the port defines as "run a full sync". That is
safe rather than lossy: after a group is found empty, ``replace`` removes every
row in the same transaction that emits the removals, so
the removals have already been produced by the poll that observed the emptiness.
The next poll re-seeds with a full sync, which emits an addition for each current
member and no removal, because there are none left to remove.

Expressing the distinction the port's docstring describes would need a row per
group rather than a row per member. The migration is the schema authority and
this ticket does not change it; the limit is reported, not
worked around by inventing a sentinel member.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

from identity_lifecycle.adapters.persistence.rows import member_ids
from identity_lifecycle.ports.unit_of_work import GroupMemberSnapshot


class GroupMemberStore:
    """The ``source_group_members`` rows."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def read(self, source: str, source_group_id: str) -> GroupMemberSnapshot | None:
        """Return the snapshot for one group, or ``None`` when it has no rows.

        See the module docstring: the schema cannot tell "never read" from
        "read, empty", so both answer ``None``, which forces the full sync the
        port asks for.
        """
        rows = (
            self._connection.execute(
                text(
                    "select source_user_id from source_group_members"
                    " where source = :source and source_group_id = :source_group_id"
                ),
                {"source": source, "source_group_id": source_group_id},
            )
            .mappings()
            .all()
        )
        if not rows:
            return None
        return GroupMemberSnapshot(
            source=source,
            source_group_id=source_group_id,
            source_user_ids=member_ids(rows),
        )

    def replace(self, snapshot: GroupMemberSnapshot) -> None:
        """Replace the whole member set for one group in the caller's transaction.

        Delete then insert, both inside the unit of work, so a repeated call with
        the same set leaves the same rows and a failed call leaves the previous
        snapshot intact. The insert is one statement for the whole
        set: a per-member loop would be a round trip per member at the 5 000-row
        scale target.
        """
        self._connection.execute(
            text(
                "delete from source_group_members"
                " where source = :source and source_group_id = :source_group_id"
            ),
            {"source": snapshot.source, "source_group_id": snapshot.source_group_id},
        )
        members = sorted(snapshot.source_user_ids)
        if not members:
            return
        statement = text(
            "insert into source_group_members (source, source_group_id, source_user_id)"
            " values (:source, :source_group_id, :source_user_id)"
        )
        self._connection.execute(
            statement,
            [
                {
                    "source": snapshot.source,
                    "source_group_id": snapshot.source_group_id,
                    "source_user_id": member,
                }
                for member in members
            ],
        )
