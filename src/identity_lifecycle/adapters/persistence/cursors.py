"""``source_cursors``: one opaque token per `` (source, feed_scope)``.

The store neither parses nor validates the token: its form belongs to the
adapter, and this module would otherwise
have to know that one source's token is JSON and another's is not.

``read`` answering ``None`` is "the feed has never run", which design 10.6 turns
into a full sync. That is absence, not an empty token, so the caller can tell a
first run from a stored value.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

from identity_lifecycle.adapters.persistence.errors import StoreError


class CursorStore:
    """The ``source_cursors`` rows."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def read(self, source: str, feed_scope: str) -> str | None:
        """Return the stored token, or ``None`` when the feed has never run."""
        row = self._connection.execute(
            text(
                "select cursor from source_cursors"
                " where source = :source and feed_scope = :feed_scope"
            ),
            {"source": source, "feed_scope": feed_scope},
        ).first()
        if row is None:
            return None
        value = row[0]
        if not isinstance(value, str):
            # ``cursor`` is text and not null; anything else is schema drift.
            raise StoreError(f"source_cursors.cursor is {type(value).__name__}, not text")
        return value

    def write(self, source: str, feed_scope: str, cursor: str) -> None:
        """Store the advanced token in the transaction that writes the page's events."""
        self._connection.execute(
            text(
                "insert into source_cursors (source, feed_scope, cursor)"
                " values (:source, :feed_scope, :cursor)"
                " on conflict (source, feed_scope) do update set"
                " cursor = excluded.cursor, updated_at = now()"
            ),
            {"source": source, "feed_scope": feed_scope, "cursor": cursor},
        )
