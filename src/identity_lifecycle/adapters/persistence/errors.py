"""The two failures this package raises, both permanent.

A stored value the domain cannot represent is schema drift: retrying the same
row reads the same bytes and fails the same way, so it is permanent, not
retryable. A settle for an ``event_id`` that has no row is a caller
bug, not a transient condition, and gets the same family.
"""

from __future__ import annotations

from identity_lifecycle.domain.errors import PermanentError


class StoreError(PermanentError):
    """A row this package cannot turn into a domain value, or a settle with no row."""
