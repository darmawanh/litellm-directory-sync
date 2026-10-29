"""The factory a use case takes, so a caller supplies the transaction boundary.

A use case opens one unit of work per transaction, but the port describes
only what is *inside* that transaction: ``ports/unit_of_work.py`` declares
``commit`` and ``rollback`` and deliberately no ``__enter__``/``__exit__``, because
whether a unit of work is a context manager is a property of the adapter's
resource handling, not of the contract a use case reads (AGENTS.md section 6: a
port gains no method without an ADR).

So this module states the one extra thing the use cases need — that the factory
returns something usable in a ``with`` that yields a ``UnitOfWork`` — without
touching the port. ``PostgresUnitOfWork`` and the in-memory double both satisfy
it structurally, and the factory takes the event's source because
``audit_events.source`` is supplied at construction
 (``adapters/persistence/access.py``).
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager

from identity_lifecycle.ports.unit_of_work import UnitOfWork

#: One transaction's worth of repositories, opened for one source.
UnitOfWorkFactory = Callable[[str], AbstractContextManager[UnitOfWork]]
