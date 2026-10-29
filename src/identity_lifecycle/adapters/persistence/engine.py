"""Engine construction, so the service and the tests share one connection setup.

Nothing here reads a credential from the environment: the URL is handed in by
the caller that already resolved it, which keeps ``config/config.example.yaml``
the only description of a connection.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine


def build_engine(database_url: str) -> Engine:
    """Return an engine for ``database_url`` with a pre-pinged pool.

    ``pool_pre_ping`` is not a retry policy: it discards a connection the server
    already closed before handing it out, which is the difference between one
    failed statement and a failed process after an idle period (design 9.2 keeps
    the retry ladder where it belongs, in the worker).
    """
    return create_engine(database_url, pool_pre_ping=True)
