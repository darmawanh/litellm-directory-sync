"""The admin bearer-token primitive sections 5 and 6."""

from __future__ import annotations

import enum
import hmac
from collections.abc import Mapping, Sequence


class AdminAuthResult(enum.Enum):
    """Why an admin request was accepted or rejected."""

    ACCEPTED = "accepted"
    MISSING = "missing"
    DUPLICATED = "duplicated"
    MISMATCH = "mismatch"

    @property
    def accepted(self) -> bool:
        return self is AdminAuthResult.ACCEPTED


class AdminAuthConfigurationError(Exception):
    """The admin credential is absent or malformed; the process cannot start."""


class AdminToken:
    """The one static admin token, compared in full and in constant time."""

    def __init__(self, secret: str) -> None:
        if not secret or secret != secret.strip():
            raise AdminAuthConfigurationError(
                "the admin token must be non-empty and carry no surrounding whitespace"
            )
        self._expected = b"Bearer " + secret.encode("utf-8")

    @classmethod
    def from_environment(cls, environ: Mapping[str, str]) -> AdminToken:
        try:
            secret = environ["LIFECYCLE_MASTER_KEY"]
        except KeyError as error:
            raise AdminAuthConfigurationError("LIFECYCLE_MASTER_KEY is not set") from error
        return cls(secret)

    def verify(self, values: Sequence[str]) -> AdminAuthResult:
        if not values:
            return AdminAuthResult.MISSING
        if len(values) != 1:
            return AdminAuthResult.DUPLICATED
        if hmac.compare_digest(self._expected, values[0].encode("utf-8")):
            return AdminAuthResult.ACCEPTED
        return AdminAuthResult.MISMATCH
