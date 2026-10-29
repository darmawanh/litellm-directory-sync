"""The typed error hierarchy of the domain.

A failure is either retryable or permanent. The two families are siblings,
not parent and child: ``isinstance`` must never let a retry policy treat a
permanent failure as retryable. Which status code or vendor failure maps to
which family is the receiving adapter's job; this module defines
the types and catches nothing.
"""


class DomainError(Exception):
    """Base class for every failure this service raises deliberately."""


class RetryableError(DomainError):
    """A failure that may succeed if tried again: 429, 5xx, timeout."""


class PermanentError(DomainError):
    """A failure that stays until the data or configuration changes."""
