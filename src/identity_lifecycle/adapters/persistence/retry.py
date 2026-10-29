"""The retry ladder and design 9.2, as one pure function.

Exponential backoff with **full jitter**: the delay is drawn uniformly from
``[0, min (max, base * 2 ** (attempt - 1))]``. Full jitter is the variant that
spreads a thundering herd of simultaneously failed rows, which is the case here:
a gateway outage fails a whole batch at once, and equal delays would retry it at
one instant.

The numbers are ADR-002 section 6's: base 1 s, maximum 60 s, maximum 8 attempts.
The limit is applied by the caller (``outbox.settle``) because reaching it
changes the row's state rather than its delay, so this module stays a function
of the attempt number and a random source.
"""

from __future__ import annotations

import random

#: ADR-002 section 6, fixed here once.
BASE_SECONDS = 1.0
MAX_SECONDS = 60.0
MAX_ATTEMPTS = 8


def backoff_delay(attempt: int, rng: random.Random) -> float:
    """Return the full-jitter delay before attempt number ``attempt + 1``.

       ``attempt`` is the number of attempts already made, so the first retry
    (``attempt == 1``) waits in ``[0, 1]`` seconds and the seventh waits in
       ``[0, 60]``. ``rng`` is injected so a test can pin the draw instead of
       asserting a range and hoping.
    """
    if attempt < 1:
        raise ValueError(f"attempt must be at least 1; got {attempt}")
    ceiling = min(MAX_SECONDS, BASE_SECONDS * 2.0 ** (attempt - 1))
    return rng.uniform(0.0, ceiling)
