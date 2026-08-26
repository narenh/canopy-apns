"""Per-instance rate limiting, in memory.

A token bucket per instance id, refilled continuously.  Nothing is persisted
and nothing is shared between replicas — with N replicas an instance gets N
buckets, so the effective ceiling is N times the configured one.  That is fine
and deliberate: this limit exists to stop one misconfigured instance from
hammering Apple with the relay operator's signing key, not to meter a paid
product, and a shared counter would mean a Redis, which would mean the relay
was no longer stateless.

Buckets are dropped once they have been full and idle for a while, so an
instance that sends one push and never returns does not occupy memory forever.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

#: A bucket that has been idle this long is at full capacity by definition, so
#: forgetting it and recreating it later is indistinguishable from keeping it.
IDLE_EVICTION_SECONDS = 3600


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


@dataclass(frozen=True)
class Decision:
    """Whether one request may proceed, and when to try again if not."""

    allowed: bool
    retry_after_seconds: int = 0
    """Whole seconds, rounded up, for the ``Retry-After`` header.  Never zero
    on a refusal — a client told to retry after 0 seconds retries immediately,
    which is the behaviour the limit exists to prevent."""


class RateLimiter:
    """Token buckets keyed by instance id.

    Held on the app's state rather than in a module global, so tests get a
    fresh one per app and two apps in one process cannot interfere.
    """

    def __init__(self, *, per_minute: float, burst: int) -> None:
        self._rate_per_second = per_minute / 60.0
        self._capacity = float(burst)
        self._buckets: dict[str, _Bucket] = {}

    @classmethod
    def per_hour(cls, rate: float, *, burst: int) -> RateLimiter:
        """A limiter expressed in requests per hour rather than per minute.

        Enrollment is the caller: a real instance enrolls once in its life, so
        its natural unit is hours and writing ``per_minute=10 / 60`` at the call
        site would only invite someone to "simplify" it to ``10``.
        """
        return cls(per_minute=rate / 60.0, burst=burst)

    def check(self, instance_id: str, *, now: float | None = None) -> Decision:
        """Spend one token for ``instance_id``, or refuse.

        Refusing does *not* spend a token, so a client that ignores
        ``Retry-After`` and retries in a tight loop is refused each time
        without being pushed further into debt.
        """
        moment = time.monotonic() if now is None else now
        self._evict_idle(moment)

        bucket = self._buckets.get(instance_id)
        if bucket is None:
            bucket = _Bucket(tokens=self._capacity, updated_at=moment)
            self._buckets[instance_id] = bucket
        else:
            elapsed = max(0.0, moment - bucket.updated_at)
            bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._rate_per_second)
            bucket.updated_at = moment

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return Decision(allowed=True)

        missing = 1.0 - bucket.tokens
        wait = missing / self._rate_per_second if self._rate_per_second > 0 else 60.0
        return Decision(allowed=False, retry_after_seconds=max(1, int(wait) + 1))

    def _evict_idle(self, now: float) -> None:
        stale = [
            key
            for key, bucket in self._buckets.items()
            if now - bucket.updated_at > IDLE_EVICTION_SECONDS
        ]
        for key in stale:
            del self._buckets[key]


__all__ = ["IDLE_EVICTION_SECONDS", "Decision", "RateLimiter"]
