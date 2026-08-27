"""The per-instance token bucket."""

from __future__ import annotations

from canopy_apns.ratelimit import IDLE_EVICTION_SECONDS, RateLimiter


def test_a_burst_is_allowed_then_refused() -> None:
    limiter = RateLimiter(per_minute=60, burst=3)

    assert [limiter.check("acme", now=0.0).allowed for _ in range(3)] == [True] * 3
    assert not limiter.check("acme", now=0.0).allowed


def test_a_refusal_names_a_retry_delay_of_at_least_a_second() -> None:
    """A client told to retry after zero seconds retries immediately."""
    limiter = RateLimiter(per_minute=60, burst=1)
    limiter.check("acme", now=0.0)

    decision = limiter.check("acme", now=0.0)
    assert not decision.allowed
    assert decision.retry_after_seconds >= 1


def test_refusals_do_not_push_a_client_further_into_debt() -> None:
    """A caller ignoring Retry-After is refused, not penalised for it."""
    limiter = RateLimiter(per_minute=60, burst=1)
    limiter.check("acme", now=0.0)
    for _ in range(50):
        limiter.check("acme", now=0.0)

    # One second of refill at 60/minute is exactly one token.
    assert limiter.check("acme", now=1.0).allowed


def test_the_bucket_refills_over_time() -> None:
    limiter = RateLimiter(per_minute=60, burst=2)
    limiter.check("acme", now=0.0)
    limiter.check("acme", now=0.0)
    assert not limiter.check("acme", now=0.5).allowed
    assert limiter.check("acme", now=1.0).allowed


def test_the_bucket_does_not_refill_past_its_capacity() -> None:
    limiter = RateLimiter(per_minute=60, burst=2)
    assert limiter.check("acme", now=0.0).allowed

    # An hour of idling should bank a burst, not an hour's worth of pushes.
    allowed = [limiter.check("acme", now=3600.0).allowed for _ in range(4)]
    assert allowed == [True, True, False, False]


def test_instances_have_separate_buckets() -> None:
    """One noisy instance must not silence a quiet one."""
    limiter = RateLimiter(per_minute=60, burst=1)
    assert limiter.check("acme", now=0.0).allowed
    assert not limiter.check("acme", now=0.0).allowed
    assert limiter.check("other", now=0.0).allowed


def test_idle_buckets_are_forgotten() -> None:
    """An instance that sends once and never returns must not leak memory."""
    limiter = RateLimiter(per_minute=60, burst=1)
    limiter.check("acme", now=0.0)

    limiter.check("someone-else", now=IDLE_EVICTION_SECONDS + 1)

    assert "acme" not in limiter._buckets


def test_per_hour_expresses_the_same_bucket_in_hourly_terms() -> None:
    """Enrollment's natural unit: an instance enrols once in its life."""
    limiter = RateLimiter.per_hour(10, burst=2)

    assert [limiter.check("ip", now=0.0).allowed for _ in range(3)] == [True, True, False]
    # 10/hour is one token every six minutes, so five minutes on is still short.
    assert not limiter.check("ip", now=300.0).allowed


def test_waiting_the_advertised_retry_after_is_always_enough() -> None:
    """The one promise a refusal makes.

    Asserted rather than assumed because the delay is computed in floating
    point: a Retry-After that rounds even fractionally short would tell every
    client to come back at the exact moment it is still refused, and the retry
    loop that produces looks like a server fault from the outside.
    """
    limiter = RateLimiter.per_hour(10, burst=1)
    limiter.check("ip", now=0.0)

    refused = limiter.check("ip", now=0.0)
    assert not refused.allowed

    assert limiter.check("ip", now=float(refused.retry_after_seconds)).allowed
