import { describe, expect, it } from "vitest";

import { type Bucket, type Limit, checkLimit, perHour, spend } from "../src/ratelimit.ts";
import { baseEnv, freshInstanceId } from "./helpers.ts";

/** Drive the pure bucket the way the Durable Object does. */
function limiter(limit: Limit) {
  let bucket: Bucket | null = null;
  return (now: number) => {
    const result = spend(bucket, limit, now);
    bucket = result.bucket;
    return result.decision;
  };
}

describe("the token bucket", () => {
  it("allows a burst, then refuses", () => {
    const check = limiter({ perMinute: 60, burst: 3 });
    expect([check(0), check(0), check(0)].map((d) => d.allowed)).toEqual([true, true, true]);
    expect(check(0).allowed).toBe(false);
  });

  it("names a retry delay of at least a second", () => {
    const check = limiter({ perMinute: 60, burst: 1 });
    check(0);
    const decision = check(0);
    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBeGreaterThanOrEqual(1);
  });

  it("does not push a client further into debt for ignoring Retry-After", () => {
    const check = limiter({ perMinute: 60, burst: 1 });
    check(0);
    for (let i = 0; i < 50; i++) check(0);
    // One second of refill at 60/minute is exactly one token.
    expect(check(1).allowed).toBe(true);
  });

  it("refills over time", () => {
    const check = limiter({ perMinute: 60, burst: 2 });
    check(0);
    check(0);
    expect(check(0.5).allowed).toBe(false);
    expect(check(1).allowed).toBe(true);
  });

  it("does not refill past its capacity", () => {
    const check = limiter({ perMinute: 60, burst: 2 });
    expect(check(0).allowed).toBe(true);
    // An hour idle banks a burst, not an hour of pushes.
    expect([check(3600), check(3600), check(3600), check(3600)].map((d) => d.allowed)).toEqual([
      true,
      true,
      false,
      false,
    ]);
  });

  it("expresses enrollment's limit per hour", () => {
    const check = limiter(perHour(10, 2));
    expect([check(0), check(0), check(0)].map((d) => d.allowed)).toEqual([true, true, false]);
    // 10/hour is one token every six minutes, so five minutes on is still short.
    expect(check(300).allowed).toBe(false);
  });

  it("always lets a client in once it has waited the advertised Retry-After", () => {
    const check = limiter(perHour(10, 1));
    check(0);
    const refused = check(0);
    expect(refused.allowed).toBe(false);
    expect(check(refused.retryAfterSeconds).allowed).toBe(true);
  });
});

describe("the Durable Object", () => {
  it("keeps one bucket per key, shared by every caller", async () => {
    const key = `push:${freshInstanceId()}`;
    const limit = { perMinute: 1, burst: 2 };
    const results = [];
    for (let i = 0; i < 3; i++) results.push((await checkLimit(baseEnv, key, limit)).allowed);
    expect(results).toEqual([true, true, false]);
  });

  it("keeps separate buckets for separate keys, so a noisy instance cannot silence a quiet one", async () => {
    const limit = { perMinute: 1, burst: 1 };
    const noisy = `push:${freshInstanceId()}`;
    expect((await checkLimit(baseEnv, noisy, limit)).allowed).toBe(true);
    expect((await checkLimit(baseEnv, noisy, limit)).allowed).toBe(false);
    expect((await checkLimit(baseEnv, `push:${freshInstanceId()}`, limit)).allowed).toBe(true);
  });
});
