/**
 * Rate limiting: a token bucket per key, held in a Durable Object.
 *
 * The Python relay kept its buckets in process memory.  On Workers that would
 * give every isolate its own buckets, and isolates are many and short-lived,
 * so the limit would reset constantly and mean nothing.  Instead each bucket is
 * a Durable Object named after what it limits — `push:<instance-id>` or
 * `enroll:<address>` — which makes the limit global rather than per replica,
 * tighter than the Python relay ever was.
 *
 * The bucket is persisted, because a Durable Object is evicted after a short
 * idle spell.  For pushes that barely matters (a bucket refills in seconds),
 * but an enrollment bucket takes half an hour to refill, and one reset by
 * every eviction would be a limit in name only.  An alarm deletes the stored
 * bucket after an hour idle — by then it is full, and a full bucket and no
 * bucket are indistinguishable.
 *
 * What is stored: the bucket's key (an instance id, or a source address for
 * enrollment), a token count and a timestamp.  No device tokens, no content.
 */
import { DurableObject } from "cloudflare:workers";

import type { Env } from "./env.ts";

/** A bucket idle this long is full by definition, so forgetting it is free. */
export const IDLE_EVICTION_SECONDS = 3600;

export interface Bucket {
  tokens: number;
  /** Seconds, on whatever clock the caller uses. */
  updatedAt: number;
}

export interface Decision {
  allowed: boolean;
  /** Whole seconds, rounded up, for `Retry-After`.  Never zero on a refusal —
   * a client told to retry after 0 seconds retries immediately. */
  retryAfterSeconds: number;
}

export interface Limit {
  perMinute: number;
  burst: number;
}

/** A limit expressed per hour.  Enrollment's natural unit: a real instance
 * enrolls once in its life. */
export function perHour(rate: number, burst: number): Limit {
  return { perMinute: rate / 60, burst };
}

/**
 * Spend one token from `bucket` (null = never seen), or refuse.
 *
 * Pure: returns the decision and the bucket to keep.  Refusing does not spend
 * a token, so a client ignoring `Retry-After` is refused without being pushed
 * further into debt.
 */
export function spend(
  bucket: Bucket | null,
  limit: Limit,
  now: number,
): { decision: Decision; bucket: Bucket } {
  const ratePerSecond = limit.perMinute / 60;
  const capacity = limit.burst;

  let next: Bucket;
  if (bucket === null) {
    next = { tokens: capacity, updatedAt: now };
  } else {
    const elapsed = Math.max(0, now - bucket.updatedAt);
    next = { tokens: Math.min(capacity, bucket.tokens + elapsed * ratePerSecond), updatedAt: now };
  }

  if (next.tokens >= 1) {
    next.tokens -= 1;
    return { decision: { allowed: true, retryAfterSeconds: 0 }, bucket: next };
  }

  const missing = 1 - next.tokens;
  const wait = ratePerSecond > 0 ? missing / ratePerSecond : 60;
  return {
    decision: { allowed: false, retryAfterSeconds: Math.max(1, Math.trunc(wait) + 1) },
    bucket: next,
  };
}

export class RateLimiter extends DurableObject<Env> {
  private bucket: Bucket | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.bucket = (await ctx.storage.get<Bucket>("bucket")) ?? null;
    });
  }

  /** Spend one token, or refuse. */
  async check(limit: Limit): Promise<Decision> {
    const now = Date.now() / 1000;
    const { decision, bucket } = spend(this.bucket, limit, now);
    this.bucket = bucket;
    await this.ctx.storage.put("bucket", bucket);
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm((now + IDLE_EVICTION_SECONDS) * 1000);
    }
    return decision;
  }

  override async alarm(): Promise<void> {
    const now = Date.now() / 1000;
    if (this.bucket === null || now - this.bucket.updatedAt >= IDLE_EVICTION_SECONDS) {
      this.bucket = null;
      await this.ctx.storage.deleteAll();
      return;
    }
    await this.ctx.storage.setAlarm((this.bucket.updatedAt + IDLE_EVICTION_SECONDS) * 1000);
  }
}

/** Ask the bucket named `key`. */
export function checkLimit(env: Env, key: string, limit: Limit): Promise<Decision> {
  const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(key));
  return stub.check(limit);
}
