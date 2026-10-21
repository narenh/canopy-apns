/**
 * Rate limiting: one token bucket per key, each in its own Durable Object.
 *
 * The Python relay kept buckets in process memory. A Worker has no shared
 * process — every request may land in a different isolate in a different
 * city — so each bucket lives in a Durable Object named after it
 * (`push:<instance>`, `enroll:<address>`), which gives the one thing a bucket
 * needs: a single place where reads and writes for that key are serialised.
 * That is also stricter than before, where N replicas meant N buckets.
 *
 * What is stored is one row per bucket: a token count and a timestamp. No
 * device token, no text, nothing about who was notified. A bucket left idle
 * for an hour is full by definition, so an alarm deletes it — exactly the
 * Python relay's idle eviction.
 *
 * The state is in storage rather than in the object's memory because a Durable
 * Object is evicted from memory after a minute or so of quiet, and for the
 * enrollment bucket (10 an hour) forgetting it after a minute would turn the
 * limit into ten a minute.
 */

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./config.ts";

export const IDLE_EVICTION_SECONDS = 3600;

export interface Decision {
	allowed: boolean;
	/** Whole seconds, never 0 on a refusal. */
	retryAfterSeconds: number;
}

interface Bucket {
	tokens: number;
	updatedAt: number;
}

export class RateLimiter extends DurableObject<Env> {
	/**
	 * Spend one token, or refuse. Refusing spends nothing, so a client that
	 * ignores `Retry-After` is refused each time without going further into debt.
	 */
	async check(ratePerSecond: number, capacity: number, now: number = Date.now() / 1000): Promise<Decision> {
		const kv = this.ctx.storage.kv;
		const stored = kv.get<Bucket>("bucket");
		const bucket: Bucket = stored
			? {
					tokens: Math.min(capacity, stored.tokens + Math.max(0, now - stored.updatedAt) * ratePerSecond),
					updatedAt: now,
				}
			: { tokens: capacity, updatedAt: now };

		let decision: Decision;
		if (bucket.tokens >= 1) {
			bucket.tokens -= 1;
			decision = { allowed: true, retryAfterSeconds: 0 };
		} else {
			const wait = ratePerSecond > 0 ? (1 - bucket.tokens) / ratePerSecond : 60;
			decision = { allowed: false, retryAfterSeconds: Math.max(1, Math.floor(wait) + 1) };
		}

		kv.put("bucket", bucket);
		if (!stored) await this.ctx.storage.setAlarm((now + IDLE_EVICTION_SECONDS) * 1000);
		return decision;
	}

	async alarm(): Promise<void> {
		const bucket = this.ctx.storage.kv.get<Bucket>("bucket");
		const now = Date.now() / 1000;
		if (!bucket || now - bucket.updatedAt >= IDLE_EVICTION_SECONDS) {
			await this.ctx.storage.deleteAll();
		} else {
			await this.ctx.storage.setAlarm((bucket.updatedAt + IDLE_EVICTION_SECONDS) * 1000);
		}
	}
}

/** Spend one token from the bucket named `key`. */
export function spend(env: Env, key: string, perMinute: number, burst: number): Promise<Decision> {
	return env.RATE_LIMITER.getByName(key).check(perMinute / 60, burst);
}
