import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/config.ts";
import { IDLE_EVICTION_SECONDS, type RateLimiter } from "../src/ratelimit.ts";

const ns = (env as unknown as Env).RATE_LIMITER;
let n = 0;
const stub = () => ns.getByName(`test-${Date.now()}-${n++}`);
// Real timestamps: the idle alarm is scheduled from them, and one in 1970 fires at once.
const T = Math.floor(Date.now() / 1000);

describe("RateLimiter", () => {
	it("allows a burst, then refuses with a positive Retry-After", async () => {
		const s = stub();
		const results = [];
		for (let i = 0; i < 4; i++) results.push(await s.check(1 / 60, 3, T));
		expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
		expect(results[3]?.retryAfterSeconds).toBe(61);
	});

	it("refills over time, and refusing does not dig deeper", async () => {
		const s = stub();
		await s.check(1, 1, T);
		expect((await s.check(1, 1, T + 0.2)).allowed).toBe(false);
		expect((await s.check(1, 1, T + 0.4)).allowed).toBe(false);
		expect((await s.check(1, 1, T + 1.1)).allowed).toBe(true);
	});

	it("survives eviction from memory", async () => {
		const s = stub();
		await s.check(1 / 3600, 1, T);
		// A fresh object instance reads the same storage.
		await runInDurableObject(s, async (_instance: RateLimiter, state) => {
			expect(state.storage.kv.get("bucket")).toBeDefined();
		});
		expect((await s.check(1 / 3600, 1, T + 60)).allowed).toBe(false);
	});

	it("forgets a bucket once it has been idle for an hour, and keeps a busy one", async () => {
		const idle = stub();
		await idle.check(1, 5, T - IDLE_EVICTION_SECONDS - 1);
		await runInDurableObject(idle, async (instance: RateLimiter, state) => {
			await instance.alarm();
			expect(state.storage.kv.get("bucket")).toBeUndefined();
		});

		const busy = stub();
		await busy.check(1, 5, T);
		await runInDurableObject(busy, async (instance: RateLimiter, state) => {
			await instance.alarm();
			expect(state.storage.kv.get("bucket")).toBeDefined();
			expect(await state.storage.getAlarm()).toBe((T + IDLE_EVICTION_SECONDS) * 1000);
		});
	});
});
