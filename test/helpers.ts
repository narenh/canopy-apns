import { env } from "cloudflare:workers";

import type { Env } from "../src/env.ts";
import { mint } from "../src/keys.ts";

export const SIGNING_SECRET = "test-signing-secret-that-is-long-enough-to-pass";
export const BUNDLE_ID = "com.example.canopy";
export const DEVICE_TOKEN = "a".repeat(64);

export const baseEnv = env as unknown as Env;

/** The test env with some values replaced.  `undefined` unsets one.  Built on
 * the real env as a prototype so the Durable Object bindings come along.
 *
 * Properties are *defined*, not assigned: the test env is a Proxy, and an
 * assignment to an object inheriting from it goes through the Proxy's `set`
 * and quietly rewrites the shared env for every later test. */
export function withEnv(overrides: Partial<Record<keyof Env, unknown>>): Env {
  const derived = Object.create(baseEnv);
  for (const [key, value] of Object.entries(overrides)) {
    Object.defineProperty(derived, key, { value, enumerable: true });
  }
  return derived as Env;
}

/** The env of a relay deployed before its `.p8` was pasted in. */
export function unconfiguredEnv(): Env {
  return withEnv({
    CANOPY_APNS_TEAM_ID: undefined,
    CANOPY_APNS_KEY_ID: undefined,
    CANOPY_APNS_BUNDLE_ID: undefined,
    CANOPY_APNS_PRIVATE_KEY: undefined,
  });
}

let counter = 0;

/** A fresh instance id per call.  Rate-limit buckets are Durable Objects and
 * outlive a single test, so sharing an id would share a bucket. */
export function freshInstanceId(): string {
  counter += 1;
  return `test-${Date.now().toString(36)}-${counter}`;
}

/** A fresh source address, for the same reason, for enrollment buckets. */
export function freshAddress(): string {
  counter += 1;
  return `198.51.100.${counter % 250}-${Date.now()}-${counter}`;
}

export async function authFor(instanceId: string, secret = SIGNING_SECRET) {
  return { authorization: `Bearer ${await mint(instanceId, secret)}` };
}
