/** The relay's endpoints, end to end inside workerd, with Apple stubbed. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PRODUCTION_HOST, SANDBOX_HOST } from "../src/apns.ts";
import type { Env } from "../src/env.ts";
import { handle } from "../src/app.ts";
import { mint } from "../src/keys.ts";
import {
  BUNDLE_ID,
  DEVICE_TOKEN,
  SIGNING_SECRET,
  authFor,
  baseEnv,
  freshAddress,
  freshInstanceId,
  unconfiguredEnv,
  withEnv,
} from "./helpers.ts";

const PUSH = { device_token: DEVICE_TOKEN, title: "The End of Oak Street (2026)" };

interface AppleCall {
  url: string;
  headers: Headers;
  body: Record<string, any>;
}

let appleCalls: AppleCall[] = [];
let appleReplies: Response[] = [];

/** Queue Apple's answers; the last one repeats. */
function appleSays(...replies: Response[]) {
  appleReplies = replies;
}

beforeEach(() => {
  appleCalls = [];
  appleReplies = [new Response(null, { status: 200 })];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const request = new Request(input as RequestInfo, init);
    appleCalls.push({
      url: request.url,
      headers: request.headers,
      body: JSON.parse(await request.text()),
    });
    const reply = appleReplies.length > 1 ? appleReplies.shift()! : appleReplies[0]!;
    return reply.clone();
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function call(
  path: string,
  init: { method?: string; headers?: Record<string, string>; json?: unknown; env?: Env } = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", freshAddress());
  let body: string | undefined;
  if (init.json !== undefined) {
    body = JSON.stringify(init.json);
    headers.set("content-type", "application/json");
  }
  const request = new Request(`https://relay.test${path}`, {
    method: init.method ?? (body ? "POST" : "GET"),
    headers,
    body,
  });
  return handle(request, init.env ?? baseEnv);
}

async function freshAuth() {
  const id = freshInstanceId();
  return { id, headers: await authFor(id) };
}

// ---------------------------------------------------------------------------
// Health and discovery
// ---------------------------------------------------------------------------

describe("health and discovery", () => {
  it("is open and reports readiness", async () => {
    const response = await call("/health");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok", apns: "configured" });
  });

  it("says so when no signing key is set", async () => {
    const response = await call("/health", { env: unconfiguredEnv() });
    expect(((await response.json()) as { apns: string }).apns).toBe("unconfigured");
  });

  it("explains itself at the root rather than 404ing", async () => {
    const response = await call("/");
    expect(response.status).toBe(200);
    expect(((await response.json()) as { service: string }).service).toBe("canopy-apns");
  });

  it("gives a browser the diagnostic page", async () => {
    const response = await call("/", { headers: { accept: "text/html" } });
    expect(response.headers.get("content-type")).toMatch(/^text\/html/);
    const html = await response.text();
    expect(html).toContain("canopy-apns");
    expect(html).toContain('data-scheme="https"');
  });

  it("escapes header values on the page", async () => {
    const response = await call("/", {
      headers: { accept: "text/html", "x-forwarded-for": "<script>alert(1)</script>" },
    });
    const html = await response.text();
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("reports an unconfigured relay on the page", async () => {
    const response = await call("/", { headers: { accept: "text/html" }, env: unconfiguredEnv() });
    expect(await response.text()).toContain("not configured");
  });

  it("404s an unknown path and 405s a wrong method", async () => {
    expect((await call("/nope")).status).toBe(404);
    const wrong = await call("/v1/push");
    expect(wrong.status).toBe(405);
    expect(wrong.headers.get("allow")).toBe("POST");
  });
});

// ---------------------------------------------------------------------------
// Configuration that must not serve
// ---------------------------------------------------------------------------

describe("configuration the relay refuses to run with", () => {
  it("answers everything with a 500 when the signing secret is a placeholder", async () => {
    const env = withEnv({ CANOPY_APNS_SIGNING_SECRET: "set this in Coolify" });
    for (const path of ["/health", "/v1/verify"]) {
      const response = await call(path, { env });
      expect(response.status).toBe(500);
      expect(((await response.json()) as { detail: string }).detail).toMatch(/placeholder/);
    }
    expect((await call("/v1/instances", { method: "POST", env })).status).toBe(500);
  });

  it("answers everything with a 500 when the .p8 is unreadable, rather than failing each push", async () => {
    const response = await call("/health", { env: withEnv({ CANOPY_APNS_PRIVATE_KEY: "garbage" }) });
    expect(response.status).toBe(500);
    expect(((await response.json()) as { detail: string }).detail).toMatch(/could not be read/);
  });
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

describe("authentication", () => {
  it("refuses a push without a key", async () => {
    const response = await call("/v1/push", { json: PUSH });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
  });

  it("refuses a forged key", async () => {
    const forged = await mint("notcanopy", "not-the-relays-secret");
    const response = await call("/v1/push", { json: PUSH, headers: { authorization: `Bearer ${forged}` } });
    expect(response.status).toBe(401);
  });

  it("refuses a non-Bearer scheme", async () => {
    const key = await mint("notcanopy", SIGNING_SECRET);
    const response = await call("/v1/push", { json: PUSH, headers: { authorization: `Basic ${key}` } });
    expect(response.status).toBe(401);
  });

  it("makes every refusal read the same", async () => {
    const forged = await mint("notcanopy", "wrong");
    const malformed = await call("/v1/push", { json: PUSH, headers: { authorization: "Bearer nonsense" } });
    const badSignature = await call("/v1/push", { json: PUSH, headers: { authorization: `Bearer ${forged}` } });
    expect(await malformed.json()).toEqual(await badSignature.json());
  });

  it("refuses a revoked instance despite a valid signature", async () => {
    const { id, headers } = await freshAuth();
    const env = withEnv({ CANOPY_APNS_REVOKED_INSTANCES: id });
    expect((await call("/v1/verify", { headers, env })).status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

describe("verify", () => {
  it("reports the instance and the topic", async () => {
    const { id, headers } = await freshAuth();
    const response = await call("/v1/verify", { headers });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      instance: id,
      bundle_id: BUNDLE_ID,
      ready: true,
      rate_limit_per_minute: 120,
    });
  });

  it("separates a good key from an unready relay", async () => {
    const { id, headers } = await freshAuth();
    const response = await call("/v1/verify", { headers, env: unconfiguredEnv() });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      instance: id,
      bundle_id: null,
      ready: false,
      rate_limit_per_minute: 120,
    });
  });
});

// ---------------------------------------------------------------------------
// Pushing
// ---------------------------------------------------------------------------

describe("pushing", () => {
  it("forwards a push to Apple", async () => {
    appleSays(new Response(null, { status: 200, headers: { "apns-id": "abc-123" } }));
    const { headers } = await freshAuth();

    const response = await call("/v1/push", {
      json: { ...PUSH, body: "Requested by Robin Example", data: { imdb_id: "tt1" } },
      headers,
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ result: "delivered", reason: null, apns_id: "abc-123" });
    expect(appleCalls[0]!.url).toBe(`${PRODUCTION_HOST}/3/device/${DEVICE_TOKEN}`);
    expect(appleCalls[0]!.body.aps.alert).toEqual({ title: PUSH.title, body: "Requested by Robin Example" });
    expect(appleCalls[0]!.body.canopy).toEqual({ imdb_id: "tt1" });
    expect(appleCalls[0]!.headers.get("authorization")).toMatch(/^bearer ey/);
  });

  it("still accepts the old subtitle field, as body", async () => {
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: { ...PUSH, subtitle: "Requested by Robin Example" }, headers });
    expect(response.status).toBe(200);
    expect(appleCalls[0]!.body.aps.alert.body).toBe("Requested by Robin Example");
    expect(appleCalls[0]!.body.aps.alert).not.toHaveProperty("subtitle");
  });

  it("forwards a badge", async () => {
    const { headers } = await freshAuth();
    await call("/v1/push", { json: { ...PUSH, badge: 4 }, headers });
    expect(appleCalls[0]!.body.aps.badge).toBe(4);
  });

  it("carries no badge key when the instance sent none", async () => {
    const { headers } = await freshAuth();
    await call("/v1/push", { json: PUSH, headers });
    expect(appleCalls[0]!.body.aps).not.toHaveProperty("badge");
  });

  it("forwards a zero badge rather than treating it as absent", async () => {
    const { headers } = await freshAuth();
    await call("/v1/push", { json: { ...PUSH, badge: 0 }, headers });
    expect(appleCalls[0]!.body.aps.badge).toBe(0);
  });

  it("refuses a negative badge", async () => {
    const { headers } = await freshAuth();
    expect((await call("/v1/push", { json: { ...PUSH, badge: -1 }, headers })).status).toBe(422);
  });

  it("sends a sandbox push to the sandbox host", async () => {
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: { ...PUSH, environment: "sandbox" }, headers });
    expect(((await response.json()) as { result: string }).result).toBe("delivered");
    expect(appleCalls[0]!.url).toBe(`${SANDBOX_HOST}/3/device/${DEVICE_TOKEN}`);
  });

  it("returns a dead token as 200 unregistered", async () => {
    appleSays(Response.json({ reason: "Unregistered" }, { status: 410 }));
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: PUSH, headers });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ result: "unregistered", reason: "Unregistered" });
  });

  it("treats Apple refusing as a successful forward", async () => {
    appleSays(Response.json({ reason: "BadTopic" }, { status: 400 }));
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: PUSH, headers });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ result: "failed", reason: "BadTopic" });
  });

  it("503s a push to an unconfigured relay, and says the key is fine", async () => {
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: PUSH, headers, env: unconfiguredEnv() });
    expect(response.status).toBe(503);
    expect(((await response.json()) as { detail: string }).detail).toContain("API key");
  });
});

// ---------------------------------------------------------------------------
// Payload constraints
// ---------------------------------------------------------------------------

describe("payload constraints", () => {
  it.each([
    ["an aps field set by the instance", { ...PUSH, aps: { "content-available": 1 } }],
    ["a non-hex device token", { ...PUSH, device_token: "not-hex" }],
    ["an empty title", { ...PUSH, title: "" }],
    ["an oversized data blob", { ...PUSH, data: { blob: "x".repeat(2000) } }],
    ["an unknown environment", { ...PUSH, environment: "staging" }],
    ["a missing title", { device_token: DEVICE_TOKEN }],
    ["a body that is not an object", ["not", "an", "object"]],
  ])("refuses %s with a 422", async (_label, body) => {
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: body, headers });
    expect(response.status).toBe(422);
    expect(Array.isArray(((await response.json()) as { detail: unknown }).detail)).toBe(true);
    expect(appleCalls).toHaveLength(0);
  });

  it("refuses a body that is not JSON", async () => {
    const { headers } = await freshAuth();
    const request = new Request("https://relay.test/v1/push", {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: "{not json",
    });
    expect((await handle(request, baseEnv)).status).toBe(422);
  });

  it("names the offending field", async () => {
    const { headers } = await freshAuth();
    const response = await call("/v1/push", { json: { ...PUSH, aps: {} }, headers });
    const { detail } = (await response.json()) as { detail: { loc: string[] }[] };
    expect(detail[0]!.loc).toEqual(["body", "aps"]);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

describe("rate limiting", () => {
  it("gives an instance over its limit a 429 with Retry-After", async () => {
    const env = withEnv({ CANOPY_APNS_RATE_LIMIT: "60", CANOPY_APNS_RATE_BURST: "2" });
    const { headers } = await freshAuth();

    const statuses = [];
    for (let i = 0; i < 3; i++) statuses.push((await call("/v1/push", { json: PUSH, headers, env })).status);
    const refused = await call("/v1/push", { json: PUSH, headers, env });

    expect(statuses).toEqual([200, 200, 429]);
    expect(Number(refused.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
  });

  it("does not spend the push budget on verify", async () => {
    const env = withEnv({ CANOPY_APNS_RATE_LIMIT: "60", CANOPY_APNS_RATE_BURST: "1" });
    const { headers } = await freshAuth();
    for (let i = 0; i < 5; i++) expect((await call("/v1/verify", { headers, env })).status).toBe(200);
    expect((await call("/v1/push", { json: PUSH, headers, env })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

describe("enrollment", () => {
  interface Enrolled {
    instance_id: string;
    api_key: string;
    bundle_id: string | null;
    ready: boolean;
  }

  it("issues a working key with no authentication", async () => {
    const response = await call("/v1/instances", { method: "POST" });
    expect(response.status).toBe(201);
    const body = (await response.json()) as Enrolled;
    expect(body.api_key.startsWith(`canopy_${body.instance_id}_`)).toBe(true);
    expect(body.bundle_id).toBe(BUNDLE_ID);
    expect(body.ready).toBe(true);

    const verified = await call("/v1/verify", { headers: { authorization: `Bearer ${body.api_key}` } });
    expect(verified.status).toBe(200);
    expect(((await verified.json()) as { instance: string }).instance).toBe(body.instance_id);
  });

  it("makes each enrollment a distinct instance", async () => {
    const first = (await (await call("/v1/instances", { method: "POST" })).json()) as Enrolled;
    const second = (await (await call("/v1/instances", { method: "POST" })).json()) as Enrolled;
    expect(first.instance_id).not.toBe(second.instance_id);
    expect(first.api_key).not.toBe(second.api_key);
  });

  it("still issues a key against an unready relay", async () => {
    const response = await call("/v1/instances", { method: "POST", env: unconfiguredEnv() });
    expect(response.status).toBe(201);
    const body = (await response.json()) as Enrolled;
    expect(body.ready).toBe(false);
    expect(body.api_key).toBeTruthy();
  });

  it("can be switched off", async () => {
    const response = await call("/v1/instances", {
      method: "POST",
      env: withEnv({ CANOPY_APNS_ENROLLMENT_ENABLED: "false" }),
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { detail: string }).detail).toContain("not issuing new keys");
  });

  it("is rate-limited per address", async () => {
    const env = withEnv({ CANOPY_APNS_ENROLLMENT_PER_HOUR: "10", CANOPY_APNS_ENROLLMENT_BURST: "2" });
    const address = { "cf-connecting-ip": freshAddress() };

    const statuses = [];
    for (let i = 0; i < 3; i++) {
      statuses.push((await call("/v1/instances", { method: "POST", headers: address, env })).status);
    }
    const refused = await call("/v1/instances", { method: "POST", headers: address, env });

    expect(statuses).toEqual([201, 201, 429]);
    expect(Number(refused.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
  });

  it("does not spend the push budget", async () => {
    const env = withEnv({ CANOPY_APNS_RATE_LIMIT: "60", CANOPY_APNS_RATE_BURST: "1" });
    const enrolled = (await (await call("/v1/instances", { method: "POST", env })).json()) as Enrolled;
    const pushed = await call("/v1/push", {
      json: PUSH,
      headers: { authorization: `Bearer ${enrolled.api_key}` },
      env,
    });
    expect(pushed.status).toBe(200);
    expect(((await pushed.json()) as { result: string }).result).toBe("delivered");
  });
});
