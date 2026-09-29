import { describe, expect, it } from "vitest";

import {
  ApnsClient,
  ApnsConfigError,
  PRODUCTION_HOST,
  SANDBOX_HOST,
  type TokenSource,
  buildPayload,
  importSigningKey,
  signProviderToken,
} from "../src/apns.ts";
import type { ApnsCredentials } from "../src/config.ts";
import { normalisePrivateKey } from "../src/config.ts";
import { BUNDLE_ID, DEVICE_TOKEN, baseEnv } from "./helpers.ts";

const PEM = normalisePrivateKey(baseEnv.CANOPY_APNS_PRIVATE_KEY ?? "");

const credentials: ApnsCredentials = {
  teamId: "TEAM123456",
  keyId: "KEY1234567",
  bundleId: BUNDLE_ID,
  privateKeyPem: PEM,
};

function segment(raw: string): unknown {
  const padded = raw.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (raw.length % 4)) % 4);
  return JSON.parse(atob(padded));
}

function bytes(raw: string): Uint8Array {
  const padded = raw.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (raw.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

async function publicKeyFor(pem: string): Promise<CryptoKey> {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const { d: _d, ...jwk } = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  return crypto.subtle.importKey("jwk", { ...jwk, key_ops: ["verify"] }, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "verify",
  ]);
}

function toPem(der: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(der)) binary += String.fromCharCode(byte);
  return `-----BEGIN PRIVATE KEY-----\n${btoa(binary)}\n-----END PRIVATE KEY-----\n`;
}

describe("signing", () => {
  it("carries the key id and team, and signs raw r||s that verifies", async () => {
    const token = await signProviderToken(credentials, 1000);
    const [header, claims, signature] = token.split(".") as [string, string, string];

    expect(segment(header)).toEqual({ alg: "ES256", kid: credentials.keyId });
    expect(segment(claims)).toEqual({ iss: credentials.teamId, iat: 1000 });
    // Raw r||s for P-256, not DER: 64 bytes, which is 86 base64url characters.
    expect(signature).toHaveLength(86);

    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await publicKeyFor(PEM),
      bytes(signature),
      new TextEncoder().encode(`${header}.${claims}`),
    );
    expect(valid).toBe(true);
  });

  it("refuses a non-PEM key with an actionable message", async () => {
    await expect(importSigningKey("not a key")).rejects.toThrow(/could not be read/);
    await expect(importSigningKey("not a key")).rejects.toBeInstanceOf(ApnsConfigError);
  });

  it("refuses an RSA key as the wrong kind", async () => {
    const rsa = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const pem = toPem((await crypto.subtle.exportKey("pkcs8", rsa.privateKey)) as ArrayBuffer);
    await expect(importSigningKey(pem)).rejects.toThrow(/elliptic-curve/);
  });
});

describe("the provider-token Durable Object", () => {
  function store() {
    const ns = baseEnv.PROVIDER_TOKEN;
    return ns.get(ns.idFromName(crypto.randomUUID()));
  }

  async function tokenAt(stub: ReturnType<typeof store>, now: number): Promise<string> {
    const result = await stub.getToken(now);
    if (!result.ok) throw new Error(result.error);
    return result.token;
  }

  it("reuses the token within its lifetime; Apple refuses more than one per 20 minutes", async () => {
    const stub = store();
    const first = await tokenAt(stub, 1_000_000);
    expect(await tokenAt(stub, 1_000_000 + 60_000)).toBe(first);
  });

  it("re-mints once the token ages out", async () => {
    const stub = store();
    const first = await tokenAt(stub, 1_000_000);
    expect(await tokenAt(stub, 1_000_000 + 46 * 60_000)).not.toBe(first);
  });

  it("re-mints after an invalidation of the current token", async () => {
    const stub = store();
    const first = await tokenAt(stub, 1_000_000);
    await stub.invalidate(first);
    expect(await tokenAt(stub, 1_001_000)).not.toBe(first);
  });

  it("ignores an invalidation of a token it has already replaced", async () => {
    // Several isolates holding the same stale token all report it; only the
    // first report should cost a mint.
    const stub = store();
    const stale = await tokenAt(stub, 1_000_000);
    await stub.invalidate(stale);
    const fresh = await tokenAt(stub, 1_001_000);
    await stub.invalidate(stale);
    expect(await tokenAt(stub, 1_002_000)).toBe(fresh);
  });

  it("hands every concurrent caller the same token", async () => {
    const stub = store();
    const tokens = await Promise.all(Array.from({ length: 10 }, () => tokenAt(stub, 1_000_000)));
    expect(new Set(tokens).size).toBe(1);
  });
});

describe("the payload", () => {
  it("is a plain alert", () => {
    expect(buildPayload({ title: "A Title", body: "A second line" })).toEqual({
      aps: { alert: { title: "A Title", body: "A second line" }, sound: "default" },
    });
  });

  it("puts the second line in body, because iOS bolds a subtitle", () => {
    const payload = buildPayload({ title: "A Title", body: "A second line" }) as {
      aps: { alert: Record<string, unknown> };
    };
    expect(payload.aps.alert).not.toHaveProperty("subtitle");
  });

  it("makes badge a sibling of alert, not a child", () => {
    const payload = buildPayload({ title: "T", badge: 3 }) as {
      aps: { badge: number; alert: Record<string, unknown> };
    };
    expect(payload.aps.badge).toBe(3);
    expect(payload.aps.alert).not.toHaveProperty("badge");
  });

  it("sends a zero badge, because zero is what clears the icon", () => {
    expect((buildPayload({ title: "T", badge: 0 }) as { aps: { badge: number } }).aps.badge).toBe(0);
  });

  it("leaves the payload untouched when there is no badge", () => {
    expect(buildPayload({ title: "A Title", body: "A second line", badge: null })).toEqual({
      aps: { alert: { title: "A Title", body: "A second line" }, sound: "default" },
    });
  });

  it("puts instance data beside aps, not inside it", () => {
    const payload = buildPayload({ title: "T", data: { imdb_id: "tt1" } }) as Record<string, Record<string, unknown>>;
    expect(payload.canopy).toEqual({ imdb_id: "tt1" });
    expect(payload.aps).not.toHaveProperty("canopy");
  });

  it("omits an absent second line rather than sending it empty", () => {
    expect(buildPayload({ title: "T" })).toEqual({ aps: { alert: { title: "T" }, sound: "default" } });
  });
});

describe("sending", () => {
  /** An in-memory TokenSource: mints a new token after each invalidation. */
  function tokens(): TokenSource {
    let generation = 0;
    return {
      get: async () => `token-${generation}`,
      invalidate: async (token) => {
        if (token === `token-${generation}`) generation += 1;
      },
    };
  }

  type Reply = Response | Error;

  function sender(...replies: Reply[]) {
    const calls: { url: string; init: RequestInit }[] = [];
    const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      const reply = replies.length > 1 ? replies.shift()! : replies[0]!;
      if (reply instanceof Error) throw reply;
      return reply.clone();
    }) as typeof fetch;
    const client = new ApnsClient(credentials, { tokens: tokens(), fetch: fakeFetch });
    const header = (i: number, name: string) => new Headers(calls[i]!.init.headers).get(name);
    return { client, calls, header };
  }

  const apple = (status: number, body?: unknown, headers: Record<string, string> = {}) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status, headers });

  it("reports a 200 as delivered, with the headers Apple needs", async () => {
    const { client, calls, header } = sender(apple(200, undefined, { "apns-id": "abc-123" }));

    const result = await client.send({ deviceToken: DEVICE_TOKEN, title: "T" });

    expect(result.outcome).toBe("delivered");
    expect(result.apnsId).toBe("abc-123");
    expect(calls[0]!.url).toBe(`${PRODUCTION_HOST}/3/device/${DEVICE_TOKEN}`);
    expect(header(0, "apns-topic")).toBe(BUNDLE_ID);
    expect(header(0, "apns-push-type")).toBe("alert");
    expect(header(0, "apns-priority")).toBe("10");
    expect(header(0, "apns-expiration")).toBe("0");
    expect(header(0, "authorization")).toBe("bearer token-0");
  });

  it("sends sandbox tokens to the sandbox host", async () => {
    const { client, calls } = sender(apple(200));
    const result = await client.send({ deviceToken: DEVICE_TOKEN, title: "T", environment: "sandbox" });
    expect(result.outcome).toBe("delivered");
    expect(calls[0]!.url).toBe(`${SANDBOX_HOST}/3/device/${DEVICE_TOKEN}`);
  });

  it("reports a 410 as unregistered, so the instance can delete its dead token", async () => {
    const { client } = sender(apple(410, { reason: "Unregistered" }));
    const result = await client.send({ deviceToken: DEVICE_TOKEN, title: "T" });
    expect(result.outcome).toBe("unregistered");
    expect(result.reason).toBe("Unregistered");
  });

  it("reports BadDeviceToken as unregistered too", async () => {
    const { client } = sender(apple(400, { reason: "BadDeviceToken" }));
    expect((await client.send({ deviceToken: DEVICE_TOKEN, title: "T" })).outcome).toBe("unregistered");
  });

  it("re-mints an expired provider token and retries", async () => {
    const { client, calls, header } = sender(apple(403, { reason: "ExpiredProviderToken" }), apple(200));

    const result = await client.send({ deviceToken: DEVICE_TOKEN, title: "T" });

    expect(result.outcome).toBe("delivered");
    expect(calls).toHaveLength(2);
    expect(header(0, "authorization")).not.toBe(header(1, "authorization"));
  });

  it("gives throttling exactly one retry", async () => {
    const { client, calls } = sender(apple(429, { reason: "TooManyRequests" }));
    expect((await client.send({ deviceToken: DEVICE_TOKEN, title: "T" })).outcome).toBe("failed");
    expect(calls).toHaveLength(2);
  });

  it("does not retry a bad request; it would fail identically", async () => {
    const { client, calls } = sender(apple(400, { reason: "BadTopic" }));
    expect((await client.send({ deviceToken: DEVICE_TOKEN, title: "T" })).outcome).toBe("failed");
    expect(calls).toHaveLength(1);
  });

  it("reports a transport failure as a failure, not an exception", async () => {
    const { client } = sender(new Error("apple is unreachable"));
    const result = await client.send({ deviceToken: DEVICE_TOKEN, title: "T" });
    expect(result.outcome).toBe("failed");
    expect(result.reason).toContain("unreachable");
  });

  it("forwards a collapse id", async () => {
    const { client, header } = sender(apple(200));
    await client.send({ deviceToken: DEVICE_TOKEN, title: "T", collapseId: "req-7" });
    expect(header(0, "apns-collapse-id")).toBe("req-7");
  });
});
