import { afterEach, describe, expect, it, vi } from "vitest";
import { APNS, BUNDLE, SECRET, TOKEN, apple, call, freshKey, makeEnv, mockApple, ok, verifyJwt } from "./helpers.ts";

afterEach(() => {
	vi.restoreAllMocks();
});

const push = (over: Record<string, unknown> = {}) => ({ device_token: TOKEN, title: "The End of Oak Street (2026)", body: "Requested by Robin", ...over });

describe("meta", () => {
	it("reports readiness on /health", async () => {
		expect(await (await call("/health")).json()).toEqual({ status: "ok", apns: "configured" });
		const bare = makeEnv({ CANOPY_APNS_PRIVATE_KEY: "" });
		expect(await (await call("/health", {}, bare)).json()).toEqual({ status: "ok", apns: "unconfigured" });
	});

	it("fails /health on a key that will not import", async () => {
		const r = await call("/health", {}, makeEnv({ CANOPY_APNS_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" }));
		expect(r.status).toBe(503);
		expect((await r.json()).detail).toMatch(/not a usable P-256 key/);
	});

	it("answers every endpoint with 503 while the signing secret is a placeholder", async () => {
		const e = makeEnv({ CANOPY_APNS_SIGNING_SECRET: "set this in Coolify" });
		for (const [path, method] of [["/health", "GET"], ["/v1/instances", "POST"], ["/v1/push", "POST"]] as const) {
			const r = await call(path, { method }, e);
			expect(r.status).toBe(503);
			expect((await r.json()).detail).toMatch(/misconfigured.*whitespace/);
		}
	});

	it("gives scripts JSON and browsers a page at /", async () => {
		expect((await (await call("/")).json()).service).toBe("canopy-apns");
		const page = await call("/", { headers: { accept: "text/html" } });
		expect(page.headers.get("content-type")).toMatch(/text\/html/);
		expect(await page.text()).toMatch(/APNs signing key<\/td><td class="v">configured/);
	});

	it("404s unknown paths and 405s wrong methods", async () => {
		expect((await call("/nope")).status).toBe(404);
		const r = await call("/v1/push");
		expect(r.status).toBe(405);
		expect(r.headers.get("allow")).toBe("POST");
	});
});

describe("authentication", () => {
	it("refuses a missing or non-Bearer header", async () => {
		for (const headers of [{}, { authorization: "Basic abc" }, { authorization: "Bearer " }] as Record<string, string>[]) {
			const r = await call("/v1/push", { method: "POST", headers, json: push() });
			expect(r.status).toBe(401);
			expect(r.headers.get("www-authenticate")).toBe("Bearer");
		}
	});

	it("reads the same for forged, malformed and revoked keys", async () => {
		const { id, key } = await freshKey();
		const e = makeEnv({ CANOPY_APNS_REVOKED_INSTANCES: `other,${id.toUpperCase()}` });
		const details = new Set<string>();
		for (const k of [`${key.slice(0, -1)}x`, "canopy_x", "nonsense", key]) {
			const r = await call("/v1/verify", { key: k }, e);
			expect(r.status).toBe(401);
			details.add((await r.json()).detail);
		}
		expect([...details]).toEqual(["This relay API key is not valid."]);
	});
});

describe("GET /v1/verify", () => {
	it("reports the instance and the topic", async () => {
		const { id, key } = await freshKey();
		expect(await (await call("/v1/verify", { key })).json()).toEqual({
			ok: true,
			instance: id,
			bundle_id: BUNDLE,
			ready: true,
			rate_limit_per_minute: 120,
		});
	});

	it("separates a good key from an unready relay", async () => {
		const { key } = await freshKey();
		const r = await call("/v1/verify", { key }, makeEnv({ CANOPY_APNS_TEAM_ID: "" }));
		expect(r.status).toBe(200);
		expect(await r.json()).toMatchObject({ ok: true, bundle_id: null, ready: false });
	});
});

describe("POST /v1/push", () => {
	it("forwards to Apple with pinned headers, payload and a valid provider token", async () => {
		const calls = mockApple(ok);
		const { key } = await freshKey();
		const r = await call("/v1/push", { method: "POST", key, json: push({ data: { imdb_id: "tt1" }, collapse_id: "req-7" }) });
		expect(r.status).toBe(200);
		expect(await r.json()).toEqual({ result: "delivered", reason: null, apns_id: "11111111-2222-3333-4444-555555555555" });

		expect(calls).toHaveLength(1);
		const [c] = calls as [(typeof calls)[0]];
		expect(c.url).toBe(`https://api.push.apple.com/3/device/${TOKEN}`);
		expect(c.headers).toMatchObject({
			"apns-topic": BUNDLE,
			"apns-push-type": "alert",
			"apns-priority": "10",
			"apns-expiration": "0",
			"apns-collapse-id": "req-7",
			"content-type": "application/json",
		});
		expect(c.body).toEqual({
			aps: { alert: { title: "The End of Oak Street (2026)", body: "Requested by Robin" }, sound: "default" },
			canopy: { imdb_id: "tt1" },
		});

		const jwt = c.headers.authorization?.replace(/^bearer /, "") ?? "";
		const { header, claims } = await verifyJwt(jwt);
		expect(header).toEqual({ alg: "ES256", kid: APNS.CANOPY_APNS_KEY_ID });
		expect(claims).toMatchObject({ iss: APNS.CANOPY_APNS_TEAM_ID });
	});

	it("reuses the provider token across pushes", async () => {
		const calls = mockApple(ok);
		const { key } = await freshKey();
		await call("/v1/push", { method: "POST", key, json: push() });
		await call("/v1/push", { method: "POST", key, json: push() });
		expect(calls[0]?.headers.authorization).toBe(calls[1]?.headers.authorization);
	});

	it("accepts the old subtitle name, and refuses both at once", async () => {
		const calls = mockApple(ok);
		const { key } = await freshKey();
		const { body: _, ...rest } = push();
		await call("/v1/push", { method: "POST", key, json: { ...rest, subtitle: "Old name" } });
		expect(calls[0]?.body).toMatchObject({ aps: { alert: { body: "Old name" } } });
		const r = await call("/v1/push", { method: "POST", key, json: push({ subtitle: "x" }) });
		expect(r.status).toBe(422);
	});

	it("forwards badges, including 0, and omits an absent one", async () => {
		const calls = mockApple(ok);
		const { key } = await freshKey();
		for (const badge of [3, 0, undefined, null]) {
			await call("/v1/push", { method: "POST", key, json: push(badge === undefined ? {} : { badge }) });
		}
		expect(calls.map((c) => (c.body as { aps: { badge?: number } }).aps.badge)).toEqual([3, 0, undefined, undefined]);
		expect("badge" in (calls[2]?.body as { aps: object }).aps).toBe(false);
	});

	it("sends a sandbox token to the sandbox host", async () => {
		const calls = mockApple(ok);
		const { key } = await freshKey();
		await call("/v1/push", { method: "POST", key, json: push({ environment: "sandbox" }) });
		expect(calls[0]?.url).toBe(`https://api.sandbox.push.apple.com/3/device/${TOKEN}`);
	});

	it("reports dead tokens as 200 unregistered, and other refusals as 200 failed", async () => {
		const { key } = await freshKey();
		for (const [status, reason, result] of [
			[410, "Unregistered", "unregistered"],
			[400, "BadDeviceToken", "unregistered"],
			[400, "DeviceTokenNotForTopic", "unregistered"],
			[400, "PayloadTooLarge", "failed"],
			[403, "InvalidProviderToken", "failed"],
		] as const) {
			mockApple(apple(status, reason));
			const r = await call("/v1/push", { method: "POST", key, json: push() });
			expect(r.status).toBe(200);
			expect(await r.json()).toEqual({ result, reason, apns_id: "aaaa" });
			vi.restoreAllMocks();
		}
	});

	it("retries once after an expired provider token, with a fresh one", async () => {
		const calls = mockApple(apple(403, "ExpiredProviderToken"), ok);
		const { key } = await freshKey();
		expect((await (await call("/v1/push", { method: "POST", key, json: push() })).json()).result).toBe("delivered");
		expect(calls).toHaveLength(2);
		expect(calls[0]?.headers.authorization).not.toBe(calls[1]?.headers.authorization);
	});

	it("retries Apple throttling or faulting once, and no more", async () => {
		const { key } = await freshKey();
		let calls = mockApple(apple(503, "ServiceUnavailable"), ok);
		expect((await (await call("/v1/push", { method: "POST", key, json: push() })).json()).result).toBe("delivered");
		expect(calls).toHaveLength(2);
		vi.restoreAllMocks();
		calls = mockApple(apple(429, "TooManyRequests"));
		expect((await (await call("/v1/push", { method: "POST", key, json: push() })).json()).result).toBe("failed");
		expect(calls).toHaveLength(2);
		vi.restoreAllMocks();
		calls = mockApple(apple(400, "BadTopic"));
		await call("/v1/push", { method: "POST", key, json: push() });
		expect(calls).toHaveLength(1);
	});

	it("reports an unreachable Apple as failed", async () => {
		mockApple(() => {
			throw new TypeError("network down");
		});
		const { key } = await freshKey();
		expect(await (await call("/v1/push", { method: "POST", key, json: push() })).json()).toEqual({
			result: "failed",
			reason: "network down",
			apns_id: null,
		});
	});

	it("is a 503 on a relay without a signing key", async () => {
		const { key } = await freshKey();
		const r = await call("/v1/push", { method: "POST", key, json: push() }, makeEnv({ CANOPY_APNS_BUNDLE_ID: "" }));
		expect(r.status).toBe(503);
		expect((await r.json()).detail).toMatch(/Nothing is wrong with your API key/);
	});

	it("refuses shapes it will not send", async () => {
		const { key } = await freshKey();
		const bad: [unknown, RegExp][] = [
			[push({ aps: { "content-available": 1 } }), /Unknown field: aps/],
			[push({ device_token: "zz" }), /device_token/],
			[push({ device_token: "a".repeat(201) }), /device_token/],
			[push({ title: "" }), /title/],
			[push({ title: "x".repeat(201) }), /title/],
			[push({ title: 5 }), /title must be a string/],
			[push({ badge: -1 }), /badge/],
			[push({ badge: 1.5 }), /badge/],
			[push({ environment: "staging" }), /environment/],
			[push({ data: [1] }), /data must be a JSON object/],
			[push({ data: { blob: "x".repeat(1100) } }), /data is \d+ bytes/],
			[push({ collapse_id: "c".repeat(65) }), /collapse_id/],
			[[1, 2], /JSON object/],
		];
		for (const [json, pattern] of bad) {
			const r = await call("/v1/push", { method: "POST", key, json });
			expect(r.status, JSON.stringify(json).slice(0, 80)).toBe(422);
			expect((await r.json()).detail).toMatch(pattern);
		}
		const r = await call("/v1/push", { method: "POST", key, body: "{nope" });
		expect(r.status).toBe(422);
	});

	it("counts title length in characters, not UTF-16 units", async () => {
		mockApple(ok);
		const { key } = await freshKey();
		const r = await call("/v1/push", { method: "POST", key, json: push({ title: "🎬".repeat(200) }) });
		expect(r.status).toBe(200);
	});

	it("rate-limits per instance with a Retry-After, and verify spends nothing", async () => {
		mockApple(ok);
		const e = makeEnv({ CANOPY_APNS_RATE_LIMIT: "1", CANOPY_APNS_RATE_BURST: "2" });
		const { key } = await freshKey();
		const other = await freshKey();
		for (let i = 0; i < 3; i++) expect((await call("/v1/verify", { key }, e)).status).toBe(200);
		expect((await call("/v1/push", { method: "POST", key, json: push() }, e)).status).toBe(200);
		expect((await call("/v1/push", { method: "POST", key, json: push() }, e)).status).toBe(200);
		const r = await call("/v1/push", { method: "POST", key, json: push() }, e);
		expect(r.status).toBe(429);
		expect(Number(r.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
		expect((await call("/v1/push", { method: "POST", key: other.key, json: push() }, e)).status).toBe(200);
	});
});

describe("POST /v1/instances", () => {
	const from = (ip: string) => ({ method: "POST", headers: { "cf-connecting-ip": ip } });
	const ip = () => `203.0.113.${Math.floor(Math.random() * 250)}-${Date.now()}-${Math.random()}`;

	it("issues a working key without authentication", async () => {
		const r = await call("/v1/instances", from(ip()));
		expect(r.status).toBe(201);
		const body = await r.json<{ instance_id: string; api_key: string }>();
		expect(body).toMatchObject({ bundle_id: BUNDLE, ready: true });
		expect(body.api_key.startsWith(`canopy_${body.instance_id}_`)).toBe(true);
		expect((await (await call("/v1/verify", { key: body.api_key })).json()).instance).toBe(body.instance_id);
	});

	it("issues distinct identities, even to an unready relay", async () => {
		const e = makeEnv({ CANOPY_APNS_PRIVATE_KEY: "" });
		const a = await (await call("/v1/instances", from(ip()), e)).json<{ instance_id: string; ready: boolean }>();
		const b = await (await call("/v1/instances", from(ip()), e)).json<{ instance_id: string }>();
		expect(a.instance_id).not.toBe(b.instance_id);
		expect(a.ready).toBe(false);
	});

	it("can be switched off", async () => {
		expect((await call("/v1/instances", from(ip()), makeEnv({ CANOPY_APNS_ENROLLMENT_ENABLED: "false" }))).status).toBe(403);
	});

	it("is rate-limited per source address", async () => {
		const e = makeEnv({ CANOPY_APNS_ENROLLMENT_BURST: "2" });
		const address = ip();
		expect((await call("/v1/instances", from(address), e)).status).toBe(201);
		expect((await call("/v1/instances", from(address), e)).status).toBe(201);
		const r = await call("/v1/instances", from(address), e);
		expect(r.status).toBe(429);
		expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(60);
		expect((await call("/v1/instances", from(ip()), e)).status).toBe(201);
	});
});

it("uses the configured secret, so keys minted elsewhere verify", async () => {
	const { mint } = await import("../src/keys.ts");
	expect((await call("/v1/verify", { key: await mint("acme", SECRET) })).status).toBe(200);
});

it("exports nothing from the main module but handlers and classes", async () => {
	// workerd refuses to start a Worker whose main module exports, say, a string.
	const exports = await import("../src/index.ts");
	for (const [name, value] of Object.entries(exports)) {
		expect(typeof value === "function" || name === "default", name).toBe(true);
	}
});
