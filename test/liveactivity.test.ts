import { afterEach, describe, expect, it, vi } from "vitest";
import { TOKEN, apple, call, freshKey, makeEnv, mockApple, ok } from "./helpers.ts";

afterEach(() => {
	vi.restoreAllMocks();
});

const APP = "com.canopysf.CanopyControl";

async function allowed(over: Record<string, string> = {}) {
	const { id, key } = await freshKey("la");
	return { id, key, e: makeEnv({ CANOPY_APNS_LIVEACTIVITY_TOPICS: `someone:com.x.Y,${id}:${APP}`, ...over }) };
}

const update = (over: Record<string, unknown> = {}) => ({
	device_token: TOKEN,
	bundle_id: APP,
	event: "update",
	content_state: { progress: 0.5, label: "Downloading" },
	...over,
});
const start = (over: Record<string, unknown> = {}) =>
	update({ event: "start", attributes_type: "DownloadAttributes", attributes: {}, alert: { title: "Started", body: "" }, ...over });

describe("POST /v1/liveactivity", () => {
	it("is off for everyone by default", async () => {
		const { key } = await freshKey();
		const r = await call("/v1/liveactivity", { method: "POST", key, json: update() });
		expect(r.status).toBe(403);
		expect((await r.json()).detail).toMatch(/does not accept Live Activity pushes from any instance/);
	});

	it("names the pair the operator would add", async () => {
		const { id, key } = await freshKey();
		const r = await call("/v1/liveactivity", { method: "POST", key, json: update() }, makeEnv({ CANOPY_APNS_LIVEACTIVITY_TOPICS: "x:com.a.B" }));
		expect(r.status).toBe(403);
		expect((await r.json()).detail).toContain(`\`${id}:${APP}\``);
	});

	it("maps fields into aps and sets the Live Activity headers", async () => {
		const calls = mockApple(ok);
		const { key, e } = await allowed();
		const r = await call(
			"/v1/liveactivity",
			{
				method: "POST",
				key,
				json: update({
					event: "end",
					environment: "sandbox",
					timestamp: 1760000000,
					stale_date: 1760003600,
					dismissal_date: 1760000900,
					relevance_score: 50,
					priority: 5,
					expiration: 1760009999,
					alert: { title: "Done", body: "All set" },
				}),
			},
			e,
		);
		expect(await r.json()).toMatchObject({ result: "delivered" });
		const [c] = calls as [(typeof calls)[0]];
		expect(c.url).toBe(`https://api.sandbox.push.apple.com/3/device/${TOKEN}`);
		expect(c.headers).toMatchObject({
			"apns-topic": `${APP}.push-type.liveactivity`,
			"apns-push-type": "liveactivity",
			"apns-priority": "5",
			"apns-expiration": "1760009999",
		});
		expect(c.body).toEqual({
			aps: {
				timestamp: 1760000000,
				event: "end",
				"content-state": { progress: 0.5, label: "Downloading" },
				alert: { title: "Done", body: "All set" },
				"stale-date": 1760003600,
				"dismissal-date": 1760000900,
				"relevance-score": 50,
			},
		});
	});

	it("starts an activity, stamping the time when none is given", async () => {
		const calls = mockApple(ok);
		const { key, e } = await allowed();
		await call("/v1/liveactivity", { method: "POST", key, json: start() }, e);
		const aps = (calls[0]?.body as { aps: Record<string, unknown> }).aps;
		expect(aps).toMatchObject({ event: "start", "attributes-type": "DownloadAttributes", attributes: {} });
		expect(Math.abs((aps.timestamp as number) - Date.now() / 1000)).toBeLessThan(5);
		expect(calls[0]?.headers["apns-priority"]).toBe("10");
		expect(calls[0]?.headers["apns-expiration"]).toBe("0");
	});

	it("enforces required-iff-start", async () => {
		const { key, e } = await allowed();
		for (const [json, pattern] of [
			[start({ attributes_type: undefined }), /start event requires attributes_type/],
			[update({ event: "start" }), /requires attributes_type, attributes, alert/],
			[update({ attributes: {} }), /attributes may only be sent with a start event/],
			[update({ dismissal_date: 1 }), /dismissal_date may only be sent with an end event/],
			[update({ event: "pause" }), /event must be/],
			[update({ content_state: undefined }), /content_state is required/],
			[update({ priority: 7 }), /priority must be 5 or 10/],
			[update({ priority: null }), /priority must be 5 or 10/],
			[update({ bundle_id: "nodots" }), /bundle_id/],
			[update({ alert: { title: "x", body: "y", sound: "z" } }), /Unknown field: sound/],
			[update({ sound: "default" }), /Unknown field: sound/],
		] as const) {
			const r = await call("/v1/liveactivity", { method: "POST", key, json }, e);
			expect(r.status, JSON.stringify(json)).toBe(422);
			expect((await r.json()).detail).toMatch(pattern);
		}
	});

	it("refuses a payload over 4096 bytes without spending budget", async () => {
		const calls = mockApple(ok);
		const { key, e } = await allowed({ CANOPY_APNS_RATE_BURST: "1" });
		const big = await call("/v1/liveactivity", { method: "POST", key, json: update({ content_state: { blob: "é".repeat(2100) } }) }, e);
		expect(big.status).toBe(422);
		expect((await big.json()).detail).toMatch(/\d+ bytes once encoded/);
		expect((await call("/v1/liveactivity", { method: "POST", key, json: update() }, e)).status).toBe(200);
		expect(calls).toHaveLength(1);
	});

	it("shares the push budget with /v1/push", async () => {
		mockApple(ok);
		const { key, e } = await allowed({ CANOPY_APNS_RATE_LIMIT: "1", CANOPY_APNS_RATE_BURST: "1" });
		expect((await call("/v1/push", { method: "POST", key, json: { device_token: TOKEN, title: "x" } }, e)).status).toBe(200);
		expect((await call("/v1/liveactivity", { method: "POST", key, json: update() }, e)).status).toBe(429);
	});

	it("reports BadDeviceToken as failed, not unregistered", async () => {
		const { key, e } = await allowed();
		mockApple(apple(400, "BadDeviceToken"));
		expect(await (await call("/v1/liveactivity", { method: "POST", key, json: update() }, e)).json()).toMatchObject({
			result: "failed",
			reason: "BadDeviceToken",
		});
		vi.restoreAllMocks();
		mockApple(apple(410, "Unregistered"));
		expect((await (await call("/v1/liveactivity", { method: "POST", key, json: update() }, e)).json()).result).toBe("unregistered");
	});

	it("leaves /v1/push on the relay's own topic whatever the allow-list says", async () => {
		const calls = mockApple(ok);
		const { key, e } = await allowed();
		await call("/v1/push", { method: "POST", key, json: { device_token: TOKEN, title: "x" } }, e);
		expect(calls[0]?.headers["apns-topic"]).toBe("com.example.canopy");
	});
});
