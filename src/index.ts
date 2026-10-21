/**
 * The relay: a handful of endpoints and no database.
 *
 * Check the API key, spend a rate-limit token, build an alert (or Live
 * Activity) payload, sign a JWT, POST it to Apple, report what happened.
 *
 * The thing the isolation story rests on: **the relay never stores a device
 * token and never learns which instance a device belongs to.** An instance can
 * only send to devices whose tokens it already holds, and it only holds tokens
 * its own users gave it. There is no routing table to get wrong.
 *
 * Deliberately absent, for the same reason: any endpoint that lists tokens,
 * looks one up, or reports whether one is known.
 */

import {
	ApnsConfigError,
	type SendResult,
	LIVE_ACTIVITY_DEAD_TOKEN_REASONS,
	LIVE_ACTIVITY_TOPIC_SUFFIX,
	buildLiveActivityPayload,
	buildPayload,
	deliver,
	encodedPayloadSize,
	importSigningKey,
} from "./apns.ts";
import { type ApnsCredentials, ConfigError, type Env, MAX_LIVE_ACTIVITY_PAYLOAD_BYTES, type Settings, loadSettings } from "./config.ts";
import { type Instance, InvalidKey, generateInstanceId, mint, verify } from "./keys.ts";
import { renderLanding, wantsHtml } from "./landing.ts";
import { spend } from "./ratelimit.ts";
import { Invalid, parseLiveActivity, parsePush } from "./validate.ts";

export { RateLimiter } from "./ratelimit.ts";

// Not exported: the main module's named exports must all be handlers or classes,
// or workerd refuses to start the Worker.
const VERSION = "2.0.0";

class HttpError extends Error {
	readonly status: number;
	readonly detail: string;
	readonly headers: Record<string, string>;

	constructor(status: number, detail: string, headers: Record<string, string> = {}) {
		super(detail);
		this.status = status;
		this.detail = detail;
		this.headers = headers;
	}
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});
}

function log(fields: Record<string, unknown>): void {
	console.log(JSON.stringify(fields));
}

const settingsCache = new WeakMap<Env, Settings | ConfigError>();

function settingsFor(env: Env): Settings {
	let cached = settingsCache.get(env);
	if (cached === undefined) {
		try {
			cached = loadSettings(env);
		} catch (err) {
			if (!(err instanceof ConfigError)) throw err;
			cached = err;
		}
		settingsCache.set(env, cached);
	}
	if (cached instanceof ConfigError) throw cached;
	return cached;
}

const UNAUTHORIZED = { "www-authenticate": "Bearer" };

async function authenticate(request: Request, settings: Settings): Promise<Instance> {
	// Bearer only, and every refusal past the header check reads the same,
	// whether the key was malformed, forged or revoked.
	const header = request.headers.get("authorization") ?? "";
	const space = header.indexOf(" ");
	const scheme = space < 0 ? header : header.slice(0, space);
	const value = space < 0 ? "" : header.slice(space + 1).trim();
	if (scheme.toLowerCase() !== "bearer" || !value) {
		throw new HttpError(401, "Send your relay API key as `Authorization: Bearer <key>`.", UNAUTHORIZED);
	}
	let instance: Instance;
	try {
		instance = await verify(value, settings.signingSecret);
	} catch (err) {
		if (err instanceof InvalidKey) throw new HttpError(401, "This relay API key is not valid.", UNAUTHORIZED);
		throw err;
	}
	if (settings.revoked.has(instance.id)) {
		log({ msg: "refused a push from a revoked instance", instance: instance.id });
		throw new HttpError(401, "This relay API key is not valid.", UNAUTHORIZED);
	}
	return instance;
}

async function readJson(request: Request): Promise<unknown> {
	try {
		return await request.json();
	} catch {
		throw new HttpError(422, "The request body must be valid JSON.");
	}
}

/** One bucket for both push endpoints: each is one request to Apple. */
async function spendPushBudget(env: Env, settings: Settings, instance: Instance): Promise<void> {
	const decision = await spend(env, `push:${instance.id}`, settings.ratePerMinute, settings.rateBurst);
	if (!decision.allowed) {
		log({ msg: "rate-limited", instance: instance.id });
		throw new HttpError(429, "Too many notifications. Slow down and try again shortly.", {
			"retry-after": String(decision.retryAfterSeconds),
		});
	}
}

function requireCredentials(settings: Settings): ApnsCredentials {
	if (settings.apns === null) {
		throw new HttpError(
			503,
			"This relay has no APNs signing key configured yet. Nothing is wrong with " +
				"your API key; the relay operator has to fix this.",
		);
	}
	return settings.apns;
}

async function send(run: () => Promise<SendResult>): Promise<SendResult> {
	try {
		return await run();
	} catch (err) {
		if (!(err instanceof ApnsConfigError)) throw err;
		console.error(JSON.stringify({ msg: "APNs credentials are unusable", reason: err.message }));
		throw new HttpError(503, "This relay's APNs signing key is not usable. The relay operator has to fix this.");
	}
}

function pushResponse(result: SendResult): Response {
	return json({ result: result.result, reason: result.reason, apns_id: result.apnsId });
}

async function health(settings: Settings): Promise<Response> {
	if (settings.apns !== null) {
		// The Python relay parsed the key at startup and refused to boot on a
		// bad one. A Worker has no startup, so /health is where it is checked.
		try {
			await importSigningKey(settings.apns.privateKeyPem);
		} catch (err) {
			if (err instanceof ApnsConfigError) throw new HttpError(503, err.message);
			throw err;
		}
	}
	return json({ status: "ok", apns: settings.apns ? "configured" : "unconfigured" });
}

async function enroll(request: Request, env: Env, settings: Settings): Promise<Response> {
	if (!settings.enrollmentEnabled) {
		throw new HttpError(403, "This relay is not issuing new keys. Ask its operator for one.");
	}
	// Cloudflare sets this to the real client; nothing upstream can forge it.
	const source = request.headers.get("cf-connecting-ip") ?? "unknown";
	const decision = await spend(env, `enroll:${source}`, settings.enrollmentPerHour / 60, settings.enrollmentBurst);
	if (!decision.allowed) {
		log({ msg: "rate-limited enrollment", source });
		throw new HttpError(429, "Too many enrollments from this address. Try again shortly.", {
			"retry-after": String(decision.retryAfterSeconds),
		});
	}

	const instanceId = generateInstanceId();
	const apiKey = await mint(instanceId, settings.signingSecret);
	// The id, never the key.
	log({ msg: "enrolled", instance: instanceId });
	return json(
		{
			instance_id: instanceId,
			api_key: apiKey,
			bundle_id: settings.apns?.bundleId ?? null,
			ready: settings.apns !== null,
		},
		201,
	);
}

async function verifyKey(request: Request, settings: Settings): Promise<Response> {
	// Not rate-limited: a settings page that costs an admin their notification
	// budget to load is a bad settings page.
	const instance = await authenticate(request, settings);
	return json({
		ok: true,
		instance: instance.id,
		bundle_id: settings.apns?.bundleId ?? null,
		ready: settings.apns !== null,
		rate_limit_per_minute: settings.ratePerMinute,
	});
}

/**
 * Always 200 when Apple answered, whatever Apple said. Non-2xx is reserved for
 * the relay's own problems, so `unregistered` is never buried in a 5xx.
 */
async function push(request: Request, env: Env, settings: Settings): Promise<Response> {
	const instance = await authenticate(request, settings);
	const notification = parsePush(await readJson(request));
	await spendPushBudget(env, settings, instance);
	const credentials = requireCredentials(settings);

	const result = await send(() =>
		deliver(credentials, {
			deviceToken: notification.deviceToken,
			payload: buildPayload(notification),
			environment: notification.environment,
			pushType: "alert",
			topic: credentials.bundleId,
			// Deliver now, and do not store-and-retry: a notification about
			// something that happened ten minutes ago is not worth a late wake.
			priority: 10,
			expiration: 0,
			collapseId: notification.collapseId,
		}),
	);

	// Instance and outcome, never the device token or the text.
	log({
		msg: "push",
		instance: instance.id,
		env: notification.environment,
		result: result.result,
		reason: result.reason,
	});
	return pushResponse(result);
}

/**
 * Same contract as /v1/push, but the topic is the caller's to name, so it is
 * checked against CANOPY_APNS_LIVEACTIVITY_TOPICS before any budget is spent.
 */
async function liveActivity(request: Request, env: Env, settings: Settings): Promise<Response> {
	const instance = await authenticate(request, settings);
	const update = parseLiveActivity(await readJson(request));

	if (!settings.liveActivityTopics.has(`${instance.id}:${update.bundleId}`)) {
		log({ msg: "refused a live activity push", instance: instance.id, bundle: update.bundleId });
		throw new HttpError(
			403,
			settings.liveActivityTopics.size === 0
				? "This relay does not accept Live Activity pushes from any instance. The relay " +
						"operator enables them per instance and bundle id in CANOPY_APNS_LIVEACTIVITY_TOPICS."
				: `Instance ${instance.id} may not send Live Activity pushes to ${update.bundleId}. ` +
						`The relay operator has to add \`${instance.id}:${update.bundleId}\` to ` +
						"CANOPY_APNS_LIVEACTIVITY_TOPICS.",
		);
	}

	const payload = buildLiveActivityPayload({
		...update,
		timestamp: update.timestamp ?? Math.floor(Date.now() / 1000),
	});
	const size = encodedPayloadSize(payload);
	if (size > MAX_LIVE_ACTIVITY_PAYLOAD_BYTES) {
		throw new HttpError(
			422,
			`The Live Activity payload is ${size} bytes once encoded; APNs accepts at most ` +
				`${MAX_LIVE_ACTIVITY_PAYLOAD_BYTES}. Trim content_state or attributes.`,
		);
	}

	await spendPushBudget(env, settings, instance);
	const credentials = requireCredentials(settings);

	const result = await send(() =>
		deliver(credentials, {
			deviceToken: update.deviceToken,
			payload,
			environment: update.environment,
			pushType: "liveactivity",
			topic: `${update.bundleId}${LIVE_ACTIVITY_TOPIC_SUFFIX}`,
			priority: update.priority,
			expiration: update.expiration,
			deadTokenReasons: LIVE_ACTIVITY_DEAD_TOKEN_REASONS,
		}),
	);

	log({
		msg: "liveactivity",
		instance: instance.id,
		bundle: update.bundleId,
		env: update.environment,
		event: update.event,
		result: result.result,
		reason: result.reason,
	});
	return pushResponse(result);
}

function root(request: Request, settings: Settings): Response {
	if (wantsHtml(request)) {
		const colo = (request.cf as { colo?: string } | undefined)?.colo ?? null;
		return new Response(
			renderLanding({
				version: VERSION,
				apnsConfigured: settings.apns !== null,
				enrollmentEnabled: settings.enrollmentEnabled,
				ratePerMinute: settings.ratePerMinute,
				colo,
			}),
			{ headers: { "content-type": "text/html; charset=utf-8" } },
		);
	}
	return json({
		service: "canopy-apns",
		description: "APNs forwarder for self-hosted Canopy+ instances.",
		version: VERSION,
	});
}

type Handler = (request: Request, env: Env, settings: Settings) => Response | Promise<Response>;

const ROUTES: Record<string, Partial<Record<string, Handler>>> = {
	"/": { GET: (r, _e, s) => root(r, s) },
	"/health": { GET: (_r, _e, s) => health(s) },
	"/v1/instances": { POST: enroll },
	"/v1/verify": { GET: (r, _e, s) => verifyKey(r, s) },
	"/v1/push": { POST: push },
	"/v1/liveactivity": { POST: liveActivity },
};

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const { pathname } = new URL(request.url);
		const methods = ROUTES[pathname];
		if (!methods) return json({ detail: "Not Found" }, 404);
		const handler = methods[request.method];
		if (!handler) {
			return json({ detail: "Method Not Allowed" }, 405, { allow: Object.keys(methods).join(", ") });
		}

		try {
			return await handler(request, env, settingsFor(env));
		} catch (err) {
			if (err instanceof HttpError) return json({ detail: err.detail }, err.status, err.headers);
			if (err instanceof Invalid) return json({ detail: err.message }, 422);
			if (err instanceof ConfigError) {
				console.error(JSON.stringify({ msg: "relay misconfigured", reason: err.message }));
				return json({ detail: `This relay is misconfigured: ${err.message}` }, 503);
			}
			console.error(JSON.stringify({ msg: "unhandled error", error: String(err) }));
			return json({ detail: "Internal Server Error" }, 500);
		}
	},
} satisfies ExportedHandler<Env>;
