/**
 * Talking to Apple: provider-token signing and the push.
 *
 * Provider tokens, not certificates: the `.p8` signs a short-lived ES256 JWT
 * that rides as a bearer token on every push.
 *
 * APNs is HTTP/2 only. A Worker's `fetch()` gives no control over the
 * protocol, but Cloudflare's edge negotiates HTTP/2 with Apple on the Worker's
 * behalf — this is what FiveSheepCo/cloudflare-apns2 relies on, and it is
 * known to work only on deployed Workers, *not* under local `wrangler dev` on
 * macOS (cloudflare/workerd#4841). So a real push from the deployed Worker is
 * the test that matters; the suite here mocks Apple.
 *
 * Nothing here knows about instances, API keys or rate limits.
 */

import { APNS_TIMEOUT_MS, type ApnsCredentials } from "./config.ts";

export const PRODUCTION_HOST = "https://api.push.apple.com";
export const SANDBOX_HOST = "https://api.sandbox.push.apple.com";

/**
 * Apple rejects a provider token older than an hour and objects to one minted
 * more often than every 20 minutes. Renewing at 45 sits inside both.
 *
 * The cache is per isolate. A Worker runs in many isolates across many
 * locations, so this is not one token for the whole relay the way it was in
 * one Python process — each warm isolate mints its own. At this relay's volume
 * that is a handful of isolates, and a `TooManyProviderTokenUpdates` is
 * retried once like any other 429. If it ever shows up in the logs, the fix is
 * to move this cache into the RateLimiter Durable Object's storage.
 */
export const PROVIDER_TOKEN_LIFETIME_SECONDS = 45 * 60;

/** Reasons that mean "this device token is dead, stop using it". */
export const DEAD_TOKEN_REASONS: ReadonlySet<string> = new Set([
	"Unregistered",
	"BadDeviceToken",
	"DeviceTokenNotForTopic",
]);

/**
 * The same for Live Activities, minus `BadDeviceToken`: for an activity token
 * that is far more often a sandbox/production mismatch than a dead token.
 */
export const LIVE_ACTIVITY_DEAD_TOKEN_REASONS: ReadonlySet<string> = new Set([
	"Unregistered",
	"DeviceTokenNotForTopic",
]);

export const LIVE_ACTIVITY_TOPIC_SUFFIX = ".push-type.liveactivity";

/** Apple throttling (429) or faulting (500, 503): worth one more attempt. */
const RETRYABLE_STATUSES = new Set([429, 500, 503]);
const EXPIRED_TOKEN_REASON = "ExpiredProviderToken";

export type Environment = "production" | "sandbox";
export type Outcome = "delivered" | "unregistered" | "failed";

export interface SendResult {
	result: Outcome;
	status: number | null;
	reason: string | null;
	apnsId: string | null;
}

/** The configured key is missing or unusable. Written for whoever set it. */
export class ApnsConfigError extends Error {}

const signingKeys = new Map<string, Promise<CryptoKey>>();

/**
 * Import a `.p8` (PKCS#8 PEM) as an ES256 signing key, cached per isolate.
 * A rejected import is not cached, so a fixed secret takes effect on the next
 * request rather than the next isolate.
 */
export function importSigningKey(pem: string): Promise<CryptoKey> {
	let key = signingKeys.get(pem);
	if (!key) {
		key = loadKey(pem);
		signingKeys.set(pem, key);
		key.catch(() => signingKeys.delete(pem));
	}
	return key;
}

async function loadKey(pem: string): Promise<CryptoKey> {
	const match = pem.match(/-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/);
	if (!match) {
		throw new ApnsConfigError(
			"The APNs key could not be read. CANOPY_APNS_PRIVATE_KEY must hold the " +
				"contents of the .p8 file, including the BEGIN and END lines (escaped " +
				"newlines and base64 of the whole file are also accepted).",
		);
	}
	if (match[1] !== "PRIVATE KEY") {
		throw new ApnsConfigError(
			`The APNs key is a "${match[1]}" PEM. Apple's .p8 files are "PRIVATE KEY" ` +
				"(PKCS#8); paste the .p8 exactly as downloaded.",
		);
	}
	try {
		const der = Uint8Array.from(atob((match[2] ?? "").replace(/\s+/g, "")), (c) => c.charCodeAt(0));
		return await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, [
			"sign",
		]);
	} catch {
		throw new ApnsConfigError(
			"The APNs key is not a usable P-256 key. Apple's push keys are ES256 .p8 " +
				"files — this looks like a different kind of key, or a damaged paste.",
		);
	}
}

function b64url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

const encoder = new TextEncoder();

/**
 * Mint one ES256 provider token. WebCrypto's ECDSA signature is already the
 * raw fixed-width `r || s` that JWS wants — the DER-vs-raw trap the Python
 * version had to handle does not exist here.
 */
export async function signProviderToken(credentials: ApnsCredentials, issuedAt: number): Promise<string> {
	const header = b64url(encoder.encode(JSON.stringify({ alg: "ES256", kid: credentials.keyId })));
	const claims = b64url(encoder.encode(JSON.stringify({ iss: credentials.teamId, iat: issuedAt })));
	const input = `${header}.${claims}`;
	const key = await importSigningKey(credentials.privateKeyPem);
	const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(input));
	return `${input}.${b64url(new Uint8Array(signature))}`;
}

const tokens = new Map<string, { token: string; issuedAt: number }>();

function cacheKey(c: ApnsCredentials): string {
	return `${c.teamId}\n${c.keyId}\n${c.privateKeyPem}`;
}

export async function providerToken(credentials: ApnsCredentials, now = Date.now() / 1000): Promise<string> {
	const cached = tokens.get(cacheKey(credentials));
	if (cached && now - cached.issuedAt < PROVIDER_TOKEN_LIFETIME_SECONDS) return cached.token;
	const issuedAt = Math.floor(now);
	const token = await signProviderToken(credentials, issuedAt);
	tokens.set(cacheKey(credentials), { token, issuedAt: now });
	return token;
}

export function invalidateProviderToken(credentials: ApnsCredentials): void {
	tokens.delete(cacheKey(credentials));
}

/** For tests: forget every cached provider token. */
export function resetProviderTokens(): void {
	tokens.clear();
}

/**
 * The APNs body for one alert. Built here rather than forwarded, so no
 * instance can reach into `aps` and send a silent background wake under the
 * operator's key. The second line is `body`, which iOS renders in regular
 * weight; `badge` is tested against null because 0 clears the icon.
 */
export function buildPayload(p: {
	title: string;
	body: string | null;
	badge: number | null;
	data: Record<string, unknown> | null;
}): Record<string, unknown> {
	const alert: Record<string, unknown> = { title: p.title };
	if (p.body) alert.body = p.body;
	const aps: Record<string, unknown> = { alert, sound: "default" };
	if (p.badge !== null) aps.badge = p.badge;
	const payload: Record<string, unknown> = { aps };
	if (p.data && Object.keys(p.data).length > 0) payload.canopy = p.data;
	return payload;
}

/**
 * The APNs body for one Live Activity start, update or end. The caller's
 * `content_state` and `attributes` go inside `aps`, where ActivityKit reads
 * them; every other key is still the relay's. Absent optionals are omitted
 * rather than sent as null.
 */
export function buildLiveActivityPayload(p: {
	event: string;
	timestamp: number;
	contentState: Record<string, unknown>;
	attributesType: string | null;
	attributes: Record<string, unknown> | null;
	alert: { title: string; body: string } | null;
	staleDate: number | null;
	dismissalDate: number | null;
	relevanceScore: number | null;
}): Record<string, unknown> {
	const aps: Record<string, unknown> = {
		timestamp: p.timestamp,
		event: p.event,
		"content-state": p.contentState,
	};
	if (p.attributesType !== null) aps["attributes-type"] = p.attributesType;
	if (p.attributes !== null) aps.attributes = p.attributes;
	if (p.alert !== null) aps.alert = p.alert;
	if (p.staleDate !== null) aps["stale-date"] = p.staleDate;
	if (p.dismissalDate !== null) aps["dismissal-date"] = p.dismissalDate;
	if (p.relevanceScore !== null) aps["relevance-score"] = p.relevanceScore;
	return { aps };
}

/** Bytes on the wire: exactly what `deliver` sends. */
export function encodedPayloadSize(payload: unknown): number {
	return encoder.encode(JSON.stringify(payload)).byteLength;
}

export interface Delivery {
	deviceToken: string;
	payload: Record<string, unknown>;
	environment: Environment;
	pushType: "alert" | "liveactivity";
	topic: string;
	priority: number;
	expiration: number;
	collapseId?: string | null;
	deadTokenReasons?: ReadonlySet<string>;
}

/**
 * Push one payload to one device, retrying once where it helps: a stale
 * provider token (mint a new one) or Apple throttling or faulting. Anything
 * still failing after that would fail identically again.
 */
export async function deliver(credentials: ApnsCredentials, d: Delivery): Promise<SendResult> {
	const host = d.environment === "sandbox" ? SANDBOX_HOST : PRODUCTION_HOST;
	const url = `${host}/3/device/${d.deviceToken}`;
	const headers: Record<string, string> = {
		"apns-topic": d.topic,
		"apns-push-type": d.pushType,
		"apns-priority": String(d.priority),
		"apns-expiration": String(d.expiration),
		"content-type": "application/json",
	};
	if (d.collapseId != null) headers["apns-collapse-id"] = d.collapseId;
	const body = JSON.stringify(d.payload);
	const dead = d.deadTokenReasons ?? DEAD_TOKEN_REASONS;

	let result = await attempt(credentials, url, headers, body, dead);
	const retry =
		result.status !== null &&
		(RETRYABLE_STATUSES.has(result.status) || (result.status === 403 && result.reason === EXPIRED_TOKEN_REASON));
	if (result.result === "failed" && retry) {
		if (result.reason === EXPIRED_TOKEN_REASON) invalidateProviderToken(credentials);
		result = await attempt(credentials, url, headers, body, dead);
	}
	return result;
}

async function attempt(
	credentials: ApnsCredentials,
	url: string,
	pushHeaders: Record<string, string>,
	body: string,
	dead: ReadonlySet<string>,
): Promise<SendResult> {
	// Re-read per attempt, so a retry after an expired token carries the new one.
	const headers = { authorization: `bearer ${await providerToken(credentials)}`, ...pushHeaders };

	let response: Response;
	try {
		response = await fetch(url, {
			method: "POST",
			headers,
			body,
			signal: AbortSignal.timeout(APNS_TIMEOUT_MS),
		});
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		console.warn(JSON.stringify({ msg: "APNs request failed", reason }));
		return { result: "failed", status: null, reason, apnsId: null };
	}

	const apnsId = response.headers.get("apns-id");
	if (response.status === 200) {
		await response.body?.cancel();
		return { result: "delivered", status: 200, reason: null, apnsId };
	}

	const reason = await reasonOf(response);
	if (response.status === 410 || (reason !== null && dead.has(reason))) {
		return { result: "unregistered", status: response.status, reason, apnsId };
	}
	console.warn(JSON.stringify({ msg: "APNs rejected a push", status: response.status, reason }));
	return { result: "failed", status: response.status, reason, apnsId };
}

async function reasonOf(response: Response): Promise<string | null> {
	try {
		const parsed: unknown = await response.json();
		if (parsed && typeof parsed === "object" && "reason" in parsed && typeof parsed.reason === "string") {
			return parsed.reason;
		}
	} catch {
		// Not the JSON Apple documents; no reason to give.
	}
	return null;
}
