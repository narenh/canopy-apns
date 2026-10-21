/**
 * Everything the relay is configured with, read from the Worker's environment.
 *
 * The relay holds exactly one secret worth stealing — the APNs signing key —
 * and one worth forging with — the instance-key signing secret. Both are
 * Worker secrets (`wrangler secret put`); everything else is a plain var in
 * `wrangler.jsonc`. Changing any of them is a redeploy.
 *
 * A Worker has no startup to fail, so what the Python relay refused to boot
 * with — a missing or placeholder signing secret, a malformed allow-list — is
 * a `ConfigError` here, and every endpoint answers 503 with its message until
 * it is fixed. A *missing* APNs key is still not an error: `/health` reports
 * `unconfigured` and pushes are refused with a 503 that says whose problem
 * it is.
 */

import { INSTANCE_ID_PATTERN } from "./keys.ts";

export interface Env {
	CANOPY_APNS_SIGNING_SECRET?: string;
	CANOPY_APNS_TEAM_ID?: string;
	CANOPY_APNS_KEY_ID?: string;
	CANOPY_APNS_BUNDLE_ID?: string;
	CANOPY_APNS_PRIVATE_KEY?: string;
	CANOPY_APNS_REVOKED_INSTANCES?: string;
	CANOPY_APNS_LIVEACTIVITY_TOPICS?: string;
	CANOPY_APNS_RATE_LIMIT?: string | number;
	CANOPY_APNS_RATE_BURST?: string | number;
	CANOPY_APNS_ENROLLMENT_ENABLED?: string | boolean;
	CANOPY_APNS_ENROLLMENT_PER_HOUR?: string | number;
	CANOPY_APNS_ENROLLMENT_BURST?: string | number;
	RATE_LIMITER: DurableObjectNamespace<import("./ratelimit.ts").RateLimiter>;
}

export const DEFAULT_RATE_LIMIT_PER_MINUTE = 120;
export const DEFAULT_RATE_BURST = 30;
export const DEFAULT_ENROLLMENT_PER_HOUR = 10;
export const DEFAULT_ENROLLMENT_BURST = 5;

/**
 * Longest payload strings the relay will forward. APNs caps the whole
 * notification at 4KB; these keep any one field from eating it.
 */
export const MAX_TITLE_LENGTH = 200;
export const MAX_BODY_LENGTH = 200;
export const MAX_DATA_BYTES = 1024;

/** Apple's cap on a Live Activity push, measured on the whole encoded payload. */
export const MAX_LIVE_ACTIVITY_PAYLOAD_BYTES = 4096;

export const APNS_TIMEOUT_MS = 10_000;

/**
 * Dot-separated segments of letters, digits and hyphens. Loose on purpose —
 * Apple is the authority on what is a real one — but tight enough that a stray
 * colon or comma in the allow-list is caught instead of becoming a topic
 * nobody can match.
 */
export const BUNDLE_ID_PATTERN = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

export class ConfigError extends Error {}

/** All four or none: three of them cannot send anything. */
export interface ApnsCredentials {
	teamId: string;
	keyId: string;
	bundleId: string;
	privateKeyPem: string;
}

export interface Settings {
	apns: ApnsCredentials | null;
	signingSecret: string;
	revoked: ReadonlySet<string>;
	ratePerMinute: number;
	rateBurst: number;
	enrollmentEnabled: boolean;
	enrollmentPerHour: number;
	enrollmentBurst: number;
	/** `"<instance_id>:<bundle_id>"` strings allowed on `/v1/liveactivity`. */
	liveActivityTopics: ReadonlySet<string>;
}

function clean(value: unknown): string {
	return value === undefined || value === null ? "" : String(value).trim();
}

function flag(name: string, value: unknown, fallback: boolean): boolean {
	const raw = clean(value).toLowerCase();
	if (!raw) return fallback;
	if (["0", "false", "no", "off"].includes(raw)) return false;
	if (["1", "true", "yes", "on"].includes(raw)) return true;
	throw new ConfigError(`${name} must be true or false, got ${JSON.stringify(raw)}`);
}

function int(name: string, value: unknown, fallback: number): number {
	const raw = clean(value);
	if (!raw) return fallback;
	if (!/^-?\d+$/.test(raw)) {
		throw new ConfigError(`${name} must be a whole number, got ${JSON.stringify(raw)}`);
	}
	const parsed = Number(raw);
	if (parsed <= 0) throw new ConfigError(`${name} must be greater than zero, got ${parsed}`);
	return parsed;
}

/**
 * Coax a `.p8` out of whatever a secret can carry: the PEM verbatim, the PEM
 * with literal `\n` where the newlines were, or base64 of the whole file.
 * Only the shape is fixed here; whether it is a usable key is asked when it
 * is imported.
 */
export function normalisePrivateKey(raw: string): string {
	let text = raw.trim();
	if (!text) return "";

	if (!text.includes("BEGIN")) {
		const compact = text.replace(/\s+/g, "");
		if (/^[A-Za-z0-9+/]*={0,2}$/.test(compact) && compact.length % 4 === 0) {
			try {
				const bytes = Uint8Array.from(atob(compact), (c) => c.charCodeAt(0));
				text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes).trim();
			} catch {
				return text;
			}
		}
	}
	return text.replaceAll("\\n", "\n");
}

/** `CANOPY_APNS_LIVEACTIVITY_TOPICS` into `instance:bundle` strings. */
export function parseLiveActivityTopics(raw: string): Set<string> {
	const pairs = new Set<string>();
	for (const part of raw.split(",")) {
		const entry = part.trim();
		if (!entry) continue;
		const sep = entry.indexOf(":");
		const instanceId = (sep < 0 ? entry : entry.slice(0, sep)).trim().toLowerCase();
		const bundleId = sep < 0 ? "" : entry.slice(sep + 1).trim();
		if (sep < 0 || !INSTANCE_ID_PATTERN.test(instanceId) || !BUNDLE_ID_PATTERN.test(bundleId)) {
			throw new ConfigError(
				"CANOPY_APNS_LIVEACTIVITY_TOPICS must be a comma-separated list of " +
					"<instance_id>:<bundle_id> pairs, e.g. `a1b2c3:com.example.App`; " +
					`could not read ${JSON.stringify(entry)}.`,
			);
		}
		pairs.add(`${instanceId}:${bundleId}`);
	}
	return pairs;
}

export const MIN_SIGNING_SECRET_LENGTH = 32;

/**
 * Substrings that mark a signing secret as boilerplate. The first is not
 * hypothetical: Coolify once deployed this relay with its secret set to the
 * literal words of a compose error message.
 */
const PLACEHOLDER_MARKERS = [
	"set this",
	"changeme",
	"change me",
	"change this",
	"replace this",
	"your secret",
	"your-secret",
	"secret here",
	"placeholder",
	"example",
	"todo",
];

function checkSigningSecret(value: string): void {
	if (/\s/.test(value)) {
		throw new ConfigError(
			"CANOPY_APNS_SIGNING_SECRET contains whitespace, so it is almost certainly " +
				"placeholder text rather than a secret. Generate one with `npm run secret`.",
		);
	}
	const lowered = value.toLowerCase();
	if (PLACEHOLDER_MARKERS.some((marker) => lowered.includes(marker))) {
		throw new ConfigError(
			"CANOPY_APNS_SIGNING_SECRET still looks like placeholder text. Every " +
				"instance API key is an HMAC under this value, so a guessable one lets " +
				"anyone mint keys. Generate one with `npm run secret`.",
		);
	}
	if (value.length < MIN_SIGNING_SECRET_LENGTH) {
		throw new ConfigError(
			`CANOPY_APNS_SIGNING_SECRET is ${value.length} characters; the minimum is ` +
				`${MIN_SIGNING_SECRET_LENGTH}. Generate one with \`npm run secret\`.`,
		);
	}
}

function credentials(env: Env): ApnsCredentials | null {
	const teamId = clean(env.CANOPY_APNS_TEAM_ID);
	const keyId = clean(env.CANOPY_APNS_KEY_ID);
	const bundleId = clean(env.CANOPY_APNS_BUNDLE_ID);
	const privateKeyPem = normalisePrivateKey(clean(env.CANOPY_APNS_PRIVATE_KEY));
	if (!(teamId && keyId && bundleId && privateKeyPem)) return null;
	return { teamId, keyId, bundleId, privateKeyPem };
}

export function loadSettings(env: Env): Settings {
	const signingSecret = clean(env.CANOPY_APNS_SIGNING_SECRET);
	if (!signingSecret) {
		throw new ConfigError(
			"CANOPY_APNS_SIGNING_SECRET is not set. Every instance API key is derived " +
				"from it; set it with `wrangler secret put CANOPY_APNS_SIGNING_SECRET`.",
		);
	}
	checkSigningSecret(signingSecret);

	const revoked = new Set(
		clean(env.CANOPY_APNS_REVOKED_INSTANCES)
			.split(",")
			.map((part) => part.trim().toLowerCase())
			.filter(Boolean),
	);

	return {
		apns: credentials(env),
		signingSecret,
		revoked,
		ratePerMinute: int("CANOPY_APNS_RATE_LIMIT", env.CANOPY_APNS_RATE_LIMIT, DEFAULT_RATE_LIMIT_PER_MINUTE),
		rateBurst: int("CANOPY_APNS_RATE_BURST", env.CANOPY_APNS_RATE_BURST, DEFAULT_RATE_BURST),
		enrollmentEnabled: flag("CANOPY_APNS_ENROLLMENT_ENABLED", env.CANOPY_APNS_ENROLLMENT_ENABLED, true),
		enrollmentPerHour: int(
			"CANOPY_APNS_ENROLLMENT_PER_HOUR",
			env.CANOPY_APNS_ENROLLMENT_PER_HOUR,
			DEFAULT_ENROLLMENT_PER_HOUR,
		),
		enrollmentBurst: int(
			"CANOPY_APNS_ENROLLMENT_BURST",
			env.CANOPY_APNS_ENROLLMENT_BURST,
			DEFAULT_ENROLLMENT_BURST,
		),
		liveActivityTopics: parseLiveActivityTopics(clean(env.CANOPY_APNS_LIVEACTIVITY_TOPICS)),
	};
}
