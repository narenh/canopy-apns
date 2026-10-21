/**
 * Instance API keys, derived rather than stored.
 *
 * An API key here is not a random string looked up in a table — there is no
 * table. It is an instance id with a MAC over it:
 *
 *     canopy_<instance-id>_<signature>
 *
 * The relay verifies a key by recomputing the signature from
 * `CANOPY_APNS_SIGNING_SECRET` and comparing. That is the whole mechanism, and
 * it is what lets the service be genuinely stateless: nothing to back up,
 * nothing to migrate, and no two edge locations that can disagree about who
 * is allowed in.
 *
 * The derivation is byte-for-byte the one the Python relay used (HMAC-SHA256,
 * truncated to 16 bytes, RFC 4648 base32 lowercased and unpadded), so every
 * key that relay ever issued verifies here under the same secret. A test pins
 * that against keys the Python code minted.
 *
 * The instance id's character set is constrained so that `_` stays an
 * unambiguous separator: ids may not contain one, so the key always splits
 * into exactly three parts.
 *
 * No Workers-only APIs outside `verify`, so `scripts/cli.ts` can import this
 * under plain Node to mint keys.
 */

export const KEY_PREFIX = "canopy";

/**
 * Lowercase alphanumerics and internal hyphens. No underscore — that is the
 * field separator — and no leading or trailing hyphen, so an id is always
 * something a human can read back over the phone.
 */
export const INSTANCE_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * 16 bytes of HMAC-SHA256 output. Truncating a MAC is safe and standard; 128
 * bits is far past forging range for a value an attacker can only test online
 * against a rate-limited endpoint.
 */
const SIGNATURE_BYTES = 16;

/**
 * Bytes of randomness behind a self-enrolled instance id. 96 bits, which is
 * about collision-avoidance rather than secrecy: the id is not the secret half
 * of a key.
 */
export const INSTANCE_ID_BYTES = 12;

/** The presented key is not one this relay issued. Deliberately detail-free. */
export class InvalidKey extends Error {}

export interface Instance {
	id: string;
}

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

/**
 * Base32, lowercased, unpadded.
 *
 * Base64url would be shorter, but its alphabet includes `_` — the field
 * separator. Base32 keeps the whole key to `[a-z0-9-]` plus the separators.
 */
export function base32(bytes: Uint8Array): string {
	let out = "";
	let value = 0;
	let bits = 0;
	for (const byte of bytes) {
		value = ((value << 8) | byte) & 0xffff;
		bits += 8;
		while (bits >= 5) {
			out += BASE32[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
	return out;
}

/** Lowercase and trim an id, or throw if unusable. Applied at mint time. */
export function normaliseInstanceId(instanceId: string): string {
	const candidate = instanceId.trim().toLowerCase();
	if (!INSTANCE_ID_PATTERN.test(candidate)) {
		throw new Error(
			"An instance id is 1-63 characters of lowercase letters, digits and " +
				"internal hyphens — no underscores, since that separates the parts " +
				`of a key. Got ${JSON.stringify(instanceId)}.`,
		);
	}
	return candidate;
}

const encoder = new TextEncoder();
const hmacKeys = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
	let key = hmacKeys.get(secret);
	if (!key) {
		key = crypto.subtle.importKey(
			"raw",
			encoder.encode(secret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);
		hmacKeys.set(secret, key);
	}
	return key;
}

/** The signature half of `instanceId`'s key. */
export async function sign(instanceId: string, secret: string): Promise<string> {
	const mac = await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(instanceId));
	return base32(new Uint8Array(mac).slice(0, SIGNATURE_BYTES));
}

/** The API key for `instanceId`. Deterministic: same id, same key. */
export async function mint(instanceId: string, secret: string): Promise<string> {
	const id = normaliseInstanceId(instanceId);
	return `${KEY_PREFIX}_${id}_${await sign(id, secret)}`;
}

/**
 * Authenticate `apiKey`, returning who it belongs to, or throw `InvalidKey`.
 * Revocation is not checked here; see `Settings.revoked`.
 */
export async function verify(apiKey: string, secret: string): Promise<Instance> {
	const parts = apiKey.trim().split("_");
	if (parts.length !== 3) throw new InvalidKey("malformed key");

	const [prefix, id, signature] = parts as [string, string, string];
	if (prefix !== KEY_PREFIX || !INSTANCE_ID_PATTERN.test(id)) {
		throw new InvalidKey("malformed key");
	}

	// Constant-time, because the comparison is the only thing standing between
	// a guessed signature and a valid one. A length mismatch leaks only that
	// the length was wrong, which the key format already says.
	const expected = encoder.encode(await sign(id, secret));
	const presented = encoder.encode(signature);
	if (
		expected.byteLength !== presented.byteLength ||
		!crypto.subtle.timingSafeEqual(expected, presented)
	) {
		throw new InvalidKey("bad signature");
	}
	return { id };
}

/** A fresh random instance id, for self-service enrollment. */
export function generateInstanceId(): string {
	return base32(crypto.getRandomValues(new Uint8Array(INSTANCE_ID_BYTES)));
}

/** A fresh signing secret: 48 random bytes as 64 URL-safe base64 characters. */
export function generateSecret(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(48));
	return btoa(String.fromCharCode(...bytes))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
}
