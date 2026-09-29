/**
 * Talking to Apple: provider-token signing and the push itself.
 *
 * Provider *tokens*, not certificates: one `.p8` signing key plus a team id and
 * key id, from which a short-lived ES256 JWT is minted and sent as a bearer
 * token on every push.
 *
 * Three things about APNs shape this module:
 *
 * * **It is HTTP/2 only.**  The Worker's `fetch()` negotiates HTTP/2 with
 *   Apple on its own; there is no client option to set, and nothing here can
 *   force it.  If a deployment ever gets protocol errors from Apple, that
 *   negotiation is the first suspect.
 * * **The provider token is reusable and rate-limited.**  Apple refuses one
 *   minted more than once in 20 minutes and rejects one older than an hour, so
 *   it is cached — across isolates, in a Durable Object; see `tokens.ts`.
 * * **A 410 is a fact, not an error.**  The app is gone from that device.  The
 *   relay stores no device tokens and so cannot act on it; it reports it back
 *   to the instance, which can.
 *
 * Nothing here knows about instances, API keys or rate limits.
 */
import type { ApnsCredentials } from "./config.ts";

export const PRODUCTION_HOST = "https://api.push.apple.com";
export const SANDBOX_HOST = "https://api.sandbox.push.apple.com";

/** Apple rejects a provider token older than an hour and refuses a new one
 * more often than every 20 minutes.  Renewing at 45 leaves room both sides. */
export const PROVIDER_TOKEN_LIFETIME_SECONDS = 45 * 60;

/** Reasons that mean "this device token is dead, stop using it". */
export const DEAD_TOKEN_REASONS = new Set(["Unregistered", "BadDeviceToken", "DeviceTokenNotForTopic"]);

/** Worth one more attempt: Apple throttling (429) or having a bad moment. */
export const RETRYABLE_STATUSES = new Set([429, 500, 503]);

/** The one 403 worth retrying, after minting a fresh provider token. */
export const EXPIRED_TOKEN_REASON = "ExpiredProviderToken";

/** How long one attempt may take before it counts as a transport failure. */
export const APNS_TIMEOUT_MS = 10_000;

/**
 * The configured signing key is unusable.  The expected cause is the wrong
 * file in the secret, so the message is written for whoever set it.
 */
export class ApnsConfigError extends Error {}

export type SendOutcome = "delivered" | "unregistered" | "failed";

export interface SendResult {
  outcome: SendOutcome;
  statusCode: number | null;
  /** Apple's own machine-readable reason string, when it gave one. */
  reason: string | null;
  /** Apple's id for the push, for correlating with their delivery console. */
  apnsId: string | null;
}

// DER for the ecPublicKey algorithm OID (1.2.840.10045.2.1), which every
// PKCS#8 EC private key names in its AlgorithmIdentifier.
const EC_PUBLIC_KEY_OID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

function containsBytes(haystack: Uint8Array, needle: number[]): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

const UNREADABLE =
  "The APNs key could not be read. CANOPY_APNS_PRIVATE_KEY must hold the contents " +
  "of the .p8 file, including the BEGIN and END lines (escaped newlines and base64 " +
  "of the whole file are also accepted).";

async function importPkcs8(pem: string): Promise<CryptoKey> {
  const match = /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/.exec(pem);
  if (!match) throw new ApnsConfigError(UNREADABLE);

  let der: Uint8Array;
  try {
    der = Uint8Array.from(atob(match[1]!.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
  } catch {
    throw new ApnsConfigError(UNREADABLE);
  }

  if (!containsBytes(der, EC_PUBLIC_KEY_OID)) {
    throw new ApnsConfigError(
      "The APNs key is not an elliptic-curve key. Apple's push keys are ES256 .p8 " +
        "files — this looks like a different kind of key.",
    );
  }

  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
  } catch {
    throw new ApnsConfigError(UNREADABLE);
  }
}

const importedKeys = new Map<string, Promise<CryptoKey>>();

/** Parse a `.p8` into a signing key, once per isolate per key. */
export function importSigningKey(pem: string): Promise<CryptoKey> {
  let key = importedKeys.get(pem);
  if (key === undefined) {
    key = importPkcs8(pem);
    importedKeys.set(pem, key);
  }
  return key;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

const encoder = new TextEncoder();

/**
 * Mint one ES256 provider token (a JWT).
 *
 * WebCrypto's ECDSA already emits the raw fixed-width `r || s` pair JWS wants,
 * so the DER-to-raw conversion the Python version needed is gone.
 */
export async function signProviderToken(
  credentials: ApnsCredentials,
  issuedAt: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const header = { alg: "ES256", kid: credentials.keyId };
  const claims = { iss: credentials.teamId, iat: issuedAt };
  const signingInput =
    base64url(encoder.encode(JSON.stringify(header))) +
    "." +
    base64url(encoder.encode(JSON.stringify(claims)));

  const key = await importSigningKey(credentials.privateKeyPem);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

/**
 * The APNs JSON body for one notification.
 *
 * Built here rather than forwarded, so no instance can reach into `aps` and
 * set `content-available`, `mutable-content` or a background push type using
 * the relay operator's signing key.
 *
 * The second line is `body`, not `subtitle`: iOS bolds title and subtitle
 * alike.  `badge` is tested against null rather than for truthiness, because 0
 * clears the icon.  `data` rides under `canopy`, beside `aps`, not inside it.
 */
export function buildPayload(input: {
  title: string;
  body?: string | null;
  badge?: number | null;
  data?: Record<string, unknown> | null;
}): Record<string, unknown> {
  const alert: Record<string, unknown> = { title: input.title };
  if (input.body) alert.body = input.body;

  const aps: Record<string, unknown> = { alert, sound: "default" };
  if (input.badge !== undefined && input.badge !== null) {
    // A sibling of `alert`, not a child of it. Nested inside, Apple ignores it.
    aps.badge = input.badge;
  }

  const payload: Record<string, unknown> = { aps };
  if (input.data && Object.keys(input.data).length > 0) payload.canopy = input.data;
  return payload;
}

/** Where provider tokens come from.  In the Worker, an isolate-local cache in
 * front of the `ProviderTokenStore` Durable Object; in tests, anything. */
export interface TokenSource {
  get(): Promise<string>;
  /** Apple said `token` expired.  Drop it, so the next `get` mints afresh. */
  invalidate(token: string): Promise<void>;
}

export interface SendInput {
  deviceToken: string;
  title: string;
  body?: string | null;
  badge?: number | null;
  data?: Record<string, unknown> | null;
  environment?: "sandbox" | "production";
  collapseId?: string | null;
}

/**
 * Sends one notification to one device token.
 *
 * Not a fan-out: the relay is a per-push forwarder, and a per-device outcome
 * is all APNs gives back anyway.
 */
export class ApnsClient {
  constructor(
    readonly credentials: ApnsCredentials,
    private readonly options: {
      tokens: TokenSource;
      fetch?: typeof fetch;
      productionHost?: string;
      sandboxHost?: string;
    },
  ) {}

  private host(environment: string): string {
    return environment === "sandbox"
      ? (this.options.sandboxHost ?? SANDBOX_HOST)
      : (this.options.productionHost ?? PRODUCTION_HOST);
  }

  /**
   * Push to one device, retrying once where it helps: a stale provider token
   * (mint a new one) or Apple throttling or faulting.  Anything still failing
   * after that is our bug or Apple being down, and hammering helps neither.
   */
  async send(input: SendInput): Promise<SendResult> {
    const payload = buildPayload(input);
    const url = `${this.host(input.environment ?? "production")}/3/device/${input.deviceToken}`;
    const collapseId = input.collapseId ?? null;

    let [result, token] = await this.attempt(url, payload, collapseId);

    const expired = result.statusCode === 403 && result.reason === EXPIRED_TOKEN_REASON;
    const retryable = result.statusCode !== null && RETRYABLE_STATUSES.has(result.statusCode);
    if (result.outcome === "failed" && (expired || retryable)) {
      if (expired) await this.options.tokens.invalidate(token);
      [result] = await this.attempt(url, payload, collapseId);
    }
    return result;
  }

  private async attempt(
    url: string,
    payload: Record<string, unknown>,
    collapseId: string | null,
  ): Promise<[SendResult, string]> {
    // Throws ApnsConfigError for an unusable key; the caller turns that into
    // a 503, since every push would fail the same way.
    const token = await this.options.tokens.get();

    const headers: Record<string, string> = {
      authorization: `bearer ${token}`,
      "apns-topic": this.credentials.bundleId,
      "apns-push-type": "alert",
      // 10 = deliver now. These are alerts about something that just happened.
      "apns-priority": "10",
      // 0 = do not store and retry. A stale notification is not worth a wake.
      "apns-expiration": "0",
      "content-type": "application/json",
    };
    if (collapseId !== null) headers["apns-collapse-id"] = collapseId;

    const doFetch = this.options.fetch ?? ((input, init) => fetch(input, init));
    let response: Response;
    try {
      response = await doFetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(APNS_TIMEOUT_MS),
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.warn(`APNs request failed: ${reason}`);
      return [{ outcome: "failed", statusCode: null, reason, apnsId: null }, token];
    }

    const apnsId = response.headers.get("apns-id");
    if (response.status === 200) {
      return [{ outcome: "delivered", statusCode: 200, reason: null, apnsId }, token];
    }

    const reason = await reasonOf(response);
    if (response.status === 410 || (reason !== null && DEAD_TOKEN_REASONS.has(reason))) {
      return [{ outcome: "unregistered", statusCode: response.status, reason, apnsId }, token];
    }

    console.warn(`APNs rejected a push: status=${response.status} reason=${reason}`);
    return [{ outcome: "failed", statusCode: response.status, reason, apnsId }, token];
  }
}

/** Apple's `reason` string, if the error body was the JSON they document. */
async function reasonOf(response: Response): Promise<string | null> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "reason" in body) {
      const reason = (body as { reason: unknown }).reason;
      if (typeof reason === "string") return reason;
    }
  } catch {
    // Not JSON; no reason to report.
  }
  return null;
}
