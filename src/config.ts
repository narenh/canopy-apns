/**
 * Everything the relay is configured with, read from the Worker's env.
 *
 * The relay holds one secret worth stealing — the APNs signing key — and one
 * worth forging with — the instance-key signing secret.  Both arrive as Worker
 * secrets and nothing else.
 *
 * A Worker has no startup to fail, so "refuses to boot" becomes "answers every
 * request with a 500 naming the problem" (see `index.ts`).  Same intent: a
 * relay with a forgeable signing secret must not serve.  *Absent* APNs
 * credentials are still not an error — the relay reports itself unconfigured
 * and refuses pushes with a 503.
 */
import type { Env } from "./env.ts";

export const DEFAULT_RATE_LIMIT_PER_MINUTE = 120;
export const DEFAULT_RATE_BURST = 30;

/** Enrollments one source address may make per hour, and how many may be
 * bunched together.  Generous for a real deployment (an instance enrolls once,
 * ever) and deliberately finite, because self-service keys are free. */
export const DEFAULT_ENROLLMENT_PER_HOUR = 10;
export const DEFAULT_ENROLLMENT_BURST = 5;

/** Longest payload strings the relay will forward.  APNs caps the whole
 * notification at 4KB; these keep any one field from eating it. */
export const MAX_TITLE_LENGTH = 200;
export const MAX_BODY_LENGTH = 200;
export const MAX_DATA_BYTES = 1024;

/** Shortest signing secret the relay will run with.  `npm run secret`
 * produces 64 characters; this floor only rules out something typed by hand. */
export const MIN_SIGNING_SECRET_LENGTH = 32;

/**
 * The environment is set up in a way the relay cannot run with.
 *
 * Only for a value that is present but unusable.  The message is shown to
 * whoever calls the relay, so it names the variable and never its value.
 */
export class ConfigError extends Error {}

export interface ApnsCredentials {
  teamId: string;
  keyId: string;
  bundleId: string;
  privateKeyPem: string;
}

export interface Settings {
  /** `null` until the signing key is in the environment. */
  apns: ApnsCredentials | null;
  /** HMAC secret behind every instance API key. */
  signingSecret: string;
  revokedInstances: ReadonlySet<string>;
  rateLimitPerMinute: number;
  rateBurst: number;
  enrollmentEnabled: boolean;
  enrollmentPerHour: number;
  enrollmentBurst: number;
}

type EnvKey = Exclude<keyof Env, "PROVIDER_TOKEN" | "RATE_LIMITER">;

function clean(env: Env, name: EnvKey): string {
  const raw = env[name];
  return raw === undefined || raw === null ? "" : String(raw).trim();
}

/** A boolean read forgivingly: `no` where the docs said `false` means what it
 * says.  Anything unrecognised is an error rather than a guessed default,
 * because the default here is a security posture. */
function flag(env: Env, name: EnvKey, fallback: boolean): boolean {
  const raw = clean(env, name).toLowerCase();
  if (!raw) return fallback;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  throw new ConfigError(`${name} must be true or false, got ${JSON.stringify(raw)}`);
}

function int(env: Env, name: EnvKey, fallback: number): number {
  const raw = clean(env, name);
  if (!raw) return fallback;
  if (!/^[+-]?\d+$/.test(raw)) {
    throw new ConfigError(`${name} must be a whole number, got ${JSON.stringify(raw)}`);
  }
  const value = Number.parseInt(raw, 10);
  if (value <= 0) {
    throw new ConfigError(`${name} must be greater than zero, got ${value}`);
  }
  return value;
}

/**
 * Coax a `.p8` out of whatever a secret variable can carry.
 *
 * Three shapes are accepted: the PEM verbatim; the PEM with literal `\n`
 * where the newlines were; base64 of the whole file.  Only the shape is fixed
 * here — whether it is a usable ES256 key is `apns.importSigningKey`'s
 * question.
 */
export function normalisePrivateKey(raw: string): string {
  let text = raw.trim();
  if (!text) return "";

  if (!text.includes("BEGIN")) {
    const compact = text.replace(/\s+/g, "");
    const decoded = decodeBase64Utf8(compact);
    if (decoded === null) return text;
    text = decoded.trim();
  }
  return text.replaceAll("\\n", "\n");
}

/** Strict base64 → UTF-8, or `null`.  Strict the way Python's
 * `b64decode(validate=True)` is: alphabet and padding both checked. */
function decodeBase64Utf8(value: string): string | null {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    return null;
  }
}

/** All four credentials or none: three of them cannot send anything. */
export function loadApnsCredentials(env: Env): ApnsCredentials | null {
  if (clean(env, "CANOPY_APNS_PRIVATE_KEY_FILE")) {
    throw new ConfigError(
      "CANOPY_APNS_PRIVATE_KEY_FILE is set, but a Worker has no filesystem to read " +
        "it from. Put the .p8 contents in the CANOPY_APNS_PRIVATE_KEY secret instead.",
    );
  }

  const teamId = clean(env, "CANOPY_APNS_TEAM_ID");
  const keyId = clean(env, "CANOPY_APNS_KEY_ID");
  const bundleId = clean(env, "CANOPY_APNS_BUNDLE_ID");
  const privateKeyPem = normalisePrivateKey(clean(env, "CANOPY_APNS_PRIVATE_KEY"));

  if (!(teamId && keyId && bundleId && privateKeyPem)) return null;
  return { teamId, keyId, bundleId, privateKeyPem };
}

/** Substrings that mark a signing secret as boilerplate rather than a secret.
 * The first is not hypothetical: Coolify once deployed the relay with its
 * secret set to the literal words `set this in Coolify`. */
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

/** Refuse a signing secret that is present but not actually a secret: every
 * key the relay issues is forgeable by anyone who can guess it. */
export function checkSigningSecret(value: string): void {
  if (/\s/.test(value)) {
    throw new ConfigError(
      "CANOPY_APNS_SIGNING_SECRET contains whitespace, so it is almost certainly " +
        "placeholder text rather than a secret. Generate a real one with `npm run secret`.",
    );
  }
  const lowered = value.toLowerCase();
  if (PLACEHOLDER_MARKERS.some((marker) => lowered.includes(marker))) {
    throw new ConfigError(
      "CANOPY_APNS_SIGNING_SECRET still looks like placeholder text. Every instance " +
        "API key is an HMAC under this value, so a guessable one lets anyone mint " +
        "keys. Generate a real one with `npm run secret`.",
    );
  }
  if (value.length < MIN_SIGNING_SECRET_LENGTH) {
    throw new ConfigError(
      `CANOPY_APNS_SIGNING_SECRET is ${value.length} characters; the minimum is ` +
        `${MIN_SIGNING_SECRET_LENGTH}. Generate one with \`npm run secret\`, which produces 64.`,
    );
  }
}

/** Build `Settings` from the env, or throw `ConfigError`. */
export function loadSettings(env: Env): Settings {
  const signingSecret = clean(env, "CANOPY_APNS_SIGNING_SECRET");
  if (!signingSecret) {
    throw new ConfigError(
      "CANOPY_APNS_SIGNING_SECRET is not set. Generate one with `npm run secret` " +
        "and set it with `wrangler secret put CANOPY_APNS_SIGNING_SECRET`; every " +
        "instance API key is derived from it.",
    );
  }
  checkSigningSecret(signingSecret);

  const revokedInstances = new Set(
    clean(env, "CANOPY_APNS_REVOKED_INSTANCES")
      .split(",")
      .map((part) => part.trim().toLowerCase())
      .filter(Boolean),
  );

  return {
    apns: loadApnsCredentials(env),
    signingSecret,
    revokedInstances,
    rateLimitPerMinute: int(env, "CANOPY_APNS_RATE_LIMIT", DEFAULT_RATE_LIMIT_PER_MINUTE),
    rateBurst: int(env, "CANOPY_APNS_RATE_BURST", DEFAULT_RATE_BURST),
    enrollmentEnabled: flag(env, "CANOPY_APNS_ENROLLMENT_ENABLED", true),
    enrollmentPerHour: int(env, "CANOPY_APNS_ENROLLMENT_PER_HOUR", DEFAULT_ENROLLMENT_PER_HOUR),
    enrollmentBurst: int(env, "CANOPY_APNS_ENROLLMENT_BURST", DEFAULT_ENROLLMENT_BURST),
  };
}
