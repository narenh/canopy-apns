/**
 * One provider token, shared by every isolate.
 *
 * Apple treats a provider token as a reusable bearer credential and answers
 * `TooManyProviderTokenUpdates` to a relay that mints them faster than one per
 * 20 minutes.  The Python relay was one process, so an in-memory cache was
 * enough.  A Worker is many short-lived isolates spread across Cloudflare's
 * network, each with its own memory: cached per isolate, every one of them
 * would mint its own token and look to Apple like a relay minting constantly.
 *
 * So the token lives in one Durable Object, `ProviderTokenStore`, and is minted
 * there.  Each isolate keeps a copy until the token ages out, so the Durable
 * Object is asked roughly once per isolate per 45 minutes rather than once per
 * push.
 *
 * Only the JWT is stored — never the signing key, and nothing about any push.
 * A JWT is worth an hour of sending as this relay; the `.p8` it came from is
 * worth forever, and stays a Worker secret.
 */
import { DurableObject } from "cloudflare:workers";

import {
  ApnsConfigError,
  PROVIDER_TOKEN_LIFETIME_SECONDS,
  signProviderToken,
  type TokenSource,
} from "./apns.ts";
import { type ApnsCredentials, ConfigError, loadApnsCredentials } from "./config.ts";
import type { Env } from "./env.ts";

const LIFETIME_MS = PROVIDER_TOKEN_LIFETIME_SECONDS * 1000;

export interface IssuedToken {
  token: string;
  /** Milliseconds since the epoch. */
  issuedAt: number;
}

/** A config error can't cross the RPC boundary as its own class, so it comes
 * back as a value and is rethrown on the calling side. */
export type TokenResult = ({ ok: true } & IssuedToken) | { ok: false; error: string };

interface StoredToken extends IssuedToken {
  /** Which credentials minted it, so a key swap takes effect on the next push
   * rather than when the old token ages out. */
  fingerprint: string;
}

async function fingerprintOf(credentials: ApnsCredentials): Promise<string> {
  const material = `${credentials.teamId}\n${credentials.keyId}\n${credentials.privateKeyPem}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class ProviderTokenStore extends DurableObject<Env> {
  private cached: StoredToken | null | undefined = undefined;

  /** The current token, minting one if it has aged out.  `now` is for tests. */
  async getToken(now: number = Date.now()): Promise<TokenResult> {
    // Minting awaits WebCrypto, which does not hold the input gate, so two
    // concurrent callers could otherwise both see an expired token and both
    // mint.  Holding every other caller for the length of one sign is cheap.
    return this.ctx.blockConcurrencyWhile(async () => {
      let credentials: ApnsCredentials | null;
      try {
        credentials = loadApnsCredentials(this.env);
      } catch (error) {
        if (error instanceof ConfigError) return { ok: false, error: error.message };
        throw error;
      }
      if (credentials === null) {
        return { ok: false, error: "This relay has no APNs signing key configured." };
      }

      const fingerprint = await fingerprintOf(credentials);
      const stored = await this.load();
      if (stored && stored.fingerprint === fingerprint && now - stored.issuedAt < LIFETIME_MS) {
        return { ok: true, token: stored.token, issuedAt: stored.issuedAt };
      }

      let token: string;
      try {
        token = await signProviderToken(credentials, Math.floor(now / 1000));
      } catch (error) {
        if (error instanceof ApnsConfigError) return { ok: false, error: error.message };
        throw error;
      }

      const fresh: StoredToken = { token, issuedAt: now, fingerprint };
      this.cached = fresh;
      await this.ctx.storage.put("token", fresh);
      return { ok: true, token, issuedAt: now };
    });
  }

  /**
   * Apple called `token` expired.  Dropped only if it is still the current
   * one: several isolates holding the same stale token will all report it, and
   * only the first report should cost a mint.
   */
  async invalidate(token: string): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      const stored = await this.load();
      if (stored?.token === token) {
        this.cached = null;
        await this.ctx.storage.delete("token");
      }
    });
  }

  private async load(): Promise<StoredToken | null> {
    if (this.cached === undefined) {
      this.cached = (await this.ctx.storage.get<StoredToken>("token")) ?? null;
    }
    return this.cached;
  }
}

/** Per-isolate copies, keyed by the credentials that minted them. */
const local = new Map<string, IssuedToken>();

function localKey(credentials: ApnsCredentials): string {
  return `${credentials.teamId}\n${credentials.keyId}\n${credentials.privateKeyPem}`;
}

/** The `TokenSource` the Worker hands to `ApnsClient`. */
export class DurableTokenSource implements TokenSource {
  constructor(
    private readonly env: Env,
    private readonly credentials: ApnsCredentials,
  ) {}

  private stub() {
    return this.env.PROVIDER_TOKEN.get(this.env.PROVIDER_TOKEN.idFromName("provider-token"));
  }

  async get(): Promise<string> {
    const key = localKey(this.credentials);
    const copy = local.get(key);
    if (copy && Date.now() - copy.issuedAt < LIFETIME_MS) return copy.token;

    const result = await this.stub().getToken();
    if (!result.ok) throw new ApnsConfigError(result.error);
    local.set(key, { token: result.token, issuedAt: result.issuedAt });
    return result.token;
  }

  async invalidate(token: string): Promise<void> {
    const key = localKey(this.credentials);
    if (local.get(key)?.token === token) local.delete(key);
    await this.stub().invalidate(token);
  }
}

/** For tests: forget this isolate's copies. */
export function clearLocalTokens(): void {
  local.clear();
}
