/**
 * The Worker's bindings.
 *
 * Every `CANOPY_APNS_*` value is a string when set: secrets always are, and
 * plain vars are strings unless someone writes a number into `wrangler.jsonc`,
 * which `config.ts` tolerates.  Optional throughout, because "absent" is a
 * state the relay has to describe rather than crash on.
 */
import type { ProviderTokenStore } from "./tokens.ts";
import type { RateLimiter } from "./ratelimit.ts";

export interface Env {
  PROVIDER_TOKEN: DurableObjectNamespace<ProviderTokenStore>;
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;

  CANOPY_APNS_SIGNING_SECRET?: string;
  CANOPY_APNS_TEAM_ID?: string;
  CANOPY_APNS_KEY_ID?: string;
  CANOPY_APNS_BUNDLE_ID?: string;
  CANOPY_APNS_PRIVATE_KEY?: string;
  /** Not supported on Workers — there is no filesystem.  Read only so that
   * setting it is a clear error rather than silently ignored. */
  CANOPY_APNS_PRIVATE_KEY_FILE?: string;
  CANOPY_APNS_REVOKED_INSTANCES?: string;
  CANOPY_APNS_RATE_LIMIT?: string | number;
  CANOPY_APNS_RATE_BURST?: string | number;
  CANOPY_APNS_ENROLLMENT_ENABLED?: string | boolean;
  CANOPY_APNS_ENROLLMENT_PER_HOUR?: string | number;
  CANOPY_APNS_ENROLLMENT_BURST?: string | number;
}
