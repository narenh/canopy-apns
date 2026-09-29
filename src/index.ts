/**
 * The Worker's entry point.
 *
 * Only the handler and the Durable Object classes are exported from here:
 * workerd treats every named export of the main module as an entrypoint and
 * refuses to start if one is anything else. Everything else lives in `app.ts`.
 */
import { handle } from "./app.ts";
import type { Env } from "./env.ts";

export { RateLimiter } from "./ratelimit.ts";
export { ProviderTokenStore } from "./tokens.ts";

export default {
  fetch: (request, env) => handle(request, env),
} satisfies ExportedHandler<Env>;
