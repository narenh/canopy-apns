/**
 * The relay's routes and handlers.
 *
 * Four endpoints and no database.  Check the API key, spend a rate-limit
 * token, build an alert payload, sign a JWT, POST it to Apple, report what
 * happened.
 *
 * The one thing worth stating loudly, because the isolation story rests on
 * it: **the relay never stores a device token and never learns which instance
 * a device belongs to.**  An instance can only send to devices whose tokens it
 * already holds, and it only holds tokens its own users gave it.  So
 * "instance A cannot notify instance B's users" is true because A has never
 * seen B's tokens — not because anything here enforces a routing rule.
 *
 * The two Durable Objects hold a provider JWT and rate-limit counters: shared
 * state the Python relay kept in one process's memory, which a fleet of
 * isolates cannot.  Neither holds anything about a device or a notification.
 */
import { ApnsClient, ApnsConfigError, importSigningKey } from "./apns.ts";
import { ConfigError, loadSettings, type Settings } from "./config.ts";
import type { Env } from "./env.ts";
import { generateInstanceId, type Instance, InvalidKey, mint, verify } from "./keys.ts";
import { renderLanding, wantsHtml } from "./landing.ts";
import { checkLimit, type Decision, type Limit, perHour } from "./ratelimit.ts";
import { validatePush } from "./schemas.ts";
import { DurableTokenSource } from "./tokens.ts";

export const VERSION = "2.0.0";

/** A response the relay produces on purpose.  Thrown from anywhere below the
 * router and turned into JSON by it, as FastAPI's HTTPException was. */
class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly detail: unknown,
    readonly headers: Record<string, string> = {},
  ) {
    super(typeof detail === "string" ? detail : "request refused");
  }
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/**
 * Settings, with the signing key parsed.
 *
 * Parsed on every request but cheaply: `importSigningKey` caches per isolate.
 * Doing it here rather than at first push is what makes a mis-pasted `.p8` a
 * 500 on `/health` — visible the moment it is deployed — instead of every push
 * failing identically later.
 */
async function settingsFor(env: Env): Promise<Settings> {
  const settings = loadSettings(env);
  if (settings.apns !== null) {
    try {
      await importSigningKey(settings.apns.privateKeyPem);
    } catch (error) {
      if (error instanceof ApnsConfigError) throw new ConfigError(error.message);
      throw error;
    }
  }
  return settings;
}

const UNAUTHORIZED = () =>
  new HttpError(401, "This relay API key is not valid.", { "www-authenticate": "Bearer" });

/**
 * Resolve the caller's API key to an instance, or refuse.
 *
 * Bearer only.  Every refusal after that is the same flat 401 with the same
 * message, whether the key was malformed, forged or revoked.
 */
async function authenticate(request: Request, settings: Settings): Promise<Instance> {
  const header = request.headers.get("authorization") ?? "";
  const space = header.indexOf(" ");
  const scheme = space === -1 ? header : header.slice(0, space);
  const value = space === -1 ? "" : header.slice(space + 1).trim();
  if (scheme.toLowerCase() !== "bearer" || !value) {
    throw new HttpError(401, "Send your relay API key as `Authorization: Bearer <key>`.", {
      "www-authenticate": "Bearer",
    });
  }

  let instance: Instance;
  try {
    instance = await verify(value, settings.signingSecret);
  } catch (error) {
    if (error instanceof InvalidKey) throw UNAUTHORIZED();
    throw error;
  }

  if (settings.revokedInstances.has(instance.id)) {
    console.warn(`refused a request from revoked instance ${instance.id}`);
    throw UNAUTHORIZED();
  }
  return instance;
}

/**
 * Spend a rate-limit token, or throw a 429.
 *
 * Fails open if the Durable Object cannot be reached: the limit exists to stop
 * a runaway instance, and dropping every push during a Cloudflare hiccup would
 * be a worse outcome than a minute of unmetered forwarding.
 */
async function enforce(env: Env, key: string, limit: Limit, refusal: string): Promise<void> {
  let decision: Decision;
  try {
    decision = await checkLimit(env, key, limit);
  } catch (error) {
    console.error(`rate limiter unavailable for ${key}; allowing: ${String(error)}`);
    return;
  }
  if (!decision.allowed) {
    console.log(`rate-limited ${key}`);
    throw new HttpError(429, refusal, { "retry-after": String(decision.retryAfterSeconds) });
  }
}

/** `GET /health` — unauthenticated, and says nothing an attacker wants. */
function health(settings: Settings): Response {
  return json(200, { status: "ok", apns: settings.apns ? "configured" : "unconfigured" });
}

/**
 * `POST /v1/instances` — issue a fresh identity and API key.  **Unauthenticated.**
 *
 * Stateless: a random id, its derived key, nothing written.  Keys being free
 * makes a per-key rate limit a speed bump; what holds the line is the
 * per-address limit here, revocation by id, and
 * `CANOPY_APNS_ENROLLMENT_ENABLED=false` to close the door.
 */
async function enroll(request: Request, env: Env, settings: Settings): Promise<Response> {
  if (!settings.enrollmentEnabled) {
    throw new HttpError(403, "This relay is not issuing new keys. Ask its operator for one.");
  }

  // Cloudflare sets this from the connection itself; a client cannot forge it.
  const source = request.headers.get("cf-connecting-ip") ?? "unknown";
  await enforce(
    env,
    `enroll:${source}`,
    perHour(settings.enrollmentPerHour, settings.enrollmentBurst),
    "Too many enrollments from this address. Try again shortly.",
  );

  const instanceId = generateInstanceId();
  const apiKey = await mint(instanceId, settings.signingSecret);

  // The id, never the key: a log line carrying the credential it just issued
  // would undo the point of never storing one.
  console.log(`enrolled instance ${instanceId}`);

  return json(201, {
    instance_id: instanceId,
    api_key: apiKey,
    bundle_id: settings.apns?.bundleId ?? null,
    ready: settings.apns !== null,
  });
}

/**
 * `GET /v1/verify` — confirm a key works, for an instance's settings page.
 *
 * Separates "your key is wrong" (401) from "your key is fine, this relay has
 * no signing key" (200, `ready: false`).  Not rate-limited against the push
 * bucket: a settings page should not cost an admin their notification budget.
 */
async function verifyKey(request: Request, settings: Settings): Promise<Response> {
  const instance = await authenticate(request, settings);
  return json(200, {
    ok: true,
    instance: instance.id,
    bundle_id: settings.apns?.bundleId ?? null,
    ready: settings.apns !== null,
    rate_limit_per_minute: settings.rateLimitPerMinute,
  });
}

/**
 * `POST /v1/push` — forward one notification to one device.
 *
 * **Always 200 when Apple answered**, whatever Apple said.  "Apple refused
 * this token" is a successful forward with a definitive answer in it; non-2xx
 * is reserved for the relay's own problems.  That matters most for
 * `unregistered`: only the instance can delete a dead token, and it can only
 * do that if it is told plainly.
 */
async function push(request: Request, env: Env, settings: Settings): Promise<Response> {
  const instance = await authenticate(request, settings);

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    throw new HttpError(422, [{ type: "json_invalid", loc: ["body"], msg: "JSON decode error" }]);
  }
  const validated = validatePush(parsed);
  if (!validated.ok) throw new HttpError(422, validated.errors);
  const notification = validated.value;

  await enforce(
    env,
    `push:${instance.id}`,
    { perMinute: settings.rateLimitPerMinute, burst: settings.rateBurst },
    "Too many notifications. Slow down and try again shortly.",
  );

  const credentials = settings.apns;
  if (credentials === null) {
    throw new HttpError(
      503,
      "This relay has no APNs signing key configured yet. Nothing is wrong with your " +
        "API key; the relay operator has to fix this.",
    );
  }

  const client = new ApnsClient(credentials, { tokens: new DurableTokenSource(env, credentials) });
  let result;
  try {
    result = await client.send(notification);
  } catch (error) {
    if (error instanceof ApnsConfigError) {
      console.error(`APNs credentials are unusable: ${error.message}`);
      throw new HttpError(
        503,
        "This relay's APNs signing key is not usable. The relay operator has to fix this.",
      );
    }
    // The provider-token Durable Object could not be reached. Apple was never
    // asked, so this is the relay's failure and worth a retry.
    console.error(`could not obtain a provider token: ${String(error)}`);
    throw new HttpError(503, "The relay could not sign this push. Try again shortly.", {
      "retry-after": "5",
    });
  }

  // Instance id and outcome, never the device token or the text: a log that
  // reconstructs what was forwarded would be a store of exactly what this
  // service promises not to keep.
  console.log(
    `push instance=${instance.id} env=${notification.environment} ` +
      `result=${result.outcome} reason=${result.reason ?? "-"}`,
  );

  return json(200, { result: result.outcome, reason: result.reason, apns_id: result.apnsId });
}

/** `GET /` — JSON for scripts, a diagnostic page for browsers. */
function root(request: Request, settings: Settings): Response {
  if (wantsHtml(request)) {
    const html = renderLanding(request, {
      version: VERSION,
      apnsConfigured: settings.apns !== null,
      enrollmentEnabled: settings.enrollmentEnabled,
      rateLimitPerMinute: settings.rateLimitPerMinute,
    });
    return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
  }
  return json(200, {
    service: "canopy-apns",
    description:
      "APNs forwarder for self-hosted Canopy+ instances. Ask the operator for a relay API key.",
    scheme: new URL(request.url).protocol.replace(":", ""),
  });
}

type Handler = (request: Request, env: Env, settings: Settings) => Response | Promise<Response>;

const ROUTES: Record<string, Record<string, Handler>> = {
  "/": { GET: (request, _env, settings) => root(request, settings) },
  "/health": { GET: (_request, _env, settings) => health(settings) },
  "/v1/instances": { POST: enroll },
  "/v1/verify": { GET: (request, _env, settings) => verifyKey(request, settings) },
  "/v1/push": { POST: push },
};

export async function handle(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  const methods = ROUTES[pathname];
  if (!methods) return json(404, { detail: "Not Found" });

  const method = request.method === "HEAD" ? "GET" : request.method;
  const handler = methods[method];
  if (!handler) {
    return json(405, { detail: "Method Not Allowed" }, { allow: Object.keys(methods).join(", ") });
  }

  try {
    // A relay that cannot trust its own configuration answers nothing else.
    // The Python relay refused to boot here; a Worker has no boot to refuse.
    let settings: Settings;
    try {
      settings = await settingsFor(env);
    } catch (error) {
      if (error instanceof ConfigError) {
        console.error(`configuration error: ${error.message}`);
        return json(500, { detail: error.message });
      }
      throw error;
    }
    return await handler(request, env, settings);
  } catch (error) {
    if (error instanceof HttpError) return json(error.status, { detail: error.detail }, error.headers);
    console.error(`unhandled error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
    return json(500, { detail: "Internal Server Error" });
  }
}
