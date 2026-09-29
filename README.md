# canopy-apns

A public APNs forwarder for self-hosted Canopy+ instances, running as a
Cloudflare Worker.

One Apple Developer account owns the app, so one signing key can push to it.
That key cannot be handed out — it signs notifications for every app on the
team — but every self-hoster still needs to send pushes. This service is the
resolution: it holds the key, and instances hand it `(device token, two lines
of text)` over an authenticated HTTP call.

It stores nothing about a device or a notification. No database, no queue, no
device tokens. Two Durable Objects hold the only shared state a fleet of
isolates needs — one Apple provider JWT, and rate-limit counters — see
[State](#state-what-the-durable-objects-hold).

> **Moved from Coolify.** This was a Python/FastAPI service in a Docker
> container on a home server. The Worker is a port of it with the same API,
> the same key format, and the same environment variable names; API keys the
> Python relay issued keep working as long as the signing secret is carried
> over. The Python service is kept, unchanged, in
> [`legacy-python/`](legacy-python/), which Cloudflare does not build or
> deploy.

---

## Contents

- [The isolation model](#the-isolation-model)
- [What the relay does and does not do](#what-the-relay-does-and-does-not-do)
- [API](#api)
- [Instance API keys](#instance-api-keys)
- [Configuration](#configuration)
- [State: what the Durable Objects hold](#state-what-the-durable-objects-hold)
- [Deploying on Cloudflare](#deploying-on-cloudflare) — including [checking that Apple is reachable](#5-check-that-apple-answers)
- [Differences from the Python relay](#differences-from-the-python-relay)
- [Privacy: what the relay operator can see](#privacy-what-the-relay-operator-can-see)
- [Development](#development)

---

## The isolation model

The question this service has to answer is: if `cplus.notcanopy.com` and
`cplus.canopysf.com` both push through `apns.canopysf.com`, what stops
one of them notifying the other's users?

**Token custody. Not the relay.**

An APNs device token is per-device, per-app, and unguessable — 32 bytes of
randomness Apple issues to one install of one app on one device. A backend only
ever learns the tokens that its own logged-in users hand it. `notcanopy.com`
has never seen `canopysf.com`'s users' tokens and has no way to obtain one, so
it cannot address a push to them, whatever it sends the relay.

The relay therefore keeps **no device→instance mapping at all**. There is no
routing table, no ownership registry, no "which instance does this token belong
to" lookup. Adding one would not make the guarantee stronger — it is already
absolute — and it would make it *weaker*, because a table that says which
instance owns which device is precisely the correlation this design does not
have to hold. The relay is a forwarder: `(token, payload)` in, one push to
Apple, the outcome back out, nothing retained.

Two consequences worth stating plainly:

* **An instance API key is a rate-limit identity and an abuse handle, not an
  access-control boundary over devices.** Stealing another instance's key buys
  you the ability to spend their rate limit. It does not buy you their users,
  because it does not buy you their tokens.
* **A compromised instance can push to its own users and nobody else's.** Which
  is the same authority it already had over those users, since it is their
  backend. The relay does not widen anyone's blast radius.

```
  ┌──────────────────────────┐        ┌──────────────────────────┐
  │  cplus.canopysf.com      │        │  cplus.notcanopy.com     │
  │  knows: tokens A, B      │        │  knows: tokens C, D      │
  └───────────┬──────────────┘        └───────────┬──────────────┘
              │ Bearer canopy_canopysf_…          │ Bearer canopy_notcanopy_…
              │ {token: A, title, body}           │ {token: C, title, body}
              └────────────────┬──────────────────┘
                               ▼
                 ┌─────────────────────────────┐
                 │     apns.canopysf.com       │  holds the .p8
                 │ stores: nothing             │  remembers: nothing
                 └──────────────┬──────────────┘
                                ▼
                              APNs
```

Neither instance can name a token it was never given. That is the whole
mechanism.

---

## What the relay does and does not do

**Does**

- Holds the APNs signing key (`.p8`), team id, key id and bundle id, from the
  environment.
- Issues instance identities on demand, so no self-hoster ever handles a
  credential. Still writes nothing down.
- Authenticates each request by instance API key, and rate-limits per instance.
- Builds the APNs payload itself from a constrained request shape, and sets the
  push headers.
- Signs a provider-token JWT, POSTs to Apple over HTTP/2, and reports the
  outcome — including telling the instance when a device token is dead so it
  can delete it.

**Does not**

- Store device tokens, notification text, any device→instance mapping, or the
  keys it issues. Enrollment computes a key and forgets it.
- Accept a raw `aps` dictionary. An instance sends text; the relay decides the
  payload shape. Otherwise any instance could send a silent
  `content-available` background wake signed with the operator's key.
- Fan out. One request, one device, one outcome. The instance owns its device
  list and what to do about each result.
- Retry beyond one attempt. A stale provider token is re-minted and retried
  once; Apple throttling or faulting is retried once. Everything else would
  fail identically.
- Queue. A push that fails is reported as failed, now. There is nothing durable
  here to hold it in.

---

## API

Base URL in production: `https://apns.canopysf.com`.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness, plus whether a signing key is configured |
| `POST /v1/instances` | none | Self-service enrollment: issues an instance id and API key |
| `GET /v1/verify` | Bearer | Confirm a key works; for an instance's settings page |
| `POST /v1/push` | Bearer | Forward one notification to one device |
| `GET /` | none | Says what this is; in a browser, a page showing what the relay saw of the request |

Authentication is `Authorization: Bearer <instance-api-key>`. Every rejection is
the same flat 401 with the same message, whether the key was malformed, forged,
or revoked — a caller who is legitimately set up knows which of those they are,
and one who is probing should not be told.

### `POST /v1/push`

```jsonc
{
  "device_token": "a1b2…",           // hex, as Apple issues it
  "environment": "production",        // or "sandbox"; a property of the token
  "title": "The End of Oak Street (2026)",
  "body": "Requested by Robin Example",   // `subtitle` also accepted; see below
  "badge": 3,                         // optional; omit to leave the icon alone
  "data": { "imdb_id": "tt1234567" }, // optional, opaque, ≤1KB
  "collapse_id": "req-7"              // optional
}
```

Becomes, at Apple:

```jsonc
{
  "aps": {
    "alert": { "title": "…", "body": "…" },
    "sound": "default",
    "badge": 3
  },
  "canopy": { "imdb_id": "tt1234567" }
}
```

with `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration: 0` and
`apns-topic` set to the relay's configured bundle id.

**`badge` is optional and absent by default.** APNs has no increment — you
send an absolute number and the last one wins — so the count has to be computed
by whoever knows the user's unread total, which is the instance. The relay
cannot compute it and should not: that would mean tracking a count per device,
which is exactly the device→instance mapping [the isolation
model](#the-isolation-model) exists in order not to have.

Three states, all distinct:

| `badge` | Effect |
|---|---|
| omitted or `null` | No `badge` key reaches Apple; the icon keeps whatever it showed |
| `0` | Sent, and clears the icon |
| a positive integer | Sent, and sets the icon to it |

Omitted is the default, so a client that has never sent a badge produces a
payload byte-identical to the one it produced before badges existed. Note that
the count is per-user while a push is per-device, so a caller with several
devices for one user sends the same number to each.

**The second line is `body`, not `subtitle`.** iOS renders an alert's title
*and* its subtitle in bold, and only `body` in regular weight — so a
notification built from title+subtitle arrives as two bold lines and reads as
shouting next to every other app on the lock screen. Messages, Mail and the
rest put the sender in `title` and the content in `body`; the relay now does
the same. `subtitle` stays accepted as an alias for `body`, because the schema
forbids unknown fields and the two services deploy separately — dropping the
old name would 422 every push from a client that has not been redeployed yet.

The response:

```jsonc
{ "result": "delivered" | "unregistered" | "failed", "reason": null, "apns_id": "…" }
```

**`POST /v1/push` returns 200 whenever Apple answered — including when Apple
said no.** The relay's job is to forward, and "Apple refused this token" is a
successful forward carrying a definitive answer. Non-2xx is reserved for the
relay's own problems, so a caller can read the status code and know whether the
*relay* worked without parsing anything:

| Status | Meaning |
|---|---|
| `200` | Forwarded. Read `result` for what Apple said |
| `401` | Bad, forged, or revoked API key |
| `422` | The request body is not a shape the relay will send |
| `429` | Over this instance's rate limit; `Retry-After` says how long |
| `503` | The relay has no usable signing key, or could not sign this push right now (`Retry-After` is set). Not the instance's fault |

That split matters most for `unregistered`. The relay stores no device tokens,
so it cannot delete a dead one — only the instance can, and burying that answer
in a 5xx alongside genuine faults is how a table fills up with tokens Apple
stopped accepting months ago.

### `GET /v1/verify`

```jsonc
{ "ok": true, "instance": "notcanopy", "bundle_id": "com.example.canopy",
  "ready": true, "rate_limit_per_minute": 120 }
```

`ready: false` means the key is fine and the *relay* has no signing key. That
is a different failure with a different owner than a 401, and separating them
is the point of the endpoint. Not counted against the push rate limit — a
settings page that costs an admin their notification budget to load is a bad
settings page.

---


## Instance API keys

There is no key table. A key is an instance id with a MAC over it:

```
canopy_<instance-id>_<base32 HMAC-SHA256 over the id, truncated to 128 bits>
```

The relay verifies by recomputing the signature from
`CANOPY_APNS_SIGNING_SECRET`. The derivation is byte-for-byte the Python
relay's, and the test suite pins it with keys minted by the Python code — so
**the same signing secret means every key already issued keeps working**.

### Instances enrol themselves

```console
$ curl -X POST https://apns.canopysf.com/v1/instances
{"instance_id":"tpg6b7n6uwtjiaqzmerq",
 "api_key":"canopy_tpg6b7n6uwtjiaqzmerq_lyxh2sd63xenlw2h3tpfbqvjmy",
 "bundle_id":"com.example.canopy","ready":true}
```

No auth, no request body, nothing stored. The relay invents a random id,
derives its key, and forgets both. A caller that loses its key enrols again and
gets a new identity. `cplus-server` calls this the moment an admin ticks
*Enable notifications*.

Keys being free weakens what a per-key rate limit is worth — anyone refused can
enrol again. What holds the line instead:

| Control | What it stops |
|---|---|
| `CANOPY_APNS_ENROLLMENT_PER_HOUR` / `_BURST` | Bulk minting from one source address |
| `CANOPY_APNS_RATE_LIMIT` / `_BURST` | One instance flooding Apple |
| `CANOPY_APNS_REVOKED_INSTANCES` | A specific instance behaving badly |
| `CANOPY_APNS_ENROLLMENT_ENABLED=false` | Enrollment entirely, if it is ever abused |

The source address is Cloudflare's `CF-Connecting-IP`, which Cloudflare sets
from the connection itself. The Python relay had to trust a proxy's
`X-Forwarded-For` to get the same thing; there is nothing to configure here.

### Issuing one by hand

For a stable id you choose:

```console
$ CANOPY_APNS_SIGNING_SECRET=… npm run mint -- acme
canopy_acme_…
```

Runs locally under Node, needs the same signing secret the Worker has, and is
deterministic, so a lost key can be handed out again. Ids are 1–63 characters
of lowercase letters, digits and internal hyphens.

### Revoking

| Scope | How | Effect |
|---|---|---|
| One instance | Add its id to `CANOPY_APNS_REVOKED_INSTANCES` | That key 401s; everyone else unaffected |
| Everything | Rotate `CANOPY_APNS_SIGNING_SECRET` | Every key ever issued 401s; instances re-enrol |

Both are a settings change rather than a code deploy: `wrangler secret put`
and a dashboard edit each roll out a new version of the Worker on their own.

---

## Configuration

The same variable names as the Python relay. Secrets go in with
`wrangler secret put`; plain settings can go in the dashboard (**Workers &
Pages → canopy-apns → Settings → Variables and Secrets**). `wrangler.jsonc`
sets `keep_vars`, so a deploy does not wipe dashboard values.

| Variable | Kind | Default | What it is |
|---|---|---|---|
| `CANOPY_APNS_SIGNING_SECRET` | **secret, required** | — | HMAC secret behind every instance API key. `npm run secret` generates one; **reuse the Coolify value** to keep existing keys valid |
| `CANOPY_APNS_TEAM_ID` | secret or var | — | Apple Developer team id |
| `CANOPY_APNS_KEY_ID` | secret or var | — | The push key's id, also in the filename `AuthKey_ABC123DEFG.p8` |
| `CANOPY_APNS_BUNDLE_ID` | secret or var | — | The app's bundle id, sent as the APNs topic |
| `CANOPY_APNS_PRIVATE_KEY` | **secret** | — | The `.p8` contents |
| `CANOPY_APNS_REVOKED_INSTANCES` | var | empty | Comma-separated instance ids to refuse |
| `CANOPY_APNS_RATE_LIMIT` | var | `120` | Pushes per minute per instance |
| `CANOPY_APNS_RATE_BURST` | var | `30` | How large a burst is tolerated |
| `CANOPY_APNS_ENROLLMENT_ENABLED` | var | `true` | Whether `POST /v1/instances` issues keys |
| `CANOPY_APNS_ENROLLMENT_PER_HOUR` | var | `10` | Enrollments per hour per source address |
| `CANOPY_APNS_ENROLLMENT_BURST` | var | `5` | How many may be bunched together |

Gone, because a Worker has no use for them: `CANOPY_APNS_PRIVATE_KEY_FILE`
(no filesystem — setting it is an error that says so), and
`CANOPY_APNS_HOST`, `_PORT`, `_LOG_LEVEL` and `_FORWARDED_ALLOW_IPS`.

**A bad signing secret or an unreadable `.p8` makes every endpoint answer 500
with a sentence naming the problem.** The Python relay refused to start in
the same situations; a Worker has no startup to refuse, and a 500 on
`/health` is the nearest equivalent that is visible the moment it is deployed.
The signing secret is refused when blank, containing whitespace, matching
known placeholder text, or under 32 characters.

**Missing APNs credentials are not an error.** `/health` reports
`"apns": "unconfigured"`, `/v1/verify` says `ready: false`, and pushes get a
503 that says whose problem it is.

The `.p8` can be pasted verbatim, with literal `\n` in place of newlines, or
as base64 of the whole file. `wrangler secret put` reads multi-line input from
a pipe, so the simplest is:

```console
$ npx wrangler secret put CANOPY_APNS_PRIVATE_KEY < AuthKey_ABC123DEFG.p8
```

---

## State: what the Durable Objects hold

The Python relay was one process, so it kept its provider token and rate-limit
buckets in memory. A Worker is many short-lived isolates across Cloudflare's
network, each with its own memory, and both of those break when split up:

- **The provider token.** Apple answers `TooManyProviderTokenUpdates` to a
  sender that mints JWTs more often than every 20 minutes. Every isolate
  minting its own would look exactly like that.
  `ProviderTokenStore` — a single Durable Object — mints the token and hands
  it out, and each isolate keeps a copy until it is 45 minutes old. So the
  Durable Object is asked about once per isolate per 45 minutes, not once per
  push. It stores the JWT and a hash of the credentials that made it; never
  the `.p8`.
- **Rate limits.** Per-isolate buckets would reset constantly and limit
  nothing. `RateLimiter` is one Durable Object per bucket (`push:<instance-id>`,
  `enroll:<address>`), running the same token bucket as before. That makes the
  limit global, which the Python relay's per-replica buckets never were. Each
  stores its key, a token count and a timestamp, and deletes itself after an
  hour idle.

Neither holds a device token, notification text, or anything relating a
device to an instance.

If the rate limiter cannot be reached, pushes and enrollments are **allowed**
and the failure is logged: dropping every push during a Cloudflare hiccup is
worse than a minute unmetered. If the token store cannot be reached, the push
gets a 503 with `Retry-After`, because nothing can be sent without a token.

**Cost.** Each push is one rate-limiter request and one storage write; token
requests are rare. Both classes are SQLite-backed, which the Workers free plan
supports. Compare that against the plan's current daily Durable Object
allowances for your push volume.

---

## Deploying on Cloudflare

### 1. Install and log in

```console
$ npm install
$ npx wrangler login
```

### 2. Deploy once, to create the Worker

```console
$ npm run deploy
```

It answers on `https://canopy-apns.<your-subdomain>.workers.dev`. With no
secrets yet, every endpoint returns a 500 saying the signing secret is not
set. That is expected.

### 3. Set the secrets

```console
$ npx wrangler secret put CANOPY_APNS_SIGNING_SECRET      # paste the Coolify value
$ npx wrangler secret put CANOPY_APNS_TEAM_ID
$ npx wrangler secret put CANOPY_APNS_KEY_ID
$ npx wrangler secret put CANOPY_APNS_BUNDLE_ID
$ npx wrangler secret put CANOPY_APNS_PRIVATE_KEY < AuthKey_ABC123DEFG.p8
```

Carrying the signing secret over is what lets instances already enrolled
against the Coolify relay switch without re-enrolling. Use `npm run secret`
only if you mean to start over.

### 4. Check it answers

```console
$ curl https://canopy-apns.<sub>.workers.dev/health
{"status":"ok","apns":"configured"}

$ curl https://canopy-apns.<sub>.workers.dev/v1/verify -H "Authorization: Bearer <an existing instance key>"
{"ok":true,"instance":"…","bundle_id":"…","ready":true,"rate_limit_per_minute":120}
```

### 5. Check that Apple answers

The open question with Workers was whether its `fetch()` reaches APNs, which
accepts only HTTP/2. This settles it without a real device: push to a made-up
token and read the `reason`.

```console
$ curl -X POST https://canopy-apns.<sub>.workers.dev/v1/push \
    -H "Authorization: Bearer <key>" -H "Content-Type: application/json" \
    -d '{"device_token":"0000000000000000000000000000000000000000000000000000000000000000","title":"test","environment":"sandbox"}'
```

- `{"result":"unregistered","reason":"BadDeviceToken",…}` — Apple parsed the
  request, accepted the provider token, and rejected the made-up device token.
  The whole path works.
- `{"result":"failed","reason":"InvalidProviderToken",…}` (or another
  Apple reason) — Apple answered, so HTTP/2 works; the team id, key id or
  `.p8` is wrong.
- A `reason` that is not an Apple reason string — a network or protocol error
  message — means the request never got a proper answer from Apple. That is
  the failure to look for, and the Worker's logs (**Observability** in the
  dashboard, or `npx wrangler tail`) will have the detail.

Then send one real push, to a device token from a development build with
`"environment": "sandbox"`.

### 6. Cut over

Once the domain's DNS is on Cloudflare, uncomment `routes` in
`wrangler.jsonc` and `npm run deploy`. Cloudflare creates the DNS record and
certificate for `apns.canopysf.com` and points it at the Worker. If the
existing record pointing at the home server is in the way, Cloudflare will
refuse and say so; remove that record and deploy again. Nothing
changes for instances: same URL, same keys. Keep the Coolify deployment
around until pushes have been flowing for a while, then stop it.

---

## Differences from the Python relay

| | Python on Coolify | Worker |
|---|---|---|
| API, key format, env var names | — | Unchanged |
| Provider token | In process memory | `ProviderTokenStore` Durable Object, copied per isolate |
| Rate limits | In memory, per replica | `RateLimiter` Durable Object per bucket; global |
| Rate limiter unavailable | n/a | Fails open, logged |
| Bad config | Refuses to start | Every endpoint 500s with the reason |
| Client address | `X-Forwarded-For` via uvicorn | `CF-Connecting-IP` |
| `.p8` from a file | `CANOPY_APNS_PRIVATE_KEY_FILE` | Not supported |
| `GET /docs` (OpenAPI) | FastAPI's | Gone; this README is the reference |
| 422 bodies | pydantic's | Same `{"detail": [{type, loc, msg}]}` shape, wording may differ |
| Minting keys locally | `python -m canopy_apns mint` | `npm run mint -- <id>` |

---

## Privacy: what the relay operator can see

Worth being honest about, because instance admins are being asked to route
their users' notifications through someone else's server.

**Notifications pass through the relay in plaintext.** APNs requires this —
Apple has to read the alert to display it. For the duration of one request the
Worker holds the device token, the title and body, the instance's `data`
blob, the instance id, and the source IP.

**Cloudflare is now in that path too.** Cloudflare terminates TLS for the
Worker and runs its code, so the same plaintext exists on Cloudflare's
machines for the length of the request. On Coolify that was a machine the
relay operator owned. Instance admins deciding whether to enable the relay
should know that.

**None of it is stored by the relay.** The log lines it writes record the
instance id, the environment and the outcome — not the device token and not
the text. With `observability` enabled in `wrangler.jsonc`, Cloudflare also
keeps per-invocation request metadata in Workers Logs. The device token and
text are in the request body and are not part of that; exactly which request
headers are retained has not been checked here. Look at one log entry after
deploying, and set `"observability": { "enabled": false }` if you would rather
keep nothing.

---

## Development

```console
$ npm install
$ npm test              # vitest, inside workerd, both Durable Objects live
$ npm run typecheck
$ cp .dev.vars.example .dev.vars && npm run dev     # a local relay on :8787
```

Requires Node 22+. Tests generate their own P-256 key per run rather than
checking one in, and stub `fetch`, so nothing reaches Apple.

### Layout

```
src/
  index.ts       the Worker entry point; exports only the handler and the Durable Objects
  app.ts         routing and the four endpoints
  config.ts      env in, Settings out; refuses a placeholder signing secret
  keys.ts        derived instance API keys, byte-compatible with the Python relay
  apns.ts        provider-token signing, the payload, the push
  tokens.ts      ProviderTokenStore, and the per-isolate copy in front of it
  ratelimit.ts   the token bucket, and the RateLimiter Durable Object
  schemas.ts     validation of POST /v1/push
  landing.ts     the browser page at /
scripts/cli.ts   npm run secret | mint
legacy-python/   the previous service, kept as it was
```

### The client side

`cplus-server` is the reference client. Its `notify/relay.py` is the whole of
what talking to this service takes: one POST per device, a `Bearer` header,
and deleting a device row when the result comes back `unregistered`.
