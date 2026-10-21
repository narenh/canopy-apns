# canopy-apns

A public APNs forwarder for self-hosted Canopy+ instances, running as a
Cloudflare Worker at `apns.canopysf.com`.

One Apple Developer account owns the app, so one signing key can push to it.
That key cannot be handed out — it signs notifications for every app on the
team — but every self-hoster still needs to send pushes. This service is the
resolution: it holds the key, and instances hand it `(device token, two lines
of text)` over an authenticated HTTP call.

It stores no device tokens, no notification text, and no keys. The only state
is a rate-limit counter per instance and per enrolling address, which deletes
itself after an hour idle.

It used to be a Python/FastAPI container on Coolify. It moved to Workers so a
push no longer depends on a home network being up; the HTTP contract, the key
format and every existing instance key are unchanged.

---

## Contents

- [The isolation model](#the-isolation-model)
- [What the relay does and does not do](#what-the-relay-does-and-does-not-do)
- [API](#api)
- [Instance API keys](#instance-api-keys) — including self-service enrollment
- [Configuration](#configuration)
- [Deploying](#deploying) — including [the cutover from Coolify](#cutting-over-from-coolify)
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

- Holds the APNs signing key (`.p8`) as a Worker secret, and the team id, key
  id and bundle id as Worker vars.
- Issues instance identities on demand, so no self-hoster ever handles a
  credential. Still writes nothing down.
- Authenticates each request by instance API key, and rate-limits per instance.
- Builds the APNs payload itself from a constrained request shape, and sets the
  push headers.
- Signs a provider-token JWT, POSTs to Apple (Cloudflare's edge speaks HTTP/2
  to Apple on the Worker's behalf), and reports the
  outcome — including telling the instance when a device token is dead so it
  can delete it.

**Does not**

- Store device tokens, notification text, any device→instance mapping, or the
  keys it issues. Enrollment computes a key and forgets it.
- Accept a raw `aps` dictionary. An instance sends text; the relay decides the
  payload shape. Otherwise any instance could send a silent
  `content-available` background wake signed with the operator's key. (Live
  Activity pushes carry the caller's `content-state` and `attributes`, because
  ActivityKit decodes them into the app's own types — but every other `aps` key
  is still the relay's; see [`POST /v1/liveactivity`](#post-v1liveactivity).)
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
| `POST /v1/liveactivity` | Bearer | Forward one Live Activity start, update or end to one token; allow-listed per instance |
| `GET /` | none | Says what this is; a browser gets a small status page |

Every non-2xx body is `{"detail": "<one sentence>"}` — including a 422, whose
`detail` was a list of pydantic errors before the move to Workers and is now
one sentence naming the field.

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
| `503` | The relay has no usable signing key, or is misconfigured. Not the instance's fault |

That split matters most for `unregistered`. The relay stores no device tokens,
so it cannot delete a dead one — only the instance can, and burying that answer
in a 5xx alongside genuine faults is how a table fills up with tokens Apple
stopped accepting months ago.

### `POST /v1/liveactivity`

Starts, updates or ends a Live Activity. Same authentication, same rate-limit
bucket, same retry and provider-token handling, and the same response shape as
`/v1/push` — but **off for everyone by default**: an instance may only push to
a bundle id the operator has paired with it in
[`CANOPY_APNS_LIVEACTIVITY_TOPICS`](#live-activity-topics).

Every field, for reference — a real request would not combine `start` with
`dismissal_date`, which is refused on anything but `end`:

```jsonc
{
  "device_token": "a1b2…",              // hex; the activity's push token, or the
                                         //   app's push-to-start token for "start"
  "environment": "production",           // or "sandbox"
  "bundle_id": "com.canopysf.CanopyControl", // the app; no topic suffix
  "event": "start",                      // "start" | "update" | "end"
  "content_state": { "progress": 0.5 },  // required; the app's ContentState
  "attributes_type": "DownloadAttributes", // required for start, refused otherwise
  "attributes": { "title": "…" },        // required for start ({} is fine), refused otherwise
  "alert": { "title": "…", "body": "…" },// required for start; optional otherwise; ≤200 chars each
  "timestamp": 1760000000,               // optional; unix seconds, default now
  "stale_date": 1760003600,              // optional; unix seconds
  "dismissal_date": 1760000900,          // optional; "end" only
  "relevance_score": 50,                 // optional
  "priority": 10,                        // 5 or 10; default 10
  "expiration": 0                        // optional; unix seconds, default 0
}
```

Becomes, at Apple, with absent optionals omitted rather than sent as `null`:

```jsonc
{
  "aps": {
    "timestamp": 1760000000,
    "event": "start",
    "content-state": { "progress": 0.5 },
    "attributes-type": "DownloadAttributes",
    "attributes": { "title": "…" },
    "alert": { "title": "…", "body": "…" },
    "stale-date": 1760003600,
    "dismissal-date": 1760000900,
    "relevance-score": 50.0
  }
}
```

| Request field | APNs |
|---|---|
| `timestamp` | `aps.timestamp` (relay's clock if omitted) |
| `event` | `aps.event` |
| `content_state` | `aps.content-state` |
| `attributes_type` | `aps.attributes-type` |
| `attributes` | `aps.attributes` |
| `alert` | `aps.alert` |
| `stale_date` | `aps.stale-date` |
| `dismissal_date` | `aps.dismissal-date` |
| `relevance_score` | `aps.relevance-score` |
| `bundle_id` | header `apns-topic: <bundle_id>.push-type.liveactivity` |
| `priority` | header `apns-priority` |
| `expiration` | header `apns-expiration` |
| — | header `apns-push-type: liveactivity` |

The whole encoded payload must be **≤ 4096 bytes** (UTF-8, measured exactly as
sent); anything larger is a 422 before Apple is contacted. The alert carries no
`sound`; the relay sends only the fields above.

```console
$ curl https://apns.canopysf.com/v1/liveactivity \
    -H "Authorization: Bearer canopy_a1b2c3_…" \
    -H "Content-Type: application/json" \
    -d '{"device_token":"80f1…","environment":"sandbox",
         "bundle_id":"com.canopysf.CanopyControl","event":"update",
         "content_state":{"progress":0.5,"label":"Downloading"}}'
{"result":"delivered","reason":null,"apns_id":"…"}
```

Status codes are `/v1/push`'s, plus one:

| Status | Meaning |
|---|---|
| `200` | Forwarded. Read `result` for what Apple said |
| `401` | Bad, forged, or revoked API key |
| `403` | This instance is not allowed this bundle id (or no instance is); the `detail` says which, and names the entry the operator would add |
| `422` | Not a shape the relay will send, a start missing `attributes_type`/`attributes`/`alert`, or over 4096 bytes |
| `429` | Over this instance's rate limit — the same bucket `/v1/push` spends |
| `503` | The relay has no usable signing key |

A 403 or 422 spends no rate-limit budget.

**`BadDeviceToken` is `failed` here, not `unregistered`.** `result:
"unregistered"` means "delete this token", and it is returned only for a 410,
`Unregistered` or `DeviceTokenNotForTopic`. A `BadDeviceToken` on an activity
token is usually a sandbox token sent to production (or the reverse), so it
comes back as `{"result": "failed", "reason": "BadDeviceToken"}` and the caller
should check its `environment` rather than drop the token. `/v1/push` is
unchanged and still reports `BadDeviceToken` as `unregistered`.

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
`CANOPY_APNS_SIGNING_SECRET`. That is what lets the service be genuinely
stateless — nothing to back up, nothing to migrate, and two replicas that
cannot disagree about who is allowed in. It is also what makes self-service
enrollment possible without a database.

### Instances enrol themselves

```console
$ curl -X POST https://apns.canopysf.com/v1/instances
{"instance_id":"tpg6b7n6uwtjiaqzmerq",
 "api_key":"canopy_tpg6b7n6uwtjiaqzmerq_ifjxemuuqtg5a7g6opkbz3je5q",
 "bundle_id":"com.example.canopy","ready":true}
```

No auth, no request body, nothing stored. The relay invents a random id, derives
its key, and forgets both. There is nothing an enrolling instance could tell the
relay that the relay could verify, so it is not asked.

**This is not recoverable.** There is nowhere the key was written down. A caller
that loses one enrols again and gets a new identity; the old id simply stops
being used.

`cplus-server` calls this the moment an admin ticks *Enable notifications*, so
no self-hoster ever sees or handles a credential.

### The trade this makes

Handing out keys for free weakens what a per-key rate limit is worth: anyone
refused can enrol again and get a fresh bucket. That is a real cost and it was
accepted deliberately, because the alternative — every admin obtaining a key out
of band and pasting it into a form — put a credential in front of people whose
actual intent was "I would like notifications", and required a human in the loop
for every single one.

What holds the line instead:

| Control | What it stops |
|---|---|
| `CANOPY_APNS_ENROLLMENT_PER_HOUR` / `_BURST` | Bulk minting from one source address |
| `CANOPY_APNS_RATE_LIMIT` / `_BURST` | One instance flooding Apple |
| `CANOPY_APNS_REVOKED_INSTANCES` | A specific instance behaving badly |
| `CANOPY_APNS_ENROLLMENT_ENABLED=false` | Enrollment entirely, if it is ever abused |

Turning enrollment off does not disturb instances already holding a key.

Per-address limiting keys on `CF-Connecting-IP`, which Cloudflare sets to the
real client and which no caller can forge — the `X-Forwarded-For` trust setting
the Docker deployment needed is gone.

### Issuing one by hand

Still supported, for a stable id you choose:

```console
$ CANOPY_APNS_SIGNING_SECRET=… npm run mint -- acme
canopy_acme_k3jd7q2mfhx4zt8bwv6nra5cyp
```

Deterministic, so an admin who lost their key can be handed the same one again.
Hand-chosen ids are 1–63 characters of lowercase letters, digits and internal
hyphens. No underscores — that separates the fields, so a key always splits into
exactly three parts. The id is legible in the key by design: it is what logs and
rate-limit buckets are keyed on, and a key in a bug report can be attributed
without a lookup. The id is an identifier; the signature is the secret part.

### Revoking

| Scope | How | Effect |
|---|---|---|
| One instance | Add its id to `CANOPY_APNS_REVOKED_INSTANCES` | That key 401s; everyone else unaffected |
| Everything | Rotate `CANOPY_APNS_SIGNING_SECRET` | Every key ever issued 401s; instances re-enrol |

Both are a `npm run deploy` (or a `wrangler secret put`). A derived key cannot be un-derived, which is the price of
having no persistence at all.

---

## Configuration

Two secrets, set with `wrangler secret put` and never written to a file:

| Secret | What it is |
|---|---|
| `CANOPY_APNS_SIGNING_SECRET` | HMAC secret behind every instance API key. `npm run secret` generates one. **Must be the same value the relay has always run with**, or every existing instance key stops verifying |
| `CANOPY_APNS_PRIVATE_KEY` | The `.p8` contents (verbatim, with literal `\n`, or base64 of the whole file) |

Everything else is a var in [`wrangler.jsonc`](wrangler.jsonc), committed,
because none of it is secret:

| Var | Default | What it is |
|---|---|---|
| `CANOPY_APNS_TEAM_ID` | — | Apple Developer team id, ten characters |
| `CANOPY_APNS_KEY_ID` | — | The push key's id; also in the filename `AuthKey_ABC123DEFG.p8` |
| `CANOPY_APNS_BUNDLE_ID` | — | The app's bundle id, sent as the APNs topic for `/v1/push` |
| `CANOPY_APNS_REVOKED_INSTANCES` | empty | Comma-separated instance ids to refuse |
| `CANOPY_APNS_LIVEACTIVITY_TOPICS` | empty | `<instance_id>:<bundle_id>` pairs allowed on `/v1/liveactivity`; empty means nobody. See [below](#live-activity-topics) |
| `CANOPY_APNS_RATE_LIMIT` | `120` | Pushes per minute per instance |
| `CANOPY_APNS_RATE_BURST` | `30` | Bucket capacity, i.e. how large a burst is tolerated |
| `CANOPY_APNS_ENROLLMENT_ENABLED` | `true` | Whether `POST /v1/instances` issues keys |
| `CANOPY_APNS_ENROLLMENT_PER_HOUR` | `10` | Enrollments per hour per source address |
| `CANOPY_APNS_ENROLLMENT_BURST` | `5` | How many may be bunched together |

A Worker has no startup to fail, so what the container used to refuse to boot
with is a **503 on every endpoint, `/health` included**, carrying the reason:
a missing signing secret; one that contains whitespace, matches known
boilerplate, or is shorter than 32 characters; a non-numeric limit; a malformed
allow-list entry. `/health` also imports the `.p8`, so a mis-pasted key shows
up there rather than as pushes quietly failing.

**A missing APNs key is not an error.** `/health` reports
`"apns": "unconfigured"`, `/v1/verify` says `ready: false`, and pushes are
refused with a 503 that says whose problem it is. Three of the four APNs values
counts as unconfigured, deliberately.

### Live Activity topics


`/v1/push` can only ever reach the relay's own `CANOPY_APNS_BUNDLE_ID`.
`/v1/liveactivity` names its bundle per request, and the relay's key signs for
every app on the team, so with enrollment open to anyone it is an allow-list:

```
CANOPY_APNS_LIVEACTIVITY_TOPICS=a1b2c3:com.canopysf.CanopyControl,acme:com.example.App
```

- Comma-separated `<instance_id>:<bundle_id>` pairs. An instance may appear
  more than once to be allowed several bundles.
- The instance id is the one in its API key (`canopy_<instance_id>_…`, also
  `instance` on `/v1/verify`), compared lowercased. The bundle id is compared
  exactly and is written **without** the `.push-type.liveactivity` suffix.
- Empty or unset: every `/v1/liveactivity` request is a 403.
- A malformed entry makes every endpoint answer 503 with a message naming it,
  rather than being skipped — a dropped pair would look exactly like a refusal
  for no reason.
- A pair for a revoked instance does nothing; revocation is checked first.

**The `.p8` must be valid for the Live Activity app's team.** The relay signs
every push with its one key. An APNs key in the Apple Developer portal is
team-scoped — it works for every app on that team — so a Live Activity bundle
on the same team as `CANOPY_APNS_BUNDLE_ID` needs no new key. A bundle on a
different team cannot be served by this relay: Apple rejects those pushes, and
the relay reports them as `failed` with Apple's `reason`. If the key was
created restricted to specific topics or to one environment rather than
team-wide, check that it covers the new app and the environments its tokens
come from.

### Rate limiting

A token bucket per instance (`push:<id>`) and per enrolling address
(`enroll:<ip>`), each in its own [Durable Object](src/ratelimit.ts). A Worker
has no shared memory — consecutive requests can land in different cities — so
the bucket needs one place where reads and writes for its key are serialised.
That makes the limit exact and global, where the container's in-memory buckets
were per replica.

Each bucket is one stored row (a token count and a timestamp) and an alarm
deletes it after an hour idle, by which point it would be full anyway.

### The provider token

Apple wants one provider token reused for 20–60 minutes, and returns
`TooManyProviderTokenUpdates` to a key that mints them too often. The token is
cached per Worker isolate and renewed at 45 minutes. A Worker runs in several
isolates at once, so unlike the single container process, a few tokens can be
live for the same key at the same time. At this relay's volume that is a
handful, and a `TooManyProviderTokenUpdates` is retried once like any 429. If it
ever shows up in the logs, move the cache into a Durable Object.

---

## Deploying

Needs a Cloudflare account with `canopysf.com` on it, and `npx wrangler login`
once on the machine you deploy from.

```console
$ npm install
$ npx wrangler secret put CANOPY_APNS_SIGNING_SECRET   # the existing value; see below
$ npx wrangler secret put CANOPY_APNS_PRIVATE_KEY < AuthKey_9C88D929Z5.p8
$ npm run deploy
$ curl https://cfapns.canopysf.com/health
{"status":"ok","apns":"configured"}
```

Changing a var is an edit to `wrangler.jsonc` and a deploy; vars set in the
dashboard are overwritten by the file on every deploy, so set them here.
Changing a secret is `wrangler secret put` (or the dashboard), which takes
effect immediately and survives deploys.

With Workers Builds connected to this repo, a push to the connected branch
deploys. The Worker's name in the dashboard has to match `name` in
`wrangler.jsonc` (`canopy-apns`).

Logs are in the Cloudflare dashboard under the Worker's **Observability** tab
(`"observability"` is on in `wrangler.jsonc`), or live with `npx wrangler tail`.
They carry the instance id, environment and outcome of each push — never the
device token or the text.

### Cutting over from Coolify

The DNS cutover is the only step clients notice, and they notice nothing:
`cplus-server` and Canopy Control both just call `https://apns.canopysf.com`.

1. **Run the Worker at `cfapns.canopysf.com` first**, alongside the Coolify
   relay, with the signing secret copied from the Coolify deployment's
   `CANOPY_APNS_SIGNING_SECRET` (production, not preview) and the same `.p8`.
   With the same secret, every key the old relay issued verifies here —
   `npm test` pins that against keys the Python code minted.
2. **Send a real push through it**, because only a deployed Worker can reach
   APNs (local `wrangler dev` on macOS cannot; see
   [cloudflare/workerd#4841](https://github.com/cloudflare/workerd/issues/4841)).
   Use an existing instance key and a device token you own:

   ```console
   $ curl https://cfapns.canopysf.com/v1/push \
       -H "Authorization: Bearer canopy_…" -H "Content-Type: application/json" \
       -d '{"device_token":"…","environment":"production","title":"Worker test"}'
   {"result":"delivered","reason":null,"apns_id":"…"}
   ```

   `delivered` and a notification on the phone is the go signal. A `failed`
   with a network-level `reason` means the edge could not reach Apple, and the
   cutover should stop there.
3. **Point `apns.canopysf.com` at the Worker.** In the Cloudflare dashboard,
   delete the existing `apns` DNS record for `canopysf.com`; add
   `{ "pattern": "apns.canopysf.com", "custom_domain": true }` to `routes` in
   `wrangler.jsonc`; deploy. Cloudflare creates the record and the
   certificate. The gap between deleting the record and the deploy finishing
   is the only downtime, typically under a minute.
4. **Check from outside**, then stop the Coolify application. Leave it stopped
   rather than deleted for a few days, so going back is a DNS record.

Rolling back: remove the `apns` route, deploy, recreate the old DNS record,
start the Coolify app.

### Getting the `.p8` in the first place

In the Apple Developer portal, **Certificates, Identifiers & Profiles → Keys**,
create a key with APNs enabled and download it. Apple lets you download it
exactly once. The key id is printed next to the key and is also in the filename
(`AuthKey_ABC123DEFG.p8`); the team id is at the top right of the portal.

The bundle id is the app's, and it must match the app the device tokens come
from — Apple rejects a push whose topic does not match. Since every instance is
pushing to the same app, that is one value for the whole relay, which is why it
is a relay-level environment variable rather than something an instance sends.
Live Activity pushes are the exception — they name their bundle per request,
which is why [they are allow-listed](#live-activity-topics) — and the same key
serves them as long as the app is on the same team.

---

## Privacy: what the relay operator can see

Worth being honest about, because instance admins are being asked to route
their users' notifications through someone else's server — and since the move,
through Cloudflare's as well.

**Notifications pass through the relay in plaintext.** APNs itself requires
this — Apple has to be able to read the alert text to display it, so there is
no end-to-end encrypted path that would let the relay forward without seeing
the content. For the duration of one request, the Worker holds:

- the device token (a random per-device identifier, not a user identity);
- the notification's title and body — which for Canopy+ means a media title
  and a username;
- the instance's own `data` blob;
- the instance id from the API key, and the source IP.

**None of the content is stored.** The logs record the instance id, the
environment, and the outcome — deliberately not the device token and not the
text. What *is* stored is the rate-limit state: a token count per instance id,
and a token count per enrolling IP address, which is the one place an address
persists — for at most an hour after its last enrollment attempt. Cloudflare
runs the Worker and so is in the path of every request, as Apple already was.

An instance admin who is not comfortable with that should not enable the relay.
That is why the toggle in cplus-server is off by default and says so on its
face, rather than being on with a note in the docs.

---

## Development

```console
$ npm install
$ npm test          # vitest inside workerd; Apple is mocked
$ npm run typecheck
$ npm run dev       # local Worker; copy .dev.vars.example to .dev.vars first
```

Requires Node 22.18+ (the CLI scripts run TypeScript directly).

The test suite generates its own P-256 key per run rather than checking one in,
verifies the provider-token signature it produces, and pins the instance-key
derivation against keys minted by the Python relay.

### Layout

```
src/
  index.ts       the endpoints
  config.ts      Worker env in, one Settings out
  keys.ts        derived instance API keys; the reason there is no database
  apns.ts        provider-token signing and the push to Apple
  ratelimit.ts   the RateLimiter Durable Object: one token bucket per key
  validate.ts    the wire contract, unknown fields refused throughout
  landing.ts     the page a browser gets at /
scripts/cli.ts   npm run secret | npm run mint -- <id>
```

### The client side

`cplus-server` is the reference client. Its `notify/relay.py` is the whole of
what talking to this service takes: one POST per device, a `Bearer` header, and
deleting a device row when the result comes back `unregistered`. Canopy
Control's `live_push.py` does the same for `/v1/liveactivity`.
