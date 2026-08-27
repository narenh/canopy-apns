# canopy-apns

A public APNs forwarder for self-hosted Canopy+ instances.

One Apple Developer account owns the app, so one signing key can push to it.
That key cannot be handed out — it signs notifications for every app on the
team — but every self-hoster still needs to send pushes. This service is the
resolution: it holds the key, and instances hand it `(device token, two lines
of text)` over an authenticated HTTP call.

It stores nothing. No database, no volume, no queue, no device tokens.

---

## Contents

- [The isolation model](#the-isolation-model)
- [What the relay does and does not do](#what-the-relay-does-and-does-not-do)
- [API](#api)
- [Instance API keys](#instance-api-keys) — including self-service enrollment
- [Configuration](#configuration)
- [Deploying on Coolify](#deploying-on-coolify) — including [checking TLS from a browser](#checking-tls-and-the-proxy-from-a-browser)
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
              │ {token: A, title, subtitle}       │ {token: C, title, subtitle}
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
| `GET /` | none | Says what this is; in a browser, [a page showing what the relay saw](#checking-tls-and-the-proxy-from-a-browser) |

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
  "subtitle": "Requested by Robin Example",
  "data": { "imdb_id": "tt1234567" }, // optional, opaque, ≤1KB
  "collapse_id": "req-7"              // optional
}
```

Becomes, at Apple:

```jsonc
{
  "aps": {
    "alert": { "title": "…", "subtitle": "…" },
    "sound": "default"
  },
  "canopy": { "imdb_id": "tt1234567" }
}
```

with `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration: 0` and
`apns-topic` set to the relay's configured bundle id.

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
| `503` | The relay has no usable signing key. Not the instance's fault |

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

Per-address limiting needs the app to see the real client rather than the proxy
in front of it, so uvicorn is run with proxy headers trusted and
`CANOPY_APNS_FORWARDED_ALLOW_IPS` defaults to `*`. That is correct while the
container is only reachable through Coolify's proxy — which `expose` (rather
than `ports`) ensures. If you ever publish the port directly, narrow it to the
proxy's address, or a client can claim any address it likes and get a fresh
bucket per request.

### Issuing one by hand

Still supported, for a stable id you choose:

```console
$ python -m canopy_apns mint acme
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

Both are redeploys. A derived key cannot be un-derived, which is the price of
having no persistence at all.

---

## Configuration

Everything is an environment variable. There is no config file and no admin UI,
because there is no storage for either to write to.

| Variable | Required | Default | What it is |
|---|---|---|---|
| `CANOPY_APNS_SIGNING_SECRET` | **yes** | — | HMAC secret behind every instance API key. `python -m canopy_apns secret` generates one |
| `CANOPY_APNS_TEAM_ID` | for pushing | — | Apple Developer team id, ten characters |
| `CANOPY_APNS_KEY_ID` | for pushing | — | The push key's id; also in the filename `AuthKey_ABC123DEFG.p8` |
| `CANOPY_APNS_BUNDLE_ID` | for pushing | — | The app's bundle id, sent as the APNs topic |
| `CANOPY_APNS_PRIVATE_KEY` | for pushing | — | The `.p8` contents |
| `CANOPY_APNS_PRIVATE_KEY_FILE` | — | — | Path to a mounted `.p8`, instead of the above |
| `CANOPY_APNS_REVOKED_INSTANCES` | — | empty | Comma-separated instance ids to refuse |
| `CANOPY_APNS_RATE_LIMIT` | — | `120` | Pushes per minute per instance |
| `CANOPY_APNS_RATE_BURST` | — | `30` | Bucket capacity, i.e. how large a burst is tolerated |
| `CANOPY_APNS_ENROLLMENT_ENABLED` | — | `true` | Whether `POST /v1/instances` issues keys |
| `CANOPY_APNS_ENROLLMENT_PER_HOUR` | — | `10` | Enrollments per hour per source address |
| `CANOPY_APNS_ENROLLMENT_BURST` | — | `5` | How many may be bunched together |
| `CANOPY_APNS_FORWARDED_ALLOW_IPS` | — | `*` | Whose `X-Forwarded-For` to trust when identifying the client |
| `CANOPY_APNS_HOST` | — | `0.0.0.0` | Bind address |
| `CANOPY_APNS_PORT` | — | `9247` | Bind port |
| `CANOPY_APNS_LOG_LEVEL` | — | `info` | uvicorn log level |

**A missing signing secret stops startup** — without it no API key can be
verified and every request would 401 anyway, so failing with one sentence beats
serving nothing but rejections.

**A missing APNs key does not.** The service starts, serves `/health` reporting
`"apns": "unconfigured"`, tells instances so on `/v1/verify`, and refuses pushes
with a 503 that says whose problem it is. A fresh deployment waiting on its
`.p8` is a supported state, not a crash loop.

### Pasting the `.p8`

A PEM file is multi-line and most secret-variable editors are not. All three
shapes are accepted, so whichever survived the paste works:

- the PEM verbatim, real newlines and all;
- the PEM with literal `\n` where the newlines were;
- base64 of the whole file.

Whether the result is a usable ES256 key is checked **at startup**, so a
mis-pasted file is one line in the deployment log rather than something
discovered later as notifications quietly not arriving.

### Rate limiting

A token bucket per instance, in memory. Nothing is shared between replicas, so
with N replicas an instance's effective ceiling is N times the configured one.
That is fine: this limit exists to stop one misconfigured instance from
hammering Apple with the operator's signing key, not to meter a paid product. A
shared counter would mean a Redis, which would mean the relay was no longer
stateless.

Buckets for instances that have gone quiet are dropped after an hour of idleness
— a full bucket and no bucket are indistinguishable, so forgetting one is free.

---

## Deploying on Coolify

1. **New resource → Docker Compose**, pointed at this repository. `build: .` is
   already in `docker-compose.yml`; nothing is published to a registry.
2. **Assign the domain** `apns.canopysf.com`. Coolify fills in
   `SERVICE_FQDN_CANOPYAPNS_8080` and wires up its proxy and TLS certificate.
   The compose file uses `expose`, not `ports`, so the container is reachable
   only through that proxy.
3. **Set the environment variables** in Coolify. Mark
   `CANOPY_APNS_SIGNING_SECRET` and `CANOPY_APNS_PRIVATE_KEY` as secrets, and as
   build-time-hidden. Generate the signing secret once:

   ```console
   $ docker run --rm ghcr.io/…/canopy-apns secret     # or, locally:
   $ python -m canopy_apns secret
   ```

4. **Deploy.** Check `GET /health` says `"apns": "configured"`. If it says
   `unconfigured`, one of the four APNs variables is missing or blank — the
   service treats three-out-of-four as not configured, deliberately, because
   three cannot send anything.
5. **Nothing else.** Instances enrol themselves through `POST /v1/instances`
   the moment their admin switches notifications on. Use
   `python -m canopy_apns mint <id>` only if you want to hand someone a stable
   id of their own; it works anywhere the same `CANOPY_APNS_SIGNING_SECRET` is
   set, since the key is derived rather than looked up.

There is **no volume and no `/data`**. If a redeploy loses something, it was not
this service's.

### Checking TLS and the proxy from a browser

Open `https://apns.canopysf.com/` in a browser and the relay renders a
diagnostic page instead of the JSON `curl` gets. There is still no web UI — the
page is a mirror, and it exists because the usual deployment failure behind a
terminating proxy is invisible from the outside.

That failure: the browser speaks HTTPS, the proxy forwards over plain HTTP, and
the app never learns the original scheme, because the proxy is not sending
`X-Forwarded-Proto` or uvicorn is not trusting it. Everything downstream — a
redirect loop, a link that drops to `http://`, a blocked mixed-content fetch —
is a symptom of that one disagreement and none of them name it. So the page
prints, side by side:

- the scheme the **relay** resolved, and the scheme the **browser** actually
  used, with a banner naming the mismatch and which direction it runs in;
- every forwarding header as received (`X-Forwarded-Proto`, `-For`, `-Host`,
  `-Port`, `Forwarded`, `X-Real-IP`, `Host`), including the ones that are
  absent — a blank `X-Forwarded-Proto` is usually the whole answer;
- the client address the relay ended up with, which is what the per-address
  enrollment limit buckets on, so a proxy trusted wrongly shows up here too;
- a live same-origin fetch of `/health`, which fails visibly if the browser is
  blocking it as mixed content or the request is being redirected across
  schemes.

Links on the page are relative, so clicking `/health` or `/docs` keeps whatever
scheme you arrived on and any redirect is the deployment's own.

Nothing on the page is privileged: it reflects your own request back at you,
plus what `/health` already says publicly. It stores nothing, and it is
`noindex`.

### Getting the `.p8` in the first place

In the Apple Developer portal, **Certificates, Identifiers & Profiles → Keys**,
create a key with APNs enabled and download it. Apple lets you download it
exactly once. The key id is printed next to the key and is also in the filename
(`AuthKey_ABC123DEFG.p8`); the team id is at the top right of the portal.

The bundle id is the app's, and it must match the app the device tokens come
from — Apple rejects a push whose topic does not match. Since every instance is
pushing to the same app, that is one value for the whole relay, which is why it
is a relay-level environment variable rather than something an instance sends.

---

## Privacy: what the relay operator can see

Worth being honest about, because instance admins are being asked to route
their users' notifications through someone else's server.

**Notifications pass through the relay in plaintext.** APNs itself requires
this — Apple has to be able to read the alert text to display it, so there is
no end-to-end encrypted path to APNs that would let the relay forward without
seeing the content. For the duration of one request, the relay process holds:

- the device token (a random per-device identifier, not a user identity);
- the notification's title and subtitle — which for Canopy+ means a media title
  and a username;
- the instance's own `data` blob;
- the instance id from the API key, and the source IP.

**None of it is stored.** There is no database to store it in. The request logs
record the instance id, the environment, and the outcome — deliberately not the
device token and not the text, because a log that reconstructs what was
forwarded is a store of exactly what this service promises not to keep.

An instance admin who is not comfortable with that should not enable the relay.
That is why the toggle in cplus-server is off by default and says so on its
face, rather than being on with a note in the docs.

---

## Development

```console
$ python -m venv .venv && .venv/bin/pip install -e ".[dev]"
$ .venv/bin/python -m pytest
$ .venv/bin/python -m ruff check .
```

Requires Python 3.12+.

The test suite generates its own P-256 key per session rather than checking one
in — a committed private key is a committed private key even when it is only
ever used against a mocked host — and mocks Apple with `respx`, so nothing
reaches the network.

### Layout

```
src/canopy_apns/
  config.py      environment in, one frozen Settings out
  keys.py        derived instance API keys; the reason there is no database
  apns.py        provider-token signing and the HTTP/2 push
  ratelimit.py   a token bucket per instance
  schemas.py     the wire contract, extra="forbid" throughout
  landing.py     the browser page at /: what the relay saw of your request
  app.py         the four endpoints
  __main__.py    serve | secret | mint
```

### The client side

`cplus-server` is the reference client. Its `notify/relay.py` is the whole of
what talking to this service takes: one POST per device, a `Bearer` header, and
deleting a device row when the result comes back `unregistered`.
