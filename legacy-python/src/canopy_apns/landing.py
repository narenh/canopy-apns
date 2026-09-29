"""The page a browser gets at ``/``.

The relay has no web UI and does not want one.  This is not that: it is a
diagnostic, and it exists because the only way to tell a TLS/proxy problem from
an application problem was to read container logs and guess.

The failure it is built for is the ordinary one behind a terminating proxy: the
browser is speaking HTTPS, the proxy forwards over plain HTTP, and the app
either never learns the original scheme (``X-Forwarded-Proto`` not trusted, so
uvicorn's ``--proxy-headers`` never applies it) or learns it wrongly.  Every
symptom that follows — a redirect loop, a link that drops to ``http://``, a
mixed-content block — is downstream of that one disagreement, and none of them
say so.  So the page prints, side by side, the scheme the *browser* used and
the scheme the *app* saw, and names the mismatch when they differ.

Everything on it is derived from the request in hand or from settings already
public on ``/health``.  Nothing here reads a credential, and nothing here is
reachable that is not otherwise: it is a nicer rendering of what any client
could learn by looking at its own connection.
"""

from __future__ import annotations

from html import escape

from starlette.requests import Request

#: Headers that decide, or claim to decide, what the app thinks the original
#: connection was.  Shown whether or not they are present, because an absent
#: ``X-Forwarded-Proto`` is the single most common cause of the mismatch this
#: page exists to catch and a blank row says that louder than a missing one.
FORWARDING_HEADERS = (
    "x-forwarded-proto",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "forwarded",
    "x-real-ip",
    "host",
)

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #fbfaf8; --fg: #1c1b19; --muted: #6b675f; --line: #e3dfd7;
  --card: #ffffff; --ok: #1c6b3c; --warn: #8a4b00; --accent: #2f5d8c;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161513; --fg: #eceae5; --muted: #9b968c; --line: #2e2c28;
    --card: #1e1d1a; --ok: #6cc08a; --warn: #e0a559; --accent: #8ab4dd;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 46rem; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .08em;
     color: var(--muted); margin: 2rem 0 .6rem; font-weight: 600; }
p { margin: .5rem 0; }
.lede { color: var(--muted); margin: 0 0 1.5rem; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
        padding: .35rem .9rem; }
.banner { border-left: 3px solid var(--ok); padding: .8rem .9rem; }
.banner.mismatch { border-left-color: var(--warn); }
.banner strong { display: block; margin-bottom: .2rem; }
.banner span { color: var(--muted); font-size: .9rem; }
table { width: 100%; border-collapse: collapse; }
td { padding: .5rem .1rem; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.k { color: var(--muted); white-space: nowrap; padding-right: 1.2rem; width: 1%; }
td.v { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem;
       word-break: break-all; }
.none { color: var(--muted); font-style: italic; }
a { color: var(--accent); }
ul { padding-left: 1.1rem; margin: .5rem 0; }
li { margin: .3rem 0; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
footer { margin-top: 2.5rem; color: var(--muted); font-size: .85rem; }
"""

# Deliberately no fetch of anything but /health, and the result is written with
# textContent: every value on this page originates from a request header, and a
# header is attacker-controlled text.
_SCRIPT = """
(function () {
  var browser = location.protocol.replace(':', '');
  var seen = document.body.dataset.scheme;
  var el = document.getElementById('browser-scheme');
  if (el) el.textContent = browser;
  var banner = document.getElementById('banner');
  if (banner && browser !== seen) {
    banner.className = 'card banner mismatch';
    banner.innerHTML = '';
    var strong = document.createElement('strong');
    strong.textContent = 'Scheme mismatch: the browser used ' + browser +
      ', the relay saw ' + seen + '.';
    var span = document.createElement('span');
    span.textContent = browser === 'https'
      ? 'The proxy terminated TLS and the relay never learned it: either the ' +
        'proxy is not sending X-Forwarded-Proto: https, or uvicorn is not ' +
        'trusting it (CANOPY_APNS_FORWARDED_ALLOW_IPS). Redirects and absolute ' +
        'links built from the request will drop to http.'
      : 'The relay believes it was reached over TLS when this browser was not ' +
        'using it — something is setting X-Forwarded-Proto: https on a plain ' +
        'HTTP call. Harmless if you reached this port directly, past the proxy; ' +
        'a problem if this is how ordinary traffic arrives, since anyone able ' +
        'to reach the port can then claim any scheme and any client address.';
    banner.appendChild(strong);
    banner.appendChild(span);
  }
  var out = document.getElementById('probe');
  if (!out) return;
  fetch('health', { headers: { accept: 'application/json' } })
    .then(function (r) { return r.json().then(function (j) {
      out.textContent = r.status + ' ' + JSON.stringify(j); }); })
    .catch(function (e) {
      out.textContent = 'failed: ' + e + ' (a same-origin fetch that fails here ' +
        'is usually mixed content or a redirect to another scheme)'; });
})();
"""


def _rows(pairs: list[tuple[str, str | None]]) -> str:
    cells = []
    for key, value in pairs:
        if value:
            rendered = f'<td class="v">{escape(value)}</td>'
        else:
            rendered = '<td class="v none">not set</td>'
        cells.append(f'<tr><td class="k">{escape(key)}</td>{rendered}</tr>')
    return "\n".join(cells)


def render_landing(
    request: Request,
    *,
    version: str,
    apns_configured: bool,
    enrollment_enabled: bool,
    rate_limit_per_minute: int,
) -> str:
    """Render the diagnostic page for one request.

    Pure: takes a request and the few public settings, returns HTML.  Every
    interpolated value goes through :func:`html.escape`, because most of them
    are request headers and a header is whatever the client felt like sending.
    """
    scheme = request.url.scheme
    client = request.client.host if request.client else None
    http_version = request.scope.get("http_version") or None

    headers = [(name, request.headers.get(name)) for name in FORWARDING_HEADERS]

    forwarded_proto = request.headers.get("x-forwarded-proto")
    if scheme == "https":
        banner_note = (
            "Redirects and absolute URLs the relay generates will use https. "
            "If your browser shows this page over http, the check below will "
            "say so."
        )
    elif forwarded_proto:
        banner_note = (
            f"X-Forwarded-Proto says {escape(forwarded_proto)}, but the relay "
            "still resolved http — uvicorn is not trusting the proxy's headers. "
            "Check CANOPY_APNS_FORWARDED_ALLOW_IPS."
        )
    else:
        banner_note = (
            "That is correct for a direct plain-HTTP call. Behind a TLS-"
            "terminating proxy it is not: the proxy should send "
            "X-Forwarded-Proto: https, and uvicorn should be trusting it."
        )

    request_rows = _rows(
        [
            ("Scheme the relay saw", scheme),
            ("Effective URL", str(request.url)),
            ("Method", request.method),
            ("HTTP version", http_version),
            ("Client address", client),
        ]
    )
    relay_rows = _rows(
        [
            ("Service", "canopy-apns"),
            ("Version", version),
            ("APNs signing key", "configured" if apns_configured else "not configured"),
            ("Enrollment", "open" if enrollment_enabled else "closed"),
            ("Push rate limit", f"{rate_limit_per_minute}/minute per instance"),
        ]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>canopy-apns relay</title>
<style>{_STYLE}</style>
</head>
<body data-scheme="{escape(scheme)}">
<main>
  <h1>canopy-apns</h1>
  <p class="lede">A stateless APNs forwarder for self-hosted Canopy+ instances.
  There is no web UI — this page exists so a browser can tell you what the relay
  sees, which is the fastest way to find a TLS or proxy problem.</p>

  <div class="card banner" id="banner">
    <strong>The relay saw this request as {escape(scheme)}.</strong>
    <span>{banner_note}</span>
  </div>

  <h2>In the browser</h2>
  <div class="card">
    <table>
      <tr><td class="k">Browser scheme</td>
          <td class="v" id="browser-scheme"><span class="none">needs JavaScript</span></td></tr>
      <tr><td class="k">Fetch of <code>/health</code></td>
          <td class="v" id="probe"><span class="none">running…</span></td></tr>
    </table>
  </div>

  <h2>This request</h2>
  <div class="card"><table>{request_rows}</table></div>

  <h2>Forwarding headers</h2>
  <div class="card"><table>{_rows(headers)}</table></div>

  <h2>Relay</h2>
  <div class="card"><table>{relay_rows}</table></div>

  <h2>Endpoints</h2>
  <ul>
    <li><a href="health">GET /health</a> — liveness, and whether a signing key is present.</li>
    <li><a href="docs">GET /docs</a> — the API, served by FastAPI.</li>
    <li><code>POST /v1/instances</code> — enroll and get an API key.</li>
    <li><code>GET /v1/verify</code> — check an API key works.</li>
    <li><code>POST /v1/push</code> — forward one notification.</li>
  </ul>

  <footer>
    <p>This page reflects your own request back at you and stores nothing, like
    the rest of the relay. <code>curl</code> and anything else not asking for
    HTML gets JSON here instead.</p>
  </footer>
</main>
<script>{_SCRIPT}</script>
</body>
</html>
"""


def wants_html(request: Request) -> bool:
    """Whether this caller is a browser rather than a script.

    ``Accept: text/html`` is what a browser sends and what ``curl`` does not,
    so it splits the two without a query parameter or a second path.  Anything
    that asks for JSON, or asks for nothing in particular, keeps the JSON.
    """
    accept = request.headers.get("accept", "")
    return "text/html" in accept.lower()


__all__ = ["FORWARDING_HEADERS", "render_landing", "wants_html"]
