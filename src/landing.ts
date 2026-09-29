/**
 * The page a browser gets at `/`.
 *
 * On Coolify this page existed to diagnose TLS termination: a proxy that
 * forwarded plain HTTP without telling the app, and every symptom downstream
 * of that.  On Workers, Cloudflare terminates TLS and the Worker sees the
 * original URL, so that failure mostly cannot happen.  The page stays as a
 * mirror of what the relay saw — scheme, client address, the Cloudflare
 * location that served it — which is still the quickest check that a custom
 * domain is routed to this Worker and not to something else.
 *
 * Everything on it comes from the request in hand or from settings already
 * public on `/health`.  Every interpolated value is escaped, because most of
 * them are request headers and a header is whatever the client sent.
 */

/** Headers worth showing whether or not they are present. */
export const FORWARDING_HEADERS = [
  "host",
  "cf-connecting-ip",
  "cf-visitor",
  "x-forwarded-proto",
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
];

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

const STYLE = `
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
`;

// Only /health is fetched, and results are written with textContent: every
// value on this page originates from a request header.
const SCRIPT = `
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
    span.textContent = 'Something between this browser and the Worker is ' +
      'rewriting the request. On Cloudflare that is unusual; check for a ' +
      'proxy or tunnel in front of the custom domain.';
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
`;

function rows(pairs: [string, string | null | undefined][]): string {
  return pairs
    .map(([key, value]) => {
      const cell = value
        ? `<td class="v">${escapeHtml(value)}</td>`
        : '<td class="v none">not set</td>';
      return `<tr><td class="k">${escapeHtml(key)}</td>${cell}</tr>`;
    })
    .join("\n");
}

export interface LandingInfo {
  version: string;
  apnsConfigured: boolean;
  enrollmentEnabled: boolean;
  rateLimitPerMinute: number;
}

/** Render the page for one request.  Pure apart from reading the request. */
export function renderLanding(request: Request, info: LandingInfo): string {
  const url = new URL(request.url);
  const scheme = url.protocol.replace(":", "");
  const cf = (request as { cf?: IncomingRequestCfProperties }).cf;

  const requestRows = rows([
    ["Scheme the relay saw", scheme],
    ["Effective URL", url.toString()],
    ["Method", request.method],
    ["HTTP version", cf?.httpProtocol as string | undefined],
    ["Client address", request.headers.get("cf-connecting-ip")],
    ["Cloudflare location", cf?.colo as string | undefined],
  ]);
  const headerRows = rows(FORWARDING_HEADERS.map((name) => [name, request.headers.get(name)]));
  const relayRows = rows([
    ["Service", "canopy-apns"],
    ["Version", info.version],
    ["Runtime", "Cloudflare Workers"],
    ["APNs signing key", info.apnsConfigured ? "configured" : "not configured"],
    ["Enrollment", info.enrollmentEnabled ? "open" : "closed"],
    ["Push rate limit", `${info.rateLimitPerMinute}/minute per instance`],
  ]);

  const note =
    scheme === "https"
      ? "Cloudflare terminated TLS and passed the original scheme through, as it should."
      : "Plain HTTP. Expected under <code>wrangler dev</code>; in production, turn on " +
        "Always Use HTTPS for the domain.";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>canopy-apns relay</title>
<style>${STYLE}</style>
</head>
<body data-scheme="${escapeHtml(scheme)}">
<main>
  <h1>canopy-apns</h1>
  <p class="lede">A stateless APNs forwarder for self-hosted Canopy+ instances.
  There is no web UI — this page shows what the relay saw of your request.</p>

  <div class="card banner" id="banner">
    <strong>The relay saw this request as ${escapeHtml(scheme)}.</strong>
    <span>${note}</span>
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
  <div class="card"><table>${requestRows}</table></div>

  <h2>Forwarding headers</h2>
  <div class="card"><table>${headerRows}</table></div>

  <h2>Relay</h2>
  <div class="card"><table>${relayRows}</table></div>

  <h2>Endpoints</h2>
  <ul>
    <li><a href="health">GET /health</a> — liveness, and whether a signing key is present.</li>
    <li><code>POST /v1/instances</code> — enroll and get an API key.</li>
    <li><code>GET /v1/verify</code> — check an API key works.</li>
    <li><code>POST /v1/push</code> — forward one notification.</li>
  </ul>

  <footer>
    <p>This page reflects your own request back at you and stores nothing.
    <code>curl</code> and anything else not asking for HTML gets JSON here instead.</p>
  </footer>
</main>
<script>${SCRIPT}</script>
</body>
</html>
`;
}

/** A browser, rather than a script: `Accept: text/html` splits the two. */
export function wantsHtml(request: Request): boolean {
  return (request.headers.get("accept") ?? "").toLowerCase().includes("text/html");
}
