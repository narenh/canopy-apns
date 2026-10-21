/**
 * The page a browser gets at `/`.
 *
 * The Python relay's page existed to catch a TLS-terminating proxy and the app
 * disagreeing about the scheme. On a Worker there is no proxy to disagree
 * with — Cloudflare terminates TLS and the Worker sees the real URL and the
 * real client — so what is left is a plain statement of what this is and
 * whether it is ready. Everything on it is already public on `/health`.
 */

export function wantsHtml(request: Request): boolean {
	return (request.headers.get("accept") ?? "").toLowerCase().includes("text/html");
}

function escape(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#x27;");
}

export function renderLanding(p: {
	version: string;
	apnsConfigured: boolean;
	enrollmentEnabled: boolean;
	ratePerMinute: number;
	colo: string | null;
}): string {
	const rows: [string, string][] = [
		["Service", "canopy-apns"],
		["Version", p.version],
		["Runs on", "Cloudflare Workers"],
		["Served from", p.colo ?? "unknown"],
		["APNs signing key", p.apnsConfigured ? "configured" : "not configured"],
		["Enrollment", p.enrollmentEnabled ? "open" : "closed"],
		["Push rate limit", `${p.ratePerMinute}/minute per instance`],
	];
	const table = rows
		.map(([k, v]) => `<tr><td class="k">${escape(k)}</td><td class="v">${escape(v)}</td></tr>`)
		.join("\n");

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>canopy-apns relay</title>
<style>
:root { color-scheme: light dark; --bg: #fbfaf8; --fg: #1c1b19; --muted: #6b675f; --line: #e3dfd7; --card: #fff; --accent: #2f5d8c; }
@media (prefers-color-scheme: dark) { :root { --bg: #161513; --fg: #eceae5; --muted: #9b968c; --line: #2e2c28; --card: #1e1d1a; --accent: #8ab4dd; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 2.5rem 1rem 4rem; background: var(--bg); color: var(--fg); font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 42rem; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; }
h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 2rem 0 .6rem; }
.lede { color: var(--muted); margin: 0 0 1.5rem; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: .35rem .9rem; }
table { width: 100%; border-collapse: collapse; }
td { padding: .5rem .1rem; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.k { color: var(--muted); white-space: nowrap; padding-right: 1.2rem; width: 1%; }
td.v, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; word-break: break-all; }
a { color: var(--accent); }
li { margin: .3rem 0; }
</style>
</head>
<body>
<main>
  <h1>canopy-apns</h1>
  <p class="lede">A stateless APNs forwarder for self-hosted Canopy+ instances. There is no web UI.</p>
  <div class="card"><table>${table}</table></div>
  <h2>Endpoints</h2>
  <ul>
    <li><a href="health">GET /health</a> — liveness, and whether a signing key is present.</li>
    <li><code>POST /v1/instances</code> — enroll and get an API key.</li>
    <li><code>GET /v1/verify</code> — check an API key works.</li>
    <li><code>POST /v1/push</code> — forward one notification.</li>
    <li><code>POST /v1/liveactivity</code> — forward one Live Activity update; allow-listed.</li>
  </ul>
</main>
</body>
</html>
`;
}
