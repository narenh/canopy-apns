import { env } from "cloudflare:test";
import { vi } from "vitest";
import { resetProviderTokens } from "../src/apns.ts";
import type { Env } from "../src/config.ts";
import worker from "../src/index.ts";
import { mint } from "../src/keys.ts";

export const SECRET = "test-signing-secret-0123456789abcdefghijklmnop";
export const BUNDLE = "com.example.canopy";
export const TOKEN = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

function pem(der: ArrayBuffer): string {
	const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
	return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----\n`;
}

/** A fresh P-256 key per run; a committed private key is a committed private key. */
export const keyPair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
	"sign",
	"verify",
])) as CryptoKeyPair;
export const PRIVATE_KEY_PEM = pem((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer);

export const APNS: Partial<Env> = {
	CANOPY_APNS_TEAM_ID: "TEAM123456",
	CANOPY_APNS_KEY_ID: "KEY1234567",
	CANOPY_APNS_BUNDLE_ID: BUNDLE,
	CANOPY_APNS_PRIVATE_KEY: PRIVATE_KEY_PEM,
};

/** An Env built fresh, so each test's settings are its own. */
export function makeEnv(overrides: Partial<Env> = {}): Env {
	// Blank the deployment's allow-list and revocations so tests start from defaults.
	return {
		...(env as unknown as Env),
		CANOPY_APNS_SIGNING_SECRET: SECRET,
		CANOPY_APNS_LIVEACTIVITY_TOPICS: "",
		CANOPY_APNS_REVOKED_INSTANCES: "",
		...APNS,
		...overrides,
	};
}

let counter = 0;
/** A key for an instance no other test uses, so rate-limit buckets never collide. */
export async function freshKey(prefix = "t"): Promise<{ id: string; key: string }> {
	const id = `${prefix}-${Date.now().toString(36)}-${(counter++).toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
	return { id, key: await mint(id, SECRET) };
}

export async function call(
	path: string,
	init: RequestInit & { json?: unknown; key?: string } = {},
	e: Env = makeEnv(),
): Promise<Omit<Response, "json"> & { json<T = any>(): Promise<T> }> {
	const headers = new Headers(init.headers);
	if (init.key) headers.set("authorization", `Bearer ${init.key}`);
	let body = init.body;
	if (init.json !== undefined) {
		headers.set("content-type", "application/json");
		body = JSON.stringify(init.json);
	}
	return worker.fetch(new Request(`https://apns.test${path}`, { ...init, headers, body }), e);
}

export interface AppleCall {
	url: string;
	headers: Record<string, string>;
	body: unknown;
}

/** Replace Apple with `responses`, in order; the last one repeats. */
export function mockApple(...responses: (() => Response | Promise<Response>)[]): AppleCall[] {
	resetProviderTokens();
	const calls: AppleCall[] = [];
	let i = 0;
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const request = new Request(input as RequestInfo, init);
		calls.push({
			url: request.url,
			headers: Object.fromEntries(request.headers),
			body: JSON.parse(await request.text()),
		});
		const next = responses[Math.min(i++, responses.length - 1)];
		if (!next) throw new Error("no mocked response");
		return next();
	});
	return calls;
}

export const ok = () => new Response(null, { status: 200, headers: { "apns-id": "11111111-2222-3333-4444-555555555555" } });
export const apple = (status: number, reason: string) => () =>
	new Response(JSON.stringify({ reason }), { status, headers: { "apns-id": "aaaa" } });

export async function verifyJwt(jwt: string): Promise<{ header: unknown; claims: unknown }> {
	const [h, c, s] = jwt.split(".") as [string, string, string];
	const decode = (part: string) => Uint8Array.from(atob(part.replaceAll("-", "+").replaceAll("_", "/")), (ch) => ch.charCodeAt(0));
	const valid = await crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		keyPair.publicKey,
		decode(s),
		new TextEncoder().encode(`${h}.${c}`),
	);
	if (!valid) throw new Error("JWT signature does not verify");
	return {
		header: JSON.parse(new TextDecoder().decode(decode(h))),
		claims: JSON.parse(new TextDecoder().decode(decode(c))),
	};
}
