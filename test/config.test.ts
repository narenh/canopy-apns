import { describe, expect, it } from "vitest";
import { ConfigError, type Env, loadSettings, normalisePrivateKey, parseLiveActivityTopics } from "../src/config.ts";
import { APNS, PRIVATE_KEY_PEM, SECRET } from "./helpers.ts";

const base = { CANOPY_APNS_SIGNING_SECRET: SECRET } as Env;

describe("config", () => {
	it("needs a signing secret", () => {
		expect(() => loadSettings({} as Env)).toThrow(/not set/);
		expect(() => loadSettings({ CANOPY_APNS_SIGNING_SECRET: "   " } as Env)).toThrow(/not set/);
	});

	it("refuses placeholder, whitespace and short secrets", () => {
		for (const [secret, pattern] of [
			["set this in Coolify", /whitespace/],
			["changeme-changeme-changeme-changeme-x", /placeholder/],
			["EXAMPLEexampleEXAMPLEexampleEXAMPLE", /placeholder/],
			["short-but-real", /minimum is 32/],
		] as const) {
			expect(() => loadSettings({ CANOPY_APNS_SIGNING_SECRET: secret } as Env)).toThrow(pattern);
		}
	});

	it("treats three of four APNs values as unconfigured", () => {
		expect(loadSettings({ ...base, ...APNS }).apns).not.toBeNull();
		expect(loadSettings({ ...base, ...APNS, CANOPY_APNS_KEY_ID: " " }).apns).toBeNull();
	});

	it("applies defaults for blank numbers and flags, and refuses bad ones", () => {
		const s = loadSettings({ ...base, CANOPY_APNS_RATE_LIMIT: "", CANOPY_APNS_ENROLLMENT_ENABLED: "" });
		expect(s.ratePerMinute).toBe(120);
		expect(s.enrollmentEnabled).toBe(true);
		expect(loadSettings({ ...base, CANOPY_APNS_ENROLLMENT_ENABLED: "no" }).enrollmentEnabled).toBe(false);
		expect(() => loadSettings({ ...base, CANOPY_APNS_RATE_LIMIT: "fast" })).toThrow(ConfigError);
		expect(() => loadSettings({ ...base, CANOPY_APNS_RATE_LIMIT: "0" })).toThrow(/greater than zero/);
		expect(() => loadSettings({ ...base, CANOPY_APNS_ENROLLMENT_ENABLED: "maybe" })).toThrow(/true or false/);
	});

	it("lowercases revoked ids", () => {
		expect([...loadSettings({ ...base, CANOPY_APNS_REVOKED_INSTANCES: " Acme, ,b " }).revoked]).toEqual(["acme", "b"]);
	});

	it("accepts the .p8 verbatim, with escaped newlines, or as base64", () => {
		expect(normalisePrivateKey(PRIVATE_KEY_PEM)).toBe(PRIVATE_KEY_PEM.trim());
		expect(normalisePrivateKey(PRIVATE_KEY_PEM.trim().replaceAll("\n", "\\n"))).toBe(PRIVATE_KEY_PEM.trim());
		const b64 = btoa(PRIVATE_KEY_PEM).replace(/(.{60})/g, "$1\n");
		expect(normalisePrivateKey(b64)).toBe(PRIVATE_KEY_PEM.trim());
		expect(normalisePrivateKey("not a key")).toBe("not a key");
	});

	it("parses the Live Activity allow-list and refuses a malformed entry", () => {
		expect([...parseLiveActivityTopics(" A1b2:com.x.App , acme:com.y.Z,")]).toEqual(["a1b2:com.x.App", "acme:com.y.Z"]);
		expect(parseLiveActivityTopics("").size).toBe(0);
		for (const bad of ["acme", "acme:", "acme:nodots", "a_b:com.x.y", "acme:com.x.y:z"]) {
			expect(() => parseLiveActivityTopics(bad)).toThrow(/could not read/);
		}
	});
});
