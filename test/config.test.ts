import { describe, expect, it } from "vitest";

import { ConfigError, loadApnsCredentials, loadSettings, normalisePrivateKey } from "../src/config.ts";
import type { Env } from "../src/env.ts";
import { generateSecret } from "../src/keys.ts";

const PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n";
const SECRET = "HpQ2rXn7YtKf3vLcB8mZsW1dJgN6uE0aTiOxV5kRlPyC4hbQzSjMwFnA9eDgUt";

/** A bare env: only what a test sets. */
function env(values: Record<string, string>): Env {
  return values as unknown as Env;
}

describe("pasting the .p8", () => {
  it("passes a verbatim PEM through", () => {
    expect(normalisePrivateKey(PEM)).toBe(PEM.trim());
  });

  it("restores escaped newlines, as a shell or JSON field leaves them", () => {
    expect(normalisePrivateKey(PEM.trim().replaceAll("\n", "\\n"))).toBe(PEM.trim());
  });

  it("accepts base64 of the whole file", () => {
    expect(normalisePrivateKey(btoa(PEM))).toBe(PEM.trim());
  });

  it("accepts wrapped base64", () => {
    const wrapped = btoa(PEM).match(/.{1,16}/g)!.join("\n");
    expect(normalisePrivateKey(wrapped)).toBe(PEM.trim());
  });

  it("leaves unrecognisable input alone for the key parser to explain", () => {
    expect(normalisePrivateKey("nonsense")).toBe("nonsense");
  });
});

describe("APNs credentials", () => {
  const three = {
    CANOPY_APNS_TEAM_ID: "TEAM123456",
    CANOPY_APNS_KEY_ID: "KEY1234567",
    CANOPY_APNS_BUNDLE_ID: "com.example.canopy",
  };

  it("are all or nothing: three of four cannot send anything", () => {
    expect(loadApnsCredentials(env(three))).toBeNull();
    const credentials = loadApnsCredentials(env({ ...three, CANOPY_APNS_PRIVATE_KEY: PEM }));
    expect(credentials?.bundleId).toBe("com.example.canopy");
  });

  it("refuse a key file, since a Worker has nowhere to read one from", () => {
    expect(() =>
      loadApnsCredentials(env({ ...three, CANOPY_APNS_PRIVATE_KEY_FILE: "/keys/AuthKey.p8" })),
    ).toThrow(ConfigError);
  });

  it("treat blank values as unset", () => {
    expect(loadApnsCredentials(env({ ...three, CANOPY_APNS_PRIVATE_KEY: "   " }))).toBeNull();
  });
});

describe("the signing secret", () => {
  it("is required", () => {
    expect(() => loadSettings(env({}))).toThrow(ConfigError);
  });

  it("is refused when it is Coolify's placeholder text", () => {
    expect(() => loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: "set this in Coolify" }))).toThrow(
      /whitespace/,
    );
  });

  it.each([
    "changeme",
    "your-secret-here",
    "PLACEHOLDER",
    "replace-this-with-a-real-secret",
    "example-secret-value-do-not-use",
  ])("is refused when it is boilerplate like %j", (value) => {
    expect(() => loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: value }))).toThrow(ConfigError);
  });

  it("is refused when short", () => {
    expect(() => loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: "s3cret" }))).toThrow(/minimum/);
  });

  it("is always accepted when it came from the generator", () => {
    expect(loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: generateSecret() })).signingSecret).toBeTruthy();
  });
});

it("starts without an APNs key; a relay waiting on its .p8 is supported", () => {
  expect(loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: SECRET })).apns).toBeNull();
});

it("parses and lowercases revocations", () => {
  const settings = loadSettings(
    env({ CANOPY_APNS_SIGNING_SECRET: SECRET, CANOPY_APNS_REVOKED_INSTANCES: " Acme , ,beta " }),
  );
  expect(settings.revokedInstances.has("acme")).toBe(true);
  expect(settings.revokedInstances.has("beta")).toBe(true);
  expect(settings.revokedInstances.has("gamma")).toBe(false);
});

it("refuses a nonsense rate limit", () => {
  expect(() =>
    loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: SECRET, CANOPY_APNS_RATE_LIMIT: "lots" })),
  ).toThrow(ConfigError);
});

it("treats a blank number as unset rather than as zero", () => {
  const settings = loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: SECRET, CANOPY_APNS_RATE_LIMIT: " " }));
  expect(settings.rateLimitPerMinute).toBe(120);
});

it("has enrollment on by default", () => {
  expect(loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: SECRET })).enrollmentEnabled).toBe(true);
});

it.each([
  ["false", false],
  ["no", false],
  ["0", false],
  ["off", false],
  ["true", true],
  ["yes", true],
  ["1", true],
  ["on", true],
])("reads the enrollment flag %j as %s", (value, expected) => {
  const settings = loadSettings(
    env({ CANOPY_APNS_SIGNING_SECRET: SECRET, CANOPY_APNS_ENROLLMENT_ENABLED: value }),
  );
  expect(settings.enrollmentEnabled).toBe(expected);
});

it("refuses a nonsense enrollment flag rather than guessing a security posture", () => {
  expect(() =>
    loadSettings(env({ CANOPY_APNS_SIGNING_SECRET: SECRET, CANOPY_APNS_ENROLLMENT_ENABLED: "sometimes" })),
  ).toThrow(ConfigError);
});
