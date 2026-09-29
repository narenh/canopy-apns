import { generateKeyPairSync } from "node:crypto";

import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// A throwaway P-256 key per run rather than one checked in: a committed private
// key is a committed private key, even one only ever used against a stub.
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const TEST_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

// Tests run inside workerd, the same runtime as production, with both Durable
// Objects live. Nothing reaches Apple: tests stub `fetch`.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          CANOPY_APNS_SIGNING_SECRET: "test-signing-secret-that-is-long-enough-to-pass",
          CANOPY_APNS_TEAM_ID: "TEAM123456",
          CANOPY_APNS_KEY_ID: "KEY1234567",
          CANOPY_APNS_BUNDLE_ID: "com.example.canopy",
          CANOPY_APNS_PRIVATE_KEY: TEST_PRIVATE_KEY,
        },
      },
    }),
  ],
});
