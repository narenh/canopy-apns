import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.jsonc" },
			miniflare: {
				bindings: {
					CANOPY_APNS_SIGNING_SECRET: "test-signing-secret-0123456789abcdefghijklmnop",
				},
			},
		}),
	],
});
