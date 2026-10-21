/**
 * `npm run secret` — print a fresh CANOPY_APNS_SIGNING_SECRET. Run once;
 * regenerating it invalidates every API key ever issued.
 *
 * `npm run mint -- <instance-id>` — print one instance's API key. Needs the
 * relay's signing secret in this shell. Deterministic: same id, same key.
 *
 * Plain Node (22.18+ runs TypeScript directly); nothing here talks to the
 * relay. A key is derived, not looked up, so minting is purely local.
 */

import { generateSecret, mint } from "../src/keys.ts";

declare const process: { argv: string[]; env: Record<string, string | undefined>; exit(code: number): never };

const [command, instanceId] = process.argv.slice(2);

if (command === "secret") {
	console.log(generateSecret());
} else if (command === "mint" && instanceId) {
	const secret = (process.env.CANOPY_APNS_SIGNING_SECRET ?? "").trim();
	if (!secret) {
		console.error(
			"CANOPY_APNS_SIGNING_SECRET is not set in this shell. Minting needs the same " +
				"secret the relay runs with.",
		);
		process.exit(2);
	}
	try {
		console.log(await mint(instanceId, secret));
	} catch (err) {
		console.error((err as Error).message);
		process.exit(2);
	}
} else {
	console.error("usage: npm run secret | npm run mint -- <instance-id>");
	process.exit(2);
}
