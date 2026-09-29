/**
 * `npm run secret` and `npm run mint -- <instance-id>` — what
 * `python -m canopy_apns secret|mint` did, run locally under Node.
 *
 * `mint` is local on purpose.  An HTTP endpoint that hands out keys for chosen
 * ids is an endpoint that hands them to anyone who finds it.  It needs the same
 * `CANOPY_APNS_SIGNING_SECRET` the Worker runs with, in this shell.
 */
import { generateSecret, mint } from "../src/keys.ts";

async function main(argv: string[]): Promise<number> {
  const [command, instanceId] = argv;

  if (command === "secret") {
    console.log(generateSecret());
    return 0;
  }

  if (command === "mint") {
    const secret = (process.env.CANOPY_APNS_SIGNING_SECRET ?? "").trim();
    if (!secret) {
      console.error(
        "CANOPY_APNS_SIGNING_SECRET is not set in this shell. Minting needs the same " +
          "secret the relay runs with; a key minted under any other secret will 401.",
      );
      return 2;
    }
    if (!instanceId) {
      console.error("Usage: npm run mint -- <instance-id>");
      return 2;
    }
    try {
      console.log(await mint(instanceId, secret));
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      return 2;
    }
    return 0;
  }

  console.error("Usage: npm run secret | npm run mint -- <instance-id>");
  return 2;
}

process.exitCode = await main(process.argv.slice(2));
