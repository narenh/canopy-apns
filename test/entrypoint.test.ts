import { expect, it } from "vitest";

import * as entrypoint from "../src/index.ts";

it("exports only what workerd accepts from a main module", () => {
  // Any other named export (a constant, a helper) makes the runtime refuse to
  // start, which unit tests importing modules directly would never notice.
  expect(Object.keys(entrypoint).sort()).toEqual(["ProviderTokenStore", "RateLimiter", "default"]);
});
