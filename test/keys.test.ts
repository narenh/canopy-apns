import { describe, expect, it } from "vitest";
import { INSTANCE_ID_PATTERN, InvalidKey, base32, generateInstanceId, mint, verify } from "../src/keys.ts";

// Minted by the Python relay (canopy_apns.keys.mint) under this secret. Every
// key that relay issued has to keep verifying after the move.
const PY_SECRET = "fixture-secret-0123456789abcdefghijklmnopqrstuvwxyz";
const PY_KEYS: Record<string, string> = {
	acme: "canopy_acme_ey53r6mrxnt35cwz43jfzpfeqy",
	tpg6b7n6uwtjiaqzmerq: "canopy_tpg6b7n6uwtjiaqzmerq_fjvz6xnplymmycosdzm5kddwqe",
	a: "canopy_a_p7tv7qcubvemr2tysqvwxrdnqq",
	"x-1-y": "canopy_x-1-y_6hi6yoozgkwjb4au3kqztjutbm",
};

describe("keys", () => {
	it("mints exactly what the Python relay minted", async () => {
		for (const [id, key] of Object.entries(PY_KEYS)) expect(await mint(id, PY_SECRET)).toBe(key);
	});

	it("verifies keys the Python relay issued", async () => {
		for (const [id, key] of Object.entries(PY_KEYS)) expect(await verify(key, PY_SECRET)).toEqual({ id });
	});

	it("normalises the id at mint time", async () => {
		expect(await mint("  ACME ", PY_SECRET)).toBe(PY_KEYS.acme);
	});

	it("refuses ids with underscores or edge hyphens", async () => {
		for (const bad of ["a_b", "-a", "a-", "", "x".repeat(64)]) {
			await expect(mint(bad, PY_SECRET)).rejects.toThrow(/instance id/);
		}
	});

	it("refuses forged, malformed and other-secret keys", async () => {
		const good = PY_KEYS.acme as string;
		const bad = [
			good.slice(0, -1) + (good.endsWith("a") ? "b" : "a"),
			good.replace("acme", "acmf"),
			"canopy_acme",
			`${good}_extra`,
			good.replace("canopy_", "other_"),
			"",
			"canopy_ACME_ey53r6mrxnt35cwz43jfzpfeqy",
		];
		for (const key of bad) await expect(verify(key, PY_SECRET)).rejects.toBeInstanceOf(InvalidKey);
		await expect(verify(good, `${PY_SECRET}x`)).rejects.toBeInstanceOf(InvalidKey);
	});

	it("generates 20-character ids inside the pattern", () => {
		const ids = new Set(Array.from({ length: 50 }, generateInstanceId));
		expect(ids.size).toBe(50);
		for (const id of ids) {
			expect(id).toHaveLength(20);
			expect(id).toMatch(INSTANCE_ID_PATTERN);
		}
	});

	it("encodes base32 per RFC 4648, lowercased and unpadded", () => {
		const enc = (s: string) => base32(new TextEncoder().encode(s));
		expect(enc("")).toBe("");
		expect(enc("f")).toBe("my");
		expect(enc("fo")).toBe("mzxq");
		expect(enc("foo")).toBe("mzxw6");
		expect(enc("foob")).toBe("mzxw6yq");
		expect(enc("fooba")).toBe("mzxw6ytb");
		expect(enc("foobar")).toBe("mzxw6ytboi");
	});
});
