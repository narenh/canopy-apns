/**
 * The relay's wire contract, and validation of the one request with a body.
 *
 * Small on purpose.  An instance sends a device token, two lines of text and
 * an opaque blob; it gets back one word saying what became of it.
 *
 * Unknown fields are refused, as the Python relay's `extra="forbid"` did: a
 * field an instance thinks it is sending and the relay silently ignores is the
 * worst kind of bug between two separately deployed services.  Errors come
 * back as a 422 in the shape FastAPI used — `{"detail": [{loc, msg, type}]}` —
 * so a client that logged them keeps logging something sensible.
 */
import { MAX_BODY_LENGTH, MAX_DATA_BYTES, MAX_TITLE_LENGTH } from "./config.ts";

export interface PushRequest {
  deviceToken: string;
  environment: "sandbox" | "production";
  title: string;
  body: string | null;
  badge: number | null;
  data: Record<string, unknown> | null;
  collapseId: string | null;
}

export interface FieldError {
  type: string;
  loc: (string | number)[];
  msg: string;
}

export type Validated = { ok: true; value: PushRequest } | { ok: false; errors: FieldError[] };

/** Every accepted key.  `subtitle` is the old name for `body`, kept because
 * the two services deploy separately and dropping it would 422 every push from
 * a client not yet redeployed. */
const KNOWN_FIELDS = new Set([
  "device_token",
  "environment",
  "title",
  "body",
  "subtitle",
  "badge",
  "data",
  "collapse_id",
]);

/** Length in code points, as Python's `len` counts, not UTF-16 units. */
function length(value: string): number {
  return [...value].length;
}

/** Bytes of `json.dumps(value, separators=(",", ":"))` in Python.  That
 * escapes every non-ASCII character as `\uXXXX` (and astral ones as two), so
 * the byte count differs from UTF-8 `JSON.stringify` and the 1KB limit would
 * otherwise land in a different place than it did. */
function pythonJsonBytes(value: unknown): number {
  const json = JSON.stringify(value);
  let bytes = 0;
  for (let i = 0; i < json.length; i++) {
    bytes += json.charCodeAt(i) > 0x7f ? 6 : 1;
  }
  return bytes;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validate a parsed JSON body against the push contract. */
export function validatePush(input: unknown): Validated {
  if (!isPlainObject(input)) {
    return {
      ok: false,
      errors: [{ type: "model_attributes_type", loc: ["body"], msg: "Input should be an object" }],
    };
  }

  const errors: FieldError[] = [];
  const fail = (field: string, type: string, msg: string) =>
    errors.push({ type, loc: ["body", field], msg });

  for (const key of Object.keys(input)) {
    if (!KNOWN_FIELDS.has(key)) fail(key, "extra_forbidden", "Extra inputs are not permitted");
  }

  const deviceToken = input.device_token;
  if (deviceToken === undefined) {
    fail("device_token", "missing", "Field required");
  } else if (typeof deviceToken !== "string") {
    fail("device_token", "string_type", "Input should be a valid string");
  } else if (length(deviceToken) < 1 || length(deviceToken) > 200) {
    fail("device_token", "string_length", "String should have 1 to 200 characters");
  } else if (!/^[0-9a-fA-F]+$/.test(deviceToken)) {
    fail("device_token", "string_pattern_mismatch", "String should be hexadecimal");
  }

  const environment = input.environment ?? "production";
  if (environment !== "sandbox" && environment !== "production") {
    fail("environment", "literal_error", "Input should be 'sandbox' or 'production'");
  }

  const title = input.title;
  if (title === undefined) {
    fail("title", "missing", "Field required");
  } else if (typeof title !== "string") {
    fail("title", "string_type", "Input should be a valid string");
  } else if (length(title) < 1) {
    fail("title", "string_too_short", "String should have at least 1 character");
  } else if (length(title) > MAX_TITLE_LENGTH) {
    fail("title", "string_too_long", `String should have at most ${MAX_TITLE_LENGTH} characters`);
  }

  // `body` wins when both are sent, as pydantic's AliasChoices did.
  const bodyField = input.body !== undefined ? "body" : "subtitle";
  const body = input.body !== undefined ? input.body : (input.subtitle ?? null);
  if (body !== null) {
    if (typeof body !== "string") {
      fail(bodyField, "string_type", "Input should be a valid string");
    } else if (length(body) > MAX_BODY_LENGTH) {
      fail(bodyField, "string_too_long", `String should have at most ${MAX_BODY_LENGTH} characters`);
    }
  }

  const badge = input.badge ?? null;
  if (badge !== null) {
    if (typeof badge !== "number" || !Number.isInteger(badge)) {
      fail("badge", "int_type", "Input should be a valid integer");
    } else if (badge < 0) {
      fail("badge", "greater_than_equal", "Input should be greater than or equal to 0");
    }
  }

  const data = input.data ?? null;
  if (data !== null) {
    if (!isPlainObject(data)) {
      fail("data", "dict_type", "Input should be a valid dictionary");
    } else {
      const size = pythonJsonBytes(data);
      if (size > MAX_DATA_BYTES) {
        fail("data", "value_error", `data is ${size} bytes; the limit is ${MAX_DATA_BYTES}`);
      }
    }
  }

  const collapseId = input.collapse_id ?? null;
  if (collapseId !== null) {
    if (typeof collapseId !== "string") {
      fail("collapse_id", "string_type", "Input should be a valid string");
    } else if (length(collapseId) > 64) {
      fail("collapse_id", "string_too_long", "String should have at most 64 characters");
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    value: {
      deviceToken: deviceToken as string,
      environment: environment as "sandbox" | "production",
      title: title as string,
      body: body as string | null,
      badge: badge as number | null,
      data: data as Record<string, unknown> | null,
      collapseId: collapseId as string | null,
    },
  };
}
