/**
 * The relay's wire contract, checked by hand.
 *
 * The same rules the Python relay's pydantic models enforced, including the
 * one that matters most between two separately-deployed services: an unknown
 * field is a 422 naming it, never silently ignored. A refusal is
 * `{"detail": "<one sentence>"}`, which is what both clients read.
 */

import { BUNDLE_ID_PATTERN, MAX_BODY_LENGTH, MAX_DATA_BYTES, MAX_TITLE_LENGTH } from "./config.ts";
import type { Environment } from "./apns.ts";

export class Invalid extends Error {}

type Json = Record<string, unknown>;

const DEVICE_TOKEN = /^[0-9a-fA-F]{1,200}$/;

function isObject(value: unknown): value is Json {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function only(body: Json, allowed: readonly string[]): void {
	const extra = Object.keys(body).filter((key) => !allowed.includes(key));
	if (extra.length > 0) {
		throw new Invalid(`Unknown field${extra.length > 1 ? "s" : ""}: ${extra.join(", ")}.`);
	}
}

/** Length in characters, as pydantic counts them — not UTF-16 code units. */
function chars(value: string): number {
	return [...value].length;
}

function string(
	body: Json,
	name: string,
	opts: { required?: boolean; min?: number; max: number; pattern?: RegExp },
): string | null {
	const value = body[name];
	if (value === undefined || value === null) {
		if (opts.required) throw new Invalid(`${name} is required.`);
		return null;
	}
	if (typeof value !== "string") throw new Invalid(`${name} must be a string.`);
	const length = chars(value);
	if (opts.min !== undefined && length < opts.min) {
		throw new Invalid(`${name} must be at least ${opts.min} character${opts.min === 1 ? "" : "s"}.`);
	}
	if (length > opts.max) throw new Invalid(`${name} must be at most ${opts.max} characters.`);
	if (opts.pattern && !opts.pattern.test(value)) throw new Invalid(`${name} is not in the expected format.`);
	return value;
}

function integer(body: Json, name: string, opts: { min?: number } = {}): number | null {
	const value = body[name];
	if (value === undefined || value === null) return null;
	if (typeof value !== "number" || !Number.isInteger(value)) throw new Invalid(`${name} must be a whole number.`);
	if (opts.min !== undefined && value < opts.min) {
		throw new Invalid(`${name} must be greater than or equal to ${opts.min}.`);
	}
	return value;
}

function object(body: Json, name: string): Json | null {
	const value = body[name];
	if (value === undefined || value === null) return null;
	if (!isObject(value)) throw new Invalid(`${name} must be a JSON object.`);
	return value;
}

function environment(body: Json): Environment {
	const value = body.environment;
	if (value === undefined) return "production";
	if (value !== "production" && value !== "sandbox") {
		throw new Invalid('environment must be "production" or "sandbox".');
	}
	return value;
}

export interface PushRequest {
	deviceToken: string;
	environment: Environment;
	title: string;
	body: string | null;
	badge: number | null;
	data: Json | null;
	collapseId: string | null;
}

/**
 * `POST /v1/push`. Deliberately not an APNs payload — text in, alert out.
 *
 * `subtitle` is accepted as an alias for `body`: the field was renamed when it
 * turned out iOS bolds subtitles, and a client not yet redeployed still sends
 * the old name. Sending both is refused rather than guessed at.
 */
export function parsePush(raw: unknown): PushRequest {
	if (!isObject(raw)) throw new Invalid("The request body must be a JSON object.");
	only(raw, ["device_token", "environment", "title", "body", "subtitle", "badge", "data", "collapse_id"]);
	if (raw.body !== undefined && raw.subtitle !== undefined) {
		throw new Invalid("Send body or subtitle, not both; subtitle is the old name for body.");
	}
	const bodyField = raw.body !== undefined ? "body" : "subtitle";

	const data = object(raw, "data");
	if (data !== null) {
		const size = new TextEncoder().encode(JSON.stringify(data)).byteLength;
		if (size > MAX_DATA_BYTES) throw new Invalid(`data is ${size} bytes; the limit is ${MAX_DATA_BYTES}.`);
	}

	return {
		deviceToken: string(raw, "device_token", { required: true, max: 200, pattern: DEVICE_TOKEN }) as string,
		environment: environment(raw),
		title: string(raw, "title", { required: true, min: 1, max: MAX_TITLE_LENGTH }) as string,
		body: string(raw, bodyField, { max: MAX_BODY_LENGTH }),
		badge: integer(raw, "badge", { min: 0 }),
		data,
		collapseId: string(raw, "collapse_id", { max: 64 }),
	};
}

export interface LiveActivityRequest {
	deviceToken: string;
	environment: Environment;
	bundleId: string;
	event: "start" | "update" | "end";
	contentState: Json;
	attributesType: string | null;
	attributes: Json | null;
	alert: { title: string; body: string } | null;
	timestamp: number | null;
	staleDate: number | null;
	dismissalDate: number | null;
	relevanceScore: number | null;
	priority: 5 | 10;
	expiration: number;
}

/** `POST /v1/liveactivity`. Required-iff-start, in both directions. */
export function parseLiveActivity(raw: unknown): LiveActivityRequest {
	if (!isObject(raw)) throw new Invalid("The request body must be a JSON object.");
	only(raw, [
		"device_token",
		"environment",
		"bundle_id",
		"event",
		"content_state",
		"attributes_type",
		"attributes",
		"alert",
		"timestamp",
		"stale_date",
		"dismissal_date",
		"relevance_score",
		"priority",
		"expiration",
	]);

	const event = raw.event;
	if (event !== "start" && event !== "update" && event !== "end") {
		throw new Invalid('event must be "start", "update" or "end".');
	}

	const contentState = object(raw, "content_state");
	if (contentState === null) throw new Invalid("content_state is required.");

	let alert: LiveActivityRequest["alert"] = null;
	const rawAlert = object(raw, "alert");
	if (rawAlert !== null) {
		only(rawAlert, ["title", "body"]);
		alert = {
			title: string(rawAlert, "title", { required: true, min: 1, max: MAX_TITLE_LENGTH }) as string,
			body: string(rawAlert, "body", { required: true, max: MAX_BODY_LENGTH }) as string,
		};
	}

	const relevance = raw.relevance_score;
	if (relevance !== undefined && relevance !== null && typeof relevance !== "number") {
		throw new Invalid("relevance_score must be a number.");
	}

	const priority = raw.priority === undefined ? 10 : raw.priority;
	if (priority !== 5 && priority !== 10) throw new Invalid("priority must be 5 or 10.");

	const expiration = raw.expiration === undefined ? 0 : integer(raw, "expiration", { min: 0 });
	if (expiration === null) throw new Invalid("expiration must be a whole number.");

	const request: LiveActivityRequest = {
		deviceToken: string(raw, "device_token", { required: true, max: 200, pattern: DEVICE_TOKEN }) as string,
		environment: environment(raw),
		bundleId: string(raw, "bundle_id", { required: true, min: 1, max: 155, pattern: BUNDLE_ID_PATTERN }) as string,
		event,
		contentState,
		attributesType: string(raw, "attributes_type", { min: 1, max: 200 }),
		attributes: object(raw, "attributes"),
		alert,
		timestamp: integer(raw, "timestamp", { min: 0 }),
		staleDate: integer(raw, "stale_date", { min: 0 }),
		dismissalDate: integer(raw, "dismissal_date", { min: 0 }),
		relevanceScore: (relevance as number | null | undefined) ?? null,
		priority,
		expiration,
	};

	// A start without these cannot create anything; sent on an update they
	// would be silently ignored by ActivityKit.
	const startOnly = { attributes_type: request.attributesType, attributes: request.attributes };
	if (event === "start") {
		const missing = Object.entries(startOnly)
			.filter(([, value]) => value === null)
			.map(([name]) => name);
		if (alert === null) missing.push("alert");
		if (missing.length > 0) throw new Invalid(`a start event requires ${missing.join(", ")}`);
	} else {
		const present = Object.entries(startOnly)
			.filter(([, value]) => value !== null)
			.map(([name]) => name);
		if (present.length > 0) throw new Invalid(`${present.join(", ")} may only be sent with a start event`);
	}
	if (request.dismissalDate !== null && event !== "end") {
		throw new Invalid("dismissal_date may only be sent with an end event");
	}
	return request;
}
