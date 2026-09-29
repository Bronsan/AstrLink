import { invalidData, type DataProblem } from "./ipc-data-error";

/** Which stored envelopes can open the raw key (plan §5.11). */
export type RawEnvelope = "password" | "local";

/** Core's operator view of raw sealing. It never carries key material. */
export interface RawSealingStatus {
  /** Sealing is set up and agent tools may ask for raw parts. */
  raw_available: boolean;
  /** A raw key pair exists; new raw parts are sealed to it. */
  configured: boolean;
  password_set: boolean;
  /** Core accepts a desktop presence check as proof. */
  local_presence: boolean;
  envelopes: RawEnvelope[];
  key_verified: boolean;
  /** The operator's own unlock session is open. */
  unlocked: boolean;
  unlock_expires_at: string | null;
  unlock_idle_seconds: number;
  /** Seconds before Core accepts another password attempt. */
  retry_after_seconds: number;
  password_min_length: number;
  password_max_length: number;
}

/** The sealing state plus whether this build can show the presence prompt. */
export interface RawSealingState extends RawSealingStatus {
  presence_available: boolean;
}

/** What a raw password reset discarded. */
export interface RawPasswordReset {
  deleted_parts: number;
  affected_records: number;
}

/**
 * What an unlock or password action ended in. Refusals the dialog can
 * recover from are outcomes, not errors, so it can stay open.
 */
export type RawSealingOutcome =
  | {
      outcome: "sealing";
      status: RawSealingStatus;
      /** Present only after a reset. */
      reset: RawPasswordReset | null;
    }
  | { outcome: "password_invalid" }
  | { outcome: "backoff"; retry_after_seconds: number }
  | { outcome: "presence_cancelled" }
  | { outcome: "presence_unsupported" };

/** The proof a raw action carries to the host. */
export type RawProof =
  | { kind: "password"; password: string }
  | { kind: "local_presence" };

export type RawPasswordAction = "set" | "change" | "reset";

export type PresencePurpose =
  | "approve_raw_access"
  | "unlock_raw"
  | "change_raw_password"
  | "reveal_access_token";

export type PresenceOutcome =
  | { outcome: "verified" }
  | { outcome: "presence_cancelled" }
  | { outcome: "presence_unsupported" };

/** How a proof dialog asks for its proof (D14). */
export type RawProofMode = "presence" | "password" | "confirm";

type JsonObject = Record<string, unknown>;

const envelopes = new Set<RawEnvelope>(["password", "local"]);
const MAX_PASSWORD_BOUND = 4096;

function invalid(
  path: string,
  problem: DataProblem,
  values?: Record<string, number>,
): never {
  return invalidData("rawSealing", path, problem, values);
}

function objectAt(value: unknown, path: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid(path, "object");
  }
  return value as JsonObject;
}

function boolAt(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") return invalid(path, "boolean");
  return value;
}

function integerAt(
  value: unknown,
  path: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    return invalid(path, "integerAtLeast", { minimum });
  }
  return value;
}

function timestampOrNullAt(value: unknown, path: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length > 64) {
    return invalid(path, "timestampOrNull");
  }
  if (Number.isNaN(Date.parse(value))) invalid(path, "timestamp");
  return value;
}

function envelopesAt(value: unknown, path: string): RawEnvelope[] {
  if (!Array.isArray(value)) return invalid(path, "array");
  if (value.length > envelopes.size) invalid(path, "tooLong");
  const seen = new Set<RawEnvelope>();
  value.forEach((item, index) => {
    if (!envelopes.has(item as RawEnvelope)) {
      invalid(`${path}[${index}]`, "unknownType");
    }
    if (seen.has(item as RawEnvelope))
      invalid(`${path}[${index}]`, "duplicate");
    seen.add(item as RawEnvelope);
  });
  return [...seen];
}

function parseStatus(value: unknown, path: string): RawSealingStatus {
  const status = objectAt(value, path);
  const minLength = integerAt(
    status.password_min_length,
    `${path}.password_min_length`,
    1,
    MAX_PASSWORD_BOUND,
  );
  const maxLength = integerAt(
    status.password_max_length,
    `${path}.password_max_length`,
    1,
    MAX_PASSWORD_BOUND,
  );
  if (maxLength < minLength) {
    invalid(`${path}.password_max_length`, "belowMinimumLength");
  }
  return {
    raw_available: boolAt(status.raw_available, `${path}.raw_available`),
    configured: boolAt(status.configured, `${path}.configured`),
    password_set: boolAt(status.password_set, `${path}.password_set`),
    local_presence: boolAt(status.local_presence, `${path}.local_presence`),
    envelopes: envelopesAt(status.envelopes, `${path}.envelopes`),
    key_verified: boolAt(status.key_verified, `${path}.key_verified`),
    unlocked: boolAt(status.unlocked, `${path}.unlocked`),
    unlock_expires_at: timestampOrNullAt(
      status.unlock_expires_at,
      `${path}.unlock_expires_at`,
    ),
    unlock_idle_seconds: integerAt(
      status.unlock_idle_seconds,
      `${path}.unlock_idle_seconds`,
      1,
    ),
    retry_after_seconds: integerAt(
      status.retry_after_seconds,
      `${path}.retry_after_seconds`,
      0,
    ),
    password_min_length: minLength,
    password_max_length: maxLength,
  };
}

function parseReset(value: unknown, path: string): RawPasswordReset | null {
  if (value === undefined || value === null) return null;
  const reset = objectAt(value, path);
  return {
    deleted_parts: integerAt(reset.deleted_parts, `${path}.deleted_parts`, 0),
    affected_records: integerAt(
      reset.affected_records,
      `${path}.affected_records`,
      0,
    ),
  };
}

function backoffSeconds(value: unknown): number {
  return integerAt(value, "$.retry_after_seconds", 1);
}

/** Parses `raw_sealing_status`, which adds the host's presence support. */
export function parseRawSealingState(value: unknown): RawSealingState {
  const status = parseStatus(value, "$");
  return {
    ...status,
    presence_available: boolAt(
      objectAt(value, "$").presence_available,
      "$.presence_available",
    ),
  };
}

/** Parses a plain Core status, such as the one `lock_raw` returns. */
export function parseRawSealingStatus(value: unknown): RawSealingStatus {
  return parseStatus(value, "$");
}

export function parseRawSealingOutcome(value: unknown): RawSealingOutcome {
  const outcome = objectAt(value, "$");
  switch (outcome.outcome) {
    case "sealing": {
      const status = objectAt(outcome.status, "$.status");
      return {
        outcome: "sealing",
        status: parseStatus(status, "$.status"),
        reset: parseReset(status.reset, "$.status.reset"),
      };
    }
    case "password_invalid":
    case "presence_cancelled":
    case "presence_unsupported":
      return { outcome: outcome.outcome };
    case "backoff":
      return {
        outcome: "backoff",
        retry_after_seconds: backoffSeconds(outcome.retry_after_seconds),
      };
    default:
      return invalid("$.outcome", "unknownOutcome");
  }
}

export function parsePresenceOutcome(value: unknown): PresenceOutcome {
  const outcome = objectAt(value, "$");
  switch (outcome.outcome) {
    case "verified":
    case "presence_cancelled":
    case "presence_unsupported":
      return { outcome: outcome.outcome };
    default:
      return invalid("$.outcome", "unknownOutcome");
  }
}

/** Keeps the host's presence support across a status that lacks it. */
export function withPresence(
  status: RawSealingStatus,
  previous: RawSealingState | null,
): RawSealingState {
  return {
    ...status,
    presence_available: previous?.presence_available ?? false,
  };
}

/** Core accepts presence and this build can show the prompt. */
export function presenceUsable(state: RawSealingState): boolean {
  return state.local_presence && state.presence_available;
}

/**
 * Picks how to ask for proof (D14): the presence prompt where it works,
 * else the raw password, else a plain confirmation.
 */
export function rawProofMode(state: RawSealingState): RawProofMode {
  if (presenceUsable(state)) return "presence";
  if (state.password_set) return "password";
  return "confirm";
}

/**
 * A keychain-only raw key opens only behind the presence prompt; while the
 * host cannot show it, nothing on this device can open the key (Core turns
 * down a bare confirmation).
 */
export function rawKeyUnreachable(state: RawSealingState): boolean {
  return state.configured && !state.password_set && !presenceUsable(state);
}

/**
 * Grace after an unlock's expiry before checking it again, so a check lands
 * after Core's own idle lock rather than just before it.
 */
export const UNLOCK_CHECK_GRACE_MS = 2000;

/** Delay before checking whether the unlock expiring at `expiresAt` ended. */
export function unlockCheckDelay(expiresAt: string, now = Date.now()): number {
  return Math.max(Date.parse(expiresAt) - now, 0) + UNLOCK_CHECK_GRACE_MS;
}

/** Which way the raw key can be opened, for the settings summary. */
export type RawPasswordState = "unset" | "password" | "keychain_only";

export function rawPasswordState(status: RawSealingStatus): RawPasswordState {
  if (status.password_set) return "password";
  if (status.configured) return "keychain_only";
  return "unset";
}

/** Core counts Unicode characters, not UTF-16 code units. */
export function passwordLength(password: string): number {
  return [...password].length;
}

export const SUGGESTED_PASSWORD_LENGTH = 12;

export type NewPasswordIssue = "too_short" | "too_long" | "mismatch";

/** Checks a new raw password and its confirmation against Core's policy. */
export function newPasswordIssue(
  password: string,
  confirmation: string,
  policy: Pick<RawSealingStatus, "password_min_length" | "password_max_length">,
): NewPasswordIssue | null {
  const length = passwordLength(password);
  if (length < policy.password_min_length) return "too_short";
  if (length > policy.password_max_length) return "too_long";
  if (password !== confirmation) return "mismatch";
  return null;
}

/** A hint, not an error: long passphrases resist offline guessing. */
export function passwordIsShort(password: string): boolean {
  const length = passwordLength(password);
  return length > 0 && length < SUGGESTED_PASSWORD_LENGTH;
}

/**
 * The Control API error code inside a host error such as
 * `POST … returned 409 Conflict: {"error":{"code":"…"}}`.
 */
export function controlErrorCode(error: unknown): string | null {
  const message = error instanceof Error ? error.message : String(error);
  const match = /"code"\s*:\s*"([a-z0-9_]{1,64})"/.exec(message);
  return match ? match[1] : null;
}
