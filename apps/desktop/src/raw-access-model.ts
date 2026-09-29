import { invalidData, type DataProblem } from "./ipc-data-error";

/** An agent's request to read one request's raw audit parts (plan §5.11). */
export interface RawAccessGrant {
  grant_id: string;
  request_id: string;
  status: RawAccessGrantStatus;
  /** How the operator decided; absent while the request is pending. */
  decision: RawAccessDecision | null;
  /** Why the agent asked, in its own words. Untrusted display text. */
  reason: string;
  /** The agent's self-reported name (the CLI's `--agent`); it authorizes nothing. */
  client_name: string;
  created_at: string;
  expires_at: string;
}

export type RawAccessGrantStatus =
  | "pending"
  | "approved"
  | "denied"
  | "expired"
  | "consumed";

export type RawAccessDecision = "once" | "window_15m" | "deny";

/**
 * What a proof-carrying decision ended in. Refusals the dialog can recover
 * from are outcomes, not errors, so it can stay open for another attempt.
 */
export type RawAccessProofOutcome =
  | { outcome: "decided"; grant: RawAccessGrant }
  | { outcome: "password_invalid" }
  | { outcome: "backoff"; retry_after_seconds: number }
  | { outcome: "not_pending" }
  /** The presence prompt was dismissed; nothing reached Core. */
  | { outcome: "presence_cancelled" }
  /** This build cannot check presence; ask for the password instead. */
  | { outcome: "presence_unsupported" };

type JsonObject = Record<string, unknown>;

const statuses = new Set<RawAccessGrantStatus>([
  "pending",
  "approved",
  "denied",
  "expired",
  "consumed",
]);
const decisions = new Set<RawAccessDecision>(["once", "window_15m", "deny"]);
const grantIDPattern = /^rawgrant_[0-9a-f]{16}$/;

function invalid(path: string, problem: DataProblem): never {
  return invalidData("rawAccess", path, problem);
}

function objectAt(value: unknown, path: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid(path, "object");
  }
  return value as JsonObject;
}

function stringAt(value: unknown, path: string, maxLength: number): string {
  if (typeof value !== "string") return invalid(path, "string");
  if (value.length > maxLength) return invalid(path, "tooLong");
  return value;
}

function timestampAt(value: unknown, path: string): string {
  const text = stringAt(value, path, 64);
  if (Number.isNaN(Date.parse(text))) invalid(path, "timestamp");
  return text;
}

function parseGrant(value: unknown, path: string): RawAccessGrant {
  const grant = objectAt(value, path);
  const grantID = stringAt(grant.grant_id, `${path}.grant_id`, 64);
  if (!grantIDPattern.test(grantID)) invalid(`${path}.grant_id`, "badFormat");
  const status = stringAt(grant.status, `${path}.status`, 32);
  if (!statuses.has(status as RawAccessGrantStatus)) {
    invalid(`${path}.status`, "unknownStatus");
  }
  let decision: RawAccessDecision | null = null;
  if (grant.decision !== undefined && grant.decision !== "") {
    const raw = stringAt(grant.decision, `${path}.decision`, 32);
    if (!decisions.has(raw as RawAccessDecision)) {
      invalid(`${path}.decision`, "unknownDecision");
    }
    decision = raw as RawAccessDecision;
  }
  return {
    grant_id: grantID,
    request_id: stringAt(grant.request_id, `${path}.request_id`, 128),
    status: status as RawAccessGrantStatus,
    decision,
    reason: stringAt(grant.reason, `${path}.reason`, 4096),
    client_name: stringAt(grant.client_name, `${path}.client_name`, 256),
    created_at: timestampAt(grant.created_at, `${path}.created_at`),
    expires_at: timestampAt(grant.expires_at, `${path}.expires_at`),
  };
}

export function parseRawAccessList(value: unknown): RawAccessGrant[] {
  const list = objectAt(value, "$");
  if (!Array.isArray(list.items)) invalid("$.items", "array");
  return list.items.map((item, index) => parseGrant(item, `$.items[${index}]`));
}

export function parseRawAccessProofOutcome(
  value: unknown,
): RawAccessProofOutcome {
  const outcome = objectAt(value, "$");
  switch (outcome.outcome) {
    case "decided":
      return {
        outcome: "decided",
        grant: parseGrant(outcome.grant, "$.grant"),
      };
    case "password_invalid":
    case "not_pending":
    case "presence_cancelled":
    case "presence_unsupported":
      return { outcome: outcome.outcome };
    case "backoff": {
      const seconds = outcome.retry_after_seconds;
      if (
        typeof seconds !== "number" ||
        !Number.isInteger(seconds) ||
        seconds < 1
      ) {
        invalid("$.retry_after_seconds", "positiveInteger");
      }
      return { outcome: "backoff", retry_after_seconds: seconds };
    }
    default:
      return invalid("$.outcome", "unknownOutcome");
  }
}

/** The oldest request still awaiting the operator, if any. */
export function oldestPendingGrant(
  grants: RawAccessGrant[],
): RawAccessGrant | null {
  let oldest: RawAccessGrant | null = null;
  for (const grant of grants) {
    if (grant.status !== "pending") continue;
    if (
      !oldest ||
      Date.parse(grant.created_at) < Date.parse(oldest.created_at)
    ) {
      oldest = grant;
    }
  }
  return oldest;
}
