import { describe, expect, it } from "vitest";

import {
  controlErrorCode,
  newPasswordIssue,
  parsePresenceOutcome,
  parseRawSealingOutcome,
  parseRawSealingState,
  parseRawSealingStatus,
  passwordIsShort,
  passwordLength,
  presenceUsable,
  rawPasswordState,
  rawProofMode,
  withPresence,
  type RawSealingState,
} from "./raw-sealing-model";

function status(overrides: Record<string, unknown> = {}) {
  return {
    raw_available: true,
    configured: true,
    password_set: true,
    local_presence: false,
    envelopes: ["password"],
    key_verified: true,
    unlocked: false,
    unlock_expires_at: null,
    unlock_idle_seconds: 900,
    retry_after_seconds: 0,
    password_min_length: 8,
    password_max_length: 128,
    ...overrides,
  };
}

function state(overrides: Partial<RawSealingState> = {}): RawSealingState {
  return {
    ...parseRawSealingStatus(status()),
    presence_available: false,
    ...overrides,
  };
}

describe("raw sealing status", () => {
  it("parses the host state with presence support", () => {
    expect(
      parseRawSealingState({
        ...status({
          unlocked: true,
          unlock_expires_at: "2026-09-28T10:15:00Z",
          envelopes: ["password", "local"],
          local_presence: true,
        }),
        presence_available: true,
      }),
    ).toMatchObject({
      unlocked: true,
      unlock_expires_at: "2026-09-28T10:15:00Z",
      envelopes: ["password", "local"],
      local_presence: true,
      presence_available: true,
    });
  });

  it("rejects malformed fields with the offending path", () => {
    expect(() => parseRawSealingStatus(status({ configured: "yes" }))).toThrow(
      "原文封存数据无效（$.configured）：应为布尔值",
    );
    expect(() =>
      parseRawSealingStatus(status({ envelopes: ["password", "password"] })),
    ).toThrow("$.envelopes[1]");
    expect(() =>
      parseRawSealingStatus(status({ envelopes: ["cloud"] })),
    ).toThrow("$.envelopes[0]");
    expect(() =>
      parseRawSealingStatus(status({ unlock_expires_at: "soon" })),
    ).toThrow("$.unlock_expires_at");
    expect(() =>
      parseRawSealingStatus(status({ unlock_idle_seconds: 0 })),
    ).toThrow("$.unlock_idle_seconds");
    expect(() =>
      parseRawSealingStatus(status({ retry_after_seconds: -1 })),
    ).toThrow("$.retry_after_seconds");
    expect(() =>
      parseRawSealingStatus(
        status({ password_min_length: 12, password_max_length: 8 }),
      ),
    ).toThrow("$.password_max_length");
    expect(() => parseRawSealingState(status())).toThrow(
      "$.presence_available",
    );
    expect(() => parseRawSealingStatus([])).toThrow("（$）：应为对象");
  });
});

describe("raw sealing outcomes", () => {
  it("parses a new status and an optional reset summary", () => {
    expect(
      parseRawSealingOutcome({ outcome: "sealing", status: status() }),
    ).toEqual({
      outcome: "sealing",
      status: parseRawSealingStatus(status()),
      reset: null,
    });
    expect(
      parseRawSealingOutcome({
        outcome: "sealing",
        status: status({ reset: { deleted_parts: 3, affected_records: 2 } }),
      }),
    ).toMatchObject({ reset: { deleted_parts: 3, affected_records: 2 } });
    expect(() =>
      parseRawSealingOutcome({
        outcome: "sealing",
        status: status({ reset: { deleted_parts: -1, affected_records: 0 } }),
      }),
    ).toThrow("$.status.reset.deleted_parts");
  });

  it("parses refusals and rejects unknown results", () => {
    for (const outcome of [
      "password_invalid",
      "presence_cancelled",
      "presence_unsupported",
    ]) {
      expect(parseRawSealingOutcome({ outcome })).toEqual({ outcome });
    }
    expect(
      parseRawSealingOutcome({ outcome: "backoff", retry_after_seconds: 5 }),
    ).toEqual({ outcome: "backoff", retry_after_seconds: 5 });
    expect(() =>
      parseRawSealingOutcome({ outcome: "backoff", retry_after_seconds: 0 }),
    ).toThrow("$.retry_after_seconds");
    expect(() => parseRawSealingOutcome({ outcome: "decided" })).toThrow(
      "$.outcome",
    );
    expect(parsePresenceOutcome({ outcome: "verified" })).toEqual({
      outcome: "verified",
    });
    expect(() => parsePresenceOutcome({ outcome: "password_invalid" })).toThrow(
      "$.outcome",
    );
  });
});

describe("raw proof mode", () => {
  it("prefers presence, then the password, then a plain confirmation", () => {
    expect(
      rawProofMode(state({ local_presence: true, presence_available: true })),
    ).toBe("presence");
    // Core accepting presence is not enough when this build cannot prompt.
    expect(
      rawProofMode(state({ local_presence: true, presence_available: false })),
    ).toBe("password");
    expect(
      rawProofMode(state({ local_presence: false, presence_available: true })),
    ).toBe("password");
    expect(rawProofMode(state({ password_set: false }))).toBe("confirm");
    expect(
      presenceUsable(state({ local_presence: true, presence_available: true })),
    ).toBe(true);
  });

  it("keeps presence support across a status that lacks it", () => {
    const previous = state({ presence_available: true });
    const next = parseRawSealingStatus(status({ unlocked: true }));
    expect(withPresence(next, previous)).toMatchObject({
      unlocked: true,
      presence_available: true,
    });
    expect(withPresence(next, null).presence_available).toBe(false);
  });

  it("summarizes how the raw key opens", () => {
    expect(
      rawPasswordState(state({ configured: false, password_set: false })),
    ).toBe("unset");
    expect(rawPasswordState(state())).toBe("password");
    expect(
      rawPasswordState(state({ password_set: false, envelopes: ["local"] })),
    ).toBe("keychain_only");
  });
});

describe("new raw passwords", () => {
  const policy = { password_min_length: 8, password_max_length: 10 };

  it("checks length in characters and the confirmation", () => {
    expect(passwordLength("口令🔑")).toBe(3);
    expect(newPasswordIssue("short", "short", policy)).toBe("too_short");
    expect(newPasswordIssue("elevenchars", "elevenchars", policy)).toBe(
      "too_long",
    );
    // Ten characters, though more UTF-16 code units.
    expect(
      newPasswordIssue("🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑", "🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑", policy),
    ).toBe(null);
    expect(newPasswordIssue("eightchr", "eightchx", policy)).toBe("mismatch");
    expect(newPasswordIssue("eightchr", "eightchr", policy)).toBe(null);
  });

  it("suggests a longer passphrase without refusing a short one", () => {
    expect(passwordIsShort("")).toBe(false);
    expect(passwordIsShort("eightchr")).toBe(true);
    expect(passwordIsShort("twelve chars")).toBe(false);
  });
});

describe("control error codes", () => {
  it("reads the code from a host error", () => {
    expect(
      controlErrorCode(
        new Error(
          'POST /control/v1/audit/raw-unlock returned 409 Conflict: {"error":{"code":"raw_access_unavailable","message":"x"}}',
        ),
      ),
    ).toBe("raw_access_unavailable");
    expect(controlErrorCode("core did not answer")).toBeNull();
  });
});
