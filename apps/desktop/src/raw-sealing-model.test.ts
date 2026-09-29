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
  rawAcknowledgeMode,
  rawKeyUnreachable,
  rawPasswordState,
  rawProofMode,
  rawResetProofMode,
  withPresence,
  type RawSealingState,
} from "./raw-sealing-model";

function status(overrides: Record<string, unknown> = {}) {
  return {
    raw_available: true,
    configured: true,
    password_set: true,
    password_required: false,
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
    keychain_build: false,
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
        keychain_build: true,
      }),
    ).toMatchObject({
      unlocked: true,
      unlock_expires_at: "2026-09-28T10:15:00Z",
      envelopes: ["password", "local"],
      local_presence: true,
      presence_available: true,
      keychain_build: true,
    });
  });

  it("reads the desktop's replaced-key verdict, absent meaning none", () => {
    expect(
      parseRawSealingStatus(status({ key_replaced: true })).key_replaced,
    ).toBe(true);
    expect(
      parseRawSealingStatus(status({ key_replaced: false })).key_replaced,
    ).toBe(false);
    expect(parseRawSealingStatus(status()).key_replaced).toBe(false);
    const outcome = parseRawSealingOutcome({
      outcome: "sealing",
      status: status({ key_replaced: true }),
    });
    expect(outcome.outcome === "sealing" && outcome.status.key_replaced).toBe(
      true,
    );
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
      parseRawSealingStatus(status({ password_required: undefined })),
    ).toThrow("$.password_required");
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
    expect(() =>
      parseRawSealingState({ ...status(), presence_available: true }),
    ).toThrow("$.keychain_build");
    expect(() => parseRawSealingStatus(status({ key_replaced: 1 }))).toThrow(
      "$.key_replaced",
    );
    expect(() =>
      parseRawSealingOutcome({
        outcome: "sealing",
        status: status({ key_replaced: null }),
      }),
    ).toThrow("$.status.key_replaced");
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

  it("keeps asking for the proof Core wants before a reset", () => {
    // Where the local envelope opens the key, Core refuses a reset without
    // a proof, so an unavailable prompt is retried rather than skipped.
    expect(
      rawResetProofMode(
        state({
          local_presence: true,
          password_set: false,
          presence_available: false,
        }),
      ),
    ).toBe("presence");
    expect(
      rawResetProofMode(
        state({ local_presence: true, presence_available: false }),
      ),
    ).toBe("password");
    expect(
      rawResetProofMode(
        state({ local_presence: true, presence_available: true }),
      ),
    ).toBe("presence");
    // A key nothing here opens is replaced with a plain confirmation.
    expect(
      rawResetProofMode(
        state({ local_presence: false, presence_available: true }),
      ),
    ).toBe("confirm");
  });

  it("keeps presence support across a status that lacks it", () => {
    const previous = state({ presence_available: true, keychain_build: true });
    const next = parseRawSealingStatus(status({ unlocked: true }));
    expect(withPresence(next, previous)).toMatchObject({
      unlocked: true,
      presence_available: true,
      keychain_build: true,
    });
    expect(withPresence(next, null)).toMatchObject({
      presence_available: false,
      keychain_build: false,
    });
  });

  it("accepts a replaced key with its password and, on a keychain build, presence too", () => {
    // Builds without a keychain have no presence check to add.
    expect(rawAcknowledgeMode(state({ presence_available: false }))).toBe(
      "password",
    );
    expect(
      rawAcknowledgeMode(
        state({ keychain_build: true, presence_available: true }),
      ),
    ).toBe("password_and_presence");
    // Where the keychain build cannot show the prompt, the password alone
    // is not enough: only a reset is left.
    expect(
      rawAcknowledgeMode(
        state({ keychain_build: true, presence_available: false }),
      ),
    ).toBe("unavailable");
  });

  it("reads raw content only once a raw password is set (D11)", () => {
    expect(rawKeyUnreachable(state())).toBe(false);
    // A keychain key the presence prompt opens is still not enough.
    expect(
      rawKeyUnreachable(
        state({
          password_set: false,
          password_required: true,
          envelopes: ["local"],
          local_presence: true,
          presence_available: true,
        }),
      ),
    ).toBe(true);
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
