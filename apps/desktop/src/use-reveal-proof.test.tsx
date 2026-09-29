// @vitest-environment happy-dom

import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RawSealingState } from "./raw-sealing-model";

const mocks = vi.hoisted(() => ({
  getRawSealingStatus: vi.fn(),
  lockRaw: vi.fn(),
  unlockRaw: vi.fn(),
  verifyLocalPresence: vi.fn(),
}));

vi.mock("./bridge", () => mocks);

const notifyMocks = vi.hoisted(() => ({ error: vi.fn(), success: vi.fn() }));
vi.mock("./notify", () => ({ notify: notifyMocks }));

import { useRevealProof } from "./use-reveal-proof";

let container: HTMLDivElement;
let root: Root;
let results: boolean[];

function sealing(overrides: Partial<RawSealingState> = {}): RawSealingState {
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
    presence_available: false,
    ...overrides,
  };
}

function sealedOutcome(overrides: Partial<RawSealingState> = {}) {
  const { presence_available: _presence, ...status } = sealing(overrides);
  return { outcome: "sealing", status, reset: null };
}

function Harness({ initialActive = true }: { initialActive?: boolean }) {
  const [active, setActive] = useState(initialActive);
  const proof = useRevealProof(active);
  return (
    <div>
      <button
        onClick={() => {
          void proof.prove().then((proved) => results.push(proved));
        }}
        type="button"
      >
        请求复制
      </button>
      <button onClick={() => setActive(false)} type="button">
        停用
      </button>
      {proof.dialog}
    </div>
  );
}

beforeEach(() => {
  (
    globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  for (const mock of Object.values(mocks)) mock.mockReset();
  notifyMocks.error.mockReset();
  mocks.lockRaw.mockResolvedValue(sealedOutcome().status);
  results = [];
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

function button(label: string): HTMLButtonElement {
  const match = [
    ...document.querySelectorAll<HTMLButtonElement>("button"),
  ].find((candidate) => candidate.textContent?.trim() === label);
  if (!match) throw new Error(`Missing button: ${label}`);
  return match;
}

function dialog(): HTMLElement | null {
  return document.querySelector<HTMLElement>(
    '[data-slot="proof-confirm-dialog"]',
  );
}

async function click(target: HTMLElement) {
  await act(async () => {
    target.click();
    await Promise.resolve();
  });
  await act(async () => {});
}

async function typePassword(value: string) {
  const input = document.querySelector<HTMLInputElement>(
    'input[type="password"]',
  );
  if (!input) throw new Error("Missing password input");
  await act(async () => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function requestProof(initialActive = true) {
  await act(async () => root.render(<Harness initialActive={initialActive} />));
  await click(button("请求复制"));
}

describe("useRevealProof", () => {
  it("proves with Touch ID where the host can show it", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(
      sealing({ local_presence: true, presence_available: true }),
    );
    mocks.verifyLocalPresence
      .mockResolvedValueOnce({ outcome: "presence_cancelled" })
      .mockResolvedValueOnce({ outcome: "verified" });
    await requestProof();

    expect(dialog()?.textContent).toContain("确认复制访问令牌");
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    await click(button("复制令牌"));
    expect(dialog()?.textContent).toContain("已取消验证");
    expect(results).toEqual([]);

    await click(button("复制令牌"));
    expect(mocks.verifyLocalPresence).toHaveBeenLastCalledWith(
      "reveal_access_token",
    );
    expect(results).toEqual([true]);
    expect(dialog()).toBeNull();
    expect(mocks.unlockRaw).not.toHaveBeenCalled();
  });

  it("checks the raw password with an unlock and locks again", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(sealing());
    mocks.unlockRaw
      .mockResolvedValueOnce({ outcome: "password_invalid" })
      .mockResolvedValueOnce(sealedOutcome({ unlocked: true }));
    await requestProof();

    await typePassword("wrong password");
    await click(button("复制令牌"));
    expect(dialog()?.textContent).toContain("原文口令不正确");
    expect(results).toEqual([]);

    await typePassword("correct horse");
    await click(button("复制令牌"));
    expect(mocks.unlockRaw).toHaveBeenLastCalledWith({
      kind: "password",
      password: "correct horse",
    });
    expect(mocks.lockRaw).toHaveBeenCalledOnce();
    expect(results).toEqual([true]);
    expect(dialog()).toBeNull();
  });

  it("leaves an unlock session the operator already opened", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(sealing({ unlocked: true }));
    mocks.unlockRaw.mockResolvedValue(sealedOutcome({ unlocked: true }));
    await requestProof();

    await typePassword("correct horse");
    await click(button("复制令牌"));
    expect(mocks.lockRaw).not.toHaveBeenCalled();
    expect(results).toEqual([true]);
  });

  it("reads the unlock session again when the password is checked", async () => {
    // The session ended while the dialog was open, so the proof's unlock
    // is a new one and has to go again.
    mocks.getRawSealingStatus
      .mockResolvedValueOnce(sealing({ unlocked: true }))
      .mockResolvedValueOnce(sealing());
    mocks.unlockRaw.mockResolvedValue(sealedOutcome({ unlocked: true }));
    await requestProof();

    await typePassword("correct horse");
    await click(button("复制令牌"));
    expect(mocks.getRawSealingStatus).toHaveBeenCalledTimes(2);
    expect(mocks.lockRaw).toHaveBeenCalledOnce();
    expect(results).toEqual([true]);
  });

  it("reports a lock that failed after the proof", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(sealing());
    mocks.unlockRaw.mockResolvedValue(sealedOutcome({ unlocked: true }));
    mocks.lockRaw.mockRejectedValue(new Error("socket closed"));
    await requestProof();

    await typePassword("correct horse");
    await click(button("复制令牌"));
    expect(results).toEqual([true]);
    expect(notifyMocks.error).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining("锁定原文失败"),
    );
  });

  it("falls back to a confirmation without a raw password", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(
      sealing({ configured: false, password_set: false, envelopes: [] }),
    );
    await requestProof();

    expect(document.querySelector('input[type="password"]')).toBeNull();
    await click(button("复制令牌"));
    expect(mocks.verifyLocalPresence).not.toHaveBeenCalled();
    expect(mocks.unlockRaw).not.toHaveBeenCalled();
    expect(results).toEqual([true]);
  });

  it("refuses when the sealing state cannot be read, and asks again", async () => {
    // A password-protected token must not become a plain confirmation just
    // because the status read failed.
    mocks.getRawSealingStatus
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce(sealing());
    await requestProof();

    expect(dialog()).toBeNull();
    expect(results).toEqual([false]);
    expect(notifyMocks.error).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining("未复制令牌"),
    );
    expect(notifyMocks.error.mock.calls[0]?.[0]).toContain("offline");

    await click(button("请求复制"));
    expect(dialog()).not.toBeNull();
    expect(document.querySelector('input[type="password"]')).not.toBeNull();
    expect(results).toEqual([false]);
  });

  it("resolves false when the user cancels", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(sealing());
    await requestProof();

    await click(button("取消"));
    expect(results).toEqual([false]);
    expect(dialog()).toBeNull();
  });

  it("resolves false when the caller goes inactive", async () => {
    mocks.getRawSealingStatus.mockResolvedValue(sealing());
    await requestProof();

    await click(button("停用"));
    expect(results).toEqual([false]);
    expect(dialog()).toBeNull();
  });

  it("does not ask while inactive", async () => {
    await requestProof(false);
    expect(mocks.getRawSealingStatus).not.toHaveBeenCalled();
    expect(results).toEqual([false]);
    expect(dialog()).toBeNull();
  });
});
