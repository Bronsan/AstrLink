// @vitest-environment happy-dom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RawAccessGrant } from "./raw-access-model";
import type { RawSealingState } from "./raw-sealing-model";

const mocks = vi.hoisted(() => ({
  decideRawAccess: vi.fn(),
  getRawSealingStatus: vi.fn(),
  getRequestRecord: vi.fn(),
  listRawAccess: vi.fn(),
  toastError: vi.fn(),
  toastInfo: vi.fn(),
  toastSuccess: vi.fn(),
}));

vi.mock("./bridge", () => ({
  decideRawAccess: mocks.decideRawAccess,
  getRawSealingStatus: mocks.getRawSealingStatus,
  getRequestRecord: mocks.getRequestRecord,
  listRawAccess: mocks.listRawAccess,
}));
vi.mock("sonner", () => ({
  toast: {
    error: mocks.toastError,
    info: mocks.toastInfo,
    success: mocks.toastSuccess,
  },
}));

import { RAW_ACCESS_POLL_MS, RawAccessApprovals } from "./RawAccessApprovals";

let container: HTMLDivElement;
let root: Root;

function grant(overrides: Partial<RawAccessGrant> = {}): RawAccessGrant {
  return {
    grant_id: "rawgrant_0123456789abcdef",
    request_id: "req_raw_01",
    status: "pending",
    decision: null,
    reason: "需要核对上游返回的原始 JSON",
    client_name: "Claude Code",
    created_at: "2026-09-28T10:00:00Z",
    expires_at: "2026-09-28T10:10:00Z",
    ...overrides,
  };
}

function sealing(overrides: Partial<RawSealingState> = {}): RawSealingState {
  return {
    raw_available: true,
    configured: true,
    password_set: true,
    password_required: overrides.password_set === false,
    envelopes: ["password"],
    key_verified: true,
    unlocked: false,
    unlock_expires_at: null,
    unlock_idle_seconds: 900,
    retry_after_seconds: 0,
    password_min_length: 8,
    password_max_length: 128,
    key_replaced: false,
    ...overrides,
  };
}

const passwordProof = { kind: "password", password: "correct horse" };

const laterGrant = grant({
  grant_id: "rawgrant_fedcba9876543210",
  request_id: "req_raw_02",
  client_name: "Codex",
  created_at: "2026-09-28T10:05:00Z",
});

beforeEach(() => {
  (
    globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.listRawAccess.mockResolvedValue([]);
  mocks.getRawSealingStatus.mockResolvedValue(sealing());
  mocks.getRequestRecord.mockImplementation(async (requestId: string) => ({
    id: requestId,
    requested_model: requestId === "req_raw_01" ? "gpt-5" : "claude-opus",
    started_at: "2026-09-28T09:58:00Z",
  }));
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  vi.useRealTimers();
  await act(async () => root.unmount());
  container.remove();
});

async function render(isReady = true) {
  await act(async () =>
    root.render(
      <RawAccessApprovals coreSessionKey="session-1" isReady={isReady} />,
    ),
  );
  await act(async () => {});
}

function dialog(): HTMLElement | null {
  return document.querySelector<HTMLElement>('[role="alertdialog"]');
}

function button(label: string): HTMLButtonElement {
  const match = [
    ...document.querySelectorAll<HTMLButtonElement>("button"),
  ].find((candidate) => candidate.textContent?.trim() === label);
  if (!match) throw new Error(`Missing button: ${label}`);
  return match;
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

describe("RawAccessApprovals", () => {
  it("stays idle while the core is not ready", async () => {
    await render(false);

    expect(mocks.listRawAccess).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
  });

  it("shows the oldest pending request with its facts", async () => {
    mocks.listRawAccess.mockResolvedValue([
      laterGrant,
      grant(),
      grant({
        grant_id: "rawgrant_1111111111111111",
        status: "approved",
        decision: "once",
        created_at: "2026-09-28T09:00:00Z",
      }),
    ]);

    await render();

    const text = dialog()?.textContent ?? "";
    expect(text).toContain("Agent 申请查看原文");
    expect(text).toContain("「Claude Code」请求查看");
    expect(text).toContain("req_raw_01");
    expect(text).toContain("gpt-5");
    expect(text).toContain("需要核对上游返回的原始 JSON");
    expect(text).toContain("原文将发送给该 Agent 使用的模型服务商。");
    expect(mocks.getRequestRecord).toHaveBeenCalledWith("req_raw_01");
    expect(button("仅本次").disabled).toBe(true);
  });

  it("falls back to unknown facts when the record cannot be read", async () => {
    mocks.listRawAccess.mockResolvedValue([grant({ client_name: "" })]);
    mocks.getRequestRecord.mockRejectedValue(new Error("not found"));

    await render();

    const facts = document.querySelector('[data-slot="raw-access-facts"]');
    expect(facts?.textContent).toContain("未知");
    expect(dialog()?.textContent).toContain("「未具名的 Agent」请求查看");
  });

  it("approves once with the typed password and moves on", async () => {
    mocks.listRawAccess.mockResolvedValueOnce([grant(), laterGrant]);
    mocks.listRawAccess.mockResolvedValue([laterGrant]);
    mocks.decideRawAccess.mockResolvedValue({
      outcome: "decided",
      grant: grant({ status: "approved", decision: "once" }),
    });
    await render();
    await typePassword("correct horse");

    await act(async () => button("仅本次").click());
    await act(async () => {});

    expect(mocks.decideRawAccess).toHaveBeenCalledExactlyOnceWith(
      "rawgrant_0123456789abcdef",
      "once",
      passwordProof,
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "已允许「Claude Code」读取一次原文",
    );
    expect(dialog()?.textContent).toContain("「Codex」请求查看");
    expect(dialog()?.textContent).toContain("claude-opus");
    const input = document.querySelector<HTMLInputElement>(
      'input[type="password"]',
    );
    expect(input?.value).toBe("");
  });

  it("names the 15-minute window when approving it", async () => {
    mocks.listRawAccess.mockResolvedValueOnce([grant()]);
    mocks.decideRawAccess.mockResolvedValue({
      outcome: "decided",
      grant: grant({ status: "approved", decision: "window_15m" }),
    });
    await render();
    await typePassword("correct horse");

    await act(async () => button("本请求 15 分钟内").click());
    await act(async () => {});

    expect(mocks.decideRawAccess).toHaveBeenCalledWith(
      "rawgrant_0123456789abcdef",
      "window_15m",
      passwordProof,
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "已允许「Claude Code」在 15 分钟内读取这条请求的原文",
    );
    expect(dialog()).toBeNull();
  });

  it("keeps the request open after a wrong password", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.decideRawAccess.mockResolvedValue({ outcome: "password_invalid" });
    await render();
    await typePassword("wrong horse");

    await act(async () => button("仅本次").click());

    expect(dialog()?.getAttribute("data-state")).toBe("open");
    expect(dialog()?.textContent).toContain("原文口令不正确。");
    expect(mocks.toastSuccess).not.toHaveBeenCalled();
  });

  it("shows the backoff the core asks for", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.decideRawAccess.mockResolvedValue({
      outcome: "backoff",
      retry_after_seconds: 8,
    });
    await render();
    await typePassword("wrong horse");

    await act(async () => button("仅本次").click());

    expect(
      document.querySelector('[data-slot="proof-backoff"]')?.textContent,
    ).toContain("8 秒后重试");
  });

  it("closes a request someone else already decided", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.decideRawAccess.mockResolvedValue({ outcome: "not_pending" });
    await render();
    await typePassword("correct horse");

    await act(async () => button("仅本次").click());

    expect(mocks.toastInfo).toHaveBeenCalledWith("该申请已过期或已被处理");
    expect(dialog()).toBeNull();
  });

  it("denies without a password and hides the request at once", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.decideRawAccess.mockResolvedValue({
      outcome: "decided",
      grant: grant({ status: "denied", decision: "deny" }),
    });
    await render();

    await act(async () => button("拒绝").click());
    await act(async () => {});

    expect(mocks.decideRawAccess).toHaveBeenCalledExactlyOnceWith(
      "rawgrant_0123456789abcdef",
      "deny",
    );
    expect(mocks.toastInfo).toHaveBeenCalledWith("已拒绝原文申请");
    // The list still says pending until the core catches up; it stays hidden.
    expect(dialog()).toBeNull();
  });

  it("brings the request back when the denial fails", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.decideRawAccess.mockRejectedValue(new Error("核心未响应"));
    await render();

    await act(async () => button("拒绝").click());
    await act(async () => {});

    expect(mocks.toastError).toHaveBeenCalledWith(
      "拒绝原文申请失败：核心未响应",
    );
    expect(dialog()?.textContent).toContain("「Claude Code」请求查看");
  });

  it("asks for the password when the sealing state cannot be read", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.getRawSealingStatus.mockRejectedValue(new Error("核心未响应"));
    await render();

    expect(document.querySelector('input[type="password"]')).not.toBeNull();
  });

  it("offers only denial until a raw password is set", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.getRawSealingStatus.mockResolvedValue(
      sealing({
        configured: false,
        password_set: false,
        password_required: true,
        envelopes: [],
      }),
    );
    await render();

    expect(
      document.querySelector('[data-testid="raw-access-unreachable"]')
        ?.textContent,
    ).toContain("无法批准");
    expect(document.querySelector('input[type="password"]')).toBeNull();
    expect(button("仅本次").disabled).toBe(true);
    expect(button("本请求 15 分钟内").disabled).toBe(true);
    expect(button("拒绝").disabled).toBe(false);
    await act(async () => button("仅本次").click());
    expect(mocks.decideRawAccess).not.toHaveBeenCalled();

    mocks.decideRawAccess.mockResolvedValue({
      outcome: "decided",
      grant: grant({ status: "denied", decision: "deny" }),
    });
    await act(async () => button("拒绝").click());
    expect(mocks.decideRawAccess).toHaveBeenCalledExactlyOnceWith(
      "rawgrant_0123456789abcdef",
      "deny",
    );
  });

  it("explains a refusal from the core in plain words", async () => {
    mocks.listRawAccess.mockResolvedValue([grant()]);
    mocks.decideRawAccess.mockRejectedValue(
      new Error(
        'POST /control/v1/raw-access/x/decision returned 409 Conflict: {"error":{"code":"raw_access_unavailable","message":"raw access is not set up"}}',
      ),
    );
    await render();
    await typePassword("correct horse");

    await act(async () => button("仅本次").click());

    expect(dialog()?.textContent).toContain("还没设置原文保护。");
  });

  it("polls for new requests while ready", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    await render();
    expect(dialog()).toBeNull();

    mocks.listRawAccess.mockResolvedValue([grant()]);
    await act(async () => vi.advanceTimersByTime(RAW_ACCESS_POLL_MS));
    await act(async () => {});

    expect(mocks.listRawAccess).toHaveBeenCalledTimes(2);
    expect(dialog()?.textContent).toContain("「Claude Code」请求查看");

    await act(async () =>
      root.render(
        <RawAccessApprovals coreSessionKey="session-1" isReady={false} />,
      ),
    );
    expect(dialog()).toBeNull();
    await act(async () => vi.advanceTimersByTime(RAW_ACCESS_POLL_MS * 2));
    expect(mocks.listRawAccess).toHaveBeenCalledTimes(2);
  });
});
