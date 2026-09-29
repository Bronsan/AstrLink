// @vitest-environment happy-dom

import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { applyLocale, i18n } from "./i18n";
import type { RawSealingState } from "./raw-sealing-model";

const mocks = vi.hoisted(() => ({
  acknowledgeRawKey: vi.fn(),
  setRawPassword: vi.fn(),
  unlockRaw: vi.fn(),
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
  toastWarning: vi.fn(),
}));

vi.mock("./bridge", () => ({
  acknowledgeRawKey: mocks.acknowledgeRawKey,
  setRawPassword: mocks.setRawPassword,
  unlockRaw: mocks.unlockRaw,
}));
vi.mock("sonner", () => ({
  toast: {
    error: mocks.toastError,
    success: mocks.toastSuccess,
    warning: mocks.toastWarning,
  },
}));

import {
  RawPasswordGate,
  RawPasswordPanel,
  RawSealingDialogs,
  rawPasswordMissing,
  unlockIdleMinutes,
  type RawDialog,
} from "./RawSealingControls";

let container: HTMLDivElement;
let root: Root;

function sealing(overrides: Partial<RawSealingState> = {}): RawSealingState {
  return {
    raw_available: true,
    configured: true,
    password_set: true,
    password_required: overrides.password_set === false,
    local_presence: false,
    envelopes: ["password"],
    key_verified: true,
    unlocked: false,
    unlock_expires_at: null,
    unlock_idle_seconds: 900,
    retry_after_seconds: 0,
    password_min_length: 8,
    password_max_length: 128,
    key_replaced: false,
    presence_available: false,
    keychain_build: false,
    ...overrides,
  };
}

const unconfigured = sealing({
  raw_available: false,
  configured: false,
  password_set: false,
  envelopes: [],
  key_verified: false,
});

/** A signed Mac from before D11: a keychain key Touch ID opens. */
const keychainOnly = sealing({
  raw_available: false,
  password_set: false,
  envelopes: ["local"],
  local_presence: true,
  presence_available: true,
});

function sealed(
  status: Partial<RawSealingState> = {},
  reset: { deleted_parts: number; affected_records: number } | null = null,
) {
  const {
    presence_available: _presence,
    keychain_build: _keychain,
    ...rest
  } = sealing(status);
  return { outcome: "sealing", status: rest, reset };
}

beforeEach(() => {
  (
    globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  for (const mock of Object.values(mocks)) mock.mockReset();
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  await applyLocale("zh-CN");
});

function button(
  label: string,
  scope: ParentNode = document,
): HTMLButtonElement {
  const match = [...scope.querySelectorAll<HTMLButtonElement>("button")].find(
    (candidate) => candidate.textContent?.trim() === label,
  );
  if (!match) throw new Error(`Missing button: ${label}`);
  return match;
}

function queryButton(label: string, scope: ParentNode = document) {
  return (
    [...scope.querySelectorAll<HTMLButtonElement>("button")].find(
      (candidate) => candidate.textContent?.trim() === label,
    ) ?? null
  );
}

function dialog(): HTMLElement | null {
  return document.querySelector<HTMLElement>(
    '[data-slot="proof-confirm-dialog"]',
  );
}

/** The plain confirmation, such as the destructive one before a reset. */
function confirmDialog(): HTMLElement | null {
  return document.querySelector<HTMLElement>(
    '[data-slot="alert-dialog-content"]',
  );
}

function newPasswordInputs(): HTMLInputElement[] {
  return [
    ...document.querySelectorAll<HTMLInputElement>(
      'input[autocomplete="new-password"]',
    ),
  ];
}

function proofPasswordInput(): HTMLInputElement | null {
  return document.querySelector<HTMLInputElement>(
    'input[type="password"][autocomplete="off"]',
  );
}

async function type(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function typeNewPassword(password: string, confirmation = password) {
  const [first, second] = newPasswordInputs();
  await type(first, password);
  await type(second, confirmation);
}

async function click(target: HTMLElement) {
  await act(async () => {
    target.click();
    await Promise.resolve();
  });
  await act(async () => {});
}

describe("raw sealing helpers", () => {
  it("rounds the idle lock to whole minutes", () => {
    expect(unlockIdleMinutes(sealing())).toBe(15);
    expect(unlockIdleMinutes(sealing({ unlock_idle_seconds: 20 }))).toBe(1);
  });

  it("misses a password on every platform until one is set (D11)", () => {
    expect(rawPasswordMissing(unconfigured)).toBe(true);
    // A keychain key with Touch ID is no longer enough on its own.
    expect(rawPasswordMissing(keychainOnly)).toBe(true);
    expect(rawPasswordMissing(sealing())).toBe(false);
    expect(rawPasswordMissing(null)).toBe(false);
  });
});

describe("RawPasswordPanel", () => {
  async function renderPanel(
    props: Partial<Parameters<typeof RawPasswordPanel>[0]> = {},
  ) {
    const onAction = vi.fn();
    const onAgentAccessChange = vi.fn();
    await act(async () =>
      root.render(
        <RawPasswordPanel
          agentAccess
          busy={false}
          error={null}
          onAction={onAction}
          onAgentAccessChange={onAgentAccessChange}
          status={sealing()}
          {...props}
        />,
      ),
    );
    return { onAction, onAgentAccessChange };
  }

  function panel(): HTMLElement {
    const match = container.querySelector<HTMLElement>(
      '[data-slot="raw-password-panel"]',
    );
    if (!match) throw new Error("Missing raw password panel");
    return match;
  }

  function agentSwitch(): HTMLButtonElement {
    const match = panel().querySelector<HTMLButtonElement>('[role="switch"]');
    if (!match) throw new Error("Missing agent access switch");
    return match;
  }

  it("offers change and reset once a password is set", async () => {
    const { onAction, onAgentAccessChange } = await renderPanel();

    expect(
      panel().querySelector('[data-slot="raw-password-state"]')?.textContent,
    ).toBe("已设置");
    expect(panel().textContent).toContain("需要输入原文口令");
    await click(button("修改", panel()));
    expect(onAction).toHaveBeenLastCalledWith("change");
    await click(button("重置", panel()));
    expect(onAction).toHaveBeenLastCalledWith("reset");

    expect(agentSwitch().disabled).toBe(false);
    expect(agentSwitch().getAttribute("aria-checked")).toBe("true");
    await click(agentSwitch());
    expect(onAgentAccessChange).toHaveBeenCalledWith(false);
  });

  it("mentions Touch ID when the host can show the presence prompt", async () => {
    await renderPanel({
      status: sealing({ local_presence: true, presence_available: true }),
    });
    expect(panel().textContent).toContain("Touch ID");
  });

  it("asks a keychain-only key for a password, or a reset", async () => {
    const { onAction } = await renderPanel({ status: keychainOnly });
    expect(
      panel().querySelector('[data-slot="raw-password-state"]')?.textContent,
    ).toBe("未设置");
    const missing = panel().querySelector<HTMLElement>(
      '[data-slot="raw-password-missing"]',
    );
    expect(missing?.textContent).toContain("本机钥匙串中已有原文密钥");
    expect(missing?.textContent).toContain("原文正文不会被记录");
    await click(button("设置口令", missing!));
    expect(onAction).toHaveBeenLastCalledWith("set");
    await click(button("重置", panel()));
    expect(onAction).toHaveBeenLastCalledWith("reset");
    expect(agentSwitch().disabled).toBe(true);
  });

  it("asks for a password whenever none is set, capture or not", async () => {
    const { onAction } = await renderPanel({ status: unconfigured });

    expect(
      panel().querySelector('[data-slot="raw-password-state"]')?.textContent,
    ).toBe("未设置");
    const missing = panel().querySelector<HTMLElement>(
      '[data-slot="raw-password-missing"]',
    );
    expect(missing?.textContent).toContain("原文正文不会被记录");
    expect(queryButton("设置", panel())).toBeNull();
    await click(button("设置口令", missing!));
    expect(onAction).toHaveBeenCalledWith("set");

    expect(agentSwitch().disabled).toBe(true);
    expect(agentSwitch().getAttribute("aria-checked")).toBe("false");
    expect(panel().textContent).toContain("请先设置原文口令");
  });

  it("leaves the agent toggle to pages that pass it", async () => {
    await renderPanel({ onAgentAccessChange: undefined });
    expect(panel().querySelector('[role="switch"]')).toBeNull();
  });

  it("shows a status failure instead of the hint", async () => {
    await renderPanel({ error: "offline", status: null });
    expect(panel().textContent).toContain("无法读取原文口令状态：offline");
    expect(
      panel().querySelector('[data-slot="raw-password-state"]')?.textContent,
    ).toBe("未知");
    expect(agentSwitch().disabled).toBe(false);
  });
});

describe("RawSealingDialogs", () => {
  const onClose = vi.fn();
  const onStatus = vi.fn();

  function Harness({
    initialDialog,
    initialStatus,
  }: {
    initialDialog: RawDialog;
    initialStatus: RawSealingState;
  }) {
    const [current, setCurrent] = useState<RawDialog | null>(initialDialog);
    const [status, setStatus] = useState(initialStatus);
    return (
      <RawSealingDialogs
        dialog={current}
        onClose={(done) => {
          onClose(done);
          setCurrent(null);
        }}
        onStatus={(next) => {
          onStatus(next);
          setStatus(next);
        }}
        status={status}
      />
    );
  }

  async function renderDialogs(dialogKind: RawDialog, status: RawSealingState) {
    await act(async () =>
      root.render(
        <Harness initialDialog={dialogKind} initialStatus={status} />,
      ),
    );
    await act(async () => {});
  }

  beforeEach(() => {
    onClose.mockReset();
    onStatus.mockReset();
  });

  it("sets a first password without a proof and clears it after submit", async () => {
    mocks.setRawPassword.mockResolvedValue(sealed());
    await renderDialogs({ kind: "set" }, unconfigured);

    expect(dialog()?.textContent).toContain("设置原文口令");
    expect(proofPasswordInput()).toBeNull();
    const submit = button("设置口令", dialog()!);
    expect(submit.disabled).toBe(true);

    await typeNewPassword("short");
    expect(submit.disabled).toBe(true);
    await typeNewPassword("correct horse", "correct horsf");
    expect(dialog()?.textContent).toContain("两次输入的口令不一致");
    expect(submit.disabled).toBe(true);

    await typeNewPassword("correct horse");
    expect(submit.disabled).toBe(false);
    await click(submit);

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "set",
      "correct horse",
      undefined,
    );
    expect(onStatus).toHaveBeenCalledWith(
      expect.objectContaining({ configured: true, presence_available: false }),
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith("已设置原文口令");
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("keeps the dialog open and empties the fields when setting fails", async () => {
    mocks.setRawPassword.mockRejectedValue(
      new Error(
        'POST /v1/raw-sealing/password returned 409 Conflict: {"error":{"code":"raw_password_already_set"}}',
      ),
    );
    await renderDialogs({ kind: "set" }, unconfigured);

    await typeNewPassword("correct horse battery");
    await click(button("设置口令", dialog()!));

    expect(dialog()?.textContent).toContain("原文口令已经设置");
    expect(newPasswordInputs().map((input) => input.value)).toEqual(["", ""]);
    expect(onClose).not.toHaveBeenCalled();
    expect(mocks.toastSuccess).not.toHaveBeenCalled();
  });

  it("adds a password to a keychain key behind the presence prompt", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({ local_presence: true, envelopes: ["local", "password"] }),
    );
    await renderDialogs(
      { kind: "set" },
      sealing({
        password_set: false,
        envelopes: ["local"],
        local_presence: true,
        presence_available: true,
      }),
    );

    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    expect(dialog()?.textContent).toContain("设置时需用 Touch ID 确认");
    expect(dialog()?.querySelector('[data-slot="raw-replace-key"]')).toBeNull();
    await typeNewPassword("correct horse");
    await click(button("设置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledWith("set", "correct horse", {
      kind: "local_presence",
    });
    expect(onStatus).toHaveBeenCalledWith(
      expect.objectContaining({ password_set: true, presence_available: true }),
    );
    expect(onClose).toHaveBeenCalledWith(true);
  });

  it("replaces a keychain key nothing here opens only after a destructive confirmation", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({}, { deleted_parts: 2, affected_records: 1 }),
    );
    // The keychain entry is gone: the local envelope no longer opens.
    await renderDialogs(
      { kind: "set" },
      sealing({ password_set: false, envelopes: ["local"] }),
    );

    const warning = dialog()?.querySelector('[data-slot="raw-replace-key"]');
    expect(warning?.textContent).toContain("已无法打开");
    expect(warning?.textContent).toContain("升级前记录的原文会被丢弃");
    expect(newPasswordInputs()).toHaveLength(0);
    await click(button("重置原文密钥", dialog()!));
    expect(mocks.setRawPassword).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
    expect(confirmDialog()?.textContent).toContain("重置原文密钥？");
    expect(confirmDialog()?.textContent).toContain("永久丢弃");
    expect(confirmDialog()?.textContent).not.toContain("Touch ID");

    await click(button("取消", confirmDialog()!));
    expect(confirmDialog()).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
    await click(button("重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));

    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).toBeNull();
    await typeNewPassword("correct horse");
    await click(button("重置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "correct horse",
      undefined,
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "已重置原文口令，删除了 1 条记录中的 2 份原文。",
    );
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("replaces a keychain key on request behind the destructive confirmation and Touch ID", async () => {
    mocks.setRawPassword.mockResolvedValue(sealed());
    await renderDialogs({ kind: "set" }, keychainOnly);

    await click(button("不保留升级前的原文？重置原文密钥", dialog()!));
    expect(mocks.setRawPassword).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
    expect(confirmDialog()?.textContent).toContain("重置原文密钥？");
    expect(confirmDialog()?.textContent).toContain(
      "升级前记录的原文会被永久丢弃",
    );
    expect(confirmDialog()?.textContent).toContain(
      "重置时仍需用 Touch ID 或 Mac 登录密码确认",
    );
    // Cancelling goes back to setting a password on the key.
    await click(button("取消", confirmDialog()!));
    expect(dialog()?.textContent).toContain("设置时需用 Touch ID 确认");
    expect(button("设置口令", dialog()!)).toBeTruthy();

    await click(button("不保留升级前的原文？重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));
    expect(
      dialog()?.querySelector('[data-slot="raw-replace-key"]')?.textContent,
    ).toContain("重置会生成新的原文密钥");
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    // Back, and forward again, without resetting anything.
    await click(button("返回", dialog()!));
    expect(button("设置口令", dialog()!)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
    await click(button("不保留升级前的原文？重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));

    await typeNewPassword("correct horse");
    await click(button("重置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "correct horse",
      { kind: "local_presence" },
    );
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("keeps asking for Touch ID when the host cannot show it right now", async () => {
    mocks.setRawPassword
      .mockResolvedValueOnce({ outcome: "presence_unsupported" })
      .mockResolvedValueOnce(
        sealed({ local_presence: true, envelopes: ["local", "password"] }),
      );
    await renderDialogs(
      { kind: "set" },
      sealing({
        password_set: false,
        envelopes: ["local"],
        local_presence: true,
        presence_available: false,
      }),
    );

    // Nothing switches to a reset on its own: the key and what it sealed
    // stay, and asking again is the retry.
    expect(dialog()?.querySelector('[data-slot="raw-replace-key"]')).toBeNull();
    expect(
      dialog()?.querySelector('[data-slot="raw-presence-unavailable"]')
        ?.textContent,
    ).toContain("升级前记录的原文不会丢失");
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    await typeNewPassword("correct horse");
    await click(button("设置口令", dialog()!));
    expect(dialog()?.textContent).toContain("此设备暂时无法使用 Touch ID 验证");
    expect(onClose).not.toHaveBeenCalled();

    await typeNewPassword("correct horse");
    await click(button("设置口令", dialog()!));
    expect(mocks.setRawPassword.mock.calls).toEqual([
      ["set", "correct horse", { kind: "local_presence" }],
      ["set", "correct horse", { kind: "local_presence" }],
    ]);
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("changes the password with the current one as proof", async () => {
    mocks.setRawPassword
      .mockResolvedValueOnce({ outcome: "password_invalid" })
      .mockResolvedValueOnce(sealed());
    await renderDialogs({ kind: "change" }, sealing());

    expect(dialog()?.textContent).toContain("当前口令");
    await type(proofPasswordInput()!, "wrong password");
    await typeNewPassword("new passphrase");
    await click(button("修改口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenLastCalledWith(
      "change",
      "new passphrase",
      { kind: "password", password: "wrong password" },
    );
    expect(dialog()?.textContent).toContain("原文口令不正确");
    expect(proofPasswordInput()?.value).toBe("");
    expect(newPasswordInputs().map((input) => input.value)).toEqual(["", ""]);
    expect(onClose).not.toHaveBeenCalled();

    await type(proofPasswordInput()!, "old password");
    await typeNewPassword("new passphrase");
    await click(button("修改口令", dialog()!));
    expect(mocks.setRawPassword).toHaveBeenLastCalledWith(
      "change",
      "new passphrase",
      { kind: "password", password: "old password" },
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith("已修改原文口令");
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("resets behind a destructive confirmation, then sets a new password", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({}, { deleted_parts: 6, affected_records: 3 }),
    );
    await renderDialogs({ kind: "reset" }, sealing());

    expect(dialog()).toBeNull();
    expect(document.body.textContent).toContain("重置原文口令？");
    await click(button("重置并删除原文"));
    expect(mocks.setRawPassword).not.toHaveBeenCalled();

    expect(dialog()?.textContent).toContain("设置新的原文口令");
    expect(proofPasswordInput()).toBeNull();
    await typeNewPassword("fresh passphrase");
    await click(button("重置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "fresh passphrase",
      undefined,
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "已重置原文口令，删除了 3 条记录中的 6 份原文。",
    );
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("resets a keychain key only together with a new password (D11)", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed(
        { envelopes: ["password", "local"] },
        { deleted_parts: 1, affected_records: 1 },
      ),
    );
    await renderDialogs({ kind: "reset" }, keychainOnly);

    await click(button("重置并删除原文"));
    expect(mocks.setRawPassword).not.toHaveBeenCalled();
    expect(dialog()?.textContent).toContain("设置新的原文口令");
    // The local envelope opens this key, so Core wants its proof.
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    await typeNewPassword("fresh passphrase");
    await click(button("重置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "fresh passphrase",
      { kind: "local_presence" },
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "已重置原文口令，删除了 1 条记录中的 1 份原文。",
    );
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("counts the deleted parts and records in English", async () => {
    await applyLocale("en");
    mocks.setRawPassword
      .mockResolvedValueOnce(
        sealed(
          { password_set: false, envelopes: ["local"] },
          { deleted_parts: 1, affected_records: 1 },
        ),
      )
      .mockResolvedValueOnce(
        sealed(
          { password_set: false, envelopes: ["local"] },
          { deleted_parts: 6, affected_records: 3 },
        ),
      );
    const keychainKey = sealing({
      envelopes: ["local", "password"],
      local_presence: true,
      presence_available: true,
    });

    const reset = async () => {
      await renderDialogs({ kind: "reset" }, keychainKey);
      await click(button(i18n.t("rawSealing.resetConfirm")));
      await typeNewPassword("fresh passphrase");
      await click(button(i18n.t("rawSealing.resetAction"), dialog()!));
    };

    await reset();
    expect(mocks.toastSuccess).toHaveBeenLastCalledWith(
      "Raw password reset. Deleted 1 raw part from 1 record.",
    );

    await act(async () => root.unmount());
    root = createRoot(container);
    await reset();
    expect(mocks.toastSuccess).toHaveBeenLastCalledWith(
      "Raw password reset. Deleted 6 raw parts from 3 records.",
    );
  });

  it("resets a password key with the current password where Touch ID is unavailable", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({}, { deleted_parts: 1, affected_records: 1 }),
    );
    await renderDialogs(
      { kind: "reset" },
      sealing({ envelopes: ["local", "password"], local_presence: true }),
    );

    await click(button("重置并删除原文"));
    expect(dialog()?.textContent).toContain("当前口令");
    await type(proofPasswordInput()!, "old passphrase");
    await typeNewPassword("fresh passphrase");
    await click(button("重置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "fresh passphrase",
      { kind: "password", password: "old passphrase" },
    );
  });

  it("closes without a change when the reset is cancelled", async () => {
    await renderDialogs({ kind: "reset" }, sealing());
    await click(button("取消"));
    expect(mocks.setRawPassword).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledExactlyOnceWith(false);
  });

  it("unlocks with the raw password and names the idle lock", async () => {
    mocks.unlockRaw.mockResolvedValue(sealed({ unlocked: true }));
    await renderDialogs({ kind: "unlock" }, sealing());

    expect(dialog()?.textContent).toContain("15 分钟无操作会自动锁定");
    expect(newPasswordInputs()).toHaveLength(0);
    await type(proofPasswordInput()!, "correct horse");
    await click(button("解锁", dialog()!));

    expect(mocks.unlockRaw).toHaveBeenCalledExactlyOnceWith({
      kind: "password",
      password: "correct horse",
    });
    expect(onStatus).toHaveBeenCalledWith(
      expect.objectContaining({ unlocked: true }),
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith("原文已解锁");
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("refuses to unlock with a bare confirmation", async () => {
    await renderDialogs(
      { kind: "unlock" },
      sealing({ password_set: false, envelopes: ["local"] }),
    );

    await click(button("解锁", dialog()!));

    expect(mocks.unlockRaw).not.toHaveBeenCalled();
    expect(dialog()?.textContent).toContain("尚未设置原文口令，无法解锁原文");
    expect(onClose).not.toHaveBeenCalled();
  });

  it("sets the password that turning on capture needs without its own toast", async () => {
    mocks.setRawPassword.mockResolvedValue(sealed());
    await renderDialogs({ kind: "capture" }, unconfigured);

    expect(dialog()?.textContent).toContain("确认开启正文捕获");
    expect(dialog()?.textContent).toContain("开启前需要设置原文口令");
    await typeNewPassword("correct horse");
    await click(button("确认开启", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "set",
      "correct horse",
      undefined,
    );
    expect(mocks.toastSuccess).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("asks a signed Mac for a password before turning on capture", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({ local_presence: true, envelopes: ["password", "local"] }),
    );
    await renderDialogs({ kind: "capture" }, keychainOnly);

    expect(dialog()?.textContent).toContain("开启前需要设置原文口令");
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    expect(button("确认开启", dialog()!).disabled).toBe(true);
    await typeNewPassword("correct horse");
    await click(button("确认开启", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "set",
      "correct horse",
      { kind: "local_presence" },
    );
    expect(onClose).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("reports a cancelled capture confirmation", async () => {
    await renderDialogs({ kind: "capture" }, unconfigured);
    await typeNewPassword("correct horse");
    await click(button("取消", dialog()!));
    expect(mocks.setRawPassword).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledExactlyOnceWith(false);
  });
});

describe("RawPasswordGate", () => {
  function Gate({
    initialStatus,
    suspended = false,
  }: {
    initialStatus: RawSealingState | null;
    suspended?: boolean;
  }) {
    const [status, setStatus] = useState(initialStatus);
    return (
      <RawPasswordGate
        onStatus={setStatus}
        status={status}
        suspended={suspended}
      />
    );
  }

  async function renderGate(
    initialStatus: RawSealingState | null,
    suspended = false,
  ) {
    await act(async () =>
      root.render(<Gate initialStatus={initialStatus} suspended={suspended} />),
    );
    await act(async () => {});
  }

  it("keeps asking for a password until one is set", async () => {
    mocks.setRawPassword.mockResolvedValue(sealed());
    await renderGate(unconfigured);

    expect(dialog()?.textContent).toContain("设置原文口令后继续");
    expect(dialog()?.textContent).toContain("设置前不会记录请求和响应的原文");
    expect(dialog()?.textContent).toContain("忘记后只能重置");
    expect(queryButton("取消", dialog()!)).toBeNull();
    await act(async () => {
      document.activeElement?.dispatchEvent(
        new KeyboardEvent("keydown", { bubbles: true, key: "Escape" }),
      );
    });
    await act(async () => {
      document
        .querySelector('[data-slot="alert-dialog-overlay"]')
        ?.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true }));
    });
    expect(dialog()).not.toBeNull();

    await typeNewPassword("correct horse");
    await click(button("设置口令", dialog()!));

    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "set",
      "correct horse",
      undefined,
    );
    expect(mocks.toastSuccess).toHaveBeenCalledWith("已设置原文口令");
    expect(dialog()).toBeNull();
  });

  it("stays up after a failed attempt", async () => {
    mocks.setRawPassword.mockRejectedValue(new Error("Core is offline"));
    await renderGate(keychainOnly);

    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).not.toBe(
      null,
    );
    await typeNewPassword("correct horse");
    await click(button("设置口令", dialog()!));

    expect(dialog()?.textContent).toContain("Core is offline");
    expect(queryButton("取消", dialog()!)).toBeNull();
  });

  it("keeps the gate up on the way to replacing a keychain key", async () => {
    mocks.setRawPassword.mockResolvedValue(sealed());
    await renderGate(keychainOnly);

    await click(button("不保留升级前的原文？重置原文密钥", dialog()!));
    await click(button("取消", confirmDialog()!));
    expect(dialog()?.textContent).toContain("设置原文口令后继续");
    expect(queryButton("取消", dialog()!)).toBeNull();

    await click(button("不保留升级前的原文？重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));
    await click(button("返回", dialog()!));
    expect(dialog()?.textContent).toContain("设置原文口令后继续");
    expect(mocks.setRawPassword).not.toHaveBeenCalled();

    await click(button("不保留升级前的原文？重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));
    await typeNewPassword("correct horse");
    await click(button("重置口令", dialog()!));
    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "correct horse",
      { kind: "local_presence" },
    );
    expect(dialog()).toBeNull();
    expect(confirmDialog()).toBeNull();
  });

  /** A key an offline `astrlink-core raw-password` reset while the app was closed. */
  const replacedKey = sealing({ key_replaced: true });

  it("warns about a key replaced outside the desktop until its password confirms it", async () => {
    mocks.acknowledgeRawKey
      .mockResolvedValueOnce({ outcome: "password_invalid" })
      .mockResolvedValueOnce(sealed());
    // A build without the keychain has no presence check to add.
    await renderGate(replacedKey);

    expect(dialog()?.textContent).toContain("原文密钥在 AstrLink 之外被更换");
    expect(
      dialog()?.querySelector('[data-slot="raw-key-replaced"]')?.textContent,
    ).toContain("设置它的人可能读得到");
    expect(dialog()?.textContent).toContain("astrlink-core raw-password");
    expect(dialog()?.textContent).toContain("确认不会解锁原文");
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).toBeNull();
    expect(
      dialog()?.querySelector('[data-slot="raw-acknowledge-presence"]'),
    ).toBeNull();
    expect(queryButton("取消", dialog()!)).toBeNull();
    await act(async () => {
      document.activeElement?.dispatchEvent(
        new KeyboardEvent("keydown", { bubbles: true, key: "Escape" }),
      );
    });
    expect(dialog()).not.toBeNull();

    await type(proofPasswordInput()!, "wrong passphrase");
    await click(button("确认是我设置的", dialog()!));
    expect(dialog()?.textContent).toContain("原文密钥在 AstrLink 之外被更换");

    await type(proofPasswordInput()!, "terminal passphrase");
    await click(button("确认是我设置的", dialog()!));
    expect(mocks.acknowledgeRawKey).toHaveBeenLastCalledWith(
      "terminal passphrase",
    );
    expect(mocks.acknowledgeRawKey).toHaveBeenCalledTimes(2);
    expect(mocks.setRawPassword).not.toHaveBeenCalled();
    expect(mocks.unlockRaw).not.toHaveBeenCalled();
    expect(mocks.toastSuccess).toHaveBeenCalledWith("已确认新的原文密钥");
    expect(dialog()).toBeNull();
  });

  it("asks a keychain build for the password and the presence check together", async () => {
    mocks.acknowledgeRawKey
      .mockResolvedValueOnce({ outcome: "presence_cancelled" })
      .mockResolvedValueOnce(sealed());
    await renderGate(
      sealing({
        key_replaced: true,
        keychain_build: true,
        envelopes: ["password", "local"],
        local_presence: true,
        presence_available: true,
      }),
    );

    // Touch ID works here, yet it never stands in for the password: the
    // dialog asks for the password and says the host checks presence too.
    expect(dialog()?.querySelector('[data-slot="proof-presence"]')).toBeNull();
    expect(proofPasswordInput()).not.toBeNull();
    expect(
      dialog()?.querySelector('[data-slot="raw-acknowledge-presence"]')
        ?.textContent,
    ).toContain("Touch ID");
    expect(button("确认是我设置的", dialog()!).disabled).toBe(true);

    // A cancelled prompt keeps the warning up for another attempt.
    await type(proofPasswordInput()!, "terminal passphrase");
    await click(button("确认是我设置的", dialog()!));
    expect(dialog()?.textContent).toContain("已取消验证，可以再试一次。");
    expect(mocks.toastSuccess).not.toHaveBeenCalled();

    await type(proofPasswordInput()!, "terminal passphrase");
    await click(button("确认是我设置的", dialog()!));
    expect(mocks.acknowledgeRawKey).toHaveBeenCalledTimes(2);
    expect(mocks.acknowledgeRawKey).toHaveBeenLastCalledWith(
      "terminal passphrase",
    );
    expect(mocks.unlockRaw).not.toHaveBeenCalled();
    expect(mocks.toastSuccess).toHaveBeenCalledWith("已确认新的原文密钥");
    expect(dialog()).toBeNull();
  });

  it("leaves only a reset where a keychain build cannot check presence", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({}, { deleted_parts: 2, affected_records: 1 }),
    );
    await renderGate(sealing({ key_replaced: true, keychain_build: true }));

    expect(dialog()?.textContent).toContain("原文密钥在 AstrLink 之外被更换");
    expect(
      dialog()?.querySelector('[data-slot="raw-acknowledge-unavailable"]')
        ?.textContent,
    ).toContain("只凭口令不能在这里确认这把密钥");
    // No password field and no way to accept the key: the only action is
    // the destructive reset, and the warning cannot be dismissed.
    expect(proofPasswordInput()).toBeNull();
    expect(queryButton("确认是我设置的", dialog()!)).toBeNull();
    expect(queryButton("取消", dialog()!)).toBeNull();

    await click(button("重置原文密钥", dialog()!));
    expect(confirmDialog()?.textContent).toContain("重置原文口令？");
    await click(button("取消", confirmDialog()!));
    expect(
      dialog()?.querySelector('[data-slot="raw-acknowledge-unavailable"]'),
    ).not.toBeNull();

    await click(button("重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));
    await typeNewPassword("fresh passphrase");
    await click(button("重置口令", dialog()!));
    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "fresh passphrase",
      undefined,
    );
    expect(mocks.acknowledgeRawKey).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
  });

  it("resets a replaced key behind the destructive confirmation", async () => {
    mocks.setRawPassword.mockResolvedValue(
      sealed({}, { deleted_parts: 2, affected_records: 1 }),
    );
    await renderGate(replacedKey);

    await click(button("不是你设置的？重置原文密钥", dialog()!));
    expect(confirmDialog()?.textContent).toContain("重置原文口令？");
    await click(button("取消", confirmDialog()!));
    expect(dialog()?.textContent).toContain("原文密钥在 AstrLink 之外被更换");

    await click(button("不是你设置的？重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));
    expect(dialog()?.textContent).toContain("设置新的原文口令");
    await click(button("返回", dialog()!));
    expect(dialog()?.textContent).toContain("原文密钥在 AstrLink 之外被更换");
    expect(mocks.setRawPassword).not.toHaveBeenCalled();

    await click(button("不是你设置的？重置原文密钥", dialog()!));
    await click(button("重置并删除原文", confirmDialog()!));
    // Nothing here opens the replaced key, so a confirmation is the proof.
    expect(proofPasswordInput()).toBeNull();
    await typeNewPassword("fresh passphrase");
    await click(button("重置口令", dialog()!));
    expect(mocks.setRawPassword).toHaveBeenCalledExactlyOnceWith(
      "reset",
      "fresh passphrase",
      undefined,
    );
    expect(mocks.acknowledgeRawKey).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
    expect(confirmDialog()).toBeNull();
  });

  it("stays away once a password is set, while suspended, or unknown", async () => {
    await renderGate(sealing());
    expect(dialog()).toBeNull();

    await renderGate(null);
    expect(dialog()).toBeNull();

    await act(async () => root.unmount());
    root = createRoot(container);
    await renderGate(unconfigured, true);
    expect(dialog()).toBeNull();

    await act(async () => root.unmount());
    root = createRoot(container);
    await renderGate(replacedKey, true);
    expect(dialog()).toBeNull();
  });
});
