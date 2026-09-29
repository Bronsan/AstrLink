// @vitest-environment happy-dom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const bridge = vi.hoisted(() => ({
  getAgentDebugStatus: vi.fn(),
  installAgentDebug: vi.fn(),
  uninstallAgentDebug: vi.fn(),
}));
vi.mock("./bridge", () => bridge);

const notifyMocks = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
  warning: vi.fn(),
}));
vi.mock("./notify", () => ({ notify: notifyMocks }));

import { applyLocale } from "./i18n";
import { AgentDebugSettings } from "./AgentDebugSettings";

const status = {
  canonical_skill: false,
  cli_binary: false,
  tools: [
    {
      id: "cursor" as const,
      detected: true,
      skill_installed: false,
      cli_access: "prompt" as const,
      cli_access_installed: false,
      guard: "skill_only" as const,
      guard_installed: false,
      preview_paths: ["/tmp/.cursor/skills/astrlink-debug"],
    },
    {
      id: "claude" as const,
      detected: false,
      skill_installed: false,
      cli_access: "allow_rules" as const,
      cli_access_installed: false,
      guard: "deny_rules" as const,
      guard_installed: false,
      preview_paths: [
        "/tmp/.claude/skills/astrlink-debug",
        "/tmp/.claude/settings.json",
      ],
    },
    {
      id: "codex" as const,
      detected: true,
      skill_installed: true,
      cli_access: "exec_policy" as const,
      cli_access_installed: true,
      guard: "instructions" as const,
      guard_installed: true,
      preview_paths: [
        "/tmp/.agents/skills/astrlink-debug",
        "/tmp/.codex/rules/astrlink.rules",
        "/tmp/.codex/AGENTS.md",
      ],
    },
    {
      id: "grok" as const,
      detected: true,
      skill_installed: false,
      cli_access: "prompt" as const,
      cli_access_installed: false,
      guard: "skill_only" as const,
      guard_installed: false,
      preview_paths: ["/tmp/.grok/skills/astrlink-debug"],
    },
  ],
  shared_paths: [
    "/tmp/.astrlink/bin/astrlink",
    "/tmp/.astrlink/agent-installs.json",
  ],
};

describe("AgentDebugSettings", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
    bridge.getAgentDebugStatus.mockReset().mockResolvedValue(status);
    bridge.installAgentDebug.mockReset().mockResolvedValue({
      version: 2,
      bundle: "astrlink-debug",
      bundle_version: "0.3.0",
      installed_at_unix: 1,
      cli_binary: "/tmp/.astrlink/bin/astrlink",
      files: status.shared_paths,
    });
    bridge.uninstallAgentDebug.mockReset().mockResolvedValue(undefined);
    notifyMocks.success.mockReset();
    notifyMocks.error.mockReset();
  });

  afterEach(async () => {
    await applyLocale("zh-CN");
    await act(async () => root.unmount());
    container.remove();
  });

  it("shows detected tools and confirms install", async () => {
    await act(async () => {
      root.render(<AgentDebugSettings />);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(container.querySelector("h1")?.textContent).toBe("Agent 工具");
    expect(container.textContent).toContain("工具接入");
    expect(container.textContent).toContain("Cursor");
    expect(
      container.querySelector("[role='img'][aria-label='已检测到']"),
    ).not.toBeNull();
    expect(
      container.querySelector("[role='img'][aria-label='未检测到']"),
    ).not.toBeNull();
    expect(container.textContent).toContain("Codex");
    expect(container.textContent).toContain("已安装");
    expect(container.textContent).toContain("Grok Build");
    expect(container.textContent).toContain("1 / 3");
    expect(container.textContent).toContain(
      "AstrLink 命令行工具缺失，请重新安装后再使用。",
    );

    const install = [...container.querySelectorAll("button")].find(
      (button) => button.textContent === "安装 / 更新",
    );
    if (!install) throw new Error("missing install button");
    await act(async () => {
      install.click();
      await Promise.resolve();
    });
    expect(document.body.textContent).toContain(
      "/tmp/.agents/skills/astrlink-debug",
    );

    const dialog = document.querySelector("[role='alertdialog']");
    const confirm = dialog
      ? [...dialog.querySelectorAll("button")].find(
          (button) => button.textContent === "安装所选工具（1）",
        )
      : undefined;
    if (!confirm) throw new Error("missing confirm");
    await act(async () => {
      confirm.click();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(bridge.installAgentDebug).toHaveBeenCalledWith(["codex"]);
    expect(notifyMocks.success).toHaveBeenCalled();
  });

  it("identifies a missing component and refreshes after repair", async () => {
    const partial = {
      ...status,
      cli_binary: true,
      tools: [{ ...status.tools[2], cli_access_installed: false }],
    };
    bridge.getAgentDebugStatus
      .mockResolvedValueOnce(partial)
      .mockResolvedValue({
        ...partial,
        tools: [{ ...partial.tools[0], cli_access_installed: true }],
      });
    await act(async () => root.render(<AgentDebugSettings />));
    const row = [...container.querySelectorAll("tbody tr")].find((row) =>
      row.textContent?.includes("Codex"),
    );
    expect(row?.querySelectorAll("td")[1]?.textContent).toBe("已安装");
    expect(row?.querySelectorAll("td")[2]?.textContent).toBe("未写入");
    expect(container.textContent).toContain("0 / 1");
    await act(async () => button("安装 / 更新").click());
    await act(async () =>
      button(
        "安装所选工具（1）",
        document.querySelector("[role='alertdialog']")!,
      ).click(),
    );
    expect(bridge.installAgentDebug).toHaveBeenCalledTimes(1);
    expect(button("安装 / 更新").disabled).toBe(false);
    expect(container.textContent).toContain("1 / 1");
  });

  it("reports how each tool may run the CLI", async () => {
    bridge.getAgentDebugStatus.mockResolvedValue({
      ...status,
      cli_binary: true,
      tools: [
        { ...status.tools[0], skill_installed: true },
        { ...status.tools[1], detected: true, cli_access_installed: true },
        status.tools[2],
        { ...status.tools[3], detected: false },
      ],
    });
    await act(async () => root.render(<AgentDebugSettings />));
    const accessCell = (name: string) =>
      [...container.querySelectorAll("tbody tr")]
        .find((row) => row.textContent?.includes(name))
        ?.querySelectorAll("td")[2];
    expect(accessCell("Cursor")?.textContent).toBe("首次询问");
    expect(accessCell("Claude")?.textContent).toBe("已放行");
    expect(accessCell("Codex")?.textContent).toBe("已放行");
    expect(accessCell("Grok")?.textContent).toBe("—");
    expect(container.querySelector("thead")?.textContent).toContain("命令权限");
    // A tool that asks on first run is configured once its skill is there.
    expect(container.textContent).toContain("2 / 3");

    bridge.getAgentDebugStatus.mockResolvedValue({
      ...status,
      tools: [{ ...status.tools[1], detected: true }],
    });
    await act(async () => button("重新检测").click());
    expect(accessCell("Claude")?.textContent).toBe("未写入");
  });

  it("reports each tool's host guard with its strength", async () => {
    bridge.getAgentDebugStatus.mockResolvedValue({
      ...status,
      tools: [
        status.tools[0],
        { ...status.tools[1], detected: true, guard_installed: true },
        status.tools[2],
        { ...status.tools[3], detected: false },
      ],
    });
    await act(async () => root.render(<AgentDebugSettings />));
    const guardCell = (name: string) =>
      [...container.querySelectorAll("tbody tr")]
        .find((row) => row.textContent?.includes(name))
        ?.querySelectorAll("td")[3];
    expect(guardCell("Cursor")?.textContent).toBe("仅 Skill");
    expect(guardCell("Claude")?.textContent).toBe("已拦截");
    expect(guardCell("Codex")?.textContent).toBe("仅提示词");
    expect(guardCell("Grok")?.textContent).toBe("—");
    expect(container.querySelector("thead")?.textContent).toContain("文件访问");

    bridge.getAgentDebugStatus.mockResolvedValue({
      ...status,
      tools: [{ ...status.tools[1], detected: true }],
    });
    await act(async () => button("重新检测").click());
    expect(guardCell("Claude")?.textContent).toBe("未写入");
  });

  it("installs only Grok and previews only its paths and the shared runtime", async () => {
    await act(async () => root.render(<AgentDebugSettings />));
    await act(async () => button("安装 / 更新").click());
    const dialog = document.querySelector("[role='alertdialog']")!;
    expect(checkbox("codex").getAttribute("aria-checked")).toBe("true");
    expect(checkbox("claude").disabled).toBe(true);
    await act(async () => checkbox("codex").click());
    expect(button("安装所选工具（0）", dialog).disabled).toBe(true);
    expect(button("取消", dialog).disabled).toBe(false);
    expect(dialog.querySelector("details")).toBeNull();
    await act(async () => checkbox("grok").click());
    expect(button("安装所选工具（1）", dialog).disabled).toBe(false);
    expect(dialog.textContent).toContain("/tmp/.grok/skills/astrlink-debug");
    expect(dialog.textContent).toContain("/tmp/.astrlink/bin/astrlink");
    expect(dialog.textContent).not.toContain("/tmp/.agents");
    expect(dialog.textContent).not.toContain("/tmp/.codex");
    expect(dialog.textContent).not.toContain("/tmp/.cursor");
    await act(async () => button("安装所选工具（1）", dialog).click());
    expect(bridge.installAgentDebug).toHaveBeenCalledExactlyOnceWith(["grok"]);
  });

  it("requires an explicit first selection and supports multiple tools", async () => {
    bridge.getAgentDebugStatus.mockResolvedValue({
      ...status,
      tools: status.tools.map((tool) => ({
        ...tool,
        skill_installed: false,
        cli_access_installed: false,
      })),
    });
    await act(async () => root.render(<AgentDebugSettings />));
    await act(async () => button("安装工具").click());
    const dialog = document.querySelector("[role='alertdialog']")!;
    expect(button("安装所选工具（0）", dialog).disabled).toBe(true);
    await act(async () => checkbox("cursor").click());
    await act(async () => checkbox("grok").click());
    await act(async () => button("安装所选工具（2）", dialog).click());
    expect(bridge.installAgentDebug).toHaveBeenCalledExactlyOnceWith([
      "cursor",
      "grok",
    ]);
  });

  it("cancels an empty selection without installing", async () => {
    await act(async () => root.render(<AgentDebugSettings />));
    await act(async () => button("安装 / 更新").click());
    await act(async () => checkbox("codex").click());
    await act(async () =>
      button("取消", document.querySelector("[role='alertdialog']")!).click(),
    );
    expect(bridge.installAgentDebug).not.toHaveBeenCalled();
    expect(document.querySelector("[role='alertdialog']")).toBeNull();
  });

  it("offers a retry after status failure and prevents installing without detected tools", async () => {
    bridge.getAgentDebugStatus.mockRejectedValueOnce(
      new Error("Status unavailable"),
    );
    await act(async () => root.render(<AgentDebugSettings />));
    expect(container.querySelector("[role='alert']")?.textContent).toBe(
      "Status unavailable",
    );
    expect(button("安装工具").disabled).toBe(true);
    expect(container.textContent).not.toContain("检查中");
    bridge.getAgentDebugStatus.mockResolvedValue({
      ...status,
      canonical_skill: false,
      cli_binary: false,
      tools: [],
    });
    await act(async () => button("重新检测").click());
    expect(container.querySelector("[role='alert']")).toBeNull();
    expect(container.textContent).toContain("暂未检测到支持的工具");
    expect(button("安装工具").disabled).toBe(true);
  });

  it("copies the diagnostic prompt and keeps uninstall behind confirmation", async () => {
    const copy = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
    await act(async () => root.render(<AgentDebugSettings />));
    await act(async () => button("复制示例").click());
    expect(copy).toHaveBeenCalledWith(
      expect.stringContaining("使用 astrlink-debug"),
    );
    expect(button("已复制")).toBeTruthy();
    await act(async () => button("卸载").click());
    expect(bridge.uninstallAgentDebug).not.toHaveBeenCalled();
    const dialog = document.querySelector("[role='alertdialog']")!;
    await act(async () => button("卸载", dialog).click());
    expect(bridge.uninstallAgentDebug).toHaveBeenCalledTimes(1);
    copy.mockRestore();
  });

  function checkbox(id: string): HTMLButtonElement {
    const found = document.querySelector<HTMLButtonElement>(
      `#agent-install-${id}`,
    );
    if (!found) throw new Error(`Missing checkbox: ${id}`);
    return found;
  }

  function button(
    text: string,
    scope: ParentNode = container,
  ): HTMLButtonElement {
    const found = [...scope.querySelectorAll("button")].find(
      (item) => item.textContent === text,
    );
    if (!found) throw new Error(`Missing button: ${text}`);
    return found;
  }
});
