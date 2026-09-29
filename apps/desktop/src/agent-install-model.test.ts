import { describe, expect, it } from "vitest";

import {
  parseAgentInstallReceipt,
  parseAgentInstallStatus,
} from "./agent-install-model";

const status = {
  canonical_skill: true,
  cli_binary: true,
  tools: [
    {
      id: "codex",
      detected: true,
      skill_installed: true,
      cli_access: "exec_policy",
      cli_access_installed: false,
      guard: "instructions",
      guard_installed: false,
      preview_paths: [
        "/tmp/.agents/skills/astrlink-debug",
        "/tmp/.codex/rules/astrlink.rules",
        "/tmp/.codex/AGENTS.md",
      ],
    },
  ],
  shared_paths: ["/tmp/.astrlink/bin/astrlink"],
};

describe("agent-install-model", () => {
  it("parses a status snapshot", () => {
    expect(parseAgentInstallStatus(status).tools[0]?.id).toBe("codex");
  });

  it("rejects unexpected fields", () => {
    expect(() => parseAgentInstallStatus({ ...status, extra: true })).toThrow(
      /unexpected field/,
    );
  });

  it("validates shared and per-tool installation paths", () => {
    expect(parseAgentInstallStatus(status).tools[0]?.preview_paths).toEqual(
      status.tools[0].preview_paths,
    );
    expect(() =>
      parseAgentInstallStatus({ ...status, shared_paths: [null] }),
    ).toThrow(/shared_paths/);
    expect(() =>
      parseAgentInstallStatus({
        ...status,
        tools: [{ ...status.tools[0], preview_paths: "not an array" }],
      }),
    ).toThrow(/preview_paths/);
  });

  it("validates the CLI access fields", () => {
    expect(parseAgentInstallStatus(status).tools[0]?.cli_access).toBe(
      "exec_policy",
    );
    expect(() =>
      parseAgentInstallStatus({
        ...status,
        tools: [{ ...status.tools[0], cli_access: "mcp" }],
      }),
    ).toThrow(/cli_access/);
    expect(() =>
      parseAgentInstallStatus({
        ...status,
        tools: [{ ...status.tools[0], cli_access_installed: 1 }],
      }),
    ).toThrow(/cli_access_installed/);
    // A status from the MCP-based installer is rejected, not half-read.
    const {
      cli_access: _access,
      cli_access_installed: _installed,
      ...current
    } = status.tools[0];
    expect(() =>
      parseAgentInstallStatus({
        ...status,
        tools: [{ ...current, mcp_installed: true }],
      }),
    ).toThrow(/unexpected field/);
  });

  it("validates the host guard fields", () => {
    expect(parseAgentInstallStatus(status).tools[0]?.guard).toBe(
      "instructions",
    );
    expect(() =>
      parseAgentInstallStatus({
        ...status,
        tools: [{ ...status.tools[0], guard: "sandbox" }],
      }),
    ).toThrow(/guard/);
    expect(() =>
      parseAgentInstallStatus({
        ...status,
        tools: [{ ...status.tools[0], guard_installed: "yes" }],
      }),
    ).toThrow(/guard_installed/);
    const { guard: _guard, ...legacy } = status.tools[0];
    expect(() =>
      parseAgentInstallStatus({ ...status, tools: [legacy] }),
    ).toThrow(/missing field/);
  });

  it("parses an install receipt", () => {
    const receipt = parseAgentInstallReceipt({
      version: 2,
      bundle: "astrlink-debug",
      bundle_version: "0.3.0",
      installed_at_unix: 1,
      cli_binary: "/tmp/.astrlink/bin/astrlink",
      files: ["/tmp/a"],
    });
    expect(receipt.bundle).toBe("astrlink-debug");
  });
});
