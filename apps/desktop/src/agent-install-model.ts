export type AgentToolId = "cursor" | "claude" | "codex" | "grok";

/**
 * How the host is kept away from AstrLink's local files: enforced deny rules
 * (Claude Code), prompt-only global instructions (Codex), or the skill text
 * alone (hosts without a verified mechanism).
 */
export type AgentGuardKind = "deny_rules" | "instructions" | "skill_only";

/**
 * How the host lets agents run the AstrLink CLI without asking each time:
 * allow rules (Claude Code), a rules file that also lifts the sandbox (Codex),
 * or a prompt on first use (hosts without a verified mechanism).
 */
export type AgentCliAccessKind = "allow_rules" | "exec_policy" | "prompt";

export interface AgentToolStatus {
  id: AgentToolId;
  detected: boolean;
  skill_installed: boolean;
  cli_access: AgentCliAccessKind;
  cli_access_installed: boolean;
  guard: AgentGuardKind;
  guard_installed: boolean;
  preview_paths: string[];
}

export interface AgentInstallStatus {
  canonical_skill: boolean;
  cli_binary: boolean;
  tools: AgentToolStatus[];
  shared_paths: string[];
}

export interface AgentInstallReceipt {
  version: number;
  bundle: string;
  bundle_version: string;
  installed_at_unix: number;
  cli_binary: string;
  files: string[];
}

const TOOL_IDS: readonly AgentToolId[] = ["cursor", "claude", "codex", "grok"];
const GUARD_KINDS: readonly AgentGuardKind[] = [
  "deny_rules",
  "instructions",
  "skill_only",
];
const CLI_ACCESS_KINDS: readonly AgentCliAccessKind[] = [
  "allow_rules",
  "exec_policy",
  "prompt",
];

function invalid(path: string, detail: string): never {
  throw new Error(`Invalid AstrLink agent-install IPC at ${path}: ${detail}`);
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid(path, "expected an object");
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  path: string,
): void {
  const keys = new Set(expected);
  for (const key of Object.keys(value)) {
    if (!keys.has(key)) invalid(`${path}.${key}`, "unexpected field");
  }
  for (const key of expected) {
    if (!Object.hasOwn(value, key)) invalid(`${path}.${key}`, "missing field");
  }
}

function boundedString(value: unknown, path: string, max = 4096): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    return invalid(path, "expected a bounded non-empty string");
  }
  return value;
}

function booleanAt(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") invalid(path, "expected a boolean");
  return value;
}

function parseTool(value: unknown, path: string): AgentToolStatus {
  const root = objectAt(value, path);
  exactKeys(
    root,
    [
      "id",
      "detected",
      "skill_installed",
      "cli_access",
      "cli_access_installed",
      "guard",
      "guard_installed",
      "preview_paths",
    ],
    path,
  );
  if (!TOOL_IDS.includes(root.id as AgentToolId)) {
    invalid(`${path}.id`, "unknown tool");
  }
  if (!CLI_ACCESS_KINDS.includes(root.cli_access as AgentCliAccessKind)) {
    invalid(`${path}.cli_access`, "unknown CLI access kind");
  }
  if (!GUARD_KINDS.includes(root.guard as AgentGuardKind)) {
    invalid(`${path}.guard`, "unknown guard kind");
  }
  return {
    id: root.id as AgentToolId,
    detected: booleanAt(root.detected, `${path}.detected`),
    skill_installed: booleanAt(root.skill_installed, `${path}.skill_installed`),
    cli_access: root.cli_access as AgentCliAccessKind,
    cli_access_installed: booleanAt(
      root.cli_access_installed,
      `${path}.cli_access_installed`,
    ),
    guard: root.guard as AgentGuardKind,
    guard_installed: booleanAt(root.guard_installed, `${path}.guard_installed`),
    preview_paths: parsePaths(root.preview_paths, `${path}.preview_paths`),
  };
}

function parsePaths(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) invalid(path, "expected an array");
  return value.map((item, index) =>
    boundedString(item, `${path}[${index}]`, 8192),
  );
}

export function parseAgentInstallStatus(value: unknown): AgentInstallStatus {
  const root = objectAt(value, "$");
  exactKeys(
    root,
    ["canonical_skill", "cli_binary", "tools", "shared_paths"],
    "$",
  );
  if (!Array.isArray(root.tools)) invalid("$.tools", "expected an array");
  return {
    canonical_skill: booleanAt(root.canonical_skill, "$.canonical_skill"),
    cli_binary: booleanAt(root.cli_binary, "$.cli_binary"),
    tools: root.tools.map((tool, index) =>
      parseTool(tool, `$.tools[${index}]`),
    ),
    shared_paths: parsePaths(root.shared_paths, "$.shared_paths"),
  };
}

export function parseAgentInstallReceipt(value: unknown): AgentInstallReceipt {
  const root = objectAt(value, "$");
  exactKeys(
    root,
    [
      "version",
      "bundle",
      "bundle_version",
      "installed_at_unix",
      "cli_binary",
      "files",
    ],
    "$",
  );
  if (!Array.isArray(root.files)) invalid("$.files", "expected an array");
  if (typeof root.version !== "number" || !Number.isInteger(root.version)) {
    invalid("$.version", "expected an integer");
  }
  if (
    typeof root.installed_at_unix !== "number" ||
    !Number.isFinite(root.installed_at_unix)
  ) {
    invalid("$.installed_at_unix", "expected a number");
  }
  return {
    version: root.version,
    bundle: boundedString(root.bundle, "$.bundle"),
    bundle_version: boundedString(root.bundle_version, "$.bundle_version"),
    installed_at_unix: root.installed_at_unix,
    cli_binary: boundedString(root.cli_binary, "$.cli_binary", 8192),
    files: root.files.map((path, index) =>
      boundedString(path, `$.files[${index}]`, 8192),
    ),
  };
}

export function toolLabelKey(
  id: AgentToolId,
): "cursor" | "claude" | "codex" | "grok" {
  return id;
}
