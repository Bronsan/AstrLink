import { describe, expect, it } from "vitest";

import type { TrajectoryChip } from "./request-trajectory-model";
import { chipDotClass, chipToneClass } from "./trajectory-chip";

const chips: TrajectoryChip[] = [
  "TURN",
  "CLIENT",
  "REDIRECT",
  "POLICY",
  "ROUTE",
  "UPSTREAM",
  "RETRY",
  "RESTORE",
  "RESULT",
];

describe("chipToneClass", () => {
  it("gives the redirect step its own colour in both appearances", () => {
    const solid = chipToneClass("REDIRECT", "ok");
    const subtle = chipToneClass("REDIRECT", "ok", "subtle");

    expect(solid).toBe("bg-accent-foreground text-primary-foreground");
    expect(subtle).toBe("bg-secondary text-accent-foreground");
    for (const chip of chips.filter((item) => item !== "REDIRECT")) {
      expect(chipToneClass(chip, "ok"), chip).not.toBe(solid);
      expect(chipToneClass(chip, "ok", "subtle"), chip).not.toBe(subtle);
    }
  });

  // A redirect is decided before any provider is tried; a later failure
  // belongs to the upstream and result phases, not to the rename.
  it("keeps the redirect step out of the failure and block colours", () => {
    for (const tone of ["failed", "blocked", "cancelled", "pending"] as const) {
      expect(chipToneClass("REDIRECT", tone), tone).toBe(
        chipToneClass("REDIRECT", "ok"),
      );
      expect(chipToneClass("REDIRECT", tone, "subtle"), tone).toBe(
        chipToneClass("REDIRECT", "ok", "subtle"),
      );
    }
    expect(chipToneClass("RESULT", "failed")).toBe(
      "bg-destructive text-destructive-foreground",
    );
  });
});

describe("chipDotClass", () => {
  // Beside a text label a coloured phase reads as a warning, so a healthy
  // call shows one green mark on the delivered result and nothing else.
  it("colours only the delivered result on a healthy call", () => {
    expect(chipDotClass("RESULT", "ok")).toBe("bg-success");
    for (const chip of chips.filter((item) => item !== "RESULT")) {
      expect(chipDotClass(chip, "ok"), chip).toBe("bg-muted-foreground/40");
    }
  });

  it("marks failures and waits only on the phases that carry them", () => {
    expect(chipDotClass("UPSTREAM", "failed")).toBe("bg-destructive");
    expect(chipDotClass("RESULT", "failed")).toBe("bg-destructive");
    expect(chipDotClass("POLICY", "blocked")).toBe("bg-blocked");
    expect(chipDotClass("RESULT", "pending")).toBe("bg-warning");
    expect(chipDotClass("CLIENT", "cancelled")).toBe("bg-warning");
    for (const tone of ["failed", "blocked", "cancelled", "pending"] as const) {
      expect(chipDotClass("REDIRECT", tone), tone).toBe(
        chipDotClass("REDIRECT", "ok"),
      );
    }
  });
});
