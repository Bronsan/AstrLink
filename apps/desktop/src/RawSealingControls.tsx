import { useEffect, useId, useRef, useState, type ReactNode } from "react";

import { CapabilityToggle } from "@/components/CapabilityToggle";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { FormMessage } from "@/components/FormMessage";
import { Panel, PanelHeader } from "@/components/Panel";
import {
  ProofConfirmDialog,
  type ProofInput,
  type ProofMode,
  type ProofResult,
} from "@/components/ProofConfirmDialog";
import { RawPasswordFields } from "@/components/RawPasswordFields";
import { StatusBadge } from "@/components/StatusBadge";
import type { StatusTone } from "@/components/StatusDot";
import { Button } from "@/components/ui/button";

import { setRawPassword, unlockRaw } from "./bridge";
import { i18n, useT } from "./i18n";
import { notify } from "./notify";
import {
  newPasswordIssue,
  presenceUsable,
  rawKeyUnreachable,
  rawPasswordState,
  rawProofMode,
  withPresence,
  type RawPasswordAction,
  type RawSealingOutcome,
  type RawSealingState,
} from "./raw-sealing-model";
import {
  rawProofOf,
  rawSealingErrorMessage,
  refusalResult,
} from "./raw-sealing-ui";

/** A raw sealing dialog the page asks for; `capture` also turns capture on. */
export type RawDialog =
  | { kind: "set" }
  | { kind: "change" }
  | { kind: "reset" }
  | { kind: "unlock" }
  | { kind: "capture" };

/** Minutes before Core locks an idle unlock session, for the copy. */
export function unlockIdleMinutes(status: RawSealingState): number {
  return Math.max(1, Math.round(status.unlock_idle_seconds / 60));
}

/**
 * Capture is on, but raw parts still fall back to the audit key: agents can
 * only ask for raw content once a raw password exists (D11).
 */
export function rawUpgradeNeeded(
  captureEnabled: boolean,
  status: RawSealingState | null,
): boolean {
  return captureEnabled && status !== null && !status.configured;
}

/**
 * The raw password summary in the audit settings: how the raw key opens,
 * the actions on it, and whether agent tools may ask for raw content.
 */
export function RawPasswordPanel({
  agentAccess,
  busy,
  captureEnabled,
  error,
  onAction,
  onAgentAccessChange,
  status,
}: {
  agentAccess: boolean;
  busy: boolean;
  captureEnabled: boolean;
  error: string | null;
  onAction: (action: RawPasswordAction) => void;
  onAgentAccessChange: (enabled: boolean) => void;
  status: RawSealingState | null;
}) {
  const t = useT();
  const titleId = useId();
  const state = status ? rawPasswordState(status) : null;
  const upgrade = rawUpgradeNeeded(captureEnabled, status);
  const unconfigured = status?.configured === false;
  const unreachable = status !== null && rawKeyUnreachable(status);

  const tone: StatusTone =
    state === "password" || state === "keychain_only"
      ? "positive"
      : state === "unset" && captureEnabled
        ? "pending"
        : "neutral";
  const label =
    state === "password"
      ? t("rawSealing.state.password")
      : state === "keychain_only"
        ? t("rawSealing.state.keychainOnly")
        : state === "unset"
          ? t("rawSealing.state.unset")
          : t("rawSealing.state.unknown");
  const hint =
    state === "password"
      ? status && presenceUsable(status)
        ? t("rawSealing.hint.passwordPresence")
        : t("rawSealing.hint.password")
      : state === "keychain_only"
        ? unreachable
          ? t("rawSealing.hint.keychainUnreachable")
          : t("rawSealing.hint.keychainOnly")
        : state === "unset"
          ? t("rawSealing.hint.unset")
          : null;

  const action = (id: RawPasswordAction, text: string, disabled = false) => (
    <Button
      disabled={busy || disabled}
      key={id}
      onClick={() => onAction(id)}
      size="xs"
      type="button"
      variant="outline"
    >
      {text}
    </Button>
  );
  const actions =
    state === "password"
      ? [
          action("change", t("rawSealing.change")),
          action("reset", t("rawSealing.reset")),
        ]
      : state === "keychain_only"
        ? [
            // Adding a password opens the key first; without the presence
            // prompt Core would always refuse.
            action("set", t("rawSealing.set"), unreachable),
            action("reset", t("rawSealing.reset")),
          ]
        : state === "unset" && !upgrade
          ? [action("set", t("rawSealing.set"))]
          : null;

  return (
    <Panel
      aria-labelledby={titleId}
      data-slot="raw-password-panel"
      role="region"
    >
      <PanelHeader actions={actions} size="sm">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold" id={titleId}>
            {t("rawSealing.title")}
          </h3>
          <StatusBadge data-slot="raw-password-state" tone={tone}>
            {label}
          </StatusBadge>
        </div>
      </PanelHeader>
      <div className="grid gap-3 px-3 py-2.5">
        {error ? (
          <FormMessage tone="error">
            {t("rawSealing.loadFailed", { message: error })}
          </FormMessage>
        ) : upgrade ? (
          <FormMessage
            className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5"
            data-slot="raw-upgrade-hint"
            tone="warning"
          >
            <span className="min-w-0">{t("rawSealing.upgradeHint")}</span>
            <Button
              disabled={busy}
              onClick={() => onAction("set")}
              size="xs"
              type="button"
              variant="outline"
            >
              {t("rawSealing.upgradeAction")}
            </Button>
          </FormMessage>
        ) : hint ? (
          <p className="text-xs leading-relaxed text-muted-foreground">
            {hint}
          </p>
        ) : null}
        <CapabilityToggle
          checked={agentAccess && !unconfigured}
          description={
            unconfigured
              ? t("rawSealing.agentAccessNeedsPassword")
              : t("rawSealing.agentAccessHint")
          }
          disabled={busy || unconfigured}
          label={t("rawSealing.agentAccess")}
          onCheckedChange={onAgentAccessChange}
          size="default"
        />
      </div>
    </Panel>
  );
}

/**
 * The dialogs behind the raw password actions and the unlock button. New
 * passwords live only in this component's state and are cleared on every
 * submit and whenever the dialog closes.
 */
export function RawSealingDialogs({
  dialog,
  onClose,
  onStatus,
  status,
}: {
  dialog: RawDialog | null;
  /** `done` is true once the action went through. */
  onClose: (done: boolean) => void;
  onStatus: (next: RawSealingState) => void;
  status: RawSealingState | null;
}) {
  const t = useT();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [resetStep, setResetStep] = useState<"confirm" | "password">("confirm");
  const [resetBusy, setResetBusy] = useState(false);
  const newPasswordRef = useRef<HTMLInputElement>(null);
  const kind = status ? (dialog?.kind ?? null) : null;

  useEffect(() => {
    setPassword("");
    setConfirmation("");
    setResetStep("confirm");
    setResetBusy(false);
  }, [kind]);

  const clearNewPassword = () => {
    setPassword("");
    setConfirmation("");
  };

  const close = (done: boolean) => {
    clearNewPassword();
    onClose(done);
  };

  /** Applies a sealing outcome; true once the action went through. */
  const settle = (
    outcome: RawSealingOutcome,
  ): { done: true } | { done: false; result: ProofResult } => {
    if (outcome.outcome !== "sealing") {
      return { done: false, result: refusalResult(outcome) };
    }
    onStatus(withPresence(outcome.status, status));
    return { done: true };
  };

  const submitPassword = async (
    action: RawPasswordAction,
    input: ProofInput,
  ): Promise<ProofResult> => {
    const next = password;
    // Nothing keeps the new password once it is on its way.
    clearNewPassword();
    let outcome: RawSealingOutcome;
    try {
      outcome = await setRawPassword(action, next, rawProofOf(input));
    } catch (error) {
      return { kind: "error", message: rawSealingErrorMessage(error) };
    }
    const settled = settle(outcome);
    if (!settled.done) return settled.result;
    if (action === "change") {
      notify.success(i18n.t("rawSealing.changed"));
    } else if (action === "reset") {
      notify.success(resetNotice(outcome));
    } else if (kind === "set") {
      notify.success(i18n.t("rawSealing.saved"));
    }
    close(true);
    return { kind: "done" };
  };

  const submitUnlock = async (input: ProofInput): Promise<ProofResult> => {
    const proof = rawProofOf(input);
    if (!proof) {
      return { kind: "error", message: i18n.t("rawSealing.unlockUnavailable") };
    }
    let outcome: RawSealingOutcome;
    try {
      outcome = await unlockRaw(proof);
    } catch (error) {
      return { kind: "error", message: rawSealingErrorMessage(error) };
    }
    const settled = settle(outcome);
    if (!settled.done) return settled.result;
    notify.success(i18n.t("rawSealing.unlocked"));
    close(true);
    return { kind: "done" };
  };

  const resetWithoutPassword = async () => {
    setResetBusy(true);
    try {
      const outcome = await setRawPassword("reset");
      const settled = settle(outcome);
      if (settled.done) {
        notify.success(resetNotice(outcome));
        close(true);
        return;
      }
      notify.error(i18n.t("proofDialog.failed"));
    } catch (error) {
      notify.error(rawSealingErrorMessage(error));
    } finally {
      setResetBusy(false);
    }
    close(false);
  };

  const invalidNew =
    status !== null &&
    newPasswordIssue(password, confirmation, status) !== null;
  const fields = status ? (
    <RawPasswordFields
      confirmation={confirmation}
      inputRef={newPasswordRef}
      onConfirmationChange={setConfirmation}
      onPasswordChange={setPassword}
      password={password}
      policy={status}
    />
  ) : null;

  let proofDialog: ProofDialogCopy | null = null;
  if (status === null || kind === null) {
    proofDialog = null;
  } else if (kind === "capture" || kind === "set") {
    // An unconfigured key needs no proof; adding a password to a keychain
    // key has to open it with a presence check first.
    const unreachable = rawKeyUnreachable(status);
    const proof: ProofMode =
      !status.configured || !presenceUsable(status) ? "confirm" : "presence";
    proofDialog = {
      action:
        kind === "capture"
          ? t("records.confirmEnable")
          : t("rawSealing.setAction"),
      description:
        kind === "capture" ? (
          <>
            <p>{t("records.enableCaptureBody")}</p>
            <p>{t("rawSealing.captureNeedsPassword")}</p>
          </>
        ) : unreachable ? (
          <FormMessage tone="warning">
            {t("rawSealing.hint.keychainUnreachable")}
          </FormMessage>
        ) : (
          <p>
            {status.configured
              ? t("rawSealing.setKeychainDescription")
              : t("rawSealing.setDescription")}
          </p>
        ),
      blocked: unreachable,
      withFields: !unreachable,
      focusNew: !unreachable,
      proof,
      submit: (input) => submitPassword("set", input),
      title:
        kind === "capture"
          ? t("records.enableCaptureTitle")
          : t("rawSealing.setTitle"),
    };
  } else if (kind === "change") {
    const proof = rawProofMode(status);
    proofDialog = {
      action: t("rawSealing.changeAction"),
      description: <p>{t("rawSealing.changeDescription")}</p>,
      withFields: true,
      focusNew: proof !== "password",
      passwordLabel: t("rawSealing.currentPassword"),
      proof,
      submit: (input) => submitPassword("change", input),
      title: t("rawSealing.changeTitle"),
    };
  } else if (kind === "reset" && resetStep === "password") {
    proofDialog = {
      action: t("rawSealing.resetAction"),
      description: <p>{t("rawSealing.resetPasswordDescription")}</p>,
      withFields: true,
      focusNew: true,
      proof: "confirm",
      submit: (input) => submitPassword("reset", input),
      title: t("rawSealing.resetPasswordTitle"),
    };
  } else if (kind === "unlock") {
    proofDialog = {
      action: t("rawSealing.unlock"),
      description: (
        <p>
          {t("rawSealing.unlockDescription", {
            minutes: unlockIdleMinutes(status),
          })}
        </p>
      ),
      focusNew: false,
      proof: rawProofMode(status),
      withFields: false,
      submit: submitUnlock,
      title: t("rawSealing.unlockTitle"),
    };
  }

  const resetConfirmOpen =
    status !== null && kind === "reset" && resetStep === "confirm";
  return (
    <>
      <ConfirmDialog
        confirmLabel={
          resetBusy ? t("common.processing") : t("rawSealing.resetConfirm")
        }
        description={<p>{t("rawSealing.resetDescription")}</p>}
        destructive
        disabled={resetBusy}
        onCancel={() => {
          if (!resetBusy) close(false);
        }}
        onConfirm={() => {
          if (status?.envelopes.includes("local")) {
            void resetWithoutPassword();
          } else {
            setResetStep("password");
          }
        }}
        open={resetConfirmOpen}
        title={t("rawSealing.resetTitle")}
      />
      <ProofConfirmDialog
        actions={[{ id: "submit", label: proofDialog?.action ?? "" }]}
        description={proofDialog?.description ?? null}
        fields={proofDialog?.withFields ? fields : undefined}
        initialFocusRef={proofDialog?.focusNew ? newPasswordRef : undefined}
        onCancel={() => close(false)}
        onSubmit={(_, input) =>
          proofDialog ? proofDialog.submit(input) : Promise.resolve(done)
        }
        open={proofDialog !== null}
        passwordFallback={status?.password_set ?? false}
        passwordLabel={proofDialog?.passwordLabel}
        proof={proofDialog?.proof ?? "confirm"}
        submitDisabled={
          proofDialog?.blocked === true ||
          (proofDialog?.withFields === true && invalidNew)
        }
        title={proofDialog?.title ?? ""}
      />
    </>
  );
}

interface ProofDialogCopy {
  action: string;
  /** No proof this device can give opens the key; the action stays off. */
  blocked?: boolean;
  description: ReactNode;
  /** Focus the new password instead of the proof on open. */
  focusNew: boolean;
  passwordLabel?: string;
  proof: ProofMode;
  submit: (input: ProofInput) => Promise<ProofResult>;
  title: string;
  /** The dialog asks for a new password. */
  withFields: boolean;
}

const done: ProofResult = { kind: "done" };

function resetNotice(outcome: RawSealingOutcome): string {
  const reset = outcome.outcome === "sealing" ? outcome.reset : null;
  return i18n.t("rawSealing.resetDone", {
    parts: i18n.t("rawSealing.resetParts", {
      count: reset?.deleted_parts ?? 0,
    }),
    records: i18n.t("rawSealing.resetRecords", {
      count: reset?.affected_records ?? 0,
    }),
  });
}
