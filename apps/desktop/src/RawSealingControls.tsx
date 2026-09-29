import { useEffect, useId, useRef, useState, type ReactNode } from "react";

import { CapabilityToggle } from "@/components/CapabilityToggle";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { FormMessage } from "@/components/FormMessage";
import { LockKeyhole } from "@/components/icons";
import { Panel, PanelHeader } from "@/components/Panel";
import {
  ProofConfirmDialog,
  type ProofInput,
  type ProofMode,
  type ProofResult,
} from "@/components/ProofConfirmDialog";
import { RawPasswordFields } from "@/components/RawPasswordFields";
import { StatusBadge } from "@/components/StatusBadge";
import { StatusDot, type StatusTone } from "@/components/StatusDot";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

import { acknowledgeRawKey, setRawPassword, unlockRaw } from "./bridge";
import { i18n, useT } from "./i18n";
import { notify } from "./notify";
import {
  newPasswordIssue,
  presenceUsable,
  rawAcknowledgeMode,
  rawPasswordState,
  rawProofMode,
  rawResetProofMode,
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
import { useRawSealingStatus } from "./use-raw-sealing-status";

/**
 * A raw sealing dialog the page asks for; `capture` also turns capture on,
 * `required` is the one the app keeps up until a password is set, and
 * `replaced` the one it keeps up for a key replaced outside the desktop.
 */
export type RawDialog =
  | { kind: "set" }
  | { kind: "change" }
  | { kind: "reset" }
  | { kind: "unlock" }
  | { kind: "capture" }
  | { kind: "required" }
  | { kind: "replaced" };

/** Minutes before Core locks an idle unlock session, for the copy. */
export function unlockIdleMinutes(status: RawSealingState): number {
  return Math.max(1, Math.round(status.unlock_idle_seconds / 60));
}

/**
 * No raw password is set: raw parts are not kept, and the ones kept before
 * the upgrade stay unreadable until one is (D11).
 */
export function rawPasswordMissing(status: RawSealingState | null): boolean {
  return status?.password_required === true;
}

/**
 * The raw password summary: how the raw key opens, the actions on it, and,
 * where the page passes it, whether agent tools may ask for raw content.
 */
export function RawPasswordPanel({
  agentAccess = false,
  busy,
  error,
  onAction,
  onAgentAccessChange,
  status,
}: {
  agentAccess?: boolean;
  busy: boolean;
  error: string | null;
  onAction: (action: RawPasswordAction) => void;
  /** Shows the agent access toggle. */
  onAgentAccessChange?: (enabled: boolean) => void;
  status: RawSealingState | null;
}) {
  const t = useT();
  const titleId = useId();
  const state = status ? rawPasswordState(status) : null;
  const missing = rawPasswordMissing(status);
  // Unknown is not missing: a failed read leaves the toggle as it was.
  const noPassword = status !== null && !status.password_set;

  const tone: StatusTone =
    state === "password" ? "positive" : missing ? "pending" : "neutral";
  const label =
    state === "password"
      ? t("rawSealing.state.password")
      : state === null
        ? t("rawSealing.state.unknown")
        : t("rawSealing.state.unset");
  const hint =
    state === "password"
      ? status && presenceUsable(status)
        ? t("rawSealing.hint.passwordPresence")
        : t("rawSealing.hint.password")
      : null;

  const action = (id: RawPasswordAction, text: string) => (
    <Button
      disabled={busy}
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
        ? [action("reset", t("rawSealing.reset"))]
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
        ) : missing ? (
          <FormMessage
            className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5"
            data-slot="raw-password-missing"
            tone="warning"
          >
            <span className="min-w-0">
              {state === "keychain_only"
                ? t("rawSealing.hint.keychainOnly")
                : t("rawSealing.hint.unset")}
            </span>
            <Button
              disabled={busy}
              onClick={() => onAction("set")}
              size="xs"
              type="button"
              variant="outline"
            >
              {t("rawSealing.setAction")}
            </Button>
          </FormMessage>
        ) : hint ? (
          <p className="text-xs leading-relaxed text-muted-foreground">
            {hint}
          </p>
        ) : null}
        {onAgentAccessChange ? (
          <CapabilityToggle
            checked={agentAccess && !noPassword}
            description={
              noPassword
                ? t("rawSealing.agentAccessNeedsPassword")
                : t("rawSealing.agentAccessHint")
            }
            disabled={busy || noPassword}
            label={t("rawSealing.agentAccess")}
            onCheckedChange={onAgentAccessChange}
            size="default"
          />
        ) : null}
      </div>
    </Panel>
  );
}

/**
 * The raw password in a page header, such as the Security page's: its state
 * at a glance, and the summary with its actions one click away.
 */
export function RawPasswordEntry({
  coreSessionKey,
  isReady,
}: {
  coreSessionKey: string | null;
  isReady: boolean;
}) {
  const t = useT();
  const { status, error, setStatus } = useRawSealingStatus(
    coreSessionKey,
    isReady,
  );
  const [open, setOpen] = useState(false);
  const [dialog, setDialog] = useState<RawDialog | null>(null);
  if (!isReady) return null;
  const tone: StatusTone = status?.password_set
    ? "positive"
    : rawPasswordMissing(status)
      ? "pending"
      : "neutral";
  const stateLabel = status?.password_set
    ? t("rawSealing.state.password")
    : rawPasswordMissing(status)
      ? t("rawSealing.state.unset")
      : t("rawSealing.state.unknown");
  return (
    <>
      <Popover onOpenChange={setOpen} open={open}>
        <PopoverTrigger asChild>
          <Button
            data-slot="raw-password-entry"
            size="sm"
            type="button"
            variant="outline"
          >
            <LockKeyhole aria-hidden="true" />
            {t("rawSealing.title")}
            <StatusDot tone={tone} />
            {/* The dot's state, for screen readers. */}
            <span className="sr-only">{stateLabel}</span>
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80 p-0">
          <RawPasswordPanel
            busy={dialog !== null}
            error={error}
            onAction={(action) => {
              // The dialog takes over from the popover.
              setOpen(false);
              setDialog({ kind: action });
            }}
            status={status}
          />
        </PopoverContent>
      </Popover>
      <RawSealingDialogs
        dialog={dialog}
        onClose={() => setDialog(null)}
        onStatus={setStatus}
        status={status}
      />
    </>
  );
}

/**
 * Keeps the required raw password dialog up while none is set (D11): only
 * setting one closes it, and the gateway keeps serving meanwhile. A key
 * replaced outside the desktop keeps its own warning up the same way, until
 * the operator confirms it with its password (and, on a keychain build, a
 * presence check) or resets it.
 * `suspended` holds it back while the first-run guide asks for the password
 * in its own step, or before it is known whether that guide opens.
 */
export function RawPasswordGate({
  onStatus,
  status,
  suspended,
}: {
  onStatus: (next: RawSealingState) => void;
  status: RawSealingState | null;
  suspended: boolean;
}) {
  const replaced = !suspended && status?.key_replaced === true;
  const required = !suspended && rawPasswordMissing(status);
  return (
    <RawSealingDialogs
      dialog={
        replaced ? { kind: "replaced" } : required ? { kind: "required" } : null
      }
      onClose={() => {}}
      onStatus={onStatus}
      status={status}
    />
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
  // Replacing the keychain key instead of setting a password on it, or a key
  // replaced outside the desktop: the destructive confirmation first, then
  // the new password.
  const [replaceStep, setReplaceStep] = useState<"confirm" | "password" | null>(
    null,
  );
  const newPasswordRef = useRef<HTMLInputElement>(null);
  const kind = status ? (dialog?.kind ?? null) : null;

  useEffect(() => {
    setPassword("");
    setConfirmation("");
    setResetStep("confirm");
    setReplaceStep(null);
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
    } else if (kind === "set" || kind === "required") {
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

  const submitAcknowledge = async (input: ProofInput): Promise<ProofResult> => {
    // Only the replaced key's password shows the operator set it; a
    // keychain build's host adds its presence check on top.
    if (input.kind !== "password") return { kind: "password_invalid" };
    let outcome: RawSealingOutcome;
    try {
      outcome = await acknowledgeRawKey(input.password);
    } catch (error) {
      return { kind: "error", message: rawSealingErrorMessage(error) };
    }
    const settled = settle(outcome);
    if (!settled.done) return settled.result;
    notify.success(i18n.t("rawSealing.replaced.accepted"));
    close(true);
    return { kind: "done" };
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
  } else if (kind === "capture" || kind === "set" || kind === "required") {
    // An unconfigured key needs no proof. A keychain key is opened with a
    // presence check before a password can open it too. Replacing it
    // instead discards what it sealed: that takes the destructive
    // confirmation and, while the local envelope opens the key, the same
    // presence check, which Core wants for a reset too.
    const keychainKey = status.configured && !status.password_set;
    const keyOpens = keychainKey && status.local_presence;
    const replacing = keychainKey ? replaceStep : null;
    const intro =
      kind === "required" ? (
        <>
          <p>{t("rawSealing.requiredBody")}</p>
          <p>{t("rawSealing.requiredForget")}</p>
        </>
      ) : kind === "capture" ? (
        <>
          <p>{t("records.enableCaptureBody")}</p>
          <p>{t("rawSealing.captureNeedsPassword")}</p>
        </>
      ) : (
        <p>{t("rawSealing.setDescription")}</p>
      );
    const title =
      kind === "required"
        ? t("rawSealing.requiredTitle")
        : kind === "capture"
          ? t("records.enableCaptureTitle")
          : t("rawSealing.setTitle");
    if (replacing === "password") {
      proofDialog = {
        action: t("rawSealing.resetAction"),
        cancelLabel: t("common.back"),
        description: (
          <>
            {intro}
            <FormMessage data-slot="raw-replace-key" tone="warning">
              {t("rawSealing.replaceKeyWarning")}
            </FormMessage>
          </>
        ),
        focusNew: true,
        onCancel: () => {
          clearNewPassword();
          setReplaceStep(null);
        },
        proof: rawResetProofMode(status),
        submit: (input) => submitPassword("reset", input),
        title,
        withFields: true,
      };
    } else if (replacing === null && keychainKey && !keyOpens) {
      // Nothing here opens this key any more, so only replacing it is left.
      proofDialog = {
        action: t("rawSealing.replaceStart"),
        description: (
          <>
            {intro}
            <FormMessage data-slot="raw-replace-key" tone="warning">
              {t("rawSealing.hint.keychainUnreachable")}
            </FormMessage>
          </>
        ),
        dismissable: kind !== "required",
        focusNew: false,
        proof: "confirm",
        submit: () => {
          setReplaceStep("confirm");
          return Promise.resolve(done);
        },
        title,
        withFields: false,
      };
    } else if (replacing === null) {
      proofDialog = {
        action:
          kind === "capture"
            ? t("records.confirmEnable")
            : t("rawSealing.setAction"),
        description: (
          <>
            {intro}
            {keyOpens && !presenceUsable(status) ? (
              // Asking again is the retry; the key and what it sealed stay.
              <FormMessage data-slot="raw-presence-unavailable" tone="warning">
                {t("rawSealing.hint.presenceUnavailable")}
              </FormMessage>
            ) : null}
            {keyOpens ? (
              <p className="flex flex-wrap items-center gap-x-2">
                <span>{t("rawSealing.setKeychainDescription")}</span>
                <Button
                  className="h-auto px-0"
                  onClick={() => {
                    clearNewPassword();
                    setReplaceStep("confirm");
                  }}
                  size="xs"
                  type="button"
                  variant="link"
                >
                  {t("rawSealing.replaceKey")}
                </Button>
              </p>
            ) : null}
          </>
        ),
        dismissable: kind !== "required",
        withFields: true,
        focusNew: true,
        proof: keyOpens ? "presence" : "confirm",
        submit: (input) => submitPassword("set", input),
        title,
      };
    }
  } else if (kind === "replaced" && replaceStep === "password") {
    const proof = rawResetProofMode(status);
    proofDialog = {
      action: t("rawSealing.resetAction"),
      cancelLabel: t("common.back"),
      description: <p>{t("rawSealing.resetPasswordDescription")}</p>,
      focusNew: proof !== "password",
      onCancel: () => {
        clearNewPassword();
        setReplaceStep(null);
      },
      passwordLabel: t("rawSealing.currentPassword"),
      proof,
      submit: (input) => submitPassword("reset", input),
      title: t("rawSealing.resetPasswordTitle"),
      withFields: true,
    };
  } else if (kind === "replaced" && replaceStep === null) {
    const mode = rawAcknowledgeMode(status);
    const warning = (
      <FormMessage data-slot="raw-key-replaced" tone="warning">
        {t("rawSealing.replaced.warning")}
      </FormMessage>
    );
    proofDialog =
      mode === "unavailable"
        ? {
            // A keychain build accepts the key only with a presence check
            // as well; where it cannot show one, a reset is all that is left.
            action: t("rawSealing.replaceStart"),
            description: (
              <>
                {warning}
                <FormMessage
                  data-slot="raw-acknowledge-unavailable"
                  tone="warning"
                >
                  {t("rawSealing.replaced.presenceUnavailable")}
                </FormMessage>
              </>
            ),
            dismissable: false,
            focusNew: false,
            proof: "confirm",
            submit: () => {
              setReplaceStep("confirm");
              return Promise.resolve(done);
            },
            title: t("rawSealing.replaced.title"),
            withFields: false,
          }
        : {
            // The password shows the operator chose it; presence alone only
            // shows someone is at this Mac. A keychain build's host checks
            // presence too once the password is submitted.
            action: t("rawSealing.replaced.acknowledge"),
            description: (
              <>
                {warning}
                <p>{t("rawSealing.replaced.cli")}</p>
                {mode === "password_and_presence" ? (
                  <p data-slot="raw-acknowledge-presence">
                    {t("rawSealing.replaced.presence")}
                  </p>
                ) : null}
                <Button
                  className="h-auto px-0"
                  onClick={() => setReplaceStep("confirm")}
                  size="xs"
                  type="button"
                  variant="link"
                >
                  {t("rawSealing.replaced.reset")}
                </Button>
              </>
            ),
            dismissable: false,
            focusNew: false,
            passwordLabel: t("rawSealing.replaced.passwordLabel"),
            proof: "password",
            submit: submitAcknowledge,
            title: t("rawSealing.replaced.title"),
            withFields: false,
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
    // Core wants the proof that opens the key while the local envelope
    // does; a password set here counts as well.
    const proof = rawResetProofMode(status);
    proofDialog = {
      action: t("rawSealing.resetAction"),
      description: <p>{t("rawSealing.resetPasswordDescription")}</p>,
      withFields: true,
      focusNew: proof !== "password",
      passwordLabel: t("rawSealing.currentPassword"),
      proof,
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
  const replaceConfirmOpen =
    status !== null &&
    status.configured &&
    !status.password_set &&
    (kind === "capture" || kind === "set" || kind === "required") &&
    replaceStep === "confirm";
  const replacedResetConfirmOpen =
    status !== null && kind === "replaced" && replaceStep === "confirm";
  return (
    <>
      <ConfirmDialog
        confirmLabel={t("rawSealing.resetConfirm")}
        description={<p>{t("rawSealing.resetDescription")}</p>}
        destructive
        // Back to the warning; it stays until the key is dealt with.
        onCancel={() => setReplaceStep(null)}
        onConfirm={() => setReplaceStep("password")}
        open={replacedResetConfirmOpen}
        title={t("rawSealing.resetTitle")}
      />
      <ConfirmDialog
        confirmLabel={t("rawSealing.resetConfirm")}
        description={<p>{t("rawSealing.resetDescription")}</p>}
        destructive
        onCancel={() => close(false)}
        // A reset always sets the new password with it (D11).
        onConfirm={() => setResetStep("password")}
        open={resetConfirmOpen}
        title={t("rawSealing.resetTitle")}
      />
      <ConfirmDialog
        confirmLabel={t("rawSealing.resetConfirm")}
        description={
          <>
            <p>{t("rawSealing.replaceDescription")}</p>
            {status?.local_presence ? (
              <p>{t("rawSealing.replaceNeedsPresence")}</p>
            ) : null}
          </>
        }
        destructive
        // Back to setting a password; a required one stays required.
        onCancel={() => setReplaceStep(null)}
        onConfirm={() => setReplaceStep("password")}
        open={replaceConfirmOpen}
        title={t("rawSealing.replaceTitle")}
      />
      <ProofConfirmDialog
        actions={[{ id: "submit", label: proofDialog?.action ?? "" }]}
        cancelLabel={proofDialog?.cancelLabel}
        description={proofDialog?.description ?? null}
        dismissable={proofDialog?.dismissable ?? true}
        fields={proofDialog?.withFields ? fields : undefined}
        initialFocusRef={proofDialog?.focusNew ? newPasswordRef : undefined}
        onCancel={proofDialog?.onCancel ?? (() => close(false))}
        onSubmit={(_, input) =>
          proofDialog ? proofDialog.submit(input) : Promise.resolve(done)
        }
        open={proofDialog !== null}
        passwordFallback={status?.password_set ?? false}
        passwordLabel={proofDialog?.passwordLabel}
        proof={proofDialog?.proof ?? "confirm"}
        submitDisabled={proofDialog?.withFields === true && invalidNew}
        title={proofDialog?.title ?? ""}
      />
    </>
  );
}

interface ProofDialogCopy {
  action: string;
  cancelLabel?: string;
  description: ReactNode;
  /** False keeps the dialog up until the action is done. */
  dismissable?: boolean;
  /** Focus the new password instead of the proof on open. */
  focusNew: boolean;
  /** Replaces closing the dialog, e.g. to step back within it. */
  onCancel?: () => void;
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
