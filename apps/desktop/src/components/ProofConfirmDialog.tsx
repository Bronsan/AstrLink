import {
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";

import { useT } from "@/i18n";
import { useExitSnapshot } from "@/lib/exit-snapshot";

import { Field } from "@/components/Field";
import { FormMessage } from "@/components/FormMessage";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { passwordLength } from "@/raw-sealing-model";

/**
 * Core refuses longer raw passwords, so a longer one cannot be correct. It
 * counts characters, so the input's UTF-16 `maxLength` would cut some short.
 */
const MAX_PASSWORD_LENGTH = 128;

/**
 * What the user chose to prove before the action. `presence` asks the host
 * to run the system prompt; a plain `confirm` click proves nothing more.
 */
export type ProofInput =
  | { kind: "password"; password: string }
  | { kind: "presence" }
  | { kind: "confirm" };

/** How a proof-carrying action ended. Only `done` lets the caller close. */
export type ProofResult =
  | { kind: "done" }
  | { kind: "password_invalid" }
  | { kind: "backoff"; retryAfterSeconds: number }
  | { kind: "presence_cancelled" }
  | { kind: "presence_unsupported" }
  | { kind: "error"; message: string };

/** How the dialog asks for its proof; see `rawProofMode`. */
export type ProofMode = "password" | "presence" | "confirm";

export interface ProofAction {
  id: string;
  label: string;
}

interface ProofConfirmDialogProps {
  /** Actions that need the proof; the first is the default for Enter. */
  actions: readonly [ProofAction, ...ProofAction[]];
  cancelLabel?: string;
  /** Facts the user decides on, shown between the description and the proof. */
  children?: ReactNode;
  description: ReactNode;
  /**
   * False keeps the dialog up until an action is `done`: no cancel button,
   * and Escape or a click outside does nothing. For a step the app cannot
   * go on without, such as setting a required raw password.
   */
  dismissable?: boolean;
  /** Inputs the action itself needs, such as a new password, after the proof. */
  fields?: ReactNode;
  /**
   * `password` asks for the raw password; `presence` lets the host show the
   * system Touch ID prompt on submit; `confirm` is for hosts where neither
   * is set up, where the dialog only keeps UI automation from acting alone.
   */
  proof: ProofMode;
  /**
   * In `presence` mode, the user also has a raw password: offer it instead,
   * and fall back to it when the prompt turns out to be unavailable.
   */
  passwordFallback?: boolean;
  /** Labels the proof password, e.g. as the current one beside a new one. */
  passwordLabel?: string;
  /** Keeps every action disabled, e.g. while `children` hold an invalid form. */
  submitDisabled?: boolean;
  /** Receives focus on open instead of the proof, e.g. a field in `children`. */
  initialFocusRef?: RefObject<HTMLElement | null>;
  /** Required unless the dialog is not `dismissable`. */
  onCancel?: () => void;
  onSubmit: (actionId: string, proof: ProofInput) => Promise<ProofResult>;
  open: boolean;
  title: string;
}

/**
 * The one confirmation that asks for a fresh proof (plan §5.11.6, D14). The
 * password lives only in this dialog's state until it is submitted, and is
 * cleared after every attempt. A presence proof is only requested here; the
 * host runs the system prompt when the caller forwards it. A refusal keeps
 * the dialog open; the caller closes it once an action is `done`.
 */
export function ProofConfirmDialog(props: ProofConfirmDialogProps) {
  const t = useT();
  const {
    dismissable = true,
    initialFocusRef,
    onCancel,
    onSubmit,
    open,
  } = props;
  // The closing frame keeps only what it shows. `fields` holds new
  // passwords and the callbacks may close over them; neither outlives the
  // dialog in the snapshot.
  const {
    actions,
    cancelLabel = t("common.cancel"),
    children,
    description,
    passwordFallback = false,
    passwordLabel = t("proofDialog.passwordLabel"),
    proof,
    submitDisabled = false,
    title,
  } = useExitSnapshot(
    {
      actions: props.actions,
      cancelLabel: props.cancelLabel,
      children: props.children,
      description: props.description,
      passwordFallback: props.passwordFallback,
      passwordLabel: props.passwordLabel,
      proof: props.proof,
      submitDisabled: props.submitDisabled,
      title: props.title,
    },
    open,
  );
  const fields = open ? props.fields : null;
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // The user chose the password over the presence prompt.
  const [preferPassword, setPreferPassword] = useState(false);
  // The host reported that it cannot show the presence prompt.
  const [presenceUnsupported, setPresenceUnsupported] = useState(false);
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const passwordRef = useRef<HTMLInputElement>(null);
  const defaultActionRef = useRef<HTMLButtonElement>(null);
  const pendingRef = useRef(false);
  const cancel = () => {
    if (dismissable && !pendingRef.current) onCancel?.();
  };

  useEffect(() => {
    if (open) return;
    setPassword("");
    setError(null);
    setNotice(null);
    setRetryAt(null);
    setPreferPassword(false);
    setPresenceUnsupported(false);
  }, [open]);

  useEffect(() => {
    if (retryAt === null) return;
    const timer = setInterval(() => {
      const current = Date.now();
      setNow(current);
      if (current >= retryAt) setRetryAt(null);
    }, 250);
    return () => clearInterval(timer);
  }, [retryAt]);

  const retrySeconds =
    retryAt === null ? 0 : Math.max(1, Math.ceil((retryAt - now) / 1000));
  const mode: ProofMode =
    proof === "presence" &&
    passwordFallback &&
    (preferPassword || presenceUnsupported)
      ? "password"
      : proof;
  const needsPassword = mode === "password";
  const passwordTooLong =
    needsPassword && passwordLength(password) > MAX_PASSWORD_LENGTH;
  const blocked =
    submitDisabled ||
    retryAt !== null ||
    (needsPassword && password === "") ||
    passwordTooLong;
  const actionsDisabled = pending || blocked;

  const focusProof = (usePassword: boolean) =>
    requestAnimationFrame(() =>
      (usePassword ? passwordRef : defaultActionRef).current?.focus({
        preventScroll: true,
      }),
    );

  const switchProof = (usePassword: boolean) => {
    if (pendingRef.current) return;
    setPreferPassword(usePassword);
    setPassword("");
    setError(null);
    setNotice(null);
    focusProof(usePassword);
  };

  const submit = async (actionId: string) => {
    if (pendingRef.current || !open || blocked) return;
    const input: ProofInput =
      mode === "password"
        ? { kind: "password", password }
        : mode === "presence"
          ? { kind: "presence" }
          : { kind: "confirm" };
    // Nothing keeps the password once it is on its way.
    setPassword("");
    setError(null);
    setNotice(null);
    pendingRef.current = true;
    setPending(true);
    let result: ProofResult;
    try {
      result = await onSubmit(actionId, input);
    } catch (reason) {
      result = {
        kind: "error",
        message: reason instanceof Error ? reason.message : String(reason),
      };
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
    let focusPassword = needsPassword;
    switch (result.kind) {
      case "done":
        return;
      case "password_invalid":
        setError(t("proofDialog.passwordInvalid"));
        break;
      case "presence_cancelled":
        setNotice(t("proofDialog.presenceCancelled"));
        break;
      case "presence_unsupported":
        setPresenceUnsupported(true);
        if (passwordFallback) {
          setNotice(t("proofDialog.presenceFallback"));
          focusPassword = true;
        } else {
          setError(t("proofDialog.presenceUnsupported"));
        }
        break;
      case "backoff": {
        const at = Date.now() + result.retryAfterSeconds * 1000;
        setNow(Date.now());
        setRetryAt(at);
        setError(null);
        break;
      }
      case "error":
        setError(result.message || t("proofDialog.failed"));
        break;
    }
    focusProof(focusPassword);
  };

  const [defaultAction, ...otherActions] = actions;
  return (
    <AlertDialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) cancel();
      }}
    >
      <AlertDialogContent
        data-slot="proof-confirm-dialog"
        onEscapeKeyDown={(event) => {
          if (!dismissable) event.preventDefault();
        }}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          const target =
            initialFocusRef?.current ??
            (needsPassword ? passwordRef : defaultActionRef).current;
          target?.focus({ preventScroll: true });
        }}
      >
        <form
          className="grid gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            void submit(defaultAction.id);
          }}
        >
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2">{description}</div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          {children}
          {mode === "presence" ? (
            <div
              className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-xs text-text-secondary"
              data-slot="proof-presence"
            >
              <span>{t("proofDialog.presenceHint")}</span>
              {passwordFallback ? (
                <Button
                  className="h-auto px-0"
                  disabled={pending}
                  onClick={() => switchProof(true)}
                  size="xs"
                  type="button"
                  variant="link"
                >
                  {t("proofDialog.usePassword")}
                </Button>
              ) : null}
            </div>
          ) : null}
          {needsPassword ? (
            <div className="grid gap-1">
              <Field label={passwordLabel}>
                <Input
                  aria-invalid={passwordTooLong || undefined}
                  autoComplete="off"
                  disabled={pending}
                  onChange={(event) => setPassword(event.target.value)}
                  ref={passwordRef}
                  spellCheck={false}
                  type="password"
                  value={password}
                />
              </Field>
              {passwordTooLong ? (
                <FormMessage tone="error">
                  {t("rawSealing.tooLong", { max: MAX_PASSWORD_LENGTH })}
                </FormMessage>
              ) : null}
              {proof === "presence" && !presenceUnsupported ? (
                <Button
                  className="h-auto justify-self-start px-0"
                  disabled={pending}
                  onClick={() => switchProof(false)}
                  size="xs"
                  type="button"
                  variant="link"
                >
                  {t("proofDialog.usePresence")}
                </Button>
              ) : null}
            </div>
          ) : null}
          {fields ? (
            // The caller's inputs wait with the proof while it is on its way.
            <fieldset
              className="contents"
              data-slot="proof-fields"
              disabled={pending}
            >
              {fields}
            </fieldset>
          ) : null}
          {retryAt !== null ? (
            <FormMessage data-slot="proof-backoff" tone="warning">
              {t("proofDialog.backoff", { seconds: retrySeconds })}
            </FormMessage>
          ) : null}
          {notice ? (
            <FormMessage data-slot="proof-notice" tone="notice">
              {notice}
            </FormMessage>
          ) : null}
          {error ? <FormMessage tone="error">{error}</FormMessage> : null}
          <AlertDialogFooter>
            {dismissable ? (
              <Button
                disabled={pending}
                onClick={cancel}
                type="button"
                variant="outline"
              >
                {cancelLabel}
              </Button>
            ) : null}
            {otherActions.map((action) => (
              <Button
                disabled={actionsDisabled}
                key={action.id}
                onClick={() => void submit(action.id)}
                type="button"
                variant="outline"
              >
                {action.label}
              </Button>
            ))}
            <Button
              disabled={actionsDisabled}
              ref={defaultActionRef}
              type="submit"
            >
              {pending ? t("common.processing") : defaultAction.label}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
