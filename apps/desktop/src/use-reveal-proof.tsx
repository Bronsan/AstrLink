import { useEffect, useRef, useState, type ReactNode } from "react";

import {
  ProofConfirmDialog,
  type ProofInput,
  type ProofMode,
  type ProofResult,
} from "@/components/ProofConfirmDialog";

import {
  getRawSealingStatus,
  lockRaw,
  unlockRaw,
  verifyLocalPresence,
} from "./bridge";
import { useT } from "./i18n";
import { notify } from "./notify";
import { rawProofMode, type RawSealingState } from "./raw-sealing-model";
import { rawSealingErrorMessage, refusalResult } from "./raw-sealing-ui";

interface PendingProof {
  mode: ProofMode;
  passwordFallback: boolean;
  resolve: (proved: boolean) => void;
}

/**
 * Asks for the shared proof before an access token leaves the app (D14):
 * Touch ID where it works, else the raw password, else a confirmation. When
 * the sealing state cannot be read it asks for nothing and refuses.
 * This keeps desktop UI automation from copying a token on its own; it does
 * not bind the token to the proof. `prove` resolves true once the user
 * proved it, and false when they cancelled or the caller went inactive.
 */
export function useRevealProof(active: boolean): {
  dialog: ReactNode;
  prove: () => Promise<boolean>;
} {
  const t = useT();
  const [pending, setPending] = useState<PendingProof | null>(null);
  const pendingRef = useRef<PendingProof | null>(null);
  const startingRef = useRef(false);
  const activeRef = useRef(active);
  const mountedRef = useRef(true);
  activeRef.current = active;

  const settle = (proved: boolean, which = pendingRef.current) => {
    if (!which || pendingRef.current !== which) return;
    pendingRef.current = null;
    if (mountedRef.current) setPending(null);
    which.resolve(proved);
  };

  useEffect(() => {
    if (!active) settle(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      settle(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const prove = async (): Promise<boolean> => {
    if (!activeRef.current || startingRef.current || pendingRef.current) {
      return false;
    }
    startingRef.current = true;
    let state: RawSealingState;
    try {
      state = await getRawSealingStatus();
    } catch (error) {
      // Without the sealing state the proof it calls for is unknown, and a
      // plain confirmation could stand in for a password or Touch ID. Refuse;
      // asking again reads the state again.
      if (activeRef.current && mountedRef.current) {
        notify.error(
          t("revealProof.statusUnavailable", {
            message: rawSealingErrorMessage(error),
          }),
        );
      }
      return false;
    } finally {
      startingRef.current = false;
    }
    if (!activeRef.current || !mountedRef.current || pendingRef.current) {
      return false;
    }
    return new Promise<boolean>((resolve) => {
      const next: PendingProof = {
        mode: rawProofMode(state),
        passwordFallback: state.password_set,
        resolve,
      };
      pendingRef.current = next;
      setPending(next);
    });
  };

  const submit = async (
    _action: string,
    input: ProofInput,
  ): Promise<ProofResult> => {
    const current = pendingRef.current;
    if (!current) return { kind: "done" };
    try {
      if (input.kind === "presence") {
        const outcome = await verifyLocalPresence("reveal_access_token");
        if (outcome.outcome !== "verified") return refusalResult(outcome);
      } else if (input.kind === "password") {
        // The session may have ended or begun since the dialog opened, so
        // read it now. Unknown counts as locked: the proof never leaves a
        // session open that the operator did not start.
        const wasUnlocked = await getRawSealingStatus().then(
          (state) => state.unlocked,
          () => false,
        );
        // The host has no separate password check; an unlock verifies it.
        const outcome = await unlockRaw({
          kind: "password",
          password: input.password,
        });
        if (outcome.outcome !== "sealing") return refusalResult(outcome);
        if (!wasUnlocked && outcome.status.unlocked) {
          // Leave the unlock session as it was; the proof was the point.
          try {
            await lockRaw();
          } catch (error) {
            // The proof still holds, but raw content stays readable until
            // the idle lock; say so.
            notify.error(
              t("rawSealing.lockFailed", {
                message: rawSealingErrorMessage(error),
              }),
            );
          }
        }
      }
    } catch (error) {
      return { kind: "error", message: rawSealingErrorMessage(error) };
    }
    settle(true, current);
    return { kind: "done" };
  };

  const dialog = (
    <ProofConfirmDialog
      actions={[{ id: "reveal", label: t("revealProof.action") }]}
      description={<p>{t("revealProof.description")}</p>}
      onCancel={() => settle(false)}
      onSubmit={submit}
      open={pending !== null}
      passwordFallback={pending?.passwordFallback ?? false}
      proof={pending?.mode ?? "confirm"}
      title={t("revealProof.title")}
    />
  );
  return { dialog, prove };
}
