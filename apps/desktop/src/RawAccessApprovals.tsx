import { useCallback, useEffect, useRef, useState } from "react";
import { DataField } from "@/components/DataRow";
import { FormMessage } from "@/components/FormMessage";
import {
  ProofConfirmDialog,
  type ProofInput,
  type ProofMode,
  type ProofResult,
} from "@/components/ProofConfirmDialog";

import {
  decideRawAccess,
  getRawSealingStatus,
  getRequestRecord,
  listRawAccess,
} from "./bridge";
import { i18n, useT } from "./i18n";
import { notify } from "./notify";
import {
  oldestPendingGrant,
  type RawAccessDecision,
  type RawAccessGrant,
  type RawAccessProofOutcome,
} from "./raw-access-model";
import {
  rawPasswordUnset,
  rawProofMode,
  type RawSealingState,
} from "./raw-sealing-model";
import {
  rawProofOf,
  rawSealingErrorMessage,
  refusalResult,
} from "./raw-sealing-ui";

export const RAW_ACCESS_POLL_MS = 3_000;

/** How to ask for proof on one request; `state` is null if it failed to load. */
interface SealingFacts {
  grantId: string;
  state: RawSealingState | null;
}

interface RequestFacts {
  requestId: string;
  model: string | null;
  startedAt: string | null;
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(i18n.language === "zh-CN" ? "zh-CN" : "en", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(date);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Shows the oldest pending agent raw access request as a proof dialog
 * (plan §5.11.6). Approval needs the raw password every time (D14).
 * Nothing here keeps the password after the attempt.
 */
export function RawAccessApprovals({
  coreSessionKey,
  isReady,
}: {
  coreSessionKey: string | null;
  isReady: boolean;
}) {
  const t = useT();
  const [grants, setGrants] = useState<RawAccessGrant[]>([]);
  // Requests decided here, hidden until the next list stops returning them.
  const [settled, setSettled] = useState<ReadonlySet<string>>(new Set());
  const [facts, setFacts] = useState<RequestFacts | null>(null);
  const [sealing, setSealing] = useState<SealingFacts | null>(null);
  const generation = useRef(0);

  const refresh = useCallback(async () => {
    const current = generation.current;
    try {
      const next = await listRawAccess();
      if (current !== generation.current) return;
      setGrants(next);
      setSettled((previous) => {
        const live = new Set(
          next
            .filter((grant) => grant.status === "pending")
            .map((grant) => grant.grant_id),
        );
        const kept = [...previous].filter((id) => live.has(id));
        return kept.length === previous.size ? previous : new Set(kept);
      });
    } catch {
      // A failed poll keeps the last list; the next one retries.
    }
  }, []);

  useEffect(() => {
    generation.current += 1;
    setGrants([]);
    setSettled(new Set());
    if (!isReady || coreSessionKey === null) return;
    void refresh();
    const timer = setInterval(() => void refresh(), RAW_ACCESS_POLL_MS);
    return () => clearInterval(timer);
  }, [coreSessionKey, isReady, refresh]);

  const grant = oldestPendingGrant(
    grants.filter((candidate) => !settled.has(candidate.grant_id)),
  );
  const requestId = grant?.request_id ?? null;
  const grantId = grant?.grant_id ?? null;

  // Read how to prove on every new request, since the raw password may have
  // been set or reset since the last one.
  useEffect(() => {
    if (grantId === null) return;
    let cancelled = false;
    void getRawSealingStatus().then(
      (state) => {
        if (!cancelled) setSealing({ grantId, state });
      },
      () => {
        if (!cancelled) setSealing({ grantId, state: null });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [grantId]);

  useEffect(() => {
    if (requestId === null) return;
    let cancelled = false;
    void getRequestRecord(requestId).then(
      (record) => {
        if (cancelled) return;
        setFacts({
          requestId,
          model: record.requested_model,
          startedAt: record.started_at,
        });
      },
      () => {
        if (!cancelled) setFacts({ requestId, model: null, startedAt: null });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [requestId]);

  const settle = (grantId: string) =>
    setSettled((previous) => new Set(previous).add(grantId));
  const unsettle = (grantId: string) =>
    setSettled((previous) => {
      const next = new Set(previous);
      next.delete(grantId);
      return next;
    });

  const approve = async (
    target: RawAccessGrant,
    decision: RawAccessDecision,
    proof: ProofInput,
  ): Promise<ProofResult> => {
    let outcome: RawAccessProofOutcome;
    try {
      outcome = await decideRawAccess(
        target.grant_id,
        decision,
        rawProofOf(proof),
      );
    } catch (error) {
      return { kind: "error", message: rawSealingErrorMessage(error) };
    }
    switch (outcome.outcome) {
      case "decided":
        settle(target.grant_id);
        notify.success(
          t(
            decision === "window_15m"
              ? "rawAccess.approvedWindow"
              : "rawAccess.approvedOnce",
            { client: target.client_name || t("rawAccess.unnamedClient") },
          ),
        );
        void refresh();
        return { kind: "done" };
      case "not_pending":
        settle(target.grant_id);
        notify.info(t("rawAccess.notPending"));
        void refresh();
        return { kind: "done" };
      case "password_invalid":
      case "backoff":
        return refusalResult(outcome);
    }
  };

  const deny = (target: RawAccessGrant) => {
    settle(target.grant_id);
    void decideRawAccess(target.grant_id, "deny").then(
      (outcome) => {
        if (outcome.outcome === "decided") {
          notify.info(t("rawAccess.denied"));
        }
        void refresh();
      },
      (error: unknown) => {
        unsettle(target.grant_id);
        notify.error(t("rawAccess.denyFailed", { message: messageOf(error) }));
      },
    );
  };

  // A new request remounts the dialog so no attempt state carries over;
  // closing keeps the key, so the exit animation shows what was decided.
  const dialogKey = useRef("none");
  if (grant) dialogKey.current = grant.grant_id;
  const client = grant?.client_name || t("rawAccess.unnamedClient");
  const currentFacts = facts?.requestId === requestId ? facts : null;
  // The dialog waits for the proof mode rather than switching under the user.
  const currentSealing = sealing?.grantId === grantId ? sealing : null;
  const sealingState = currentSealing?.state ?? null;
  // Core wants a proof for every approval and reads raw content only through
  // the raw password; without one only denying is left.
  const unreachable = sealingState !== null && rawPasswordUnset(sealingState);
  const proofMode: ProofMode = !sealingState
    ? "password"
    : unreachable
      ? "confirm"
      : rawProofMode(sealingState);
  return (
    <ProofConfirmDialog
      actions={[
        { id: "once", label: t("rawAccess.once") },
        { id: "window_15m", label: t("rawAccess.window") },
      ]}
      cancelLabel={t("rawAccess.deny")}
      description={<p>{t("rawAccess.description", { client })}</p>}
      key={dialogKey.current}
      onCancel={() => {
        if (grant) deny(grant);
      }}
      onSubmit={(actionId, proof) =>
        grant
          ? approve(grant, actionId as RawAccessDecision, proof)
          : Promise.resolve({ kind: "done" })
      }
      open={grant !== null && currentSealing !== null}
      proof={proofMode}
      submitDisabled={unreachable}
      title={t("rawAccess.title")}
    >
      {grant ? (
        <div className="grid gap-3" data-slot="raw-access-facts">
          <div className="grid grid-cols-2 gap-3">
            <DataField
              label={t("rawAccess.request")}
              value={
                <code className="font-mono text-xs break-all">
                  {grant.request_id}
                </code>
              }
            />
            <DataField
              label={t("rawAccess.model")}
              value={currentFacts?.model ?? t("common.unknown")}
            />
            <DataField
              label={t("rawAccess.requestTime")}
              value={
                currentFacts?.startedAt
                  ? formatTimestamp(currentFacts.startedAt)
                  : t("common.unknown")
              }
            />
            <DataField
              label={t("rawAccess.expires")}
              value={formatTimestamp(grant.expires_at)}
            />
          </div>
          <DataField
            label={t("rawAccess.reason")}
            value={
              <span className="block max-h-24 overflow-y-auto text-xs whitespace-pre-wrap text-text-secondary [overflow-wrap:anywhere]">
                {grant.reason}
              </span>
            }
          />
          <FormMessage tone="warning">
            {t("rawAccess.providerWarning")}
          </FormMessage>
          {unreachable ? (
            <FormMessage data-testid="raw-access-unreachable" tone="warning">
              {t("rawAccess.proofUnavailable")}
            </FormMessage>
          ) : null}
        </div>
      ) : null}
    </ProofConfirmDialog>
  );
}
