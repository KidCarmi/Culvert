// 2B.6 — the default policy action (GET/POST /api/default-action): a
// SEPARATE LIVE mutation, deliberately OUTSIDE the Policy Draft transaction.
// The backend applies it immediately — even while Require Commit is armed —
// so the ceremony says so in unmistakable copy and the control never renders
// as one of the draft's pending changes.
import { useState, type JSX } from "react";
import { Button, Callout, StatusBadge } from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { useSnapshot } from "../../shared/snapshot";
import { getDefaultAction, setDefaultAction } from "../../api/policyWrite";
import type { DefaultAction } from "../../api/policyWrite";
import { useQueryClient } from "@tanstack/react-query";
import type { RequestRunOwner } from "../../shared/runOwner";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import styles from "./policy.module.css";

const DEFAULT_ACTION_KEY = ["policy", "default-action"] as const;

export interface DefaultActionControlProps {
  canWrite: boolean;
  /** the page-level uncertainty latch also blocks this control */
  blocked: boolean;
  owner: RequestRunOwner;
}

export function DefaultActionControl(
  props: DefaultActionControlProps,
): JSX.Element {
  const { canWrite, blocked, owner } = props;
  const qc = useQueryClient();
  const q = useSnapshot(DEFAULT_ACTION_KEY, (signal) =>
    getDefaultAction(signal),
  );
  const [target, setTarget] = useState<DefaultAction | null>(null);
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  // Local unknown latch (§32): an unconfirmed change blocks THIS control
  // until a fresh successful GET of the default-action truth.
  const [unknown, setUnknown] = useState(false);

  const refreshToResolve = (): void => {
    const before = q.dataUpdatedAt;
    void q.refetch().then((res) => {
      if (res.isSuccess && res.dataUpdatedAt > before) setUnknown(false);
    });
  };

  const run = (t: DefaultAction): void => {
    const signal = owner.begin();
    setResult("pending");
    setDefaultAction(t, signal)
      .then((serverValue) => {
        // Render ONLY the returned server value.
        qc.setQueryData(DEFAULT_ACTION_KEY, serverValue);
        setTarget(null);
        setResult("idle");
        setErrorText("");
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setTarget(null);
          setResult("idle");
          setUnknown(true);
          return;
        }
        setResult("failed");
        setErrorText(serverErrorText(err, "The appliance refused the change."));
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  const current = q.data;

  return (
    <div className={styles.defaultActionRow}>
      <span>
        Default action for unmatched traffic:{" "}
        {current === undefined ? (
          <StatusBadge status="neutral">
            {q.isError ? "unavailable" : "loading…"}
          </StatusBadge>
        ) : current === "deny" ? (
          <StatusBadge status="critical">Deny</StatusBadge>
        ) : (
          <StatusBadge status="warn">Allow</StatusBadge>
        )}
      </span>
      {canWrite && current !== undefined && !unknown && (
        <Button
          size="sm"
          variant="ghost"
          disabled={blocked}
          onClick={() => {
            setTarget(current === "deny" ? "allow" : "deny");
            setResult("idle");
            setErrorText("");
          }}
        >
          Change…
        </Button>
      )}
      {unknown && (
        <Callout
          variant="unknown"
          title="Default-action change unconfirmed"
          role="alert"
        >
          The connection was lost before the appliance&apos;s answer arrived.
          Refresh the current default action before trying again.
          <div className={styles.fallbackAction}>
            <Button size="sm" onClick={refreshToResolve}>
              Refresh default action
            </Button>
          </div>
        </Callout>
      )}
      {target !== null && current !== undefined && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Set default action to ${target === "deny" ? "Deny" : "Allow"}`}
          body={
            <>
              Unmatched traffic — every request no Access Rule matches — is
              currently{" "}
              <strong>{current === "deny" ? "denied" : "allowed"}</strong> and
              will be{" "}
              <strong>{target === "deny" ? "denied" : "allowed"}</strong>. This
              takes effect LIVE immediately for all traffic. It is never staged
              in the Policy Draft — even while Require Commit is on.
            </>
          }
          impact={
            target === "allow"
              ? "Every request not matched by an Access Rule is ALLOWED the moment you confirm — a fleet-wide loosening of enforcement."
              : "Every request not matched by an Access Rule is DENIED the moment you confirm — clients relying on unmatched traffic lose access instantly."
          }
          rollback="Switch it back the same way; the change itself cannot be batched or staged."
          confirmLabel={`Set default to ${target}`}
          destructive={target === "allow"}
          result={result}
          errorText={errorText}
          onConfirm={() => {
            if (result !== "pending") run(target);
          }}
          onCancel={() => {
            if (result !== "pending") {
              setTarget(null);
              setResult("idle");
              setErrorText("");
            }
          }}
        />
      )}
    </div>
  );
}
