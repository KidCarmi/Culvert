// 2C.3 — the global Default Authentication Outcome control (§17–§19).
// ADMIN-only, LIVE immediately, never part of any draft. The change is the
// single most consequential authentication setting on the appliance, so BOTH
// directions run a TIER-3 typed ceremony: "OPEN" to switch unmatched traffic
// to Exempt, "REQUIRE" to switch it back to Default. The copy states the
// exact semantics — Exempt is NOT Allow; Stage-2 Access Policy still decides;
// scoped Authentication Rules always evaluate first.
//
// Unknown current value (§19): the read decoder fails closed on any outcome
// outside {Default, Exempt}; this control then renders a blocked error state
// and offers NO change until a fresh read returns recognizable truth.
import { useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { useSnapshot } from "../../shared/snapshot";
import {
  getDefaultAuthOutcome,
  putDefaultAuthOutcome,
} from "../../api/policyAuth";
import type { DefaultAuthOutcome } from "../../api/policyAuth";
import type { RequestRunOwner } from "../../shared/runOwner";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import styles from "./policy.module.css";

export interface DefaultAuthOutcomeControlProps {
  isAdmin: boolean;
  /** the page-level uncertainty latch also blocks this control */
  blocked: boolean;
  owner: RequestRunOwner;
}

export function DefaultAuthOutcomeControl(
  props: DefaultAuthOutcomeControlProps,
): JSX.Element {
  const { isAdmin, owner } = props;
  const q = useSnapshot(["authpolicy", "default-outcome"], (signal) =>
    getDefaultAuthOutcome(signal),
  );

  const [target, setTarget] = useState<DefaultAuthOutcome | null>(null);
  const [typed, setTyped] = useState("");
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  // Local unknown latch (2B.6 pattern, §34): an unconfirmed change blocks
  // THIS control until a fresh successful GET of the default-outcome truth.
  const [unknown, setUnknown] = useState(false);
  const blocked = props.blocked || unknown;

  const refreshToResolve = (): void => {
    const before = q.dataUpdatedAt;
    void q.refetch().then((res) => {
      if (res.isSuccess && res.dataUpdatedAt > before) setUnknown(false);
    });
  };

  const run = (outcome: DefaultAuthOutcome): void => {
    const signal = owner.begin();
    setResult("pending");
    putDefaultAuthOutcome(outcome, signal)
      .then(() => {
        setTarget(null);
        setTyped("");
        setResult("idle");
        setErrorText("");
        void q.refetch();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setTarget(null);
          setTyped("");
          setResult("idle");
          setUnknown(true);
          return;
        }
        setResult("failed");
        setErrorText(
          serverErrorText(err, "The appliance refused the change."),
        );
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  const current = q.data;

  return (
    <Card title="Default authentication (unmatched traffic)">
      {q.isPending && <Skeleton />}
      {q.isError && (
        <Callout
          variant="critical"
          title="Current default is unavailable or unrecognized"
          role="alert"
        >
          The appliance&apos;s global authentication default could not be read
          as a recognized value. Changing it is blocked until a refresh
          returns recognizable truth.
          <div className={styles.draftBarActions}>
            <Button
              size="sm"
              onClick={() => {
                void q.refetch();
              }}
            >
              Refresh
            </Button>
          </div>
        </Callout>
      )}
      {unknown && (
        <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
          The last change&apos;s outcome is unconfirmed — the default shown may
          be stale. Refresh to confirm the appliance&apos;s current default
          before changing it again.
          <div className={styles.draftBarActions}>
            <Button size="sm" onClick={refreshToResolve}>
              Refresh
            </Button>
          </div>
        </Callout>
      )}
      {current !== undefined && (
        <>
          <p>
            {current === "Exempt" ? (
              <>
                <StatusBadge status="warn">Open</StatusBadge> Unmatched clients
                proceed WITHOUT end-user authentication
                (defaultAuthOutcome=Exempt). This is NOT Allow — Stage-2
                Access Policy still decides, and default-deny still applies.
                Scoped Authentication Rules evaluate first.
              </>
            ) : (
              <>
                <StatusBadge status="ok">Require</StatusBadge> Unmatched
                clients must authenticate (defaultAuthOutcome=Default).
                Scoped Authentication Rules evaluate first.
              </>
            )}
          </p>
          {isAdmin && (
            <div className={styles.draftBarActions}>
              {current === "Default" ? (
                <Button
                  size="sm"
                  variant="danger"
                  disabled={blocked}
                  onClick={() => {
                    setTarget("Exempt");
                    setTyped("");
                    setResult("idle");
                    setErrorText("");
                  }}
                >
                  Open unmatched traffic…
                </Button>
              ) : (
                <Button
                  size="sm"
                  disabled={blocked}
                  onClick={() => {
                    setTarget("Default");
                    setTyped("");
                    setResult("idle");
                    setErrorText("");
                  }}
                >
                  Require authentication…
                </Button>
              )}
            </div>
          )}
        </>
      )}

      {target === "Exempt" && (
        <ConfirmationDialog
          open
          tier={3}
          title="Open unmatched traffic (no authentication)"
          body={
            <>
              Unmatched clients may proceed without end-user authentication.
              This does NOT allow traffic by itself; Stage-2 Access Policy
              still decides. Scoped Authentication Rules still evaluate first.
            </>
          }
          impact="Every client that matches no Authentication Rule stops being challenged for credentials, appliance-wide, immediately."
          rollback="Switch back to Require authentication at any time — also immediate."
          confirmLabel="Open unmatched traffic"
          confirmWord="OPEN"
          typedValue={typed}
          onTypedChange={setTyped}
          destructive
          result={result}
          errorText={errorText}
          onConfirm={() => {
            if (result !== "pending") run("Exempt");
          }}
          onCancel={() => {
            if (result !== "pending") {
              setTarget(null);
              setTyped("");
              setResult("idle");
              setErrorText("");
            }
          }}
        />
      )}
      {target === "Default" && (
        <ConfirmationDialog
          open
          tier={3}
          title="Require authentication for unmatched traffic"
          body={
            <>
              Every client that matches no Authentication Rule must
              authenticate before its traffic proceeds. Clients without
              credentials receive an authentication challenge immediately.
            </>
          }
          impact="Unauthenticated clients that were relying on the open default lose access appliance-wide, immediately."
          rollback="Switch back to Open unmatched traffic at any time — also immediate."
          confirmLabel="Require authentication"
          confirmWord="REQUIRE"
          typedValue={typed}
          onTypedChange={setTyped}
          destructive
          result={result}
          errorText={errorText}
          onConfirm={() => {
            if (result !== "pending") run("Default");
          }}
          onCancel={() => {
            if (result !== "pending") {
              setTarget(null);
              setTyped("");
              setResult("idle");
              setErrorText("");
            }
          }}
        />
      )}
    </Card>
  );
}
