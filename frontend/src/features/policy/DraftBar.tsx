// 2B.3 — the Access Rules Draft Bar: first-class presentation of the policy
// write mode, derived DELIBERATELY from BOTH server contracts (§18) — the
// draft surface (GET /api/policy/draft: requireCommit/active/actor/diff) and
// the policy snapshot (GET /api/policy: draft flag = the rulebase actually
// rendered). Four states:
//   A. Require Commit OFF, no active draft  → live-write mode
//   B. Require Commit ON,  no active draft  → next write opens a candidate
//   C. Require Commit ON,  active draft     → editing the shared candidate
//   D. Require Commit OFF, active draft     → STRANDED / recovery draft
//
// Stranded safety (§19): a candidate whose rules cannot currently be reviewed
// (state D renders/writes RUNNING) must never be blindly committed. Admin may
// explicitly resume draft review by re-arming Require Commit; commit review
// is offered ONLY once the policy snapshot again reports the candidate
// (draft=true). Operators see the warning and may safely revert through the
// normal ceremony.
//
// Multi-admin truth (§21): ONE shared candidate. When the draft's opening
// actor differs from the authenticated user a prominent warning says so —
// version fencing, not frontend ownership theater, is the concurrency
// control; nobody is locked out unless the server refuses.
import { useState, type JSX } from "react";
import { Button, Callout, StatusBadge } from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import type { DraftState } from "../../api/policyDraft";
import { putRequireCommit, revertDraft } from "../../api/policyDraft";
import type { RequestRunOwner } from "../../shared/runOwner";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import styles from "./policy.module.css";

export interface DraftBarProps {
  draft: DraftState | undefined;
  draftError: boolean;
  /** GET /api/policy `draft` flag — the rulebase the page is rendering */
  snapshotIsDraft: boolean;
  isAdmin: boolean;
  canWrite: boolean;
  currentUser: string;
  blocked: boolean;
  owner: RequestRunOwner;
  refetchAll: () => void;
  latchUnknown: (op: "commit mode change" | "revert") => void;
  /** provided by the commit-review slice; absent ⇒ no commit entry rendered */
  onOpenCommit?: () => void;
}

export function DraftBar(props: DraftBarProps): JSX.Element {
  const {
    draft,
    draftError,
    snapshotIsDraft,
    isAdmin,
    canWrite,
    currentUser,
    blocked,
    owner,
    refetchAll,
    latchUnknown,
    onOpenCommit,
  } = props;

  // ── Require Commit mode ceremony (§20) ───────────────────────────────────
  const [modeTarget, setModeTarget] = useState<boolean | null>(null);
  const [modeResult, setModeResult] = useState<ConfirmResult>("idle");
  const [modeError, setModeError] = useState("");

  const runModeChange = (on: boolean): void => {
    const signal = owner.begin();
    setModeResult("pending");
    putRequireCommit(on, signal)
      .then(() => {
        setModeTarget(null);
        setModeResult("idle");
        setModeError("");
        refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setModeTarget(null);
          setModeResult("idle");
          latchUnknown("commit mode change");
          return;
        }
        setModeResult("failed");
        setModeError(
          serverErrorText(err, "The appliance refused the mode change."),
        );
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  // ── Revert ceremony (§31) ────────────────────────────────────────────────
  const [revertOpen, setRevertOpen] = useState(false);
  const [revertResult, setRevertResult] = useState<ConfirmResult>("idle");
  const [revertError, setRevertError] = useState("");

  const runRevert = (): void => {
    const signal = owner.begin();
    setRevertResult("pending");
    revertDraft(signal)
      .then(() => {
        setRevertOpen(false);
        setRevertResult("idle");
        setRevertError("");
        refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setRevertOpen(false);
          setRevertResult("idle");
          latchUnknown("revert");
          return;
        }
        setRevertResult("failed");
        setRevertError(
          serverErrorText(err, "The appliance refused the revert."),
        );
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  if (draft === undefined) {
    return draftError ? (
      <div className={styles.calloutSpace}>
        <Callout variant="warning" title="Draft state unavailable">
          The Policy Draft state could not be loaded — the write mode shown may
          be stale. Refresh before making changes.
        </Callout>
      </div>
    ) : (
      <></>
    );
  }

  const stranded = draft.active && !draft.requireCommit;
  const editingCandidate = draft.active && draft.requireCommit;
  const sharedActor =
    draft.active && draft.actor !== "" && draft.actor !== currentUser;

  const modeDialog = modeTarget !== null && (
    <ConfirmationDialog
      open
      tier={2}
      title={
        modeTarget ? "Require commit for policy changes" : "Disable commit mode"
      }
      body={
        modeTarget ? (
          <>
            With Require Commit ON, future Access Rule changes by ANY operator
            are staged into one shared Policy Draft and take effect only when
            the draft is committed.
          </>
        ) : (
          <>
            With Require Commit OFF, future Access Rule changes by ANY operator
            are LIVE immediately. A draft with pending changes must be committed
            or reverted first — the appliance refuses to strand one.
          </>
        )
      }
      impact={
        modeTarget
          ? "Changes how every operator's future policy edits behave: staged for review instead of live."
          : "Changes how every operator's future policy edits behave: live immediately instead of staged."
      }
      rollback="Switch the mode back at any time (with no pending draft)."
      confirmLabel={modeTarget ? "Require commit" : "Disable commit mode"}
      destructive={false}
      result={modeResult}
      errorText={modeError}
      onConfirm={() => {
        if (modeResult !== "pending") runModeChange(modeTarget);
      }}
      onCancel={() => {
        if (modeResult !== "pending") {
          setModeTarget(null);
          setModeResult("idle");
          setModeError("");
        }
      }}
    />
  );

  const revertDialog = revertOpen && draft.active && (
    <ConfirmationDialog
      open
      tier={2}
      title="Revert the shared Policy Draft"
      body={
        <>
          This discards the ENTIRE shared draft candidate
          {sharedActor ? (
            <>
              {" "}
              — including changes staged by <strong>{draft.actor}</strong>, who
              opened it
            </>
          ) : (
            ""
          )}
          . The running policy is untouched.
        </>
      }
      impact={`Discards ${String(draft.pendingCount)} pending ${
        draft.pendingCount === 1 ? "change" : "changes"
      }: ${String(draft.diff.added.length)} added, ${String(
        draft.diff.modified.length,
      )} modified, ${String(draft.diff.removed.length)} removed.`}
      rollback="None — discarded staged changes must be re-entered."
      confirmLabel="Revert draft"
      destructive
      result={revertResult}
      errorText={revertError}
      onConfirm={() => {
        if (revertResult !== "pending") runRevert();
      }}
      onCancel={() => {
        if (revertResult !== "pending") {
          setRevertOpen(false);
          setRevertResult("idle");
          setRevertError("");
        }
      }}
    />
  );

  return (
    <div className={styles.calloutSpace} data-testid="draft-bar">
      {/* State D — stranded recovery draft: never hidden, never blindly committable */}
      {stranded && (
        <Callout variant="warning" title="Stranded Policy Draft" role="alert">
          A draft candidate opened by{" "}
          <strong>{draft.actor === "" ? "an operator" : draft.actor}</strong>{" "}
          still exists, but Require Commit is OFF — this page shows and edits
          the RUNNING policy, so the candidate&apos;s rules cannot be reviewed
          here right now.{" "}
          {isAdmin
            ? "Resume draft review to inspect and commit it, or revert to discard it."
            : "An administrator can resume draft review; you can revert to discard the candidate."}
          <div className={styles.draftBarActions}>
            {isAdmin && (
              <Button
                size="sm"
                disabled={blocked}
                onClick={() => {
                  setModeTarget(true);
                  setModeResult("idle");
                  setModeError("");
                }}
              >
                Resume draft review…
              </Button>
            )}
            {canWrite && (
              <Button
                size="sm"
                variant="danger"
                disabled={blocked}
                onClick={() => {
                  setRevertOpen(true);
                  setRevertResult("idle");
                  setRevertError("");
                }}
              >
                Revert draft…
              </Button>
            )}
          </div>
        </Callout>
      )}

      {/* State C — editing the shared candidate */}
      {editingCandidate && (
        <Callout variant="warning" title="Editing the shared Policy Draft">
          <StatusBadge status="warn">Draft</StatusBadge> Opened by{" "}
          <strong>{draft.actor === "" ? "an operator" : draft.actor}</strong>
          {draft.startedAt !== "" && <> at {draft.startedAt}</>} ·{" "}
          {String(draft.pendingCount)} pending{" "}
          {draft.pendingCount === 1 ? "change" : "changes"} (
          {String(draft.diff.added.length)} added,{" "}
          {String(draft.diff.modified.length)} modified,{" "}
          {String(draft.diff.removed.length)} removed). Changes take effect only
          when the draft is committed.
          {sharedActor && (
            <p className={styles.sharedActorWarning}>
              This shared draft was opened by <strong>{draft.actor}</strong>.
              Your edits modify the same candidate.
            </p>
          )}
          {canWrite && (
            <div className={styles.draftBarActions}>
              {onOpenCommit !== undefined && snapshotIsDraft && (
                <Button size="sm" disabled={blocked} onClick={onOpenCommit}>
                  Review &amp; commit…
                </Button>
              )}
              <Button
                size="sm"
                variant="danger"
                disabled={blocked}
                onClick={() => {
                  setRevertOpen(true);
                  setRevertResult("idle");
                  setRevertError("");
                }}
              >
                Revert draft…
              </Button>
            </div>
          )}
        </Callout>
      )}

      {/* State B — armed, no draft yet */}
      {!draft.active && draft.requireCommit && (
        <Callout variant="info" title="Commit mode armed">
          The next Access Rule change opens a shared Policy Draft — nothing goes
          live until it is committed.
          {isAdmin && (
            <div className={styles.draftBarActions}>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                onClick={() => {
                  setModeTarget(false);
                  setModeResult("idle");
                  setModeError("");
                }}
              >
                Disable commit mode…
              </Button>
            </div>
          )}
        </Callout>
      )}

      {/* State A — live-write mode */}
      {!draft.active && !draft.requireCommit && (
        <Callout variant="info" title="Live-write mode">
          Access Rule changes take effect immediately. This is the effective
          rulebase currently enforcing traffic.
          {isAdmin && (
            <div className={styles.draftBarActions}>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                onClick={() => {
                  setModeTarget(true);
                  setModeResult("idle");
                  setModeError("");
                }}
              >
                Require commit for changes…
              </Button>
            </div>
          )}
        </Callout>
      )}

      {modeDialog}
      {revertDialog}
    </div>
  );
}
