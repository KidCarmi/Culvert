// 2B.5 — the Policy Commit review ceremony (§28–§30). NOT a generic confirm
// dialog: opening it fetches a FRESH draft state and a FRESH candidate
// snapshot, and the SAME reviewed candidate version is used for display and
// for the commit's ifVersion — a commit can never activate changes that were
// not in the reviewed candidate (a later staged change moves the candidate
// generation, and the fenced commit conflicts).
//
// Success requires the refreshed server truth to AGREE with the commit
// response (draft no longer active, running rulebase visible); disagreement
// renders a controlled inconsistency state instead of a stale "candidate"
// label. Failure keeps the draft — the server retains it and commits nothing
// on validation/version/persistence failures — and says exactly what the
// server said (bounded). Unknown transport outcomes latch the page-level
// uncertainty doctrine.
import { useEffect, useRef, useState, type JSX } from "react";
import { Link } from "react-router";
import { Button, Callout, Spinner } from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { TextareaField } from "../../design-system/forms";
import { getPolicy } from "../../api/policy";
import type { PolicySnapshot } from "../../api/policy";
import { commitDraft, getDraftState } from "../../api/policyDraft";
import type { DraftActive } from "../../api/policyDraft";
import { asPolicyConflict } from "../../api/policyWrite";
import type { RequestRunOwner } from "../../shared/runOwner";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import styles from "./policy.module.css";

type ReviewPhase =
  | { kind: "loading" }
  | { kind: "loadError"; text: string }
  | { kind: "notReviewable"; text: string }
  | { kind: "ready"; draft: DraftActive; snapshot: PolicySnapshot }
  | { kind: "committing"; draft: DraftActive }
  | { kind: "failed"; draft: DraftActive; text: string }
  | { kind: "conflict"; draft: DraftActive; text: string }
  | { kind: "committed"; committed: number }
  | { kind: "inconsistent" };

export interface CommitReviewProps {
  owner: RequestRunOwner;
  blocked: boolean;
  refetchAll: () => void;
  latchUnknown: (op: "commit") => void;
  onClose: () => void;
}

export function CommitReview(props: CommitReviewProps): JSX.Element {
  const { owner, blocked, refetchAll, latchUnknown, onClose } = props;
  const [phase, setPhase] = useState<ReviewPhase>({ kind: "loading" });
  const [comment, setComment] = useState("");
  const loadAbort = useRef<AbortController | null>(null);

  const loadFresh = (): void => {
    loadAbort.current?.abort();
    const ctl = new AbortController();
    loadAbort.current = ctl;
    setPhase({ kind: "loading" });
    void Promise.all([getDraftState(ctl.signal), getPolicy(ctl.signal)])
      .then(([draft, snapshot]) => {
        if (ctl.signal.aborted) return;
        if (!draft.active) {
          setPhase({
            kind: "notReviewable",
            text: "There is no active draft to commit — it may have been committed or reverted elsewhere.",
          });
          return;
        }
        if (!draft.requireCommit || !snapshot.draft) {
          setPhase({
            kind: "notReviewable",
            text: "The draft candidate is not currently reviewable on this surface (Require Commit is off or the running rulebase is being shown). Resume draft review first.",
          });
          return;
        }
        setPhase({ kind: "ready", draft, snapshot });
      })
      .catch((err: unknown) => {
        if (ctl.signal.aborted) return;
        setPhase({
          kind: "loadError",
          text: serverErrorText(
            err,
            "The draft state could not be loaded for review.",
          ),
        });
      });
  };

  useEffect(() => {
    loadFresh();
    return () => {
      loadAbort.current?.abort();
    };
    // Mount-only: the review is a fresh capture; Retry re-runs it explicitly.
  }, []);

  const runCommit = (draft: DraftActive): void => {
    const signal = owner.begin();
    setPhase({ kind: "committing", draft });
    commitDraft(comment.trim(), draft.version, signal)
      .then(async (res) => {
        // §29: no optimistic transition — require the refreshed server truth
        // to agree with the commit response before declaring success.
        refetchAll();
        try {
          const [freshDraft, freshSnap] = await Promise.all([
            getDraftState(),
            getPolicy(),
          ]);
          if (freshDraft.active || freshSnap.draft) {
            setPhase({ kind: "inconsistent" });
            return;
          }
        } catch {
          setPhase({ kind: "inconsistent" });
          return;
        }
        setPhase({ kind: "committed", committed: res.committed });
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          latchUnknown("commit");
          onClose();
          return;
        }
        const conflict = asPolicyConflict(err);
        if (conflict !== null) {
          setPhase({ kind: "conflict", draft, text: conflict.error });
          return;
        }
        // Known HTTP failure: candidate validation, base-generation stale
        // (plain-text 409), or running-policy persistence failure. The server
        // RETAINS the draft and commits nothing — surface its exact detail.
        setPhase({
          kind: "failed",
          draft,
          text: serverErrorText(err, "The commit was refused."),
        });
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  const committing = phase.kind === "committing";

  return (
    <Dialog
      open
      onClose={committing ? () => undefined : onClose}
      title="Review & commit Policy Draft"
      closeOnEscape={!committing}
    >
      <DialogBody>
        {phase.kind === "loading" && <Skeletonish />}
        {phase.kind === "loadError" && (
          <Callout variant="critical" title="Review unavailable">
            {phase.text}
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={loadFresh}>
                Retry
              </Button>
            </div>
          </Callout>
        )}
        {phase.kind === "notReviewable" && (
          <Callout variant="warning" title="Nothing to commit here">
            {phase.text}
          </Callout>
        )}
        {phase.kind === "inconsistent" && (
          <Callout
            variant="unknown"
            title="Commit reported success, but the refreshed state disagrees"
            role="alert"
          >
            The appliance confirmed the commit, but the refreshed draft/policy
            state still reports a candidate. Refresh the rulebase and review the
            current state before doing anything else.
          </Callout>
        )}
        {phase.kind === "committed" && (
          <Callout variant="success" title="Draft committed">
            {String(phase.committed)}{" "}
            {phase.committed === 1 ? "change is" : "changes are"} now the
            running enforcement policy. The refreshed state confirms no draft
            remains active.
          </Callout>
        )}

        {(phase.kind === "ready" ||
          phase.kind === "committing" ||
          phase.kind === "failed" ||
          phase.kind === "conflict") && (
          <ReviewBody
            draft={phase.draft}
            comment={comment}
            onComment={setComment}
            disabled={committing}
          />
        )}
        {phase.kind === "conflict" && (
          <Callout variant="warning" title="The draft changed" role="alert">
            {phase.text} Reload the review to see the current candidate — this
            commit would have activated changes you had not reviewed.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={loadFresh}>
                Reload review
              </Button>
            </div>
          </Callout>
        )}
        {phase.kind === "failed" && (
          <Callout variant="critical" title="Commit refused" role="alert">
            {phase.text}
          </Callout>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" onClick={onClose} disabled={committing}>
          {phase.kind === "committed" ? "Close" : "Cancel"}
        </Button>
        {(phase.kind === "ready" || phase.kind === "committing") && (
          <Button
            variant="primary"
            disabled={blocked || committing || comment.trim() === ""}
            onClick={() => {
              if (phase.kind === "ready") runCommit(phase.draft);
            }}
          >
            {committing ? <Spinner label="Committing" /> : null}
            Commit draft
          </Button>
        )}
      </DialogFooter>
    </Dialog>
  );
}

function Skeletonish(): JSX.Element {
  return (
    <p className={styles.editorScope}>Loading a fresh candidate review…</p>
  );
}

function ReviewBody({
  draft,
  comment,
  onComment,
  disabled,
}: {
  draft: DraftActive;
  comment: string;
  onComment: (v: string) => void;
  disabled: boolean;
}): JSX.Element {
  return (
    <>
      <p className={styles.editorScope}>
        Committing activates the reviewed candidate (generation{" "}
        {String(draft.version)}) as the running enforcement policy. Opened by{" "}
        {draft.actor === "" ? "an operator" : draft.actor}
        {draft.startedAt !== "" ? ` at ${draft.startedAt}` : ""}.
      </p>
      <div className={styles.commitDiff}>
        <DiffList label="Added" names={draft.diff.added} />
        <DiffList label="Modified" names={draft.diff.modified} />
        <DiffList label="Removed" names={draft.diff.removed} />
      </div>
      {draft.shadows.length > 0 && (
        <Callout variant="warning" title="Shadowed rules in the candidate">
          <ul className={styles.shadowList}>
            {draft.shadows.map((sh) => (
              <li key={`${sh.rule}::${sh.shadowedBy}`}>
                <strong>{sh.rule}</strong> is shadowed by{" "}
                <strong>{sh.shadowedBy}</strong>
              </li>
            ))}
          </ul>
          Shadow detection is advisory and covers only provable cases — it is
          not a complete semantic analysis. Verify with the{" "}
          <Link to="/policies/tester">Policy Tester</Link>.
        </Callout>
      )}
      {draft.shadows.length === 0 && (
        <p className={styles.editorScope}>
          No provable shadowing detected. Shadow detection is advisory only —
          verify behavior with the{" "}
          <Link to="/policies/tester">Policy Tester</Link>.
        </p>
      )}
      <TextareaField
        label="Commit comment"
        required
        help="Required. Recorded in the audit log and the configuration history."
        value={comment}
        disabled={disabled}
        onChange={(e) => {
          onComment(e.target.value);
        }}
      />
    </>
  );
}

function DiffList({
  label,
  names,
}: {
  label: string;
  names: readonly string[];
}): JSX.Element {
  return (
    <div>
      <strong>
        {label} {String(names.length)}
      </strong>
      {names.length > 0 && (
        <ul className={styles.diffNameList}>
          {names.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
