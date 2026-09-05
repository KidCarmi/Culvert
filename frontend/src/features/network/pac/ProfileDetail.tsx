// 2F-E — one PAC profile's lifecycle: ACTIVE (the cluster-synced,
// authoritative store) vs DRAFT + HISTORY (node-local), the publish /
// rollback intent state machine, the bound DIRECT challenge, the
// history-reset acknowledgement, ambiguity repair, and the lost-response
// recovery that resolves an operation AUTHORITATIVELY from the lifecycle
// GET before any fresh dispatch is allowed.
//
// Truth rules (contract §8.D7/D12/D13, migration-plan C1/C2/C8):
//  - every publish/rollback carries the tokens the candidate was REVIEWED
//    against (expectedActiveRevision + collectionEtag) and the SAVED server
//    draft — never the editor's unsaved state;
//  - a transport death after dispatch is UNKNOWN: the operation identity was
//    persisted BEFORE the POST and only "Recover" (a GET) or the typed
//    abandon ceremony clears it; nothing is ever re-dispatched blindly;
//  - "pending_reconciliation" is a PROVEN commit whose node-local effects are
//    still being completed — rendered as published, never "not published".
import { useEffect, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../../design-system/primitives";
import { InputField } from "../../../design-system/forms";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../../design-system/dialog";
import { SnapshotBar } from "../../../shared/snapshot";
import { useAuth } from "../../../auth/AuthProvider";
import { useObjectPage } from "../../objects/useObjectPage";
import {
  serverErrorText,
  unknownOutcome,
} from "../../../shared/mutationOutcome";
import {
  acknowledgePacHistoryReset,
  asPacFence,
  asPacIssues,
  deletePacProfile,
  getPacLifecycle,
  mintPacOperationId,
  publishPacProfile,
  repairPacProfile,
  rollbackPacProfile,
  savePacDraft,
  simulatePac,
} from "../../../api/pac";
import type {
  PacChallenge,
  PacConfirmEcho,
  PacFenceRefusal,
  PacHistoryReset,
  PacIssuesRefusal,
  PacLifecycle,
  PacPool,
  PacProfileInput,
  PacSimResult,
} from "../../../api/pac";
import {
  classifyDispatchFailure,
  classifyRecovery,
  failureKeepsMarker,
  landedStateCommitted,
  shortDigest,
} from "./pacLifecycle";
import {
  clearPacRecovery,
  readPacRecovery,
  writePacRecovery,
  type PacRecoveryAction,
  type PacRecoveryMarker,
} from "./pacRecovery";
import {
  ChallengeCeremony,
  ChallengeStaleCallout,
  FenceCallout,
  IssuesCallout,
  NODE_LOCAL_NOTE,
} from "./pacShared";
import { ProfileDraftEditor } from "./ProfileDraftEditor";
import styles from "../../policy/policy.module.css";

interface OpArgs {
  action: PacRecoveryAction;
  operationId: string;
  draft: PacProfileInput;
  targetN: number;
  expectedActiveRevision: number;
  expectedActiveSpecDigest: string;
  collectionEtag: string;
  reason: string;
}

type Ceremony =
  | { kind: "none" }
  | {
      kind: "publish";
      reason: string;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "rollback";
      targetN: number;
      reason: string;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "challenge";
      args: OpArgs;
      challenge: PacChallenge;
      result: ConfirmResult;
      errorText: string;
    }
  | { kind: "repair"; result: ConfirmResult; errorText: string }
  | { kind: "ack"; result: ConfirmResult; errorText: string }
  | { kind: "abandon"; typed: string }
  | { kind: "delete"; typed: string; result: ConfirmResult; errorText: string };

interface Notice {
  variant: "success" | "info" | "warning" | "critical";
  title: string;
  text: string;
}

export interface ProfileDetailProps {
  id: string;
  isAdmin: boolean;
  pools: readonly PacPool[];
  onBack: () => void;
  onChanged: () => void;
}

export function ProfileDetail(p: ProfileDetailProps): JSX.Element {
  const { state: auth } = useAuth();
  const subject = auth.user ?? "";
  const page = useObjectPage(["network", "pac", "lifecycle", p.id], (signal) =>
    getPacLifecycle(p.id, signal),
  );
  const lc = page.q.data;
  // The REVIEWED CANDIDATE: the saved node-local draft when one exists,
  // otherwise the current active spec (an initial publish records the
  // profile as it is served today — the backend keeps no draft until one
  // is saved).
  const candidate = lc === undefined ? undefined : (lc.draft ?? lc.active);
  const [ceremony, setCeremony] = useState<Ceremony>({ kind: "none" });
  const [notice, setNotice] = useState<Notice | null>(null);
  const [fence, setFence] = useState<{
    fence: PacFenceRefusal;
    token: string;
  } | null>(null);
  const [staleChallenge, setStaleChallenge] = useState<PacChallenge | null>(
    null,
  );
  const [issues, setIssues] = useState<PacIssuesRefusal | null>(null);
  const [resetRefusal, setResetRefusal] = useState<{
    reset: PacHistoryReset;
    activeRevision: number;
    activeSpecDigest: string;
  } | null>(null);
  const [unresolved, setUnresolved] = useState<PacRecoveryMarker | null>(null);
  const [recovering, setRecovering] = useState(false);
  const [editorDirty, setEditorDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [simUrl, setSimUrl] = useState("");
  const [sim, setSim] = useState<PacSimResult | null>(null);
  const [simError, setSimError] = useState("");

  // Recovery hydration: a marker for THIS profile written under THIS
  // subject latches the surface until it is resolved (never on unmount).
  useEffect(() => {
    const read = readPacRecovery(subject);
    if (read.kind === "valid" && read.marker.profileId === p.id)
      setUnresolved(read.marker);
    if (read.kind === "unreadable" || read.kind === "unavailable") {
      setNotice({
        variant: "warning",
        title:
          "Recovery store " +
          (read.kind === "unreadable" ? "unreadable" : "unavailable"),
        text: "An earlier operation marker could not be read; publish and rollback stay withheld until the browser storage is repaired or this tab is closed.",
      });
    }
  }, [subject, p.id]);

  const clearRefusals = (): void => {
    setFence(null);
    setStaleChallenge(null);
    setIssues(null);
  };

  const historyReset =
    resetRefusal ??
    (lc?.historyState === "history_reset" && lc.historyReset !== undefined
      ? {
          reset: lc.historyReset,
          activeRevision: lc.activeRevision,
          activeSpecDigest: lc.activeSpecDigest,
        }
      : null);
  const lifecycleBlocked =
    unresolved !== null ||
    page.unknown !== null ||
    historyReset !== null ||
    (lc !== undefined && lc.state !== "idle");
  const canPublish =
    p.isAdmin &&
    lc !== undefined &&
    candidate !== undefined &&
    !lifecycleBlocked &&
    !editorDirty &&
    !saving;

  // ── the operation runner (publish / rollback, challenge retry) ─────────
  const runOperation = async (
    args: OpArgs,
    confirm: PacConfirmEcho | undefined,
  ): Promise<void> => {
    if (lc === undefined) return;
    const marker: PacRecoveryMarker = {
      operationId: args.operationId,
      action: args.action,
      profileId: p.id,
      expectedActiveRevision: args.expectedActiveRevision,
      expectedActiveSpecDigest: args.expectedActiveSpecDigest,
      candidateSpecDigest: "",
      targetN: args.targetN,
      startedAt: Date.now(),
    };
    // NO DURABLE MARKER ⇒ NO DISPATCH.
    if (!writePacRecovery(subject, marker)) {
      setCeremony((c) =>
        c.kind === "publish" || c.kind === "rollback" || c.kind === "challenge"
          ? {
              ...c,
              result: "failed",
              errorText:
                "The operation identity could not be persisted in this browser; nothing was sent. Repair browser storage and retry.",
            }
          : c,
      );
      return;
    }
    clearRefusals();
    const signal = page.owner.begin();
    try {
      const res =
        args.action === "publish"
          ? await publishPacProfile(
              p.id,
              {
                operationId: args.operationId,
                draft: args.draft,
                expectedActiveRevision: args.expectedActiveRevision,
                collectionEtag: args.collectionEtag,
                reason: args.reason,
                ...(confirm !== undefined ? { confirm } : {}),
              },
              signal,
            )
          : await rollbackPacProfile(
              p.id,
              {
                operationId: args.operationId,
                targetN: args.targetN,
                expectedActiveRevision: args.expectedActiveRevision,
                collectionEtag: args.collectionEtag,
                reason: args.reason,
                ...(confirm !== undefined ? { confirm } : {}),
              },
              signal,
            );
      clearPacRecovery();
      setUnresolved(null);
      setCeremony({ kind: "none" });
      const pendingNote =
        res.historyState === "pending_reconciliation"
          ? " The commit is PROVEN; its node-local history/version/cluster effects are still being completed (pending reconciliation) — refresh to see them settle."
          : "";
      setNotice({
        variant: "success",
        title: args.action === "publish" ? "Published" : "Rolled back",
        text:
          (args.action === "publish"
            ? `Active revision ${String(res.activeRevision)} (history revision ${String(res.revision)}), operation ${shortDigest(res.operationId)}.`
            : `Rolled back to revision ${String(res.toRevision)} as new history revision ${String(res.newRevision)} (active revision ${String(res.activeRevision)}), operation ${shortDigest(res.operationId)}.`) +
          pendingNote +
          " Scope: node-local history.",
      });
      page.refreshToResolve();
      p.onChanged();
    } catch (err) {
      const f = classifyDispatchFailure(err);
      if (failureKeepsMarker(f)) {
        setUnresolved(marker);
        setCeremony({ kind: "none" });
        setNotice(null);
        return;
      }
      clearPacRecovery();
      switch (f.kind) {
        case "fence":
          setCeremony({ kind: "none" });
          setFence({ fence: f.fence, token: "revision" });
          page.refreshToResolve();
          break;
        case "challenge":
          if (f.challenge.code === "confirm_required") {
            setCeremony({
              kind: "challenge",
              args,
              challenge: f.challenge,
              result: "idle",
              errorText: "",
            });
          } else {
            setCeremony({ kind: "none" });
            setStaleChallenge(f.challenge);
            page.refreshToResolve();
          }
          break;
        case "history_reset":
          setCeremony({ kind: "none" });
          setResetRefusal({
            reset: f.reset.reset,
            activeRevision: f.reset.activeRevision,
            activeSpecDigest: f.reset.activeSpecDigest,
          });
          page.refreshToResolve();
          break;
        case "operation_pending":
          setCeremony({ kind: "none" });
          setNotice({
            variant: "warning",
            title: "Another operation is pending",
            text: `Operation ${shortDigest(f.pending.operationId)} is ${f.pending.state} on the appliance; refresh to let it reconcile. Nothing was changed.`,
          });
          page.refreshToResolve();
          break;
        case "ambiguous":
          setCeremony({ kind: "none" });
          setNotice({
            variant: "critical",
            title: "Outcome ambiguous on the appliance",
            text: `The appliance cannot classify operation ${shortDigest(f.ambiguous.operationId)} (observed revision ${String(f.ambiguous.observedRevision)}). Repair below records the observed active profile; the active store is never rewritten.`,
          });
          page.refreshToResolve();
          break;
        case "server_outcome":
          setCeremony({ kind: "none" });
          setNotice({
            variant: "critical",
            title: "Write failed — nothing was changed",
            text: f.outcome.message,
          });
          page.refreshToResolve();
          break;
        case "issues":
          setCeremony({ kind: "none" });
          setIssues(f.issues);
          break;
        case "refused":
          setCeremony((c) =>
            c.kind === "publish" ||
            c.kind === "rollback" ||
            c.kind === "challenge"
              ? { ...c, result: "failed", errorText: f.text }
              : c,
          );
          break;
        case "unknown":
          break;
      }
    } finally {
      page.owner.settle(signal);
    }
  };

  const startPublish = (reason: string): void => {
    if (lc === undefined || candidate === undefined) return;
    setCeremony({ kind: "publish", reason, result: "pending", errorText: "" });
    void runOperation(
      {
        action: "publish",
        operationId: mintPacOperationId(),
        draft: candidate,
        targetN: 0,
        expectedActiveRevision: lc.activeRevision,
        expectedActiveSpecDigest: lc.activeSpecDigest,
        collectionEtag: lc.collectionEtag,
        reason,
      },
      undefined,
    );
  };

  const startRollback = (targetN: number, reason: string): void => {
    if (lc === undefined || candidate === undefined) return;
    setCeremony({
      kind: "rollback",
      targetN,
      reason,
      result: "pending",
      errorText: "",
    });
    void runOperation(
      {
        action: "rollback",
        operationId: mintPacOperationId(),
        draft: candidate,
        targetN,
        expectedActiveRevision: lc.activeRevision,
        expectedActiveSpecDigest: lc.activeSpecDigest,
        collectionEtag: lc.collectionEtag,
        reason,
      },
      undefined,
    );
  };

  // ── authoritative recovery ─────────────────────────────────────────────
  const recover = async (): Promise<void> => {
    if (unresolved === null) return;
    setRecovering(true);
    const signal = page.owner.begin();
    try {
      const fresh = await getPacLifecycle(p.id, signal);
      const r = classifyRecovery(unresolved, fresh);
      const id = shortDigest(unresolved.operationId);
      switch (r.kind) {
        case "landed":
          clearPacRecovery();
          setUnresolved(null);
          setNotice({
            variant: landedStateCommitted(r.state) ? "success" : "warning",
            title: `Operation ${id} landed`,
            text: `The appliance decided this ${unresolved.action}: ${r.state} (HTTP ${String(r.status)}). ${landedStateCommitted(r.state) ? "The candidate is the active profile." : "Nothing was committed."}`,
          });
          break;
        case "pending":
          setNotice({
            variant: "info",
            title: `Operation ${id} still pending`,
            text: "The appliance is reconciling it; recover again in a moment. Nothing is re-dispatched.",
          });
          break;
        case "ambiguous":
          clearPacRecovery();
          setUnresolved(null);
          setNotice({
            variant: "critical",
            title: `Operation ${id} is ambiguous on the appliance`,
            text: "Repair (accept active) below records the observed active profile; nothing is re-dispatched.",
          });
          break;
        case "not_landed":
          clearPacRecovery();
          setUnresolved(null);
          setNotice({
            variant: "info",
            title: `Operation ${id} did not land`,
            text:
              "No intent for it exists on the appliance — nothing was committed." +
              (r.baseMoved
                ? " The active revision moved meanwhile: review the draft against the fresh active profile before publishing again."
                : " You may dispatch a fresh operation."),
          });
          break;
      }
      page.refreshToResolve();
    } catch (err) {
      setNotice({
        variant: "warning",
        title: "Recovery read failed",
        text: `${serverErrorText(err, "The lifecycle could not be read.")} The operation stays unresolved.`,
      });
    } finally {
      page.owner.settle(signal);
      setRecovering(false);
    }
  };

  // ── draft save / repair / ack / delete ─────────────────────────────────
  const saveDraft = async (draft: PacProfileInput): Promise<void> => {
    if (lc === undefined) return;
    setSaving(true);
    clearRefusals();
    const signal = page.owner.begin();
    try {
      await savePacDraft(p.id, draft, lc.draftRevision, signal);
      setNotice({
        variant: "success",
        title: "Draft saved",
        text: "The node-local draft was updated; publish sends exactly this saved draft.",
      });
      page.refreshToResolve();
    } catch (err) {
      const f = asPacFence(err);
      const i = asPacIssues(err);
      if (f !== null) {
        setFence({ fence: f, token: "draft revision" });
        page.refreshToResolve();
      } else if (i !== null) setIssues(i);
      else if (unknownOutcome(err)) page.latchUnknown("edit");
      else
        setNotice({
          variant: "critical",
          title: "Draft not saved",
          text: serverErrorText(err, "The appliance refused the draft."),
        });
    } finally {
      page.owner.settle(signal);
      setSaving(false);
    }
  };

  const runRepair = async (): Promise<void> => {
    setCeremony({ kind: "repair", result: "pending", errorText: "" });
    const signal = page.owner.begin();
    try {
      const r = await repairPacProfile(p.id, mintPacOperationId(), signal);
      setCeremony({ kind: "none" });
      setNotice({
        variant: "success",
        title: "Repaired",
        text: `The observed active profile was recorded as history revision ${String(r.revision)} (repaired). The active store was not rewritten.`,
      });
      page.refreshToResolve();
    } catch (err) {
      if (unknownOutcome(err)) {
        setCeremony({ kind: "repair", result: "unknown", errorText: "" });
        page.latchUnknown("edit");
      } else
        setCeremony({
          kind: "repair",
          result: "failed",
          errorText: serverErrorText(err, "Repair refused."),
        });
    } finally {
      page.owner.settle(signal);
    }
  };

  const runAck = async (): Promise<void> => {
    if (historyReset === null) return;
    setCeremony({ kind: "ack", result: "pending", errorText: "" });
    const signal = page.owner.begin();
    try {
      await acknowledgePacHistoryReset(
        p.id,
        {
          operationId: mintPacOperationId(),
          expectedActiveRevision: historyReset.activeRevision,
          expectedActiveSpecDigest: historyReset.activeSpecDigest,
        },
        signal,
      );
      setCeremony({ kind: "none" });
      setResetRefusal(null);
      setNotice({
        variant: "success",
        title: "History reset acknowledged",
        text: "Publish and rollback are available again; the quarantined history file stays on disk as evidence.",
      });
      page.refreshToResolve();
    } catch (err) {
      if (unknownOutcome(err)) {
        setCeremony({ kind: "ack", result: "unknown", errorText: "" });
        page.latchUnknown("edit");
      } else
        setCeremony({
          kind: "ack",
          result: "failed",
          errorText: serverErrorText(
            err,
            "Acknowledgement refused (the active revision may have moved — refresh).",
          ),
        });
    } finally {
      page.owner.settle(signal);
    }
  };

  const runDelete = async (): Promise<void> => {
    if (lc === undefined) return;
    setCeremony({
      kind: "delete",
      typed: p.id,
      result: "pending",
      errorText: "",
    });
    const signal = page.owner.begin();
    try {
      await deletePacProfile(p.id, lc.activeRevision, signal);
      setCeremony({ kind: "none" });
      p.onChanged();
      p.onBack();
    } catch (err) {
      if (unknownOutcome(err)) {
        setCeremony({
          kind: "delete",
          typed: p.id,
          result: "unknown",
          errorText: "",
        });
        page.latchUnknown("delete");
      } else {
        const f = asPacFence(err);
        setCeremony({
          kind: "delete",
          typed: p.id,
          result: "failed",
          errorText:
            f !== null
              ? `Refused: current revision ${String(f.current["revision"])} — refresh and retry.`
              : serverErrorText(err, "Delete refused."),
        });
      }
    } finally {
      page.owner.settle(signal);
    }
  };

  const runSimulate = async (): Promise<void> => {
    setSimError("");
    const signal = page.owner.begin();
    try {
      setSim(await simulatePac(p.id, { url: simUrl }, signal));
    } catch (err) {
      setSim(null);
      setSimError(serverErrorText(err, "Simulation failed."));
    } finally {
      page.owner.settle(signal);
    }
  };

  // ── render ─────────────────────────────────────────────────────────────
  return (
    <div>
      <div className={styles.toolbar}>
        <Button size="sm" variant="ghost" onClick={p.onBack}>
          ← All profiles
        </Button>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={lc !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
          }}
        />
      </div>
      <p className={styles.authNote}>{NODE_LOCAL_NOTE}</p>

      {unresolved !== null && (
        <Callout
          variant="unknown"
          title={`Outcome unknown — ${unresolved.action} operation ${shortDigest(unresolved.operationId)}`}
          role="alert"
        >
          <p>
            The request was dispatched but no result was observed. Its identity
            (<Mono>{unresolved.operationId}</Mono>) was persisted before
            dispatch; the appliance decides an operation at most once. Recover
            reads the lifecycle and resolves it authoritatively — nothing is
            retried blindly.
          </p>
          {p.isAdmin && (
            <div className={styles.toolbarActions}>
              <Button
                size="sm"
                variant="primary"
                disabled={recovering}
                onClick={() => {
                  void recover();
                }}
              >
                Recover
              </Button>
              <Button
                size="sm"
                variant="danger-quiet"
                disabled={recovering}
                onClick={() => {
                  setCeremony({ kind: "abandon", typed: "" });
                }}
              >
                Abandon marker
              </Button>
            </div>
          )}
        </Callout>
      )}
      {page.unknown !== null && (
        <Callout variant="unknown" title="Last change unconfirmed" role="alert">
          A request was sent but no result was observed. Refresh to resolve
          against the appliance before making further changes.
        </Callout>
      )}
      {notice !== null && (
        <Callout variant={notice.variant} title={notice.title} role="status">
          {notice.text}
        </Callout>
      )}
      {fence !== null && (
        <FenceCallout fence={fence.fence} tokenLabel={fence.token} />
      )}
      {staleChallenge !== null && (
        <ChallengeStaleCallout challenge={staleChallenge} />
      )}
      {issues !== null && <IssuesCallout issues={issues} />}

      {lc === undefined && page.q.isPending && (
        <Skeleton>Loading lifecycle…</Skeleton>
      )}
      {lc === undefined && page.q.isError && (
        <ErrorState title="Lifecycle unavailable">
          {serverErrorText(page.q.error, "The lifecycle could not be read.")}
        </ErrorState>
      )}
      {lc !== undefined && (
        <>
          {historyReset !== null && (
            <Callout
              variant="critical"
              title="Publish history quarantined — acknowledgement required"
              role="alert"
            >
              <p>
                The node-local publish history of this profile was found corrupt
                and quarantined to{" "}
                <Mono>{historyReset.reset.quarantinedTo}</Mono> (cause:{" "}
                {historyReset.reset.cause !== ""
                  ? historyReset.reset.cause
                  : "unknown"}
                , at {historyReset.reset.at}). Publish and rollback are withheld
                until an admin acknowledges against the reviewed active revision{" "}
                {String(historyReset.activeRevision)} (
                <Mono>{shortDigest(historyReset.activeSpecDigest)}</Mono>). The
                active profile itself is intact.
              </p>
              {p.isAdmin && (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    setCeremony({ kind: "ack", result: "idle", errorText: "" });
                  }}
                >
                  Acknowledge history reset
                </Button>
              )}
            </Callout>
          )}
          {lc.state === "ambiguous" && lc.ambiguous !== undefined && (
            <Callout
              variant="critical"
              title="Outcome ambiguous — repair required"
              role="alert"
            >
              <p>
                Operation <Mono>{lc.ambiguous.op.operationId}</Mono> (
                {lc.ambiguous.op.action}) could not be classified: observed
                active revision {String(lc.ambiguous.observedRevision)} (
                <Mono>{shortDigest(lc.ambiguous.observedSpecDigest)}</Mono>) at{" "}
                {lc.ambiguous.observedAt}. Repair records the OBSERVED active
                profile as a new history revision; it never rewrites the active
                store.
              </p>
              {p.isAdmin && (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    setCeremony({
                      kind: "repair",
                      result: "idle",
                      errorText: "",
                    });
                  }}
                >
                  Repair (accept active)
                </Button>
              )}
            </Callout>
          )}
          {lc.state === "pending" && lc.pendingOp !== undefined && (
            <Callout variant="info" title="Operation pending reconciliation">
              Operation <Mono>{lc.pendingOp.operationId}</Mono> (
              {lc.pendingOp.action}) is {lc.pendingOp.state}; effects — history{" "}
              {lc.pendingOp.progress.history ? "✓" : "…"}, config version{" "}
              {lc.pendingOp.progress.configVersion ? "✓" : "…"}, cluster{" "}
              {lc.pendingOp.progress.cluster ? "✓" : "…"}. Refresh reconciles
              it; publish and rollback wait.
            </Callout>
          )}

          <Card
            title={`${lc.active !== undefined && lc.active.name !== "" ? lc.active.name : p.id} — active profile`}
            actions={
              <span>
                <StatusBadge
                  status={
                    lc.historyState === "recorded"
                      ? "ok"
                      : lc.historyState === "pending_reconciliation"
                        ? "info"
                        : "critical"
                  }
                >
                  history {lc.historyState}
                </StatusBadge>{" "}
                <StatusBadge status="neutral">node-local history</StatusBadge>
              </span>
            }
          >
            <KeyValue
              items={[
                ["Profile id", <Mono key="id">{p.id}</Mono>],
                ["Active revision", String(lc.activeRevision)],
                [
                  "Active spec digest",
                  <Mono key="d">{shortDigest(lc.activeSpecDigest)}</Mono>,
                ],
                ["History revision", String(lc.activeN)],
                ...(lc.active !== undefined
                  ? [
                      ["Enabled", lc.active.enabled ? "yes" : "no"] as const,
                      [
                        "Pool",
                        lc.active.poolId !== "" ? lc.active.poolId : "—",
                      ] as const,
                      [
                        "Availability mode",
                        lc.active.availabilityMode,
                      ] as const,
                      ["Private networks", lc.active.privateNetworks] as const,
                      ["Rules", String(lc.active.rules.length)] as const,
                    ]
                  : [["Active profile", "not present on this node"] as const]),
                ["PAC path", <Mono key="p">{`/pac/${p.id}.pac`}</Mono>],
              ]}
            />
            {lc.poolChangedSince && (
              <Callout
                variant="warning"
                title="A referenced pool changed since this revision was published"
              >
                The served PAC now resolves to different pool endpoints than the
                ones reviewed at publish time. Review and publish again to
                record the current pools.
              </Callout>
            )}
          </Card>

          <Card
            title="Draft (node-local)"
            actions={
              <span>
                <StatusBadge status={lc.draftDirty ? "warn" : "neutral"}>
                  {lc.draftDirty
                    ? "draft differs from active"
                    : "draft = active"}
                </StatusBadge>{" "}
                <StatusBadge status="neutral">
                  draft revision {String(lc.draftRevision)}
                </StatusBadge>
              </span>
            }
          >
            {lc.draftDiff !== undefined && (
              <Callout
                variant={lc.draftDiff.securitySensitive ? "warning" : "info"}
                title="Reviewed difference vs active"
              >
                <ul>
                  {lc.draftDiff.newDirectPaths.map((d) => (
                    <li key={`n-${d}`}>
                      NEW DIRECT path: <Mono>{d}</Mono>
                    </li>
                  ))}
                  {lc.draftDiff.removedDirectPaths.map((d) => (
                    <li key={`r-${d}`}>
                      removed DIRECT path: <Mono>{d}</Mono>
                    </li>
                  ))}
                  {lc.draftDiff.rulesAdded.map((d) => (
                    <li key={`a-${d}`}>
                      rule added: <Mono>{d}</Mono>
                    </li>
                  ))}
                  {lc.draftDiff.rulesRemoved.map((d) => (
                    <li key={`x-${d}`}>
                      rule removed: <Mono>{d}</Mono>
                    </li>
                  ))}
                  {lc.draftDiff.rulesReordered && <li>rules reordered</li>}
                  {lc.draftDiff.poolChanged && (
                    <li>
                      pool {lc.draftDiff.oldPool} → {lc.draftDiff.newPool}
                    </li>
                  )}
                  {lc.draftDiff.availabilityChange !== "" && (
                    <li>availability: {lc.draftDiff.availabilityChange}</li>
                  )}
                  {lc.draftDiff.privateNetChange !== "" && (
                    <li>private networks: {lc.draftDiff.privateNetChange}</li>
                  )}
                </ul>
              </Callout>
            )}
            {candidate === undefined ? (
              <p>
                No draft and no active spec exist for this profile on this node
                — nothing can be reviewed or published.
              </p>
            ) : p.isAdmin ? (
              <ProfileDraftEditor
                serverDraft={candidate}
                pools={p.pools}
                disabled={lifecycleBlocked}
                saving={saving}
                onSave={(d) => {
                  void saveDraft(d);
                }}
                onDirtyChange={setEditorDirty}
              />
            ) : (
              <KeyValue
                items={[
                  ["Name", candidate.name],
                  ["Enabled", candidate.enabled ? "yes" : "no"],
                  ["Pool", candidate.poolId !== "" ? candidate.poolId : "—"],
                  ["Availability mode", candidate.availabilityMode],
                  ["Private networks", candidate.privateNetworks],
                  [
                    "Rules",
                    candidate.rules
                      .map(
                        (r) =>
                          `${r.kind} ${r.pattern} → ${r.action}${r.poolId !== undefined && r.poolId !== "" ? ` (${r.poolId})` : ""}`,
                      )
                      .join("; ") || "none",
                  ],
                ]}
              />
            )}
            {p.isAdmin && (
              <div className={styles.toolbarActions}>
                <Button
                  variant="primary"
                  disabled={!canPublish}
                  onClick={() => {
                    setCeremony({
                      kind: "publish",
                      reason: "",
                      result: "idle",
                      errorText: "",
                    });
                  }}
                >
                  Publish
                </Button>
              </div>
            )}
          </Card>

          <Card title="Publish history (node-local)">
            {lc.revisions.length === 0 ? (
              <p>No published revision recorded on this node yet.</p>
            ) : (
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <caption className={styles.srOnly}>
                    Published revisions
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">#</th>
                      <th scope="col">When</th>
                      <th scope="col">By</th>
                      <th scope="col">Reason</th>
                      <th scope="col">Spec digest</th>
                      <th scope="col">Operation</th>
                      {p.isAdmin && <th scope="col">Actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {[...lc.revisions].reverse().map((r) => (
                      <tr key={r.n}>
                        <td>
                          {r.n}
                          {r.n === lc.activeN && " (active)"}
                          {r.repaired && " (repaired)"}
                        </td>
                        <td>{r.ts}</td>
                        <td>{r.author}</td>
                        <td>{r.reason}</td>
                        <td>
                          <Mono>{shortDigest(r.specDigest)}</Mono>
                        </td>
                        <td>
                          <Mono>
                            {r.operationId !== ""
                              ? shortDigest(r.operationId)
                              : "—"}
                          </Mono>
                        </td>
                        {p.isAdmin && (
                          <td className={styles.rowActions}>
                            {r.n !== lc.activeN && (
                              <Button
                                size="sm"
                                disabled={lifecycleBlocked}
                                onClick={() => {
                                  setCeremony({
                                    kind: "rollback",
                                    targetN: r.n,
                                    reason: "",
                                    result: "idle",
                                    errorText: "",
                                  });
                                }}
                              >
                                {`Roll back to ${String(r.n)}`}
                              </Button>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="Simulate a URL against the active profile">
            <div className={styles.testerForm}>
              <InputField
                label="URL"
                placeholder="https://intranet.example/path"
                value={simUrl}
                onChange={(e) => {
                  setSimUrl(e.target.value);
                }}
              />
              <Button
                size="sm"
                disabled={simUrl.trim() === ""}
                onClick={() => {
                  void runSimulate();
                }}
              >
                Simulate
              </Button>
            </div>
            {simError !== "" && (
              <Callout variant="critical">{simError}</Callout>
            )}
            {sim !== null && (
              <KeyValue
                items={[
                  ["Directive", <Mono key="d">{sim.directive}</Mono>],
                  ["Outcome", sim.outcome],
                  [
                    "Matched rule",
                    sim.matchedRule !== undefined
                      ? `#${String(sim.matchedRule.index + 1)} ${sim.matchedRule.kind} ${sim.matchedRule.pattern} → ${sim.matchedRule.action}`
                      : "—",
                  ],
                  ["Reason", sim.reason],
                  [
                    "DIRECT possible",
                    sim.directPossible ? "yes (bypass path)" : "no",
                  ],
                  [
                    "Compiler",
                    `${sim.compilerVersion} · revision ${String(sim.revision)}`,
                  ],
                ]}
              />
            )}
          </Card>

          {p.isAdmin && (
            <Card title="Danger zone">
              <Button
                variant="danger"
                disabled={lifecycleBlocked}
                onClick={() => {
                  setCeremony({
                    kind: "delete",
                    typed: "",
                    result: "idle",
                    errorText: "",
                  });
                }}
              >
                Delete profile
              </Button>
            </Card>
          )}
        </>
      )}

      {/* ── ceremonies ── */}
      {ceremony.kind === "publish" && lc !== undefined && (
        <ConfirmationDialog
          open
          tier={2}
          title="Publish the saved draft"
          body={
            <div>
              <p>
                Publishes the SAVED node-local draft as active revision{" "}
                {String(lc.activeRevision + 1)} (reviewed against active
                revision {String(lc.activeRevision)}). The served PAC changes
                for every client that fetches <Mono>{`/pac/${p.id}.pac`}</Mono>.
              </p>
              {lc.draftDiff !== undefined &&
                lc.draftDiff.newDirectPaths.length > 0 && (
                  <p>
                    This draft introduces{" "}
                    {String(lc.draftDiff.newDirectPaths.length)} new DIRECT
                    path(s); the appliance will require a typed confirmation.
                  </p>
                )}
              <InputField
                label="Reason (recorded in the history)"
                value={ceremony.reason}
                onChange={(e) => {
                  setCeremony({ ...ceremony, reason: e.target.value });
                }}
              />
            </div>
          }
          impact="Clients receive the new PAC on their next fetch; there is no staged rollout."
          rollback="Roll back to the previous revision from the history (recorded as a new revision)."
          confirmLabel="Publish now"
          result={ceremony.result}
          {...(ceremony.errorText !== ""
            ? { errorText: ceremony.errorText }
            : {})}
          onConfirm={() => {
            if (ceremony.result !== "pending") startPublish(ceremony.reason);
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
      {ceremony.kind === "rollback" && lc !== undefined && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Roll back to revision ${String(ceremony.targetN)}`}
          body={
            <div>
              <p>
                Re-publishes the spec recorded as history revision{" "}
                {String(ceremony.targetN)} as a NEW revision (reviewed against
                active revision {String(lc.activeRevision)}). The history is
                never rewritten.
              </p>
              <InputField
                label="Reason (recorded in the history)"
                value={ceremony.reason}
                onChange={(e) => {
                  setCeremony({ ...ceremony, reason: e.target.value });
                }}
              />
            </div>
          }
          impact="Clients receive the rolled-back PAC on their next fetch. If the target reintroduces DIRECT paths the appliance will require a typed confirmation."
          rollback="Roll forward again from the history."
          confirmLabel="Roll back now"
          result={ceremony.result}
          {...(ceremony.errorText !== ""
            ? { errorText: ceremony.errorText }
            : {})}
          onConfirm={() => {
            if (ceremony.result !== "pending")
              startRollback(ceremony.targetN, ceremony.reason);
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
      {ceremony.kind === "challenge" && (
        <ChallengeCeremony
          open
          actionLabel={
            ceremony.args.action === "publish"
              ? "Publish bypass"
              : "Roll back with bypass"
          }
          challenge={ceremony.challenge}
          result={ceremony.result}
          errorText={ceremony.errorText}
          onConfirm={(typed) => {
            if (ceremony.result === "pending") return;
            setCeremony({ ...ceremony, result: "pending" });
            void runOperation(ceremony.args, {
              challenge: ceremony.challenge.challenge,
              value: typed,
              binding: ceremony.challenge.binding,
            });
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
      {ceremony.kind === "repair" && (
        <ConfirmationDialog
          open
          tier={2}
          title="Repair — accept the observed active profile"
          body={
            <p>
              Records the profile the appliance is CURRENTLY serving as a new
              history revision marked repaired, and clears the ambiguity. The
              active store is not rewritten.
            </p>
          }
          impact="The ambiguity is resolved in favour of what is actually active."
          rollback="Roll back from the history afterwards if the observed profile is not the intended one."
          confirmLabel="Repair"
          result={ceremony.result}
          {...(ceremony.errorText !== ""
            ? { errorText: ceremony.errorText }
            : {})}
          onConfirm={() => {
            if (ceremony.result !== "pending") void runRepair();
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
      {ceremony.kind === "ack" && historyReset !== null && (
        <ConfirmationDialog
          open
          tier={2}
          title="Acknowledge the quarantined history"
          body={
            <p>
              Binds the acknowledgement to active revision{" "}
              {String(historyReset.activeRevision)} (
              <Mono>{shortDigest(historyReset.activeSpecDigest)}</Mono>). If the
              active profile changed since you reviewed it, the appliance
              refuses.
            </p>
          }
          impact="Publish and rollback become available again on this node; the quarantined file stays on disk."
          rollback="None needed — the active profile is unchanged."
          confirmLabel="Acknowledge and continue"
          result={ceremony.result}
          {...(ceremony.errorText !== ""
            ? { errorText: ceremony.errorText }
            : {})}
          onConfirm={() => {
            if (ceremony.result !== "pending") void runAck();
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
      {ceremony.kind === "abandon" && unresolved !== null && (
        <ConfirmationDialog
          open
          tier={3}
          title="Abandon the unresolved operation marker"
          body={
            <p>
              Forgets operation <Mono>{unresolved.operationId}</Mono> in THIS
              browser only. Nothing is sent to the appliance; if the operation
              landed, its effect stays — check the history after refreshing.
            </p>
          }
          impact="The identity of a possibly-landed operation is discarded locally."
          rollback="None — recover first if you need certainty."
          confirmLabel="Abandon"
          confirmWord="ABANDON"
          typedValue={ceremony.typed}
          onTypedChange={(v) => {
            setCeremony({ kind: "abandon", typed: v });
          }}
          result="idle"
          onConfirm={() => {
            clearPacRecovery();
            setUnresolved(null);
            setCeremony({ kind: "none" });
            page.refreshToResolve();
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
      {ceremony.kind === "delete" && (
        <ConfirmationDialog
          open
          tier={3}
          title={`Delete profile ${p.id}`}
          body={
            <p>
              Removes the active profile, its node-local draft, its publish
              history and its DIRECT-exception governance record. Clients
              fetching its PAC path get 404.
            </p>
          }
          impact="Every client configured with this PAC path loses its proxy configuration."
          rollback="None — irreversible (recreate and republish)."
          confirmLabel="Delete profile"
          confirmWord={p.id}
          typedValue={ceremony.typed}
          onTypedChange={(v) => {
            setCeremony({ ...ceremony, typed: v });
          }}
          result={ceremony.result}
          {...(ceremony.errorText !== ""
            ? { errorText: ceremony.errorText }
            : {})}
          onConfirm={() => {
            if (ceremony.result !== "pending") void runDelete();
          }}
          onCancel={() => {
            setCeremony({ kind: "none" });
          }}
        />
      )}
    </div>
  );
}

export type { PacLifecycle };
