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
  resendContinuityRefusal,
  shortDigest,
  verifyOperationResult,
} from "./pacLifecycle";
import type { PacUnresolvedReason } from "./pacLifecycle";
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
  /** the history epoch the candidate was reviewed in (2F-E correction
   * round 2; "" on an appliance that predates the identity) */
  historyIncarnation: string;
  reason: string;
}

/** The run context that MUST survive every continuation of one attempt
 * (the DIRECT challenge ceremony above all — 2F-E correction round 2):
 * `marker` is the attempt's ORIGINAL recovery marker, carried verbatim, so
 * its bindings and dispatch time are never restamped (the store refuses a
 * rebinding anyway); `resend` says the attempt re-sends an earlier,
 * still-unresolved operation, whose marker a refusal must never erase —
 * only the authoritative read that follows may. */
interface RunOpts {
  marker?: PacRecoveryMarker;
  resend?: boolean;
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
      /** the attempt's run context, carried through the ceremony */
      opts: RunOpts;
      challenge: PacChallenge;
      result: ConfirmResult;
      errorText: string;
    }
  | { kind: "repair"; result: ConfirmResult; errorText: string }
  | { kind: "resend"; result: ConfirmResult; errorText: string }
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
  /** 2F-E correction (finding 4): local navigation is guarded on it */
  onDirtyChange?: (dirty: boolean) => void;
}

/** The recovery store as this profile sees it (2F-E correction, finding
 * 2): ONE outstanding operation across the whole PAC surface — a marker of
 * another profile, or a store that cannot be read, withholds every
 * lifecycle dispatch here just like an own unresolved operation does. */
type RecoveryState =
  | { kind: "none" }
  | { kind: "own"; marker: PacRecoveryMarker }
  | { kind: "foreign"; marker: PacRecoveryMarker }
  | { kind: "unreadable" }
  | { kind: "unavailable" };

function readRecoveryState(subject: string, profileId: string): RecoveryState {
  const read = readPacRecovery(subject);
  switch (read.kind) {
    case "valid":
      return read.marker.profileId === profileId
        ? { kind: "own", marker: read.marker }
        : { kind: "foreign", marker: read.marker };
    case "none":
      return { kind: "none" };
    case "unreadable":
    case "unavailable":
      return { kind: read.kind };
  }
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
  const [recovery, setRecovery] = useState<RecoveryState>({ kind: "none" });
  const unresolved = recovery.kind === "own" ? recovery.marker : null;
  // why the last authoritative read left the own operation unresolved
  const [basis, setBasis] = useState<PacUnresolvedReason | null>(null);
  const [recovering, setRecovering] = useState(false);
  const [editorDirty, setEditorDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [simUrl, setSimUrl] = useState("");
  const [sim, setSim] = useState<PacSimResult | null>(null);
  const [simError, setSimError] = useState("");

  // Recovery hydration: the store is read under THIS subject; an own
  // marker, a foreign marker, or an unreadable/unavailable store all latch
  // the surface until resolved (never cleared on unmount).
  useEffect(() => {
    setRecovery(readRecoveryState(subject, p.id));
  }, [subject, p.id]);
  const { onDirtyChange } = p;
  useEffect(() => {
    onDirtyChange?.(editorDirty);
  }, [editorDirty, onDirtyChange]);

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
    recovery.kind !== "none" ||
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
  // The server digest of the candidate an operation commits — a publish
  // sends the saved draft (else the active spec when no draft exists), a
  // rollback re-publishes the recorded spec of revision targetN.
  const candidateDigest = (
    action: PacRecoveryAction,
    targetN: number,
  ): string => {
    if (lc === undefined) return "";
    if (action === "publish")
      return lc.draft !== undefined ? lc.draftSpecDigest : lc.activeSpecDigest;
    return lc.revisions.find((r) => r.n === targetN)?.specDigest ?? "";
  };

  const runOperation = async (
    args: OpArgs,
    confirm: PacConfirmEcho | undefined,
    opts: RunOpts = {},
  ): Promise<void> => {
    if (lc === undefined) return;
    // A continuation (the challenge confirmation) or a re-send is the SAME
    // attempt: the original marker, verbatim (its write below is then an
    // identical no-op — the store refuses any rebinding). A fresh dispatch
    // binds the candidate, the fences and the history epoch it was
    // reviewed in.
    const marker: PacRecoveryMarker = opts.marker ?? {
      operationId: args.operationId,
      action: args.action,
      profileId: p.id,
      expectedActiveRevision: args.expectedActiveRevision,
      expectedActiveSpecDigest: args.expectedActiveSpecDigest,
      candidateSpecDigest: candidateDigest(args.action, args.targetN),
      targetN: args.targetN,
      startedAt: Date.now(),
      collectionEtag: args.collectionEtag,
      historyIncarnation: args.historyIncarnation,
    };
    // NO DURABLE MARKER ⇒ NO DISPATCH — and never over another operation's
    // marker or an unreadable store (single outstanding operation).
    if (!writePacRecovery(subject, marker)) {
      const state = readRecoveryState(subject, p.id);
      setRecovery(state);
      setCeremony((c) =>
        c.kind === "publish" ||
        c.kind === "rollback" ||
        c.kind === "challenge" ||
        c.kind === "resend"
          ? {
              ...c,
              result: "failed",
              errorText:
                state.kind === "foreign" || state.kind === "own"
                  ? "Another operation is still unresolved in this browser; nothing was sent. Resolve it first."
                  : "The operation identity could not be persisted in this browser; nothing was sent. Repair browser storage and retry.",
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
                historyIncarnation: args.historyIncarnation,
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
                historyIncarnation: args.historyIncarnation,
                ...(confirm !== undefined ? { confirm } : {}),
              },
              signal,
            );
      // A 2xx is a PROVEN commit only when it names THIS operation and
      // carries the action's positive commit flag; anything else keeps the
      // marker and is resolved authoritatively.
      const verdict = verifyOperationResult(res, {
        operationId: args.operationId,
        action: args.action,
      });
      if (!verdict.ok) {
        setRecovery({ kind: "own", marker });
        setBasis(null);
        setCeremony({ kind: "none" });
        setNotice({
          variant: "warning",
          title: "Response could not be tied to this operation",
          text:
            verdict.reason === "identity"
              ? `The appliance answered for operation ${shortDigest(res.operationId)}, not ${shortDigest(args.operationId)}. Nothing is assumed — use Recover.`
              : "The answer carries no positive commit evidence for this action. Nothing is assumed — use Recover.",
        });
        return;
      }
      clearPacRecovery(args.operationId);
      setRecovery(readRecoveryState(subject, p.id));
      setBasis(null);
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
        setRecovery({ kind: "own", marker });
        setBasis(null);
        setCeremony({ kind: "none" });
        setNotice(null);
        return;
      }
      const continuesSameOperation =
        f.kind === "challenge" && f.challenge.code === "confirm_required";
      // A refusal of a RE-SEND keeps the marker: whether the operation
      // committed earlier is decided by the authoritative read that follows.
      if (!continuesSameOperation && opts.resend !== true)
        clearPacRecovery(args.operationId);
      if (!continuesSameOperation)
        setRecovery(readRecoveryState(subject, p.id));
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
              // the confirmation continues THIS attempt: same marker, same
              // re-send posture
              opts: {
                marker,
                ...(opts.resend === true ? { resend: true } : {}),
              },
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
            c.kind === "challenge" ||
            c.kind === "resend"
              ? { ...c, result: "failed", errorText: f.text }
              : c,
          );
          break;
        case "unknown":
          break;
      }
      if (opts.resend === true && !continuesSameOperation) {
        setCeremony({ kind: "none" });
        await recoverMarker(marker);
      }
    } finally {
      page.owner.settle(signal);
    }
  };

  // ── re-send of an UNRESOLVED operation: the SAME operationId, the SAME
  // candidate and fences. At most once on the appliance: a landed one is
  // replayed, a stale one is refused, otherwise it lands now. ──────────────
  const resendBlocked = (): string | null => {
    if (unresolved === null || lc === undefined) return "nothing to re-send";
    // replay safety first (2F-E correction round 2): at-most-once holds only
    // within the history epoch the operation was dispatched in
    const continuity = resendContinuityRefusal(unresolved, lc);
    if (continuity !== null) return continuity;
    const digest = candidateDigest(unresolved.action, unresolved.targetN);
    if (digest !== unresolved.candidateSpecDigest)
      return unresolved.action === "publish"
        ? "the reviewed candidate is no longer the saved draft"
        : "the reviewed rollback target is no longer recorded";
    if (unresolved.action === "publish" && candidate === undefined)
      return "no candidate exists any more";
    return null;
  };
  const startResend = (): void => {
    if (unresolved === null || lc === undefined || candidate === undefined)
      return;
    setCeremony({ kind: "resend", result: "pending", errorText: "" });
    void runOperation(
      {
        action: unresolved.action,
        operationId: unresolved.operationId,
        draft: candidate,
        targetN: unresolved.targetN,
        expectedActiveRevision: unresolved.expectedActiveRevision,
        expectedActiveSpecDigest: unresolved.expectedActiveSpecDigest,
        // the ORIGINAL fences and epoch — never the freshest tokens
        collectionEtag: unresolved.collectionEtag,
        historyIncarnation: unresolved.historyIncarnation,
        reason: "",
      },
      undefined,
      { marker: unresolved, resend: true },
    );
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
        historyIncarnation: lc.historyIncarnation ?? "",
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
        historyIncarnation: lc.historyIncarnation ?? "",
        reason,
      },
      undefined,
    );
  };

  // ── authoritative recovery ─────────────────────────────────────────────
  const recoverMarker = async (marker: PacRecoveryMarker): Promise<void> => {
    setRecovering(true);
    const signal = page.owner.begin();
    try {
      const fresh = await getPacLifecycle(p.id, signal, {
        operationId: marker.operationId,
      });
      const r = classifyRecovery(marker, fresh);
      const id = shortDigest(marker.operationId);
      const resolved = (): void => {
        clearPacRecovery(marker.operationId);
        setRecovery(readRecoveryState(subject, p.id));
        setBasis(null);
      };
      switch (r.kind) {
        case "landed":
          resolved();
          setNotice({
            variant: r.committed ? "success" : "warning",
            title: r.committed
              ? `Operation ${id} landed — committed as history revision ${String(r.revisionN)}`
              : `Operation ${id} landed — decided ${r.state}, nothing committed`,
            text: r.committed
              ? (r.currentlyActive
                  ? "It is the active revision on this node."
                  : "It is no longer the active revision — a later publish or rollback superseded it; see the publish history.") +
                ` (decided ${r.state}, HTTP ${String(r.status)})`
              : `The appliance decided this ${marker.action} as ${r.state} (HTTP ${String(r.status)}) — nothing was committed.`,
          });
          break;
        case "pending":
          setBasis(null);
          setNotice({
            variant: "info",
            title: `Operation ${id} still pending`,
            text: "The appliance is reconciling it; recover again in a moment. Nothing is re-dispatched.",
          });
          break;
        case "ambiguous":
          resolved();
          setNotice({
            variant: "critical",
            title: `Operation ${id} is ambiguous on the appliance`,
            text: "Repair (accept active) below records the observed active profile; nothing is re-dispatched.",
          });
          break;
        case "not_landed":
          resolved();
          setNotice({
            variant: "info",
            title: `Operation ${id} did not land`,
            text: "Proven: the appliance's retained history is complete and holds no record of it, and the reviewed active revision has moved, so it can no longer be committed. Review the draft against the fresh active profile before publishing again.",
          });
          break;
        case "unresolved":
          setBasis(r.reason);
          setNotice({
            variant: "warning",
            title:
              r.reason === "not_observed"
                ? `Operation ${id} not observed on the appliance`
                : r.reason === "history_bounded"
                  ? `Operation ${id} — history evidence is bounded`
                  : r.reason === "history_reset"
                    ? `Operation ${id} — the history was reset`
                    : r.reason === "history_discontinuity"
                      ? `Operation ${id} — history continuity is broken`
                      : `Operation ${id} — the history is missing`,
            text:
              r.reason === "not_observed"
                ? "The appliance holds no record of it and the reviewed base is unchanged, so the request may still be in flight or may never have arrived. Nothing is proven. Re-send the SAME operation (at most once on the appliance: a landed one is replayed, a stale one is refused, otherwise it lands now) or abandon it deliberately."
                : r.reason === "history_bounded"
                  ? `The appliance retains only the last ${String(fresh.operationsCap ?? 64)} decisions for this profile and this operation is not among them; older decisions were evicted, so absence proves nothing. Re-send the SAME operation (a still-retained landed one is replayed; a stale one is refused) or review the publish history and abandon deliberately.`
                  : r.reason === "history_reset"
                    ? "The node-local history was quarantined after this operation was dispatched, so its record may be lost. Acknowledge the reset first; the operation then stays unresolved (the reset started a new history epoch) — review the current lifecycle and abandon it deliberately, or dispatch a NEW operation."
                    : r.reason === "history_discontinuity"
                      ? "The appliance's history epoch is not the one this operation was dispatched in (the profile was deleted and recreated, or its history was reset — or the epoch is unknown on one side), so its decision record may simply be gone: absence proves nothing, and a re-send would run it AGAIN as a new operation, so it is withheld. Review the current active profile and history; abandon the marker deliberately once you have."
                      : "No active spec or history exists for this profile on this node any more, so nothing can prove or disprove the commit. Abandon it deliberately once you have reviewed the profile.",
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

  const recover = async (): Promise<void> => {
    if (unresolved === null) return;
    await recoverMarker(unresolved);
  };

  // ── draft save / repair / ack / delete ─────────────────────────────────
  // The save carries the BASE revision the edit was made against (2F-E
  // correction, finding 4) — never the freshest token the page holds.
  const saveDraft = async (
    draft: PacProfileInput,
    baseRevision: number,
  ): Promise<void> => {
    if (lc === undefined) return;
    setSaving(true);
    clearRefusals();
    const signal = page.owner.begin();
    try {
      await savePacDraft(p.id, draft, baseRevision, signal);
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
            The request was dispatched but no verified result was observed. Its
            identity (<Mono>{unresolved.operationId}</Mono>) was persisted
            before dispatch; the appliance decides an operation at most once.
            Recover reads the lifecycle and resolves it from the appliance's own
            records — nothing is retried blindly. Publish and rollback are
            withheld on every profile until it is resolved.
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
              {basis !== null &&
                basis !== "history_reset" &&
                basis !== "history_discontinuity" &&
                basis !== "history_missing" && (
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={recovering || resendBlocked() !== null}
                    title={resendBlocked() ?? undefined}
                    onClick={() => {
                      setCeremony({
                        kind: "resend",
                        result: "idle",
                        errorText: "",
                      });
                    }}
                  >
                    Re-send same operation
                  </Button>
                )}
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
          {basis !== null && resendBlocked() !== null && (
            <p>Re-send is not possible: {resendBlocked()}.</p>
          )}
        </Callout>
      )}
      {recovery.kind === "foreign" && (
        <Callout
          variant="unknown"
          title={`Unresolved ${recovery.marker.action} operation on profile ${recovery.marker.profileId}`}
          role="alert"
        >
          Operation <Mono>{recovery.marker.operationId}</Mono> on profile{" "}
          <Mono>{recovery.marker.profileId}</Mono> was dispatched without an
          observed result. One operation may be outstanding across the whole PAC
          surface: publish and rollback are withheld here until it is resolved
          on that profile (Recover, or the typed Abandon).
        </Callout>
      )}
      {(recovery.kind === "unreadable" || recovery.kind === "unavailable") && (
        <Callout
          variant="warning"
          title={`Recovery store ${recovery.kind}`}
          role="alert"
        >
          The browser storage that holds the operation-identity marker is{" "}
          {recovery.kind}; an earlier operation may be unresolved and no new
          identity could be persisted. Publish and rollback are withheld until
          the storage is repaired or this tab is closed.
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
                serverRevision={lc.draft !== undefined ? lc.draftRevision : 0}
                pools={p.pools}
                disabled={lifecycleBlocked}
                saving={saving}
                onSave={(d, baseRevision) => {
                  void saveDraft(d, baseRevision);
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
            void runOperation(
              ceremony.args,
              {
                challenge: ceremony.challenge.challenge,
                value: typed,
                binding: ceremony.challenge.binding,
              },
              ceremony.opts,
            );
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
      {ceremony.kind === "resend" &&
        unresolved !== null &&
        lc !== undefined && (
          <ConfirmationDialog
            open
            tier={2}
            title={`Re-send the unresolved ${unresolved.action}`}
            body={
              <div>
                <p>
                  Sends operation <Mono>{unresolved.operationId}</Mono> again
                  with the SAME reviewed candidate (
                  <Mono>{shortDigest(unresolved.candidateSpecDigest)}</Mono>)
                  and the same fence (active revision{" "}
                  {String(unresolved.expectedActiveRevision)}). The appliance
                  decides an operation at most once: if it already landed, the
                  recorded outcome is replayed; if the active revision moved, it
                  is refused; otherwise it lands now.
                </p>
              </div>
            }
            impact="Clients receive the new PAC on their next fetch if the operation lands now; nothing else is changed."
            rollback="Roll back to the previous history revision through the Publish history."
            confirmLabel="Re-send now"
            result={ceremony.result}
            {...(ceremony.errorText !== ""
              ? { errorText: ceremony.errorText }
              : {})}
            onConfirm={() => {
              if (ceremony.result !== "pending") startResend();
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
            clearPacRecovery(unresolved.operationId);
            setRecovery(readRecoveryState(subject, p.id));
            setBasis(null);
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
