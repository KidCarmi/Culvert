// FE-6B.2 — the Certificates & CA WRITE surfaces: the ceremonies (rotate
// through the server-issued challenge, import / replace with the dry-run
// review, the typed delete, the OCSP posture set, the typed abandon), the
// recovery marker lifecycle and the bounded outcome callouts, composed by
// CertificatesPage through useCertMutations.
//
// Binding behaviour (FE-6B.2 directive):
//   1. every write carries the server-owned revision captured with the
//      REVIEWED candidate (the dry run's `current`, the challenge's
//      caRevision, the loaded inventory revision); a fence refusal renders
//      the authoritative current token and nothing retries;
//   2. the operationId is minted BEFORE dispatch and retained through the
//      challenge, the confirm and recovery (a re-send is the SAME operation);
//   3. a 2xx is a verdict only when action-bound (src/api/certificates.ts);
//      a malformed or contradictory answer is UNPROVEN;
//   4. ONE outstanding operation lives in the non-secret, subject-bound
//      marker written before dispatch; an unavailable store refuses dispatch;
//   5. a lost or unproven answer closes the ceremony (dropping every typed
//      secret with the dialog tree), keeps the marker and blocks every
//      mutation until recovery or explicit abandonment;
//   6. recovery is the authoritative lookup, preserving pending / committed /
//      audit-pending / aborted / recoverable-unknown / TERMINAL-unknown; a
//      404 alone is never proof of non-commit — it is "never recorded";
//   7. no automatic retry; an explicit Re-send only after a 404 (the
//      contract makes re-dispatching the same operation, candidate and
//      ORIGINAL fence safe: replay / 409 stale / 409 candidate_duplicate);
//   8. writer_evidence_superseded stays TERMINAL UNKNOWN; abandoning a
//      marker discards this browser's marker only, never a server operation;
//   9. private keys exist only in the OPEN ceremony's textareas and the
//      request body — never a URL, storage, the marker or a summary;
//  10. persisted ≠ served: a replace is not activation; a delete does not
//      stop the running listener; nothing restarts the appliance.
import { useEffect, useRef, useState } from "react";
import type { JSX, ReactNode } from "react";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { Switch, TextareaField } from "../../design-system/forms";
import {
  Button,
  Callout,
  KeyValue,
  Mono,
  StatusBadge,
} from "../../design-system/primitives";
import { ApiError } from "../../api/client";
import {
  CERT_TERMINAL_NOTHING_WRITTEN,
  activationPosture,
  asCertRefusal,
  certLookupRefusal,
  certUnproven,
  confirmCARotation,
  deleteUICert,
  dryRunCAImport,
  dryRunUIReplace,
  getCertOperation,
  importCA,
  operationPosture,
  pemDigest,
  replaceUICert,
  requestCARotationChallenge,
  setOCSPPosture,
} from "../../api/certificates";
import type {
  ActivationPosture,
  CADryRun,
  CARotateChallenge,
  CertOperation,
  CertRefusal,
  CertWriteOutcome,
  CertificateInventory,
  OCSPStatus,
  PEMPair,
  UIDryRun,
} from "../../api/certificates";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  certResendAllowed,
  clearCertRecovery,
  operationBoundToCertMarker,
  readCertRecovery,
  writeCertRecovery,
} from "./certRecovery";
import type {
  CertRecoveryAction,
  CertRecoveryMarker,
  CertRecoveryRead,
  CertRecoveryView,
} from "./certRecovery";

const ROTATE_WORD = "ROTATE";

function digestOf(colon: string): string {
  return colon.replace(/:/g, "").toLowerCase();
}

/** The CA identity that stands at a car1: fence IS the fence's digest (the
 * token is the DER digest), so the marker's previousFingerprint is derived
 * from the fence — the same value before and after the challenge. */
function fenceDigest(fence: string): string {
  return fence.replace(/^car1:/, "");
}

/** The typed word of the delete ceremony: the persisted certificate's first
 * eight fingerprint bytes exactly as displayed (identity-bound, bounded). */
export function deleteConfirmWord(fingerprint: string): string {
  return fingerprint.slice(0, 23);
}

function mintOperationId(): string {
  return crypto.randomUUID();
}

// ── Ceremony state ─────────────────────────────────────────────────────────

type Ceremony =
  | { kind: "closed" }
  | {
      kind: "rotate";
      operationId: string;
      fence: string;
      /** the CA the inventory shows now (the challenge states the exact one) */
      current: string;
      challenge: CARotateChallenge | null;
      expired: boolean;
      resend: boolean;
    }
  | {
      kind: "pair";
      target: "mitm" | "ui";
      operationId: string;
      pem: PEMPair;
      review: CADryRun | UIDryRun | null;
      /** re-send: the marker's fence + candidate identity the review must match */
      bound: { fence: string; candidate: string } | null;
    }
  | {
      kind: "delete";
      operationId: string;
      fence: string;
      fingerprint: string;
      subject: string;
      posture: ActivationPosture;
      resend: boolean;
    }
  | {
      kind: "ocsp";
      operationId: string;
      fence: string;
      desired: { enabled: boolean; source: string };
      runtime: { enabled: boolean };
      unchecked: number;
      enabled: boolean;
      resend: boolean;
    }
  | { kind: "abandon"; marker: CertRecoveryMarker };

export interface CertMutationOpeners {
  rotate: () => void;
  importCA: () => void;
  replaceUI: () => void;
  deleteUI: () => void;
  ocsp: () => void;
}

export interface CertMutations {
  /** every mutation control is disabled while an operation is outstanding */
  blocked: boolean;
  /** the control may be offered at all (admin + the object exists) */
  can: { rotate: boolean; deleteUI: boolean };
  open: CertMutationOpeners;
  /** callouts + the recovery card (render at the top of the tab) */
  notices: ReactNode;
  /** the open ceremony, if any (render once near the page root) */
  dialog: ReactNode;
}

interface UnprovenNote {
  action: string;
  status: number | undefined;
  /** the appliance answered the NON-terminal outcome_unknown */
  detail?: string;
}

function actionWord(a: CertRecoveryAction): string {
  switch (a) {
    case "rotate":
      return "Root CA rotation";
    case "import":
      return "Root CA import";
    case "replace":
      return "UI certificate replacement";
    case "delete":
      return "UI certificate deletion";
    case "ocsp":
      return "OCSP posture change";
  }
}

export function useCertMutations(args: {
  subject: string;
  isAdmin: boolean;
  inv: CertificateInventory | undefined;
  ocsp: OCSPStatus | undefined;
  refreshAll: () => void;
}): CertMutations {
  const { subject, isAdmin, inv, ocsp, refreshAll } = args;
  const [ceremony, setCeremony] = useState<Ceremony>({ kind: "closed" });
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState<string | undefined>(undefined);
  const [notice, setNotice] = useState<ReactNode>(null);
  const [refusal, setRefusal] = useState<{
    action: string;
    refusal: CertRefusal;
  } | null>(null);
  const [unproven, setUnproven] = useState<UnprovenNote | null>(null);
  const [markerFault, setMarkerFault] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<CertRecoveryRead>({
    kind: "unresolved",
  });
  const [view, setView] = useState<CertRecoveryView>({ kind: "none" });
  const ownerRef = useRef(createRequestRunOwner());
  /** the dispatch in flight — a second confirm never dispatches */
  const inFlight = useRef(false);

  useEffect(() => {
    setRecovery(readCertRecovery(subject));
  }, [subject]);

  // Auth boundary: abort the request, drop every ceremony (and its typed
  // secrets) and every rendered outcome; the marker module purges itself.
  useEffect(() => {
    const owner = ownerRef.current;
    const cleanup = (): void => {
      owner.abort();
      inFlight.current = false;
      setCeremony({ kind: "closed" });
      setResult("idle");
      setErrorText(undefined);
      setNotice(null);
      setRefusal(null);
      setUnproven(null);
      setMarkerFault(null);
      setView({ kind: "none" });
    };
    const unregister = registerAuthCleanup(cleanup);
    return () => {
      unregister();
      owner.abort();
    };
  }, []);

  const rereadRecovery = (): void => {
    setRecovery(readCertRecovery(subject));
  };
  const close = (): void => {
    setCeremony({ kind: "closed" });
    setResult("idle");
    setErrorText(undefined);
  };
  const clearOutcome = (): void => {
    setNotice(null);
    setRefusal(null);
    setUnproven(null);
    setMarkerFault(null);
  };

  const dirty =
    ceremony.kind === "pair" &&
    (ceremony.pem.cert !== "" || ceremony.pem.key !== "");
  const guard = useDirtyGuard(dirty, "the certificate candidate");

  const blocked = recovery.kind !== "none" || result === "pending";
  const canMutate = isAdmin && inv !== undefined && !blocked;

  /** Persist (or re-adopt, field for field) the marker BEFORE dispatch. */
  const armMarker = (m: CertRecoveryMarker): boolean => {
    // The SAME operation (the challenge step, then the confirm; a re-send)
    // keeps its recorded start instant — the marker is immutable evidence.
    const stored = readCertRecovery(subject);
    const marker =
      stored.kind === "valid" && stored.marker.operationId === m.operationId
        ? { ...m, startedAt: stored.marker.startedAt }
        : m;
    if (writeCertRecovery(subject, marker)) return true;
    setMarkerFault(
      "The recovery marker could not be stored in this browser session (storage unavailable, or another operation is outstanding), so nothing was sent.",
    );
    return false;
  };

  /** One dispatch protocol for every mutation. */
  const dispatch = async <T extends CertWriteOutcome>(
    action: CertRecoveryAction,
    marker: CertRecoveryMarker,
    run: (signal: AbortSignal) => Promise<T>,
    render: (out: T) => ReactNode,
  ): Promise<void> => {
    if (inFlight.current) return;
    clearOutcome();
    if (!armMarker(marker)) return;
    inFlight.current = true;
    setResult("pending");
    const signal = ownerRef.current.begin();
    try {
      const out = await run(signal);
      clearCertRecovery(marker.operationId);
      close();
      setNotice(render(out));
      setView({ kind: "none" });
    } catch (err: unknown) {
      if (err instanceof ApiError && err.kind === "aborted") return;
      const r = asCertRefusal(err);
      if (r !== null) {
        if (CERT_TERMINAL_NOTHING_WRITTEN.includes(r.code)) {
          clearCertRecovery(marker.operationId);
          if (
            action === "rotate" &&
            r.code === "challenge_stale" &&
            r.facts.changed?.includes("expired") === true
          ) {
            // The confirm was refused and the challenge NOT consumed: the
            // ceremony stays open and offers a new challenge for the SAME
            // operation; nothing is re-sent on its own.
            setCeremony((c) =>
              c.kind === "rotate" ? { ...c, expired: true } : c,
            );
            setResult("failed");
            setErrorText(
              "The challenge expired before the confirmation reached the appliance; nothing was changed. Request a new challenge for this operation.",
            );
            return;
          }
          close();
          setRefusal({ action: actionWord(action), refusal: r });
        } else {
          // outcome_unknown (non-terminal), operation_in_progress,
          // operation_mismatch, operation_outcome_unknown: an intent the
          // ledger still has to settle — keep the marker, drop the secrets.
          close();
          setUnproven({
            action: actionWord(action),
            status: r.status,
            ...(r.facts.detail !== undefined ? { detail: r.facts.detail } : {}),
          });
        }
      } else if (
        err instanceof ApiError &&
        err.kind === "http" &&
        (err.status === 401 || err.status === 403)
      ) {
        clearCertRecovery(marker.operationId);
        close();
        setRefusal({
          action: actionWord(action),
          refusal: { status: err.status, code: "forbidden", facts: {} },
        });
      } else if (!certUnproven(err)) {
        clearCertRecovery(marker.operationId);
        close();
        setRefusal({
          action: actionWord(action),
          refusal: { status: 0, code: "invalid_input", facts: {} },
        });
      } else {
        close(); // drops every typed secret with the dialog tree
        setUnproven({
          action: actionWord(action),
          status: err instanceof ApiError ? err.status : undefined,
        });
      }
    } finally {
      ownerRef.current.settle(signal);
      inFlight.current = false;
      setResult((r) => (r === "pending" ? "idle" : r));
      rereadRecovery();
      refreshAll();
    }
  };

  // ── rotate ────────────────────────────────────────────────────────────
  const openRotate = (
    operationId = mintOperationId(),
    resend = false,
  ): void => {
    if (inv === undefined) return;
    clearOutcome();
    setCeremony({
      kind: "rotate",
      operationId,
      fence: inv.ca.revision,
      current: inv.ca.fingerprint ?? "",
      challenge: null,
      expired: false,
      resend,
    });
  };
  const requestChallenge = async (): Promise<void> => {
    if (ceremony.kind !== "rotate" || inFlight.current) return;
    const marker: CertRecoveryMarker = {
      operationId: ceremony.operationId,
      action: "rotate",
      fence: ceremony.fence,
      candidate: "",
      previousFingerprint: fenceDigest(ceremony.fence),
      startedAt: Date.now(),
    };
    if (!armMarker(marker)) return;
    inFlight.current = true;
    setResult("pending");
    setErrorText(undefined);
    const signal = ownerRef.current.begin();
    try {
      const ch = await requestCARotationChallenge(
        { operationId: ceremony.operationId, caRevision: ceremony.fence },
        signal,
      );
      setCeremony((c) =>
        c.kind === "rotate"
          ? { ...c, challenge: ch, expired: false, current: ch.fingerprint }
          : c,
      );
      setResult("idle");
    } catch (err: unknown) {
      if (err instanceof ApiError && err.kind === "aborted") return;
      const r = asCertRefusal(err);
      if (r !== null && CERT_TERMINAL_NOTHING_WRITTEN.includes(r.code)) {
        // Nothing durable is involved in a challenge: the marker is cleared
        // and the refusal (a stale fence, a CA-less node, a known id) is
        // rendered on the page with the authoritative current facts.
        clearCertRecovery(marker.operationId);
        close();
        setRefusal({ action: "Root CA rotation", refusal: r });
      } else if (r !== null) {
        clearCertRecovery(marker.operationId);
        close();
        setRefusal({ action: "Root CA rotation", refusal: r });
      } else {
        // The challenge itself is not a mutation: stay in the ceremony and
        // let the operator request it again explicitly.
        clearCertRecovery(marker.operationId);
        setResult("failed");
        setErrorText(
          "The challenge request was not answered; nothing was changed. Request the challenge again.",
        );
      }
    } finally {
      ownerRef.current.settle(signal);
      inFlight.current = false;
      rereadRecovery();
    }
  };
  const confirmRotate = (): void => {
    if (ceremony.kind !== "rotate" || ceremony.challenge === null) return;
    const ch = ceremony.challenge;
    const marker: CertRecoveryMarker = {
      operationId: ceremony.operationId,
      action: "rotate",
      fence: ceremony.fence,
      candidate: "",
      previousFingerprint: fenceDigest(ceremony.fence),
      startedAt: Date.now(),
    };
    void dispatch(
      "rotate",
      marker,
      (signal) =>
        confirmCARotation(
          {
            operationId: ceremony.operationId,
            caRevision: ceremony.fence,
            challenge: ch.challenge,
            previousFingerprint: ch.fingerprint,
          },
          signal,
        ),
      (out) => (
        <OutcomeNotice title="Root CA rotated" out={out}>
          <KeyValue
            items={[
              ["New revision", <Mono key="r">{out.ca.revision}</Mono>],
              ["New fingerprint", <Mono key="f">{out.ca.fingerprint}</Mono>],
              [
                "Replaced",
                <Mono key="p">{out.previous.fingerprint ?? "—"}</Mono>,
              ],
            ]}
          />
          <p>
            Every client must trust the new CA certificate; existing leaf
            certificates are no longer valid. The bundle was written before the
            new root was installed.
          </p>
        </OutcomeNotice>
      ),
    );
  };
  const cancelRotate = (): void => {
    if (ceremony.kind !== "rotate") return;
    // No mutation was dispatched (a dispatched one closes the ceremony
    // itself): the marker written for the challenge is this browser's only.
    clearCertRecovery(ceremony.operationId);
    close();
    rereadRecovery();
  };

  // ── import / replace (one editor, two targets) ────────────────────────
  const openPair = (
    target: "mitm" | "ui",
    bound: { operationId: string; fence: string; candidate: string } | null,
  ): void => {
    clearOutcome();
    setCeremony({
      kind: "pair",
      target,
      operationId: bound?.operationId ?? mintOperationId(),
      pem: { cert: "", key: "" },
      review: null,
      bound:
        bound !== null
          ? { fence: bound.fence, candidate: bound.candidate }
          : null,
    });
  };
  const setPem = (patch: Partial<PEMPair>): void => {
    setResult("idle");
    setErrorText(undefined);
    setCeremony((c) =>
      c.kind === "pair"
        ? { ...c, pem: { ...c.pem, ...patch }, review: null }
        : c,
    );
  };
  const review = async (): Promise<void> => {
    if (ceremony.kind !== "pair" || inFlight.current) return;
    if (ceremony.pem.cert.trim() === "" || ceremony.pem.key.trim() === "") {
      setResult("failed");
      setErrorText("Paste both the certificate and its private key (PEM).");
      return;
    }
    inFlight.current = true;
    setResult("pending");
    setErrorText(undefined);
    const signal = ownerRef.current.begin();
    try {
      const r =
        ceremony.target === "mitm"
          ? await dryRunCAImport(ceremony.pem, signal)
          : await dryRunUIReplace(ceremony.pem, signal);
      // A re-send must present the SAME candidate the marker recorded.
      if (ceremony.bound !== null) {
        const id =
          r.target === "mitm"
            ? digestOf(r.candidate.fingerprint)
            : await pemDigest(ceremony.pem.cert);
        if (id !== ceremony.bound.candidate) {
          setResult("failed");
          setErrorText(
            "This is not the candidate the unresolved operation was dispatched with; a different candidate needs a new operation once the outstanding one is resolved or abandoned.",
          );
          return;
        }
      }
      setCeremony((c) => (c.kind === "pair" ? { ...c, review: r } : c));
      setResult("idle");
    } catch (err: unknown) {
      if (err instanceof ApiError && err.kind === "aborted") return;
      const r = asCertRefusal(err);
      setResult("failed");
      if (r !== null) {
        setErrorText(
          r.code === "candidate_invalid"
            ? `Candidate refused: ${r.facts.reason ?? "invalid"}. Nothing was changed.`
            : `The review was refused (${r.code}); nothing was changed.`,
        );
      } else {
        setErrorText(
          "The review was not answered (or its answer could not be verified); nothing was changed.",
        );
      }
    } finally {
      ownerRef.current.settle(signal);
      inFlight.current = false;
    }
  };
  const commitPair = async (): Promise<void> => {
    if (ceremony.kind !== "pair") return;
    const c = ceremony;
    const rev = c.review;
    if (rev === null) return;
    if (rev.target === "mitm") {
      const fence = c.bound?.fence ?? rev.caRevision;
      const marker: CertRecoveryMarker = {
        operationId: c.operationId,
        action: "import",
        fence,
        candidate: digestOf(rev.candidate.fingerprint),
        previousFingerprint: "",
        startedAt: Date.now(),
      };
      await dispatch(
        "import",
        marker,
        (signal) =>
          importCA(
            {
              operationId: c.operationId,
              caRevision: fence,
              pem: c.pem,
              candidateFingerprint: rev.candidate.fingerprint,
            },
            signal,
          ),
        (out) => (
          <OutcomeNotice title="Root CA imported" out={out}>
            <KeyValue
              items={[
                ["Subject", out.ca.subject ?? rev.candidate.subject],
                ["New revision", <Mono key="r">{out.ca.revision}</Mono>],
                ["Fingerprint", <Mono key="f">{out.ca.fingerprint}</Mono>],
              ]}
            />
          </OutcomeNotice>
        ),
      );
      return;
    }
    const certDigest = await pemDigest(c.pem.cert);
    const fence = c.bound?.fence ?? rev.uiCertRevision;
    const marker: CertRecoveryMarker = {
      operationId: c.operationId,
      action: "replace",
      fence,
      candidate: certDigest,
      previousFingerprint: "",
      startedAt: Date.now(),
    };
    await dispatch(
      "replace",
      marker,
      (signal) =>
        replaceUICert(
          {
            operationId: c.operationId,
            uiCertRevision: fence,
            pem: c.pem,
            candidateFingerprint: rev.candidate.fingerprint,
            certDigest,
          },
          signal,
        ),
      (out) => (
        <OutcomeNotice title="UI certificate replaced" out={out}>
          <KeyValue
            items={[
              ["Persisted", <Mono key="f">{out.candidate.fingerprint}</Mono>],
              ["Revision", <Mono key="r">{out.uiCert.revision}</Mono>],
            ]}
          />
          <p>
            The pair is persisted, not active: the running listener keeps
            serving the pair it loaded, and the next restart serves this one.
            Nothing restarts on its own.
          </p>
        </OutcomeNotice>
      ),
    );
  };

  // ── delete ────────────────────────────────────────────────────────────
  const openDelete = (
    operationId = mintOperationId(),
    fence?: string,
  ): void => {
    if (inv === undefined) return;
    clearOutcome();
    setCeremony({
      kind: "delete",
      operationId,
      fence: fence ?? inv.uiCert.revision,
      fingerprint: inv.uiCert.fingerprint ?? "",
      subject: inv.uiCert.subject ?? "",
      posture: activationPosture(inv),
      resend: fence !== undefined,
    });
  };
  const confirmDelete = (): void => {
    if (ceremony.kind !== "delete") return;
    const c = ceremony;
    const marker: CertRecoveryMarker = {
      operationId: c.operationId,
      action: "delete",
      fence: c.fence,
      candidate: "",
      previousFingerprint: "",
      startedAt: Date.now(),
    };
    void dispatch(
      "delete",
      marker,
      (signal) =>
        deleteUICert(
          { operationId: c.operationId, uiCertRevision: c.fence },
          signal,
        ),
      (out) => (
        <OutcomeNotice title="UI certificate deleted" out={out}>
          <p>
            Cleanup: <Mono>{out.cleanup}</Mono>.{" "}
            {out.activation === "restart_required"
              ? "The running listener keeps serving the pair it loaded until the next restart, which falls back to the automatic self-signed certificate."
              : "The running listener was not serving this pair; the next restart falls back to the automatic self-signed certificate."}
          </p>
        </OutcomeNotice>
      ),
    );
  };

  // ── OCSP ──────────────────────────────────────────────────────────────
  const openOCSP = (
    operationId = mintOperationId(),
    bound?: { fence: string; enabled: boolean },
  ): void => {
    if (inv === undefined) return;
    clearOutcome();
    setCeremony({
      kind: "ocsp",
      operationId,
      fence: bound?.fence ?? inv.ocsp.revision,
      desired: inv.ocsp.desired,
      runtime: inv.ocsp.runtime,
      unchecked: ocsp?.uncheckedEnforcingPaths.length ?? -1,
      enabled: bound?.enabled ?? inv.ocsp.desired.enabled,
      resend: bound !== undefined,
    });
  };
  const confirmOCSP = (): void => {
    if (ceremony.kind !== "ocsp") return;
    const c = ceremony;
    const marker: CertRecoveryMarker = {
      operationId: c.operationId,
      action: "ocsp",
      fence: c.fence,
      candidate: c.enabled ? "enabled" : "disabled",
      previousFingerprint: "",
      startedAt: Date.now(),
    };
    void dispatch(
      "ocsp",
      marker,
      (signal) =>
        setOCSPPosture(
          {
            operationId: c.operationId,
            ocspRevision: c.fence,
            enabled: c.enabled,
          },
          signal,
        ),
      (out) => (
        <OutcomeNotice title="OCSP posture set" out={out}>
          <KeyValue
            items={[
              [
                "Desired",
                `Desired: ${out.desired.enabled ? "Enabled" : "Disabled"} (source: ${out.desired.source}, durable)`,
              ],
              [
                "Runtime",
                `Runtime: ${out.runtime.enabled ? "Enabled" : "Disabled"}`,
              ],
              ["Revision", <Mono key="r">{out.revision}</Mono>],
            ]}
          />
        </OutcomeNotice>
      ),
    );
  };

  // ── recovery ──────────────────────────────────────────────────────────
  const recover = async (marker: CertRecoveryMarker): Promise<void> => {
    setView({ kind: "looking" });
    try {
      const op = await getCertOperation(marker.operationId);
      if (!operationBoundToCertMarker(op, marker)) {
        setView({ kind: "unbound", op });
        return;
      }
      setView({ kind: "op", op });
      if (op.state === "committed") {
        clearCertRecovery(marker.operationId);
        setNotice(
          <Callout
            variant="success"
            title="Operation resolved from the appliance's ledger"
            role="status"
          >
            Operation <Mono>{marker.operationId}</Mono> (
            {actionWord(marker.action)}) is committed on the appliance
            {op.audited ? "" : " (success audit still owed)"}; the object's
            committed revision is <Mono>{op.committedRevision}</Mono>.
          </Callout>,
        );
        setUnproven(null);
        setView({ kind: "none" });
        rereadRecovery();
        refreshAll();
      }
    } catch (err: unknown) {
      const code = certLookupRefusal(err);
      if (code === "not_found") {
        setView({ kind: "never_recorded" });
        return;
      }
      setView(code !== null ? { kind: "refused", code } : { kind: "unproven" });
    }
  };
  const resend = (marker: CertRecoveryMarker): void => {
    switch (marker.action) {
      case "rotate":
        openRotate(marker.operationId, true);
        return;
      case "import":
        openPair("mitm", {
          operationId: marker.operationId,
          fence: marker.fence,
          candidate: marker.candidate,
        });
        return;
      case "replace":
        openPair("ui", {
          operationId: marker.operationId,
          fence: marker.fence,
          candidate: marker.candidate,
        });
        return;
      case "delete":
        openDelete(marker.operationId, marker.fence);
        return;
      case "ocsp":
        openOCSP(marker.operationId, {
          fence: marker.fence,
          enabled: marker.candidate === "enabled",
        });
        return;
    }
  };
  const abandon = (marker: CertRecoveryMarker): void => {
    clearCertRecovery(marker.operationId);
    close();
    setUnproven(null);
    setView({ kind: "none" });
    rereadRecovery();
  };

  // ── render ────────────────────────────────────────────────────────────
  const canDelete =
    inv !== undefined &&
    (inv.uiCert.pairState === "complete" ||
      inv.uiCert.pairState === "incomplete");
  const canRotate = inv !== undefined && inv.ca.present;

  const notices: ReactNode = isAdmin ? (
    <>
      {notice}
      {markerFault !== null && (
        <Callout variant="critical" title="Nothing was sent" role="alert">
          {markerFault}
        </Callout>
      )}
      {refusal !== null && (
        <CertRefusalCallout action={refusal.action} refusal={refusal.refusal} />
      )}
      {recovery.kind === "valid" && (
        <RecoveryCard
          marker={recovery.marker}
          view={view}
          unproven={unproven}
          onRecover={() => void recover(recovery.marker)}
          onResend={() => resend(recovery.marker)}
          onAbandon={() =>
            setCeremony({ kind: "abandon", marker: recovery.marker })
          }
        />
      )}
      {recovery.kind === "unavailable" && (
        <Callout
          variant="unknown"
          title="Recovery marker storage unavailable"
          role="alert"
        >
          This browser session cannot store the recovery marker, so no
          certificate mutation can be dispatched from it.
        </Callout>
      )}
      {recovery.kind === "unreadable" && (
        <Callout
          variant="unknown"
          title="Recovery marker unreadable"
          role="alert"
        >
          The stored recovery marker cannot be read; every mutation stays
          blocked until it is abandoned (sign out and back in purges it).
        </Callout>
      )}
    </>
  ) : null;

  let dialog: ReactNode = null;
  switch (ceremony.kind) {
    case "closed":
      break;
    case "rotate":
      dialog = (
        <RotateCeremony
          c={ceremony}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onRequest={() => void requestChallenge()}
          onConfirm={confirmRotate}
          onCancel={cancelRotate}
        />
      );
      break;
    case "pair":
      dialog = (
        <PairCeremony
          c={ceremony}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onPem={setPem}
          onReview={() => void review()}
          onCommit={() => void commitPair()}
          onCancel={close}
        />
      );
      break;
    case "delete":
      dialog = (
        <DeleteCeremony
          c={ceremony}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={confirmDelete}
          onCancel={close}
        />
      );
      break;
    case "ocsp":
      dialog = (
        <OCSPCeremony
          c={ceremony}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onToggle={(enabled) =>
            setCeremony((cur) =>
              cur.kind === "ocsp" ? { ...cur, enabled } : cur,
            )
          }
          onConfirm={confirmOCSP}
          onCancel={close}
        />
      );
      break;
    case "abandon":
      dialog = (
        <AbandonCeremony
          marker={ceremony.marker}
          onConfirm={() => abandon(ceremony.marker)}
          onCancel={close}
        />
      );
      break;
  }

  return {
    blocked: !canMutate,
    can: { rotate: canRotate, deleteUI: canDelete },
    open: {
      rotate: () => openRotate(),
      importCA: () => openPair("mitm", null),
      replaceUI: () => openPair("ui", null),
      deleteUI: () => openDelete(),
      ocsp: () => openOCSP(),
    },
    notices,
    dialog: (
      <>
        {dialog}
        {guard.element}
      </>
    ),
  };
}

// ── Outcome callouts ───────────────────────────────────────────────────────

function OutcomeNotice({
  title,
  out,
  children,
}: {
  title: string;
  out: CertWriteOutcome;
  children: ReactNode;
}): JSX.Element {
  return (
    <Callout variant="success" title={title} role="status">
      <KeyValue
        items={[
          ["Operation", <Mono key="op">{out.operationId}</Mono>],
          [
            "Record",
            out.recordState === "committed"
              ? "Terminal record durable"
              : "Terminal record pending reconciliation (the lookup settles it)",
          ],
          [
            "Audit",
            out.auditState === "pending"
              ? "Success audit still owed (completed by the lookup or at boot)"
              : "Operation-keyed success audit emitted",
          ],
          ...(out.replayed
            ? ([
                [
                  "Replay",
                  "The recorded result of an earlier dispatch; nothing was done again",
                ],
              ] as const)
            : []),
        ]}
      />
      {children}
    </Callout>
  );
}

function fenceText(r: CertRefusal): ReactNode {
  const f = r.facts;
  const token = f.caRevision ?? f.uiCertRevision ?? f.ocspRevision;
  return token !== undefined ? <Mono>{token}</Mono> : "unknown";
}

export function CertRefusalCallout({
  action,
  refusal,
}: {
  action: string;
  refusal: CertRefusal;
}): JSX.Element {
  const f = refusal.facts;
  let body: ReactNode;
  switch (refusal.code) {
    case "stale":
      body = (
        <>
          The object changed since it was loaded; its current revision is{" "}
          {fenceText(refusal)}. Refresh, review the current state and start
          again. Nothing was changed.
        </>
      );
      break;
    case "precondition_required":
      body = (
        <>
          The appliance required the current revision ({fenceText(refusal)});
          nothing was changed.
        </>
      );
      break;
    case "challenge_stale":
      body = (
        <>
          The challenge did not bind the confirmation (changed:{" "}
          <Mono>{(f.changed ?? []).join(", ")}</Mono>); the challenge was not
          consumed and nothing was changed.
        </>
      );
      break;
    case "candidate_invalid":
      body = (
        <>
          The candidate was refused (<Mono>{f.reason ?? "invalid"}</Mono>);
          nothing was changed.
        </>
      );
      break;
    case "candidate_duplicate":
      body = (
        <>The candidate is already the installed object; nothing was changed.</>
      );
      break;
    case "operation_aborted":
      body = (
        <>
          The appliance recorded this operation as refused
          {f.code !== undefined ? (
            <>
              {" "}
              (<Mono>{f.code}</Mono>)
            </>
          ) : null}
          ; nothing was written.
        </>
      );
      break;
    case "persist_failed":
      body = (
        <>
          The appliance could not persist the change
          {f.class !== undefined ? (
            <>
              {" "}
              (<Mono>{f.class}</Mono>)
            </>
          ) : null}
          ; the current object is unchanged and the operation is recorded as
          aborted.
        </>
      );
      break;
    case "forbidden":
      body = (
        <>
          The appliance refused this action for your role (HTTP{" "}
          {String(refusal.status)}); nothing was changed.
        </>
      );
      break;
    case "invalid_input":
      body = (
        <>The appliance refused the request as invalid; nothing was changed.</>
      );
      break;
    default:
      body = (
        <>
          The appliance refused this action (<Mono>{refusal.code}</Mono>);
          nothing was changed.
        </>
      );
  }
  return (
    <Callout variant="warning" title={`${action} refused`} role="alert">
      {body}
    </Callout>
  );
}

function RecoveryCard({
  marker,
  view,
  unproven,
  onRecover,
  onResend,
  onAbandon,
}: {
  marker: CertRecoveryMarker;
  view: CertRecoveryView;
  unproven: UnprovenNote | null;
  onRecover: () => void;
  onResend: () => void;
  onAbandon: () => void;
}): JSX.Element {
  const abandonable =
    view.kind === "never_recorded" ||
    view.kind === "unbound" ||
    (view.kind === "op" &&
      (view.op.state === "aborted" ||
        (view.op.state === "outcome_unknown" &&
          operationPosture(view.op).kind !== "unknown_recoverable")));
  return (
    <Callout
      variant="unknown"
      title="Unresolved certificate operation"
      role="alert"
    >
      <p>
        A {actionWord(marker.action)} was dispatched as operation{" "}
        <Mono>{marker.operationId}</Mono> (fenced on <Mono>{marker.fence}</Mono>
        ) and its answer was not verified
        {unproven !== null && unproven.detail !== undefined ? (
          <>
            {" "}
            — the appliance answered that nothing was decided yet (
            <Mono>{unproven.detail}</Mono>, intent pending)
          </>
        ) : unproven !== null && unproven.status !== undefined ? (
          <> (HTTP {String(unproven.status)}, not a verdict)</>
        ) : null}
        . Every mutation stays blocked until the appliance's ledger settles it;
        nothing is re-sent automatically.
      </p>
      <div>
        <Button
          size="sm"
          variant="primary"
          disabled={view.kind === "looking"}
          onClick={onRecover}
        >
          Recover
        </Button>{" "}
        {certResendAllowed(view) && (
          <>
            <Button size="sm" variant="secondary" onClick={onResend}>
              Re-send
            </Button>{" "}
          </>
        )}
        {abandonable && (
          <Button size="sm" variant="danger-quiet" onClick={onAbandon}>
            Abandon
          </Button>
        )}
      </div>
      <div>
        {view.kind === "looking" && "Looking the operation up…"}
        {view.kind === "op" && <RecoveredState op={view.op} />}
        {view.kind === "never_recorded" && (
          <span>
            The appliance never recorded this operation: the write did not
            start, or this node's ledger no longer holds it (a 404 alone is not
            proof of non-commit — the current object state above is). The same
            operation may be re-sent under its identity and original fence (a
            known id replays, a moved fence is refused), or the marker
            abandoned.
          </span>
        )}
        {view.kind === "unbound" && (
          <StatusBadge status="unknown">
            The appliance's record under this operation id is not bound to the
            dispatched intent (it is a {view.op.action} record fenced on{" "}
            {view.op.fence}) — outcome unproven; the marker is kept and nothing
            is re-sent
          </StatusBadge>
        )}
        {view.kind === "refused" && (
          <StatusBadge status="unknown">
            Lookup refused: {view.code}
          </StatusBadge>
        )}
        {view.kind === "unproven" && (
          <StatusBadge status="unknown">
            Lookup outcome unproven — try Recover again
          </StatusBadge>
        )}
      </div>
    </Callout>
  );
}

function RecoveredState({ op }: { op: CertOperation }): JSX.Element {
  const p = operationPosture(op);
  switch (p.kind) {
    case "pending":
      return (
        <StatusBadge status="unknown">
          The operation is still pending on the appliance (its evidence could
          not decide it yet); recover again later — the marker is kept
        </StatusBadge>
      );
    case "committed":
    case "committed_audit_pending":
      return <StatusBadge status="ok">Committed</StatusBadge>;
    case "aborted":
      return (
        <StatusBadge status="warn">
          Refused ({p.code}): nothing was written — the marker may be abandoned
        </StatusBadge>
      );
    case "unknown_recoverable":
      return (
        <StatusBadge status="unknown">
          Outcome unknown ({p.code}) — re-decided by a later settlement; recover
          again later
        </StatusBadge>
      );
    case "unknown_unproven":
      return (
        <StatusBadge status="unknown">
          TERMINAL UNKNOWN ({p.code}): whether this operation committed will
          never be known from this node's evidence — never treated as succeeded,
          failed or safe to retry
        </StatusBadge>
      );
    case "unknown_superseded":
      return (
        <StatusBadge status="unknown">
          TERMINAL UNKNOWN: a later writer ({p.supersededBy}) replaced the
          evidence before this operation could be decided; whether it committed
          will never be known — abandoning the marker cancels nothing on the
          appliance
        </StatusBadge>
      );
  }
}

// ── Ceremonies ─────────────────────────────────────────────────────────────

interface CeremonyCommon {
  result: ConfirmResult;
  errorText?: string;
  onCancel: () => void;
}

function RotateCeremony(
  p: CeremonyCommon & {
    c: Extract<Ceremony, { kind: "rotate" }>;
    onRequest: () => void;
    onConfirm: () => void;
  },
): JSX.Element {
  const [typed, setTyped] = useState("");
  const { c } = p;
  const step1 = c.challenge === null;
  return (
    <ConfirmationDialog
      open
      tier={step1 ? 2 : 3}
      title="Rotate the Root CA"
      body={
        <>
          <KeyValue
            items={[
              ["Operation", <Mono key="op">{c.operationId}</Mono>],
              ["Fenced on CA revision", <Mono key="f">{c.fence}</Mono>],
              [
                step1 ? "Current CA" : "CA being replaced",
                <Mono key="cur">{c.current}</Mono>,
              ],
              ...(c.challenge !== null
                ? ([
                    [
                      "Challenge",
                      `Expires at ${c.challenge.expiresAt} (${String(c.challenge.expiresInSeconds)} s from issue); single-use, bound to you, this operation and this revision`,
                    ],
                  ] as const)
                : []),
            ]}
          />
          {c.resend && (
            <p>
              Re-sends the unresolved operation <Mono>{c.operationId}</Mono>{" "}
              under its original fence; the appliance replays a committed
              rotation or refuses a moved revision.
            </p>
          )}
          {step1 ? (
            <p>
              The appliance issues a server-owned challenge bound to your
              identity, this operation and the current CA revision; the rotation
              is confirmed only with that challenge. Requesting it is audited (
              <Mono>ca.rotate_requested</Mono>).
            </p>
          ) : (
            <p>{c.challenge?.warning}</p>
          )}
          {c.expired && (
            <p>
              <Button
                size="sm"
                variant="secondary"
                onClick={p.onRequest}
                disabled={p.result === "pending"}
              >
                Request a new challenge
              </Button>
            </p>
          )}
        </>
      }
      impact={
        step1
          ? "Nothing durable changes until the confirmation; the challenge expires on its own."
          : "Every existing leaf certificate and the current trust chain become invalid; every client workstation and device must trust the new CA certificate. The new bundle is written to disk before the new root is installed."
      }
      rollback="None — irreversible (the previous root stays trusted only through the dual-CA overlap)."
      confirmLabel={step1 ? "Request challenge" : "Rotate"}
      {...(step1
        ? {}
        : {
            confirmWord: ROTATE_WORD,
            typedValue: typed,
            onTypedChange: setTyped,
          })}
      destructive={!step1}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={step1 ? p.onRequest : p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

function candidateItems(
  r: CADryRun | UIDryRun,
): ReadonlyArray<readonly [string, ReactNode]> {
  if (r.target === "mitm") {
    return [
      ["Subject", r.candidate.subject],
      ["Issuer", r.candidate.issuer],
      ["Certificate authority", r.candidate.isCA ? "Yes" : "No"],
      ["Key", r.candidate.keyAlgorithm],
      ["Not before", r.candidate.notBefore],
      ["Not after", r.candidate.notAfter],
      ["Fingerprint (SHA-256)", <Mono key="f">{r.candidate.fingerprint}</Mono>],
      ["Fenced on CA revision", <Mono key="fence">{r.caRevision}</Mono>],
    ];
  }
  return [
    ["Subject", r.candidate.subject],
    ["Issuer", r.candidate.issuer],
    [
      "DNS names",
      r.candidate.dnsNames.length > 0 ? r.candidate.dnsNames.join(", ") : "—",
    ],
    ["Chain length", String(r.candidate.chainLength)],
    ["Not before", r.candidate.notBefore],
    ["Not after", r.candidate.notAfter],
    ["Fingerprint (SHA-256)", <Mono key="f">{r.candidate.fingerprint}</Mono>],
    [
      "Fenced on UI certificate revision",
      <Mono key="fence">{r.uiCertRevision}</Mono>,
    ],
  ];
}

function PairCeremony(
  p: CeremonyCommon & {
    c: Extract<Ceremony, { kind: "pair" }>;
    onPem: (patch: Partial<PEMPair>) => void;
    onReview: () => void;
    onCommit: () => void;
  },
): JSX.Element {
  const { c } = p;
  const mitm = c.target === "mitm";
  const reviewed = c.review !== null;
  return (
    <ConfirmationDialog
      open
      tier={reviewed ? 2 : 1}
      title={mitm ? "Import a Root CA" : "Replace the UI certificate"}
      body={
        <>
          <p>
            <Mono>{c.operationId}</Mono>
            {c.bound !== null
              ? " — re-sends the unresolved operation under its original fence; the review must present the same candidate."
              : ""}
          </p>
          {reviewed && c.review !== null ? (
            <KeyValue items={candidateItems(c.review)} />
          ) : (
            <>
              <TextareaField
                label={mitm ? "CA certificate (PEM)" : "Certificate (PEM)"}
                rows={6}
                spellCheck={false}
                autoComplete="off"
                value={c.pem.cert}
                onChange={(e) => p.onPem({ cert: e.target.value })}
                disabled={p.result === "pending"}
              />
              <TextareaField
                label={mitm ? "CA private key (PEM)" : "Private key (PEM)"}
                rows={6}
                spellCheck={false}
                autoComplete="off"
                value={c.pem.key}
                onChange={(e) => p.onPem({ key: e.target.value })}
                disabled={p.result === "pending"}
              />
              <p>
                Review sends the pair once to the appliance for validation only
                (nothing is written, no operation is recorded); the reviewed
                facts and the fence to echo come back. The private key is sent
                in the request body, never in a URL, and is dropped with this
                dialog.
              </p>
            </>
          )}
        </>
      }
      impact={
        mitm
          ? "The reviewed certificate becomes this node's inspection Root CA: the bundle is written to disk before it is installed; every client must trust it; the previous root is replaced under the fence shown."
          : "The reviewed pair is persisted only: the running listener keeps serving the pair it loaded, and the pair takes effect at the next restart (activation: restart_required). Nothing restarts on its own."
      }
      rollback={
        mitm
          ? "Import the previous root again, or rotate."
          : "Replace the pair again, or delete it (the next restart falls back to self-signed)."
      }
      confirmLabel={
        reviewed ? (mitm ? "Import" : "Replace") : "Review candidate"
      }
      destructive={reviewed}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={reviewed ? p.onCommit : p.onReview}
      onCancel={p.onCancel}
    />
  );
}

function servedWords(posture: ActivationPosture, fingerprint: string): string {
  switch (posture.kind) {
    case "custom_matches":
      return "The running listener serves THIS pair; deleting it does not stop the listener — it keeps serving the pair it loaded until the next restart, which falls back to the automatic self-signed certificate.";
    case "custom_differs":
    case "custom_not_persisted":
      return `The running listener serves a different pair (${posture.served.fingerprint}); it keeps serving it and is not affected by this deletion.`;
    case "custom_persisted_unusable":
      return `The running listener serves ${posture.served.fingerprint}; it keeps serving it and is not affected by this deletion.`;
    case "self_signed":
    case "tls_configured":
      return `The running listener serves ${posture.served.fingerprint} (not the persisted pair); it keeps serving it and is not affected by this deletion.`;
    case "plain_http":
      return "The running listener serves plain HTTP and keeps serving it; the deletion affects only what a restart would load.";
    case "unknown":
      return `The running listener's served pair is not observed; whatever it loaded, it keeps serving it (persisted ${fingerprint} is what a restart would have loaded).`;
  }
}

function DeleteCeremony(
  p: CeremonyCommon & {
    c: Extract<Ceremony, { kind: "delete" }>;
    onConfirm: () => void;
  },
): JSX.Element {
  const [typed, setTyped] = useState("");
  const { c } = p;
  const word = deleteConfirmWord(c.fingerprint);
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Delete the UI certificate"
      body={
        <>
          <KeyValue
            items={[
              ["Operation", <Mono key="op">{c.operationId}</Mono>],
              ["Persisted subject", c.subject !== "" ? c.subject : "—"],
              [
                "Persisted fingerprint",
                <Mono key="f">
                  {c.fingerprint !== "" ? c.fingerprint : "—"}
                </Mono>,
              ],
              [
                "Fenced on UI certificate revision",
                <Mono key="fence">{c.fence}</Mono>,
              ],
            ]}
          />
          <p>{servedWords(c.posture, c.fingerprint)}</p>
          {c.resend && (
            <p>
              Re-sends the unresolved operation under its original fence; the
              appliance replays a committed deletion or refuses a moved
              revision.
            </p>
          )}
        </>
      }
      impact="The persisted pair is removed from this node (the private key first). This does not stop the running listener and does not restart the appliance."
      rollback="Replace the pair again from your own copy; the appliance keeps none."
      confirmLabel="Delete"
      confirmWord={word}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

function OCSPCeremony(
  p: CeremonyCommon & {
    c: Extract<Ceremony, { kind: "ocsp" }>;
    onToggle: (enabled: boolean) => void;
    onConfirm: () => void;
  },
): JSX.Element {
  const { c } = p;
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Set the OCSP posture"
      body={
        <>
          <KeyValue
            items={[
              ["Operation", <Mono key="op">{c.operationId}</Mono>],
              [
                "Scope",
                "Node-local (this node only; never exported, rolled back or synced)",
              ],
              [
                "Desired",
                `Desired: ${c.desired.enabled ? "Enabled" : "Disabled"} (source: ${c.desired.source})`,
              ],
              [
                "Runtime",
                `Runtime: ${c.runtime.enabled ? "Enabled" : "Disabled"}`,
              ],
              ["Fenced on OCSP revision", <Mono key="fence">{c.fence}</Mono>],
            ]}
          />
          <p>
            {c.unchecked > 0
              ? `${String(c.unchecked)} enforcing handshake path${c.unchecked === 1 ? " is" : "s are"} not consulted by the checker (see the coverage table): the desired posture does not cover ${c.unchecked === 1 ? "it" : "them"}.`
              : c.unchecked === 0
                ? "Every enforcing handshake path is consulted by the checker."
                : "The checker's coverage was not read; the posture set here does not cover any path the checker does not consult."}
          </p>
          <Switch
            label="Enable OCSP revocation checking"
            checked={c.enabled}
            onChange={(e) => p.onToggle(e.target.checked)}
            disabled={p.result === "pending"}
          />
          {c.resend && (
            <p>
              Re-sends the unresolved operation under its original fence with
              the same target posture; the appliance replays a committed set or
              refuses a moved revision.
            </p>
          )}
        </>
      }
      impact="The DESIRED posture is persisted first and the running checker is flipped only after the write landed; the runtime posture is reported separately and never inferred."
      rollback="Set the posture again."
      confirmLabel="Apply"
      destructive={false}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

function AbandonCeremony(p: {
  marker: CertRecoveryMarker;
  onConfirm: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Abandon the unresolved operation"
      body={
        <KeyValue
          items={[
            ["Operation", <Mono key="op">{p.marker.operationId}</Mono>],
            ["Intent", actionWord(p.marker.action)],
            ["Fence", <Mono key="f">{p.marker.fence}</Mono>],
          ]}
        />
      }
      impact="Only this browser's recovery marker is discarded; the appliance's ledger record (if any) is untouched — abandoning cancels or reverses nothing on the appliance, and the record stays visible through the operation lookup."
      rollback="None — the marker cannot be re-created."
      confirmLabel="Abandon"
      confirmWord={p.marker.operationId}
      typedValue={typed}
      onTypedChange={setTyped}
      result="idle"
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}
