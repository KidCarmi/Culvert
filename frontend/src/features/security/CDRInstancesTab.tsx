// 2E-C Instances: the Sluice TRUST registry. An instance's registry key is
// its immutable enrollment name; its SECURITY identity is the client-cert
// SHA-256 fingerprint LINEAGE — every generation Sluice ever issued for it
// (a renewal never retires its predecessor at Sluice), shown on the row and
// on every trust ceremony.
//
// The two removal actions are DIFFERENT operations and are never conflated:
//   REVOKE — retires EVERY live generation ON THE SLUICE SIDE (irreversible)
//            and prunes locally ONLY after Sluice PROVES a durable deny for
//            each; per-generation progress is durable, so a retry after a
//            failure or unknown outcome is safe. Needs a second enrolled
//            instance (Sluice refuses self-revocation).
//   DELETE — LOCAL only: prunes this appliance's registry and shreds its
//            copy of the credential. Sluice keeps trusting every live
//            fingerprint until expiry or a Sluice-side revocation; the
//            ceremony and the completion notice both list them.
//
// Enrollment consumes a SINGLE-USE token (never echoed, never stored) and is
// non-idempotent. Every dispatch carries an OPERATION ID that is persisted
// in a verified, subject-bound, non-secret browser marker BEFORE the POST
// (no marker ⇒ nothing is sent) and in a server-side receipt; an unresolved
// outcome is RESOLVED against the engine (LANDED / ISSUED-BUT-NOT-STORED
// with an exact revocation path / NOT-ISSUED / AMBIGUOUS) — never guessed,
// never blindly retried.
import { useCallback, useEffect, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { InputField } from "../../design-system/forms";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../design-system/dialog";
import { SnapshotBar } from "../../shared/snapshot";
import { useAuth } from "../../auth/AuthProvider";
import { useObjectPage, type ObjectPageState } from "../objects/useObjectPage";
import { unknownOutcome, serverErrorText } from "../../shared/mutationOutcome";
import {
  deleteCDRInstance,
  enrollCDRInstance,
  enrollFailureIsUnresolved,
  getCDRInstances,
  recoverCDREnrollment,
  revokeCDRFingerprint,
  revokeCDRInstance,
  type CDREnrollRecovery,
  type CDREnrollResult,
  type CDRInstance,
  type CDRInstances,
  type CDRRevokeResult,
} from "../../api/cdr";
import {
  clearEnrollRecovery,
  mintEnrollOperationId,
  readEnrollRecovery,
  writeEnrollRecovery,
  type EnrollRecoveryMarker,
  type EnrollRecoveryRead,
} from "./enrollRecovery";
import styles from "../policy/policy.module.css";

type InstPage = ObjectPageState<CDRInstances>;

function fpShort(fp: string): string {
  if (fp === "") return "unknown";
  const hex = fp.startsWith("sha256:") ? fp.slice(7) : fp;
  return hex.length > 16 ? `${hex.slice(0, 16)}…` : hex;
}

function FingerprintList({ fps }: { fps: readonly string[] }): JSX.Element {
  if (fps.length === 0) return <Mono>(fingerprint unknown)</Mono>;
  return (
    <ul>
      {fps.map((fp) => (
        <li key={fp}>
          <Mono>{fp}</Mono>
        </li>
      ))}
    </ul>
  );
}

// ── Delete (LOCAL-only) ceremony ────────────────────────────────────────────

function DeleteDialog({
  page,
  target,
  onOrphan,
  onCancel,
}: {
  page: InstPage;
  target: CDRInstance;
  onOrphan: (name: string, fingerprints: readonly string[]) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title={`Delete ${target.name} from this appliance`}
      body={
        <>
          <p>
            This removes <Mono>{target.name}</Mono> from THIS appliance only:
            the registry entry is pruned and the local mTLS key material is
            destroyed. It does NOT revoke anything on the Sluice side — Sluice
            keeps trusting every still-valid generation of this credential until
            it expires or is revoked there:
          </p>
          <FingerprintList fps={target.liveFingerprints} />
          <p>
            If this credential may be compromised, use <strong>Revoke</strong>{" "}
            instead — after Delete, revoking from this appliance is no longer
            possible (the local key and certificate are shredded).
          </p>
          <p>
            If this is the only dialed instance, CDR calls stop being served and
            matching downloads follow the configured fail mode. Reversal
            requires re-enrollment with a NEW single-use token.
          </p>
        </>
      }
      impact="Local trust and key material are destroyed; every live generation remains valid at Sluice until it expires or is revoked there."
      rollback="None for the shredded key — re-enroll with a new token to use this engine again."
      confirmLabel="Delete locally"
      confirmWord={target.name}
      typedValue={typed}
      onTypedChange={setTyped}
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        deleteCDRInstance(target.name, signal)
          .then((res) => {
            onOrphan(res.removed, res.clientCertFingerprints);
            page.refreshToResolve();
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The delete failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

// ── Revoke (Sluice-side, whole lineage) ceremony ────────────────────────────

function RevokeDialog({
  page,
  target,
  onDone,
  onCancel,
}: {
  page: InstPage;
  target: CDRInstance;
  onDone: (res: CDRRevokeResult) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title={`Revoke the credentials of ${target.name}`}
      body={
        <>
          <p>
            This tells Sluice to permanently refuse EVERY still-valid generation
            of this instance&apos;s client credential — a renewal never retired
            its predecessor at Sluice, so all of these are revoked:
          </p>
          <FingerprintList
            fps={
              target.liveFingerprints.length === 0
                ? ["(fingerprint read from disk at revoke time)"]
                : target.liveFingerprints
            }
          />
          <p>
            <Mono>{target.name}</Mono> is removed from this appliance and its
            local key material destroyed ONLY after Sluice proves a durable deny
            for each generation; a response that proves nothing changes nothing
            here. The revocation is IRREVERSIBLE — using this engine again
            requires re-enrollment with a new single-use token.
          </p>
          <p>
            Sluice refuses self-revocation, so the call is issued through
            another enrolled instance; with no other reachable instance this
            action fails with a clear error and nothing changes. Progress is
            recorded per generation, so a failure midway is safe to retry.
          </p>
          <InputField
            label="Reason (recorded in the Sluice ledger and the audit trail)"
            value={reason}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        </>
      }
      impact="Every live generation stops working at Sluice permanently; if this was the last usable instance, CDR calls follow the configured fail mode."
      rollback="None — irreversible. Re-enrollment with a new token is the only way back."
      confirmLabel="Revoke credential"
      confirmWord={target.name}
      typedValue={typed}
      onTypedChange={setTyped}
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        revokeCDRInstance(target.name, reason, signal)
          .then((res) => {
            onDone(res);
            page.refreshToResolve();
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The revocation failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

// ── Orphan revocation (by fingerprint) ceremony ─────────────────────────────

function RevokeFingerprintDialog({
  page,
  fingerprint,
  onDone,
  onCancel,
}: {
  page: InstPage;
  fingerprint: string;
  onDone: (res: CDRRevokeResult) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  const [typed, setTyped] = useState("");
  const word = fpShort(fingerprint).replace("…", "").slice(0, 8);
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Revoke the orphaned credential"
      body={
        <>
          <p>
            Sluice issued client certificate <Mono>{fingerprint}</Mono> for this
            appliance, but this appliance holds no key material for it. Until it
            is revoked at Sluice it remains a valid credential that nothing here
            controls. This tells Sluice to refuse it permanently — the appliance
            accepts success only after Sluice proves the durable deny.
          </p>
          <p>Type the first 8 hex characters of the fingerprint to confirm.</p>
        </>
      }
      impact="The orphaned credential stops working at Sluice permanently."
      rollback="None — irreversible."
      confirmLabel="Revoke orphaned credential"
      confirmWord={word}
      typedValue={typed}
      onTypedChange={setTyped}
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        revokeCDRFingerprint(fingerprint, "orphaned enrollment", signal)
          .then((res) => {
            onDone(res);
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              setResult("unknown");
              setErrorText(
                "The appliance did not answer. Resolve the enrollment again to learn whether the credential is now revoked.",
              );
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The revocation failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

// ── Enrollment (admin) ──────────────────────────────────────────────────────

interface EnrollForm {
  name: string;
  endpoint: string;
  serverFingerprint: string;
  token: string;
}

const EMPTY_FORM: EnrollForm = {
  name: "",
  endpoint: "",
  serverFingerprint: "",
  token: "",
};

function EnrollConfirmDialog({
  page,
  form,
  subject,
  onDone,
  onUnresolved,
  onBlocked,
  onFail,
  onCancel,
}: {
  page: InstPage;
  form: EnrollForm;
  subject: string;
  onDone: (res: CDREnrollResult) => void;
  /** The outcome is NOT settled (transport lost, or the appliance named the
   * operation in its refusal): the marker stays for resolution. */
  onUnresolved: (transportLost: boolean, serverText: string) => void;
  /** No durable recovery marker could be written: nothing was sent. */
  onBlocked: () => void;
  /** Failure closes the ceremony and reports at page level — the parent
   * clears the single-use token field on EVERY dispatch outcome (secret
   * hygiene: a controlled input's value is serialized into the DOM, so a
   * dispatched token must not linger there). */
  onFail: (error: string) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={`Enroll ${form.name}`}
      body={
        <>
          Contacts <Mono>{form.endpoint}</Mono>, verifies its server certificate
          against the pasted fingerprint (trust-on-first-use pin), and exchanges
          the single-use token for an mTLS client credential stored on this
          appliance. The token is consumed by a successful exchange and cannot
          be used again. The exchange carries a recovery identity (operation id)
          recorded before it is sent, so an unconfirmed outcome can be resolved
          against the engine. The first successful enrollment also enables CDR
          processing (persisted).
        </>
      }
      impact="Establishes mutual trust with the engine; with CDR enabled, matching file downloads are processed by it."
      rollback="Revoke the credential (preferred) or delete the instance locally."
      confirmLabel="Enroll instance"
      result={result}
      onConfirm={() => {
        if (result === "pending") return;
        const name = form.name.trim();
        const endpoint = form.endpoint.trim();
        const serverFingerprint = form.serverFingerprint.trim();
        const operationId = mintEnrollOperationId();
        // The durable, verified, non-secret marker is written BEFORE the
        // dispatch; without it NOTHING is sent.
        if (
          !writeEnrollRecovery(subject, {
            operationId,
            name,
            endpoint,
            serverFingerprint,
            startedAt: Date.now(),
          })
        ) {
          setResult("failed");
          onBlocked();
          return;
        }
        const signal = page.owner.begin();
        setResult("pending");
        enrollCDRInstance(
          { name, endpoint, serverFingerprint, token: form.token, operationId },
          signal,
        )
          .then((res) => {
            clearEnrollRecovery();
            onDone(res);
            page.refreshToResolve();
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("create");
              setResult("unknown");
              onUnresolved(true, "");
              return;
            }
            if (enrollFailureIsUnresolved(err, operationId)) {
              setResult("failed");
              onUnresolved(false, serverErrorText(err, ""));
              return;
            }
            // Authoritative refusal naming no operation: nothing was issued.
            clearEnrollRecovery();
            setResult("failed");
            onFail(serverErrorText(err, "The enrollment failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

// ── Recovery surface ────────────────────────────────────────────────────────

function AbandonRecoveryDialog({
  marker,
  onDone,
  onCancel,
}: {
  marker: EnrollRecoveryMarker;
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Abandon this recovery"
      body={
        <>
          Forgets operation <Mono>{marker.operationId}</Mono> (instance{" "}
          <Mono>{marker.name}</Mono>) in THIS browser tab only. The appliance
          keeps its durable receipt, so the operation can still be resolved
          later from the receipts list or with the operation id. If the engine
          did issue a credential for it, that credential stays trusted until it
          is revoked.
        </>
      }
      impact="The recovery prompt disappears here; nothing changes on the appliance or at Sluice."
      rollback="Resolve the operation later via its receipt."
      confirmLabel="Abandon recovery"
      result="idle"
      onConfirm={() => {
        clearEnrollRecovery();
        onDone();
      }}
      onCancel={onCancel}
    />
  );
}

function RecoverySurface({
  page,
  marker,
  transportLost,
  serverText,
  onCleared,
  onLanded,
}: {
  page: InstPage;
  marker: EnrollRecoveryMarker;
  transportLost: boolean;
  serverText: string;
  onCleared: () => void;
  onLanded: (name: string, fingerprint: string) => void;
}): JSX.Element {
  const [resolving, setResolving] = useState(false);
  const [resolution, setResolution] = useState<CDREnrollRecovery | null>(null);
  const [resolveError, setResolveError] = useState("");
  const [abandon, setAbandon] = useState(false);
  const [revokeOrphan, setRevokeOrphan] = useState(false);
  const [orphanDone, setOrphanDone] = useState<CDRRevokeResult | null>(null);

  const resolve = (): void => {
    if (resolving) return;
    const signal = page.owner.begin();
    setResolving(true);
    setResolveError("");
    recoverCDREnrollment(
      {
        operationId: marker.operationId,
        endpoint: marker.endpoint,
        serverFingerprint: marker.serverFingerprint,
      },
      signal,
    )
      .then((res) => {
        setResolution(res);
        if (res.classification === "LANDED_AND_STORED") {
          clearEnrollRecovery();
          onLanded(res.name === "" ? marker.name : res.name, res.fingerprint);
          page.refreshToResolve();
        } else if (res.classification === "NOT_ISSUED") {
          clearEnrollRecovery();
        } else if (
          res.classification === "ISSUED_BUT_NOT_STORED" &&
          res.revoked
        ) {
          clearEnrollRecovery();
        }
      })
      .catch((err: unknown) => {
        setResolveError(
          serverErrorText(err, "The appliance could not be reached."),
        );
      })
      .finally(() => {
        setResolving(false);
        page.owner.settle(signal);
      });
  };

  const cls = resolution?.classification;
  return (
    <>
      <Callout
        variant={cls === "ISSUED_BUT_NOT_STORED" ? "critical" : "warning"}
        title="Enrollment outcome unknown"
      >
        <p>
          Enrollment of <Mono>{marker.name}</Mono> at{" "}
          <Mono>{marker.endpoint}</Mono> (operation{" "}
          <Mono>{marker.operationId}</Mono>){" "}
          {transportLost
            ? "was dispatched, but the appliance did not answer."
            : "was dispatched, and the appliance could not settle its outcome."}{" "}
          {serverText !== "" && <>Appliance: {serverText} </>}
          Do NOT retry with the same token — it is single-use. Resolve the
          operation against the engine: it reports whether a credential was
          issued and, if one exists that this appliance never stored, exactly
          how to revoke it.
        </p>
        {resolveError !== "" && <p>Resolution failed: {resolveError}</p>}
        {resolution !== null && !resolution.receiptUpdated && (
          <p>
            The appliance classified the operation but could not persist the
            receipt transition ({resolution.receiptError}); its previous durable
            state is kept — resolve again later.
          </p>
        )}
        {resolution !== null && cls === "AMBIGUOUS" && (
          <p>
            <strong>AMBIGUOUS</strong> — the engine could not be asked
            {resolution.error !== "" ? ` (${resolution.error})` : ""}. The
            outcome stays unresolved; retry the resolution when the engine is
            reachable.
          </p>
        )}
        {resolution !== null && cls === "NOT_ISSUED" && (
          <p>
            <strong>NOT ISSUED</strong> — the engine has no credential for this
            operation. Nothing needs revoking; request a fresh token if the
            previous one was consumed.
          </p>
        )}
        {resolution !== null && cls === "ISSUED_BUT_NOT_STORED" && (
          <div>
            <p>
              <strong>ISSUED BUT NOT STORED</strong> — the engine issued client
              certificate <Mono>{resolution.fingerprint}</Mono> for this
              operation, but this appliance holds no key material for it.
              {resolution.revoked
                ? " Sluice already refuses it — nothing further is needed."
                : " It stays trusted by Sluice until it is revoked."}
            </p>
            {!resolution.revoked && orphanDone === null && (
              <>
                {resolution.revocation?.apiAvailable === true ? (
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => {
                      setRevokeOrphan(true);
                    }}
                  >
                    Revoke orphaned credential…
                  </Button>
                ) : (
                  <p>
                    No enrolled, reachable instance can issue the revocation
                    from here. Run on the Sluice host:{" "}
                    <Mono>{resolution.revocation?.cli ?? ""}</Mono>
                  </p>
                )}
              </>
            )}
            {orphanDone !== null && (
              <p>
                Revocation proven ({orphanDone.outcomes[orphanDone.fingerprint]}
                ) — Sluice now refuses <Mono>{orphanDone.fingerprint}</Mono>.
              </p>
            )}
          </div>
        )}
        <p>
          <Button
            size="sm"
            variant="primary"
            disabled={resolving}
            onClick={resolve}
          >
            {resolving ? "Resolving…" : "Resolve enrollment"}
          </Button>{" "}
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setAbandon(true);
            }}
          >
            Abandon recovery…
          </Button>{" "}
          {(cls === "NOT_ISSUED" ||
            (cls === "ISSUED_BUT_NOT_STORED" &&
              (resolution?.revoked === true || orphanDone !== null))) && (
            <Button size="sm" variant="ghost" onClick={onCleared}>
              Dismiss
            </Button>
          )}
        </p>
      </Callout>
      {abandon && (
        <AbandonRecoveryDialog
          marker={marker}
          onDone={() => {
            setAbandon(false);
            onCleared();
          }}
          onCancel={() => {
            setAbandon(false);
          }}
        />
      )}
      {revokeOrphan && resolution !== null && (
        <RevokeFingerprintDialog
          page={page}
          fingerprint={resolution.fingerprint}
          onDone={(res) => {
            setRevokeOrphan(false);
            setOrphanDone(res);
            clearEnrollRecovery();
          }}
          onCancel={() => {
            setRevokeOrphan(false);
          }}
        />
      )}
    </>
  );
}

// ── Tab ─────────────────────────────────────────────────────────────────────

export function CDRInstancesTab({
  isAdmin,
}: {
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(["security", "cdr", "instances"], getCDRInstances);
  const d = page.q.data;
  // Subject binding for the recovery marker: the authenticated username.
  const subject = useAuth().state.user;
  const [form, setForm] = useState<EnrollForm>(EMPTY_FORM);
  const [confirmEnroll, setConfirmEnroll] = useState(false);
  const [recovery, setRecovery] = useState<EnrollRecoveryRead>({
    kind: "none",
  });
  const [unresolvedCtx, setUnresolvedCtx] = useState<{
    transportLost: boolean;
    serverText: string;
  }>({ transportLost: true, serverText: "" });
  const [enrollBlocked, setEnrollBlocked] = useState(false);
  const [enrollError, setEnrollError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<CDRInstance | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<CDRInstance | null>(null);
  const [notice, setNotice] = useState<
    | { kind: "deleted"; name: string; fingerprints: readonly string[] }
    | { kind: "revoked"; name: string; result: CDRRevokeResult }
    | {
        kind: "enrolled";
        name: string;
        fingerprint: string;
        facts: CDREnrollResult | null;
      }
    | null
  >(null);

  const rereadRecovery = useCallback((): void => {
    setRecovery(readEnrollRecovery(subject));
  }, [subject]);
  useEffect(() => {
    rereadRecovery();
  }, [rereadRecovery]);

  const canEnroll =
    form.name.trim() !== "" &&
    form.endpoint.trim() !== "" &&
    form.serverFingerprint.trim() !== "" &&
    form.token !== "" &&
    recovery.kind === "none";

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={d !== undefined}
          onRefresh={page.refreshToResolve}
        />
      </div>

      {page.unknown !== null && (
        <Callout variant="warning" title="Last change unconfirmed">
          The outcome of the last change is unknown (the appliance did not
          answer). Refresh to load the authoritative registry before making
          further changes.
        </Callout>
      )}

      {enrollBlocked && (
        <Callout variant="critical" title="Enrollment not dispatched">
          No enrollment was sent: the recovery marker for the operation could
          not be persisted in this browser (storage unavailable or full), and an
          exchange whose outcome could never be resolved is not attempted. The
          token is unused. Free browser storage or use another browser and try
          again.
        </Callout>
      )}

      {enrollError !== "" && (
        <Callout variant="critical" title="Enrollment failed">
          {enrollError} For safety the token field was cleared — re-enter a
          token to retry (a name or validation error never reached the engine,
          so the same token is still unused; after an engine-side rejection,
          request a fresh token).
        </Callout>
      )}

      {recovery.kind === "valid" && (
        <RecoverySurface
          page={page}
          marker={recovery.marker}
          transportLost={unresolvedCtx.transportLost}
          serverText={unresolvedCtx.serverText}
          onCleared={() => {
            rereadRecovery();
          }}
          onLanded={(name, fingerprint) => {
            setNotice({ kind: "enrolled", name, fingerprint, facts: null });
            rereadRecovery();
          }}
        />
      )}
      {(recovery.kind === "unavailable" || recovery.kind === "unreadable") && (
        <Callout
          variant="critical"
          title="Enrollment recovery store unreadable"
        >
          This browser&apos;s enrollment-recovery record{" "}
          {recovery.kind === "unavailable"
            ? "cannot be inspected (storage access failed)"
            : "exists but cannot be interpreted"}
          . New enrollments are blocked until it can be read, so no operation
          can be dispatched without a resolvable identity.
        </Callout>
      )}

      {notice !== null && (
        <Callout
          variant={notice.kind === "enrolled" ? "info" : "warning"}
          title={
            notice.kind === "deleted"
              ? `Deleted ${notice.name} (locally)`
              : notice.kind === "revoked"
                ? `Revoked the credentials of ${notice.name}`
                : `Enrolled ${notice.name}`
          }
        >
          {notice.kind === "deleted" && (
            <>
              Sluice still trusts{" "}
              {notice.fingerprints.length === 1
                ? "client certificate"
                : `${String(notice.fingerprints.length)} client certificates`}{" "}
              <FingerprintList fps={notice.fingerprints} /> until{" "}
              {notice.fingerprints.length === 1
                ? "it expires or is revoked"
                : "each expires or is revoked"}{" "}
              on the Sluice side. These fingerprints are also in the audit
              trail.
            </>
          )}
          {notice.kind === "revoked" && (
            <>
              Sluice proved a durable deny for every generation:
              <ul>
                {notice.result.fingerprints.map((fp) => (
                  <li key={fp}>
                    <Mono>{fp}</Mono> — {notice.result.outcomes[fp] ?? "proven"}
                  </li>
                ))}
              </ul>
              {notice.result.localPruned
                ? "Local key material was destroyed."
                : "The local registry entry could not be pruned — refresh and retry (safe: the deny is durable at Sluice)."}
            </>
          )}
          {notice.kind === "enrolled" && (
            <>
              Credential issued and stored; client certificate fingerprint{" "}
              <Mono>{notice.fingerprint}</Mono>.{" "}
              {notice.facts === null
                ? "The engine confirmed the enrollment landed."
                : notice.facts.cdrEnabled
                  ? notice.facts.autoEnable.succeeded
                    ? `CDR processing was enabled (persisted); ${notice.facts.clientActive ? "a client is active." : "no client is active yet — check the pool state after a refresh."}`
                    : `CDR processing is enabled; ${notice.facts.clientActive ? "a client is active." : "no client is active yet."}`
                  : notice.facts.autoEnable.attempted
                    ? "CDR is still disabled: the automatic enable could NOT be persisted" +
                      (notice.facts.autoEnable.error !== ""
                        ? ` (${notice.facts.autoEnable.error})`
                        : "") +
                      ". Do not re-enroll — the credential is already stored; enable CDR processing from the Overview toggle."
                    : "CDR is still disabled."}
              {notice.facts !== null && !notice.facts.receiptRecorded && (
                <>
                  {" "}
                  The recovery receipt could not be marked stored (
                  {notice.facts.receiptError}); it stays
                  &ldquo;dispatched&rdquo; and a later resolution reports LANDED
                  from the registry.
                </>
              )}
              {notice.facts !== null && notice.facts.clientInitError !== "" && (
                <> Client dial failed: {notice.facts.clientInitError}.</>
              )}
            </>
          )}{" "}
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setNotice(null);
            }}
          >
            Dismiss
          </Button>
        </Callout>
      )}

      {d === undefined && page.q.isPending && (
        <Skeleton>Loading enrolled instances…</Skeleton>
      )}
      {d === undefined && page.q.isError && (
        <ErrorState title="Instance registry unavailable">
          The enrolled-instance registry could not be loaded. Refresh to try
          again.
        </ErrorState>
      )}

      {d !== undefined && (
        <Card title={`Enrolled instances (${String(d.count)})`}>
          {d.instances.length === 0 ? (
            <EmptyState title="No instances enrolled">
              Enroll a Sluice instance below to activate CDR processing.
            </EmptyState>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className="sr-only">Enrolled Sluice instances</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Endpoint</th>
                    <th scope="col">Client cert fingerprint</th>
                    <th scope="col">Credential lineage</th>
                    <th scope="col">Cert expiry</th>
                    <th scope="col">Pool state</th>
                    {isAdmin && <th scope="col">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {d.instances.map((inst) => (
                    <tr key={inst.name}>
                      <td>
                        <Mono>{inst.name}</Mono>
                        {!inst.enabled && " (disabled)"}
                      </td>
                      <td>
                        <Mono>{inst.endpoint}</Mono>
                      </td>
                      <td title={inst.clientCertFingerprint}>
                        <Mono>{fpShort(inst.clientCertFingerprint)}</Mono>
                      </td>
                      <td title={inst.liveFingerprints.join("\n")}>
                        {String(inst.liveFingerprints.length)} live
                        {inst.credentials.length > 0 &&
                          ` (${inst.credentials.map((g) => g.state).join(", ")})`}
                      </td>
                      <td>
                        {inst.clientCertDaysRemaining === undefined
                          ? "unknown"
                          : `${String(inst.clientCertDaysRemaining)} day(s)`}
                      </td>
                      <td>
                        {inst.poolHealthy === undefined
                          ? "not pooled"
                          : `${inst.poolHealthy ? "last probe answered" : "last probe failed"}${
                              inst.cbState !== undefined
                                ? `; breaker ${inst.cbState}`
                                : ""
                            }`}
                      </td>
                      {isAdmin && (
                        <td>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={page.unknown !== null}
                            onClick={() => {
                              setRevokeTarget(inst);
                            }}
                          >
                            Revoke…
                          </Button>{" "}
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={page.unknown !== null}
                            onClick={() => {
                              setDeleteTarget(inst);
                            }}
                          >
                            Delete…
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className={styles.refDetail}>
            &ldquo;Last probe answered&rdquo; means the most recent health probe
            succeeded — it is not a claim that production file traffic is
            flowing through the instance. A row&apos;s fingerprint is the
            credential Sluice uses to identify this appliance; the lineage
            column counts every generation Sluice may still trust (a renewal
            never retires its predecessor at Sluice — revoke does). An
            &ldquo;unknown&rdquo; fingerprint marks an entry enrolled before
            fingerprints were recorded durably.
          </p>
        </Card>
      )}

      {isAdmin && (
        <Card title="Enroll a new instance">
          <p className={styles.refDetail}>
            Requires a single-use enrollment token and the server-certificate
            fingerprint from the Sluice operator. The token is sent once and
            never stored or displayed by this appliance.
            {recovery.kind === "valid" &&
              " Resolve or abandon the pending enrollment above before starting another."}
          </p>
          <InputField
            label="Instance name"
            required
            help="Unique, immutable after enrollment; letters/digits then letters/digits/dot/dash/underscore (max 64)."
            value={form.name}
            onChange={(e) => {
              setForm({ ...form, name: e.target.value });
            }}
          />
          <InputField
            label="Endpoint (host:port)"
            required
            value={form.endpoint}
            onChange={(e) => {
              setForm({ ...form, endpoint: e.target.value });
            }}
          />
          <InputField
            label="Server certificate fingerprint (TOFU pin)"
            required
            help="SHA-256 of the Sluice server certificate, as provided out-of-band."
            value={form.serverFingerprint}
            onChange={(e) => {
              setForm({ ...form, serverFingerprint: e.target.value });
            }}
          />
          <InputField
            label="Enrollment token (single-use)"
            required
            type="password"
            autoComplete="off"
            value={form.token}
            onChange={(e) => {
              setForm({ ...form, token: e.target.value });
            }}
          />
          <div className={styles.toolbar}>
            <Button
              variant="primary"
              disabled={!canEnroll || page.unknown !== null}
              onClick={() => {
                setConfirmEnroll(true);
              }}
            >
              Enroll instance…
            </Button>
          </div>
        </Card>
      )}

      {confirmEnroll && (
        <EnrollConfirmDialog
          page={page}
          form={form}
          subject={subject}
          onDone={(res) => {
            setForm(EMPTY_FORM);
            setEnrollBlocked(false);
            setEnrollError("");
            setNotice({
              kind: "enrolled",
              name: res.instance.name,
              fingerprint: res.instance.clientCertFingerprint,
              facts: res,
            });
            setConfirmEnroll(false);
            rereadRecovery();
          }}
          onUnresolved={(transportLost, serverText) => {
            // The single-use token must not linger for an accidental retry.
            setForm({ ...form, token: "" });
            setEnrollBlocked(false);
            setEnrollError("");
            setUnresolvedCtx({ transportLost, serverText });
            setConfirmEnroll(false);
            rereadRecovery();
          }}
          onBlocked={() => {
            setEnrollBlocked(true);
            setConfirmEnroll(false);
            rereadRecovery();
          }}
          onFail={(error) => {
            // Secret hygiene: a dispatched token is cleared on EVERY
            // outcome — a controlled input's value is serialized into the
            // DOM, and a sent token must not be reconstructable from it.
            setForm({ ...form, token: "" });
            setEnrollBlocked(false);
            setEnrollError(error);
            setConfirmEnroll(false);
            rereadRecovery();
          }}
          onCancel={() => {
            setConfirmEnroll(false);
          }}
        />
      )}
      {deleteTarget !== null && (
        <DeleteDialog
          page={page}
          target={deleteTarget}
          onOrphan={(name, fingerprints) => {
            setNotice({ kind: "deleted", name, fingerprints });
            setDeleteTarget(null);
          }}
          onCancel={() => {
            setDeleteTarget(null);
          }}
        />
      )}
      {revokeTarget !== null && (
        <RevokeDialog
          page={page}
          target={revokeTarget}
          onDone={(result) => {
            setNotice({ kind: "revoked", name: result.revoked, result });
            setRevokeTarget(null);
          }}
          onCancel={() => {
            setRevokeTarget(null);
          }}
        />
      )}
    </div>
  );
}
