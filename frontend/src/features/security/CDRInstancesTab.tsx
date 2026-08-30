// 2E-C Instances: the Sluice TRUST registry. An instance's registry key is
// its immutable enrollment name; its SECURITY identity is the client-cert
// SHA-256 fingerprint (the only key Sluice accepts for revocation) — shown
// on the row and on every trust ceremony.
//
// The two removal actions are DIFFERENT operations and are never conflated:
//   REVOKE — retires the credential ON THE SLUICE SIDE (irreversible), then
//            prunes locally. Idempotent at Sluice → safe to retry after an
//            unknown outcome. Needs a second enrolled instance (Sluice
//            refuses self-revocation).
//   DELETE — LOCAL only: prunes this appliance's registry and shreds its
//            copy of the credential. Sluice keeps trusting the fingerprint
//            until expiry or a Sluice-side revocation; the ceremony and the
//            completion notice both carry that fingerprint.
//
// Enrollment consumes a SINGLE-USE token (never echoed, never stored) and is
// non-idempotent: an unknown outcome is latched with explicit recovery
// guidance and is NEVER blindly retried.
import { useState, type JSX } from "react";
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
import { useObjectPage, type ObjectPageState } from "../objects/useObjectPage";
import { unknownOutcome, serverErrorText } from "../../shared/mutationOutcome";
import {
  deleteCDRInstance,
  enrollCDRInstance,
  getCDRInstances,
  revokeCDRInstance,
  type CDRInstance,
  type CDRInstances,
} from "../../api/cdr";
import styles from "../policy/policy.module.css";

type InstPage = ObjectPageState<CDRInstances>;

function fpShort(fp: string): string {
  if (fp === "") return "unknown";
  const hex = fp.startsWith("sha256:") ? fp.slice(7) : fp;
  return hex.length > 16 ? `${hex.slice(0, 16)}…` : hex;
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
  onOrphan: (name: string, fingerprint: string) => void;
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
            keeps trusting client certificate{" "}
            <Mono>
              {target.clientCertFingerprint === ""
                ? "(fingerprint unknown)"
                : target.clientCertFingerprint}
            </Mono>{" "}
            until it expires or is revoked there.
          </p>
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
      impact="Local trust and key material are destroyed; the credential itself remains valid at Sluice until it expires or is revoked there."
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
            onOrphan(res.removed, res.clientCertFingerprint);
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

// ── Revoke (Sluice-side) ceremony ───────────────────────────────────────────

function RevokeDialog({
  page,
  target,
  onDone,
  onCancel,
}: {
  page: InstPage;
  target: CDRInstance;
  onDone: (name: string, fingerprint: string) => void;
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
      title={`Revoke the credential of ${target.name}`}
      body={
        <>
          <p>
            This tells Sluice to permanently refuse client certificate{" "}
            <Mono>
              {target.clientCertFingerprint === ""
                ? "(fingerprint read from disk at revoke time)"
                : target.clientCertFingerprint}
            </Mono>
            , then removes <Mono>{target.name}</Mono> from this appliance and
            destroys the local key material. The revocation is IRREVERSIBLE —
            using this engine again requires re-enrollment with a new single-use
            token.
          </p>
          <p>
            Sluice refuses self-revocation, so the call is issued through
            another enrolled instance; with no other reachable instance this
            action fails with a clear error and nothing changes.
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
      impact="The credential stops working at Sluice permanently; if this was the last usable instance, CDR calls follow the configured fail mode."
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
            onDone(res.revoked, res.fingerprint);
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
  onDone,
  onUnknown,
  onFail,
  onCancel,
}: {
  page: InstPage;
  form: EnrollForm;
  onDone: (inst: CDRInstance) => void;
  onUnknown: () => void;
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
          be used again. The first successful enrollment also enables CDR
          processing (persisted).
        </>
      }
      impact="Establishes mutual trust with the engine; with CDR enabled, matching file downloads are processed by it."
      rollback="Revoke the credential (preferred) or delete the instance locally."
      confirmLabel="Enroll instance"
      result={result}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        enrollCDRInstance(
          {
            name: form.name.trim(),
            endpoint: form.endpoint.trim(),
            serverFingerprint: form.serverFingerprint.trim(),
            token: form.token,
          },
          signal,
        )
          .then((inst) => {
            onDone(inst);
            page.refreshToResolve();
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("create");
              setResult("unknown");
              onUnknown();
              return;
            }
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

// ── Tab ─────────────────────────────────────────────────────────────────────

export function CDRInstancesTab({
  isAdmin,
}: {
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(["security", "cdr", "instances"], getCDRInstances);
  const d = page.q.data;
  const [form, setForm] = useState<EnrollForm>(EMPTY_FORM);
  const [confirmEnroll, setConfirmEnroll] = useState(false);
  const [enrollUnknown, setEnrollUnknown] = useState(false);
  const [enrollError, setEnrollError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<CDRInstance | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<CDRInstance | null>(null);
  const [notice, setNotice] = useState<{
    kind: "deleted" | "revoked" | "enrolled";
    name: string;
    fingerprint: string;
  } | null>(null);

  const canEnroll =
    form.name.trim() !== "" &&
    form.endpoint.trim() !== "" &&
    form.serverFingerprint.trim() !== "" &&
    form.token !== "";

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

      {enrollError !== "" && (
        <Callout variant="critical" title="Enrollment failed">
          {enrollError} For safety the token field was cleared — re-enter a
          token to retry (a name or validation error never reached the engine,
          so the same token is still unused; after an engine-side rejection,
          request a fresh token).
        </Callout>
      )}

      {enrollUnknown && (
        <Callout variant="warning" title="Enrollment outcome unknown">
          The appliance did not answer, so the enrollment may or may not have
          completed. Do NOT retry with the same token — it is single-use.
          Refresh: if the instance appears in the list, the enrollment landed.
          If it does not appear and the token was consumed on the engine side, a
          certificate may exist in the engine&apos;s ledger that this appliance
          never stored — issue a new token to enroll again, and revoke the
          orphaned certificate on the Sluice side if required.
        </Callout>
      )}

      {notice !== null && (
        <Callout
          variant={notice.kind === "enrolled" ? "info" : "warning"}
          title={
            notice.kind === "deleted"
              ? `Deleted ${notice.name} (locally)`
              : notice.kind === "revoked"
                ? `Revoked the credential of ${notice.name}`
                : `Enrolled ${notice.name}`
          }
        >
          {notice.kind === "deleted" && (
            <>
              Sluice still trusts client certificate{" "}
              <Mono>
                {notice.fingerprint === ""
                  ? "(fingerprint unknown — the cert could not be read before the shred)"
                  : notice.fingerprint}
              </Mono>{" "}
              until it expires or is revoked on the Sluice side. This
              fingerprint is also in the audit trail.
            </>
          )}
          {notice.kind === "revoked" && (
            <>
              Client certificate <Mono>{notice.fingerprint}</Mono> is now
              refused by the engine. Local key material was destroyed.
            </>
          )}
          {notice.kind === "enrolled" && (
            <>
              Credential issued; client certificate fingerprint{" "}
              <Mono>{notice.fingerprint}</Mono>. CDR was auto-enabled if it was
              off.
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
            credential Sluice uses to identify this appliance; an
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
          onDone={(inst) => {
            setForm(EMPTY_FORM);
            setEnrollUnknown(false);
            setEnrollError("");
            setNotice({
              kind: "enrolled",
              name: inst.name,
              fingerprint: inst.clientCertFingerprint,
            });
            setConfirmEnroll(false);
          }}
          onUnknown={() => {
            // The single-use token must not linger for an accidental retry.
            setForm({ ...form, token: "" });
            setEnrollError("");
            setEnrollUnknown(true);
            setConfirmEnroll(false);
          }}
          onFail={(error) => {
            // Secret hygiene: a dispatched token is cleared on EVERY
            // outcome — a controlled input's value is serialized into the
            // DOM, and a sent token must not be reconstructable from it.
            setForm({ ...form, token: "" });
            setEnrollUnknown(false);
            setEnrollError(error);
            setConfirmEnroll(false);
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
          onOrphan={(name, fingerprint) => {
            setNotice({ kind: "deleted", name, fingerprint });
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
          onDone={(name, fingerprint) => {
            setNotice({ kind: "revoked", name, fingerprint });
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
