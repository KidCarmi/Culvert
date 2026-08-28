// 2D-A.3 — Decryption Profiles: the "how to decrypt" object Access Rules
// reference for SSL-inspected traffic. Security-critical presentation rules
// (§15/§16):
//   - the enum vocabularies are locked to the backend contract (objects.ts
//     constants, pinned at compile time and by the Go lockstep test);
//     "permissive" is retired and never rendered or submitted;
//   - certVerification=skip is stated plainly as "verification disabled" —
//     never euphemized;
//   - onInspectError=fail-open carries an explicit pre-save warning: it opts
//     matched traffic into the adaptive decryption-exclusion cache (learned
//     bypass). It is a different failure class from onUnsupported=fail-open
//     and the copy never conflates them;
//   - InspectHTTP2 is tri-state (inherit / native HTTP/2 / force strip) —
//     inherit is never collapsed into false;
//   - a profile whose stored values violate the contract renders as a
//     DEGRADED read-only row (decoder truth, never coerced).
import { useEffect, useState, type JSX } from "react";
import { useSearchParams } from "react-router";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  ErrorState,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { InputField, SelectField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  CERT_VERIFICATION_VALUES,
  ON_INSPECT_ERROR_VALUES,
  ON_UNSUPPORTED_VALUES,
  STALL_TIMEOUT_MAX_SECS,
  STALL_TIMEOUT_MIN_SECS,
  TLS_VERSION_VALUES,
  createDecryptionProfile,
  deleteDecryptionProfile,
  getDecryptionProfiles,
  updateDecryptionProfile,
} from "../../api/objects";
import type {
  CertVerification,
  DecryptionProfileView,
  DecryptionProfileWrite,
  OnInspectError,
  OnUnsupported,
  TLSVersion,
} from "../../api/objects";
import { asPolicyConflict } from "../../api/policyWrite";
import { WhereUsed } from "../policy/WhereUsed";
import { useObjectPage } from "./useObjectPage";
import { ObjectDeleteDialog } from "./ObjectDeleteDialog";
import styles from "../policy/policy.module.css";

// ── security-precise vocabulary (§16) ───────────────────────────────────────

const CERT_LABEL: Record<CertVerification, string> = {
  "": "Inherit (rule's TLS setting)",
  strict: "Strict — verify origin certificate, fail closed",
  skip: "Skip — certificate verification DISABLED",
};
const ON_UNSUPPORTED_LABEL: Record<OnUnsupported, string> = {
  "": "Inherit (fail closed)",
  "fail-close": "Fail closed — drop when origin TLS cannot be inspected",
  "fail-open": "Fail open — relay uninspected when origin TLS is unsupported",
};
const ON_INSPECT_ERROR_LABEL: Record<OnInspectError, string> = {
  "": "Inherit (fail closed)",
  "fail-close": "Fail closed — refuse the session (502)",
  "fail-open": "Fail open — learn an adaptive decryption exclusion",
};
const TLS_LABEL: Record<TLSVersion, string> = {
  "": "Inherit",
  "1.2": "TLS 1.2",
  "1.3": "TLS 1.3",
};

type H2Choice = "inherit" | "native" | "strip";
const H2_CHOICES = ["inherit", "native", "strip"] as const;

/** Narrow a <select> value back into its closed vocabulary without a type
 * assertion (decoder discipline): an unexpected value keeps the current one. */
function pickEnum<T extends string>(
  values: readonly T[],
  v: string,
  fallback: T,
): T {
  for (const x of values) if (x === v) return x;
  return fallback;
}

function h2Choice(v: boolean | null): H2Choice {
  if (v === null) return "inherit";
  return v ? "native" : "strip";
}

function h2Value(c: H2Choice): boolean | null {
  if (c === "inherit") return null;
  return c === "native";
}

function h2Display(v: boolean | null): string {
  if (v === null) return "inherit (strip → HTTP/1.1)";
  return v ? "native HTTP/2 inspection" : "force strip → HTTP/1.1";
}

type EditorMode =
  { kind: "create" } | { kind: "edit"; profile: DecryptionProfileView };

export function DecryptionProfilesPage(): JSX.Element {
  const page = useObjectPage(
    ["objects", "decryption-profiles"],
    getDecryptionProfiles,
  );
  const q = page.q;
  const snap = q.data;
  const { state } = useAuth();
  const canWrite = hasRole(state.role ?? "viewer", "operator");
  const [openId, setOpenId] = useState<string | null>(null);
  const [params] = useSearchParams();

  const [editor, setEditor] = useState<EditorMode | null>(null);
  const [editorDirty, setEditorDirty] = useState(false);
  const [deleting, setDeleting] = useState<DecryptionProfileView | null>(null);
  const [notice, setNotice] = useState("");

  const closeAllWriteState = (): void => {
    setEditor(null);
    setEditorDirty(false);
    setDeleting(null);
    setNotice("");
  };
  page.setBoundaryCleanup(closeAllWriteState);

  const blocked = page.unknown !== null;
  const profiles = snap?.profiles ?? [];
  const degraded = snap?.degraded ?? [];
  const version = snap?.version ?? 0;

  const guard = useDirtyGuard(
    editorDirty,
    "the unsaved decryption-profile changes in the editor",
  );

  const linkedId = params.get("id");
  useEffect(() => {
    if (linkedId !== null && linkedId !== "") setOpenId(linkedId);
  }, [linkedId]);

  return (
    <>
      <PageHeader
        title="Decryption Profiles"
        subtitle="How SSL-inspected tunnels are decrypted: HTTP/2 posture, origin certificate verification, unsupported-TLS and inspection-error postures, TLS bounds, and the stream stall timeout. Rules link by the stable object ID."
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={snap !== undefined}
            onRefresh={page.refreshToResolve}
          />
        }
      />

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the {page.unknown} may or may not have been applied. Refresh and
            review the current objects before making further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh objects
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {notice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Not applied" role="alert">
            {notice}
          </Callout>
        </div>
      )}

      {snap === undefined && q.isPending && (
        <Skeleton>Loading decryption profiles…</Skeleton>
      )}
      {snap === undefined && q.isError && (
        <ErrorState title="Decryption profiles unavailable">
          The decryption-profile snapshot could not be loaded. Refresh to try
          again.
        </ErrorState>
      )}

      {snap !== undefined && (
        <>
          <div className={styles.toolbar}>
            {canWrite && (
              <div className={styles.toolbarActions}>
                <Button
                  disabled={blocked}
                  onClick={() => {
                    setEditor({ kind: "create" });
                    setNotice("");
                  }}
                >
                  New decryption profile…
                </Button>
              </div>
            )}
            <span className={styles.counts}>
              {String(profiles.length + degraded.length)} decryption{" "}
              {profiles.length + degraded.length === 1 ? "profile" : "profiles"}
            </span>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">Decryption profiles</caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Details" />
                  <th scope="col">Name</th>
                  <th scope="col">Object ID</th>
                  <th scope="col">HTTP/2</th>
                  <th scope="col">Cert verification</th>
                  <th scope="col">On inspect error</th>
                  {canWrite && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {profiles.length === 0 && degraded.length === 0 && (
                  <tr>
                    <td colSpan={canWrite ? 7 : 6}>
                      No decryption profiles are defined. Inspected tunnels use
                      the rule-level settings and engine defaults.
                    </td>
                  </tr>
                )}
                {profiles.map((p) => {
                  const open = openId === p.id;
                  return (
                    <ProfileRow
                      key={p.id}
                      p={p}
                      open={open}
                      canWrite={canWrite}
                      blocked={blocked}
                      highlighted={linkedId === p.id}
                      onToggle={() => {
                        setOpenId(open ? null : p.id);
                      }}
                      onEdit={() => {
                        setEditor({ kind: "edit", profile: p });
                        setNotice("");
                      }}
                      onDelete={() => {
                        setDeleting(p);
                        setNotice("");
                      }}
                    />
                  );
                })}
                {degraded.map((d, i) => (
                  <tr key={d.id !== "" ? d.id : `degraded-${String(i)}`}>
                    <td />
                    <td>{d.name === "" ? "(unnamed)" : d.name}</td>
                    <td>{d.id === "" ? "—" : <Mono>{d.id}</Mono>}</td>
                    <td colSpan={canWrite ? 4 : 3}>
                      <StatusBadge status="warn">degraded</StatusBadge>{" "}
                      <span className={styles.refDetail}>
                        This profile carries a value outside this console&apos;s
                        security contract ({d.reason}). It stays enforced as
                        stored and is read-only here.
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {editor !== null && canWrite && snap !== undefined && (
        <ProfileEditor
          mode={editor}
          version={version}
          blocked={blocked}
          page={page}
          onDone={() => {
            setEditor(null);
            setEditorDirty(false);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setEditor(null);
            setEditorDirty(false);
          }}
          onDirtyChange={setEditorDirty}
          onConflictNotice={setNotice}
        />
      )}

      {deleting !== null && canWrite && (
        <ObjectDeleteDialog
          objType="decryption-profile"
          objName={deleting.name}
          objId={deleting.id}
          body={
            <>
              This deletes the decryption profile{" "}
              <strong>{deleting.name}</strong> (<Mono>{deleting.id}</Mono>). The
              delete is refused while any Access Rule — running or staged in an
              active Policy Draft — references it.
            </>
          }
          doDelete={(signal) =>
            deleteDecryptionProfile(deleting.id, version, signal)
          }
          page={page}
          onDone={() => {
            setDeleting(null);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setDeleting(null);
          }}
          onConflictNotice={(text) => {
            setDeleting(null);
            setNotice(text);
            page.refreshToResolve();
          }}
        />
      )}
      {guard.element}
    </>
  );
}

function certBadge(p: DecryptionProfileView): JSX.Element {
  switch (p.certVerification) {
    case "strict":
      return <StatusBadge status="ok">strict</StatusBadge>;
    case "skip":
      // Verification disabled — a warning state, never neutral.
      return <StatusBadge status="warn">skip (disabled)</StatusBadge>;
    case "":
      return <StatusBadge status="neutral">inherit</StatusBadge>;
  }
}

function inspectErrorBadge(p: DecryptionProfileView): JSX.Element {
  switch (p.onInspectError) {
    case "fail-open":
      return <StatusBadge status="warn">fail-open</StatusBadge>;
    case "fail-close":
      return <StatusBadge status="ok">fail-close</StatusBadge>;
    case "":
      return <StatusBadge status="neutral">inherit</StatusBadge>;
  }
}

function ProfileRow({
  p,
  open,
  canWrite,
  blocked,
  highlighted,
  onToggle,
  onEdit,
  onDelete,
}: {
  p: DecryptionProfileView;
  open: boolean;
  canWrite: boolean;
  blocked: boolean;
  highlighted: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
}): JSX.Element {
  return (
    <>
      <tr
        className={styles.ruleRow}
        data-highlight={highlighted ? "true" : undefined}
      >
        <td>
          <Button
            size="sm"
            variant="ghost"
            aria-expanded={open}
            aria-label={`Details for profile ${p.name}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </Button>
        </td>
        <td>{p.name}</td>
        <td>
          <Mono>{p.id}</Mono>
        </td>
        <td>{h2Display(p.inspectHttp2)}</td>
        <td>{certBadge(p)}</td>
        <td>{inspectErrorBadge(p)}</td>
        {canWrite && (
          <td>
            <span className={styles.rowActions}>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                aria-label={`Edit profile ${p.name}`}
                onClick={onEdit}
              >
                Edit
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                aria-label={`Delete profile ${p.name}`}
                onClick={onDelete}
              >
                Delete
              </Button>
            </span>
          </td>
        )}
      </tr>
      {open && (
        <tr>
          <td colSpan={canWrite ? 7 : 6}>
            <div className={styles.rowDetail}>
              <dl className={styles.kvGrid}>
                <div>
                  <dt className={styles.refDetail}>Object ID</dt>
                  <dd>
                    <Mono>{p.id}</Mono>
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Inspect HTTP/2</dt>
                  <dd>{h2Display(p.inspectHttp2)}</dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Certificate verification</dt>
                  <dd>{CERT_LABEL[p.certVerification]}</dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Unsupported TLS</dt>
                  <dd>{ON_UNSUPPORTED_LABEL[p.onUnsupported]}</dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>On inspect error</dt>
                  <dd>{ON_INSPECT_ERROR_LABEL[p.onInspectError]}</dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>TLS bounds</dt>
                  <dd>
                    {TLS_LABEL[p.minTlsVersion]} → {TLS_LABEL[p.maxTlsVersion]}
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Stall timeout</dt>
                  <dd>
                    {p.stallTimeoutSecs === 0
                      ? "inherit engine default"
                      : `${String(p.stallTimeoutSecs)}s`}
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Updated</dt>
                  <dd>{p.updatedAt === "" ? "—" : p.updatedAt}</dd>
                </div>
              </dl>
              {p.onInspectError === "fail-open" && (
                <Callout
                  variant="warning"
                  title="Fail-open participates in adaptive decryption exclusion"
                >
                  Sessions matched to this profile that cannot be inspected can
                  LEARN a temporary decryption exclusion: subsequent connections
                  to the learned host bypass inspection until the entry expires.
                  Review the Decryption Exclusions surface for the live cache.
                </Callout>
              )}
              <WhereUsed type="decryption-profile" name={p.name} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Editor ──────────────────────────────────────────────────────────────────

function ProfileEditor({
  mode,
  version,
  blocked,
  page,
  onDone,
  onCancel,
  onDirtyChange,
  onConflictNotice,
}: {
  mode: EditorMode;
  version: number;
  blocked: boolean;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getDecryptionProfiles>>>
  >;
  onDone: () => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const emptyWrite: DecryptionProfileWrite = {
    name: "",
    inspectHttp2: null,
    certVerification: "",
    onUnsupported: "",
    onInspectError: "",
    minTlsVersion: "",
    maxTlsVersion: "",
    stallTimeoutSecs: 0,
  };
  const initial: DecryptionProfileWrite =
    mode.kind === "edit"
      ? {
          name: mode.profile.name,
          inspectHttp2: mode.profile.inspectHttp2,
          certVerification: mode.profile.certVerification,
          onUnsupported: mode.profile.onUnsupported,
          onInspectError: mode.profile.onInspectError,
          minTlsVersion: mode.profile.minTlsVersion,
          maxTlsVersion: mode.profile.maxTlsVersion,
          stallTimeoutSecs: mode.profile.stallTimeoutSecs,
        }
      : emptyWrite;
  const [w, setW] = useState<DecryptionProfileWrite>(initial);
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");

  const dirty =
    w.name !== initial.name ||
    w.inspectHttp2 !== initial.inspectHttp2 ||
    w.certVerification !== initial.certVerification ||
    w.onUnsupported !== initial.onUnsupported ||
    w.onInspectError !== initial.onInspectError ||
    w.minTlsVersion !== initial.minTlsVersion ||
    w.maxTlsVersion !== initial.maxTlsVersion ||
    w.stallTimeoutSecs !== initial.stallTimeoutSecs;
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);

  const renaming =
    mode.kind === "edit" &&
    w.name.trim() !== "" &&
    w.name.trim().toLowerCase() !== mode.profile.name.toLowerCase();

  const localError = ((): string => {
    if (w.name.trim() === "") return "A profile name is required.";
    if (
      w.minTlsVersion !== "" &&
      w.maxTlsVersion !== "" &&
      w.minTlsVersion > w.maxTlsVersion
    ) {
      return "The TLS floor exceeds the TLS cap.";
    }
    if (
      w.stallTimeoutSecs !== 0 &&
      (w.stallTimeoutSecs < STALL_TIMEOUT_MIN_SECS ||
        w.stallTimeoutSecs > STALL_TIMEOUT_MAX_SECS)
    ) {
      return `Stall timeout must be 0 (inherit) or between ${String(STALL_TIMEOUT_MIN_SECS)} and ${String(STALL_TIMEOUT_MAX_SECS)} seconds.`;
    }
    return "";
  })();

  const submit = (): void => {
    if (localError !== "") {
      setServerError(localError);
      return;
    }
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    const write = { ...w, name: w.name.trim() };
    const call =
      mode.kind === "create"
        ? createDecryptionProfile(write, version, signal)
        : updateDecryptionProfile(mode.profile.id, write, version, signal);
    call
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown(
            mode.kind === "create" ? "create" : renaming ? "rename" : "edit",
          );
          onCancel();
          return;
        }
        const conflict = asPolicyConflict(err);
        if (conflict !== null) {
          onConflictNotice(
            "The decryption profiles changed since you loaded them. The change was not applied — review the refreshed objects and reapply.",
          );
          onCancel();
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance rejected the profile."),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
        setPending(false);
      });
  };

  return (
    <Dialog
      open
      onClose={onCancel}
      title={
        mode.kind === "create"
          ? "New decryption profile"
          : `Edit decryption profile: ${mode.profile.name}`
      }
    >
      <DialogBody>
        {mode.kind === "edit" && (
          <p className={styles.refDetail}>
            Object ID <Mono>{mode.profile.id}</Mono> — stable across renames;
            referencing Access Rules follow this ID.
          </p>
        )}
        <InputField
          label="Profile name"
          required
          help="Letters, digits, space, . _ - (1–64 characters)."
          value={w.name}
          disabled={pending}
          onChange={(e) => {
            setW({ ...w, name: e.target.value });
          }}
        />
        {renaming && (
          <Callout variant="info" title="This is a rename">
            The stable object ID is preserved, so every referencing Access Rule
            keeps pointing at this same profile, and learned adaptive decryption
            exclusions scoped to it remain valid — the security posture is
            unchanged by a rename. The appliance updates the display name on
            referencing rules in the running policy and in any open Policy Draft
            candidate.
          </Callout>
        )}

        <SelectField
          label="Inspect HTTP/2"
          help="Inherit follows the matched rule (today: strip to HTTP/1.1)."
          value={h2Choice(w.inspectHttp2)}
          disabled={pending}
          onChange={(e) => {
            setW({
              ...w,
              inspectHttp2: h2Value(
                pickEnum(H2_CHOICES, e.target.value, h2Choice(w.inspectHttp2)),
              ),
            });
          }}
        >
          <option value="inherit">Inherit (rule setting / strip)</option>
          <option value="native">Inspect natively as HTTP/2</option>
          <option value="strip">Force strip → HTTP/1.1</option>
        </SelectField>

        <SelectField
          label="Certificate verification"
          help="How the origin (upstream) certificate is checked on the inspect leg."
          value={w.certVerification}
          disabled={pending}
          onChange={(e) => {
            setW({
              ...w,
              certVerification: pickEnum(
                CERT_VERIFICATION_VALUES,
                e.target.value,
                w.certVerification,
              ),
            });
          }}
        >
          {CERT_VERIFICATION_VALUES.map((v) => (
            <option key={v} value={v}>
              {CERT_LABEL[v]}
            </option>
          ))}
        </SelectField>
        {w.certVerification === "skip" && (
          <Callout variant="warning" title="Certificate verification disabled">
            Matching inspected sessions accept ANY origin certificate —
            including expired, untrusted, or actively forged ones. This removes
            the man-in-the-middle protection on the origin leg.
          </Callout>
        )}

        <SelectField
          label="Unsupported TLS"
          help="Posture when the ORIGIN's TLS parameters cannot be inspected (version/cipher outside the supported range)."
          value={w.onUnsupported}
          disabled={pending}
          onChange={(e) => {
            setW({
              ...w,
              onUnsupported: pickEnum(
                ON_UNSUPPORTED_VALUES,
                e.target.value,
                w.onUnsupported,
              ),
            });
          }}
        >
          {ON_UNSUPPORTED_VALUES.map((v) => (
            <option key={v} value={v}>
              {ON_UNSUPPORTED_LABEL[v]}
            </option>
          ))}
        </SelectField>

        <SelectField
          label="On inspect error"
          help="Posture when an inspected session cannot be established because the HOST is incompatible with inspection (client cert demanded, pinned client, unsupported parameters). A different failure class from Unsupported TLS above."
          value={w.onInspectError}
          disabled={pending}
          onChange={(e) => {
            setW({
              ...w,
              onInspectError: pickEnum(
                ON_INSPECT_ERROR_VALUES,
                e.target.value,
                w.onInspectError,
              ),
            });
          }}
        >
          {ON_INSPECT_ERROR_VALUES.map((v) => (
            <option key={v} value={v}>
              {ON_INSPECT_ERROR_LABEL[v]}
            </option>
          ))}
        </SelectField>
        {w.onInspectError === "fail-open" && (
          <Callout
            variant="warning"
            title="Fail-open enables adaptive decryption exclusion"
          >
            Hosts that repeatedly fail inspection under this profile are LEARNED
            into a temporary exclusion cache and subsequent sessions to them
            BYPASS inspection (no DLP/AV/content scanning) until the entry
            expires. The learned scope is isolated to this profile, but this is
            a real, automatic reduction of inspection coverage — save only if
            that is intended.
          </Callout>
        )}

        <SelectField
          label="Minimum TLS version"
          value={w.minTlsVersion}
          disabled={pending}
          onChange={(e) => {
            setW({
              ...w,
              minTlsVersion: pickEnum(
                TLS_VERSION_VALUES,
                e.target.value,
                w.minTlsVersion,
              ),
            });
          }}
        >
          {TLS_VERSION_VALUES.map((v) => (
            <option key={v} value={v}>
              {TLS_LABEL[v]}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Maximum TLS version"
          value={w.maxTlsVersion}
          disabled={pending}
          onChange={(e) => {
            setW({
              ...w,
              maxTlsVersion: pickEnum(
                TLS_VERSION_VALUES,
                e.target.value,
                w.maxTlsVersion,
              ),
            });
          }}
        >
          {TLS_VERSION_VALUES.map((v) => (
            <option key={v} value={v}>
              {TLS_LABEL[v]}
            </option>
          ))}
        </SelectField>

        <InputField
          label="Stall timeout (seconds)"
          type="number"
          help={`0 = inherit the engine default; otherwise ${String(STALL_TIMEOUT_MIN_SECS)}–${String(STALL_TIMEOUT_MAX_SECS)} seconds.`}
          value={String(w.stallTimeoutSecs)}
          disabled={pending}
          onChange={(e) => {
            const n = Number(e.target.value);
            setW({ ...w, stallTimeoutSecs: Number.isFinite(n) ? n : 0 });
          }}
        />

        {serverError !== "" && (
          <Callout variant="critical" title="Not saved" role="alert">
            {serverError}
          </Callout>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" disabled={pending} onClick={onCancel}>
          Cancel
        </Button>
        <Button disabled={pending || blocked} onClick={submit}>
          {mode.kind === "create" ? "Create profile" : "Save changes"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
