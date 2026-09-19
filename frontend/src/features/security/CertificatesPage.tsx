// FE-6B.1 — Certificates & CA: the READ surfaces for FE-V28 (Certificates)
// and FE-V29 (CA Management) over the frozen FE-6B.0 backend read models
// (GET /api/certificates, /api/ca/status, /api/ocsp, /api/settings/network
// = viewer; GET /api/ca/operations/{id} = admin).
//
// SERVER TRUTH ONLY, rendered from STRUCTURED facts:
//   - historical COMMITMENT (the operation ledger), present ACTIVATION (what
//     the running listener / signer holds) and DURABILITY (what is persisted
//     and whether the audit/persist is proven) stay three distinct facts;
//   - "unavailable" evidence is never rendered as absence, "incomplete" never
//     as a pair, and a corrupt pair never as a usable one;
//   - `writer_evidence_superseded` is a TERMINAL UNKNOWN — never described
//     as succeeded, failed, cancelled or safe to retry;
//   - a pending audit is a committed operation whose durable audit is still
//     owed — not a failed mutation;
//   - the two independent listener reads (inventory vs network settings) are
//     cross-checked; a disagreement is reported as a contradiction, never
//     resolved into either side's claim;
//   - bounded classes and refusal codes only — the server's detail lines,
//     raw transport errors and filesystem paths never reach the DOM.
//
// NO mutation exists here (upload, import, rotate, challenge, delete, OCSP
// toggle, repair, retry, re-send belong to FE-6B.2) and no disabled
// placeholder stands in for one. Nothing is persisted in the browser.
// The admin operation lookup is issued ONLY on an explicit "Look up": the
// backend GET is not a pure read (it may settle a pending intent from the
// object's own evidence and complete its owed audit once), so it is never
// polled and never issued on mount.
import { useEffect, useRef, useState } from "react";
import type { JSX, ReactNode } from "react";
import { useSearchParams } from "react-router";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
  Timestamp,
} from "../../design-system/primitives";
import { InputField } from "../../design-system/forms";
import { DataTable } from "../../design-system/table";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { readErrorSummary, refusalCodeOf } from "../../shared/readErrorSummary";
import { createDownloadOwner } from "../../shared/blobOwner";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { ApiError } from "../../api/client";
import {
  CERT_LOOKUP_REFUSAL_CODES,
  downloadCACertPEM,
  getCAStatus,
  getCertOperation,
  getCertificateInventory,
  getListenerFacts,
  getOCSPStatus,
  isValidOperationId,
  listenerContradiction,
  ocspAgreement,
  operationPosture,
  uiPairPosture,
} from "../../api/certificates";
import type {
  CAFacts,
  CAStatus,
  CertLookupRefusalCode,
  CertOperation,
  CertificateInventory,
  ListenerContradiction,
  ListenerFacts,
  MTLSClientCertFacts,
  OCSPPosture,
  OCSPStatus,
  UICertFacts,
} from "../../api/certificates";
import policyStyles from "../policy/policy.module.css";
import styles from "../diagnostics/diagnostics.module.css";

const TABS = ["Certificates", "CA Management"] as const;
type Tab = (typeof TABS)[number];

function tabFromParam(v: string | null): Tab {
  return v === "ca" ? "CA Management" : "Certificates";
}

function NodeLocal(): JSX.Element {
  return <StatusBadge status="neutral">Node-local</StatusBadge>;
}

function maybeTime(iso: string | undefined): ReactNode {
  if (iso === undefined || iso === "") return "—";
  return <Timestamp iso={iso} />;
}

// ── Inspection CA (inventory facts + runtime status) ────────────────────────

function CAIdentityItems(ca: {
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  fingerprint?: string;
}): ReadonlyArray<readonly [string, ReactNode]> {
  return [
    ["Subject", ca.subject ?? "—"],
    ["Issuer", ca.issuer ?? "—"],
    ["Not before", maybeTime(ca.notBefore)],
    ["Not after", maybeTime(ca.notAfter)],
    [
      "Fingerprint (SHA-256)",
      ca.fingerprint !== undefined ? <Mono>{ca.fingerprint}</Mono> : "—",
    ],
  ];
}

function UsableBadge({
  usable,
  unusableClass,
}: {
  usable: boolean;
  unusableClass?: string;
}): JSX.Element {
  if (usable) return <StatusBadge status="ok">Usable</StatusBadge>;
  return (
    <span>
      <StatusBadge status="critical">Unusable</StatusBadge>{" "}
      {unusableClass !== undefined && <Mono>{unusableClass}</Mono>}
    </span>
  );
}

interface ReadView<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
}

/** The inspection CA card is composed from TWO independent reads — the
 * inventory identity (GET /api/certificates) and the signer runtime (GET
 * /api/ca/status). Each renders its own data, loading or bounded error, so
 * one failed read never blanks the other. */
function InspectionCASection({
  inv,
  status,
  download,
}: {
  inv: ReadView<CertificateInventory>;
  status: ReadView<CAStatus>;
  download: { run: () => void; busy: boolean; error: string };
}): JSX.Element {
  const ca = inv.data?.ca;
  return (
    <Card
      title="Inspection CA"
      actions={
        <>
          <NodeLocal />
          {ca?.present === true && (
            <Button size="sm" onClick={download.run} disabled={download.busy}>
              Download CA certificate (PEM)
            </Button>
          )}
        </>
      }
    >
      {download.error !== "" && (
        <Callout variant="warning" title="Download not delivered">
          {download.error}
        </Callout>
      )}
      {ca !== undefined ? (
        <CAInventoryFacts ca={ca} encryptedAtRest={ca.encryptedAtRest} />
      ) : inv.loading ? (
        <p>
          <Skeleton>Loading…</Skeleton>
        </p>
      ) : (
        <ErrorState title="Certificate inventory unavailable">
          {readErrorSummary(inv.error, "certificate inventory")}
        </ErrorState>
      )}
      <CARuntimeLine {...status} />
    </Card>
  );
}

function CAInventoryFacts({
  ca,
  encryptedAtRest,
}: {
  ca: CAFacts;
  encryptedAtRest: boolean;
}): JSX.Element {
  return (
    <>
      {ca.loadFailed && (
        <Callout variant="critical" title="Load failed">
          The persisted CA bundle could not be loaded
          {ca.loadFailureClass !== undefined && (
            <>
              {" "}
              (<Mono>{ca.loadFailureClass}</Mono>)
            </>
          )}
          . The recovery campaign and its outcome are on the CA Management tab.
        </Callout>
      )}
      {ca.persistDegraded && (
        <Callout variant="warning" title="Last rotation could not be persisted">
          The live CA rotated but the bundle write failed
          {ca.persistClass !== undefined && (
            <>
              {" "}
              (<Mono>{ca.persistClass}</Mono>)
            </>
          )}
          ; the running root is not on disk.
        </Callout>
      )}
      {!ca.present ? (
        <p>
          No Root CA is installed on this node
          {ca.unusableClass !== undefined && (
            <>
              {" "}
              (<Mono>{ca.unusableClass}</Mono>)
            </>
          )}
          .
        </p>
      ) : (
        <KeyValue items={CAIdentityItems(ca)} />
      )}
      <KeyValue
        items={[
          ["Revision", <Mono key="rev">{ca.revision}</Mono>],
          [
            "Usability",
            <UsableBadge
              key="u"
              usable={ca.usable}
              {...(ca.unusableClass !== undefined
                ? { unusableClass: ca.unusableClass }
                : {})}
            />,
          ],
          ["Key provider", ca.keyProvider],
          [
            "Persistence",
            ca.persistenceConfigured
              ? "Bundle path configured"
              : "No bundle path configured (nothing persists)",
          ],
          [
            "At rest",
            encryptedAtRest ? (
              <StatusBadge status="ok">Encrypted at rest</StatusBadge>
            ) : (
              <StatusBadge status="warn">Not encrypted at rest</StatusBadge>
            ),
          ],
          [
            "Dual-CA overlap",
            ca.dualCAActive ? "Active (previous root still trusted)" : "Off",
          ],
        ]}
      />
    </>
  );
}

/** The signer's runtime facts (GET /api/ca/status) shown beside the
 * inventory identity; an independent read with its own bounded error. */
function CARuntimeLine({
  data,
  error,
  loading,
}: ReadView<CAStatus>): JSX.Element {
  if (data !== undefined) {
    return (
      <KeyValue
        items={[
          [
            "Signer runtime",
            data.ready
              ? data.expiresIn !== undefined
                ? `Ready — expires in ${data.expiresIn}`
                : "Ready"
              : "Not ready",
          ],
          [
            "Inspect refusals",
            `Inspect blocked: ${String(data.inspectBlocked)}; Sign refused: ${String(data.signRefused)}`,
          ],
        ]}
      />
    );
  }
  if (loading) {
    return (
      <p>
        <Skeleton>Signer runtime…</Skeleton>
      </p>
    );
  }
  return (
    <Callout variant="warning" title="Signer runtime unavailable">
      {readErrorSummary(error, "inspection CA status")}
    </Callout>
  );
}

// ── UI listener certificate ────────────────────────────────────────────────

function contradictionText(c: ListenerContradiction): string {
  switch (c) {
    case "active_on_plain_http_listener":
      return "The inventory claims the persisted pair is active, but the listener reports it fell back to plain HTTP. No activation claim is made.";
    case "active_disagrees":
      return "The inventory and the network settings disagree about whether a custom pair is active on the running listener. No activation claim is made.";
    case "present_disagrees":
      return "The inventory and the network settings disagree about whether a custom pair is persisted.";
    case "corrupt_disagrees":
      return "The inventory and the network settings disagree about whether the persisted pair is corrupt.";
  }
}

function ActivationLine({ active }: { active: boolean }): JSX.Element {
  return active ? (
    <StatusBadge status="ok">Active on the running listener</StatusBadge>
  ) : (
    <StatusBadge status="neutral">
      Not active on the running listener
    </StatusBadge>
  );
}

function UICertCard({
  ui,
  listener,
}: {
  ui: UICertFacts;
  listener: ReadView<ListenerFacts>;
}): JSX.Element {
  const posture = uiPairPosture(ui);
  const contradiction =
    listener.data !== undefined
      ? listenerContradiction(ui, listener.data)
      : null;
  const activation = (): ReactNode => {
    if (contradiction !== null) return null;
    return <ActivationLine active={ui.active} />;
  };
  let head: JSX.Element;
  let body: ReactNode;
  switch (posture) {
    case "persisted_restart_required":
      head = <StatusBadge status="ok">Complete pair persisted</StatusBadge>;
      body = (
        <>
          {activation()}
          {contradiction === null && (
            <p>
              Activation requires a restart: the listener loads the persisted
              pair only at boot.
            </p>
          )}
        </>
      );
      break;
    case "active_persisted":
      head = <StatusBadge status="ok">Complete pair persisted</StatusBadge>;
      body = activation();
      break;
    case "active_not_persisted":
      head = <StatusBadge status="warn">No persisted pair</StatusBadge>;
      body = (
        <>
          {activation()}
          <p>
            The running listener holds a pair that is no longer persisted on
            disk; a restart falls back to the self-signed certificate.
          </p>
        </>
      );
      break;
    case "absent":
      head = <StatusBadge status="neutral">No persisted pair</StatusBadge>;
      body = (
        <>
          <p>
            The pair is positively absent: neither file exists. The listener
            serves the self-signed certificate.
          </p>
          {activation()}
        </>
      );
      break;
    case "incomplete":
      head = <StatusBadge status="critical">Incomplete pair</StatusBadge>;
      body = (
        <>
          <p>
            The pair is incomplete: exactly one of the two files (certificate or
            key) is present; the listener never loads an incomplete pair.
          </p>
          {activation()}
        </>
      );
      break;
    case "unavailable":
      head = <StatusBadge status="unknown">Evidence unavailable</StatusBadge>;
      body = (
        <>
          <p>
            The persisted pair cannot be examined or read (an unreadable path, a
            directory, or an unreadable key). This is not absent: the files may
            exist, and the evidence blocks mutations until it can be read.
          </p>
          {activation()}
        </>
      );
      break;
    case "corrupt":
      head = <StatusBadge status="critical">Corrupt pair</StatusBadge>;
      body = (
        <>
          <p>
            The persisted files are readable but did not parse as a matching
            pair; the listener never loads them.
          </p>
          {activation()}
        </>
      );
      break;
  }
  return (
    <Card title="UI listener certificate" actions={<NodeLocal />}>
      {contradiction !== null && (
        <Callout variant="critical" title="Contradictory listener facts">
          {contradictionText(contradiction)}
        </Callout>
      )}
      {listener.data === undefined && !listener.loading && (
        <Callout variant="warning" title="Listener facts unavailable">
          {readErrorSummary(listener.error, "network settings")}; the activation
          claim above is the inventory's alone and was not cross-checked.
        </Callout>
      )}
      <p>{head}</p>
      {body}
      <KeyValue
        items={[
          ["Revision", <Mono key="rev">{ui.revision}</Mono>],
          ["Subject", ui.subject ?? "—"],
          ["Not after", maybeTime(ui.notAfter)],
          [
            "Fingerprint (SHA-256)",
            ui.fingerprint !== undefined ? <Mono>{ui.fingerprint}</Mono> : "—",
          ],
        ]}
      />
    </Card>
  );
}

// ── mTLS client certificate ────────────────────────────────────────────────

function MTLSCard({ m }: { m: MTLSClientCertFacts }): JSX.Element {
  let posture: ReactNode;
  if (!m.configured) {
    posture = <StatusBadge status="neutral">Not configured</StatusBadge>;
  } else if (m.loaded) {
    posture = <StatusBadge status="ok">Loaded</StatusBadge>;
  } else {
    posture = (
      <span>
        <StatusBadge status="critical">Not loaded</StatusBadge>{" "}
        {m.reason !== undefined && <Mono>{m.reason}</Mono>}
      </span>
    );
  }
  return (
    <Card
      title="mTLS client certificate (OCSP responder)"
      actions={<NodeLocal />}
    >
      <KeyValue
        items={[
          ["Posture", posture],
          ["Not after", maybeTime(m.notAfter)],
          [
            "Days remaining",
            m.daysRemaining !== undefined ? String(m.daysRemaining) : "—",
          ],
        ]}
      />
    </Card>
  );
}

// ── OCSP ────────────────────────────────────────────────────────────────────

function OCSPPostureFacts({ o }: { o: OCSPPosture | OCSPStatus }): JSX.Element {
  return (
    <>
      {ocspAgreement(o) === "differ" && (
        <Callout
          variant="warning"
          title="Runtime differs from the desired posture"
        >
          The durable desired state and the running checker disagree; both are
          shown as stated. A restart applies the durable state.
        </Callout>
      )}
      <KeyValue
        items={[
          [
            "Desired",
            <span key="d">
              <span>{`Desired: ${o.desired.enabled ? "Enabled" : "Disabled"}`}</span>{" "}
              <span>{`(source: ${o.desired.source})`}</span>{" "}
              {o.durable ? (
                <StatusBadge status="ok">Durable</StatusBadge>
              ) : (
                <StatusBadge status="neutral">Not durable</StatusBadge>
              )}
            </span>,
          ],
          ["Runtime", `Runtime: ${o.runtime.enabled ? "Enabled" : "Disabled"}`],
          ["Revision", <Mono key="rev">{o.revision}</Mono>],
        ]}
      />
    </>
  );
}

interface CoverageRow {
  path: string;
  checked: boolean;
  enforcing: boolean;
}

function OCSPStatusCard({ s }: { s: OCSPStatus }): JSX.Element {
  const rows: CoverageRow[] = s.coverage.map((c) => ({
    path: c.path,
    checked: c.checked,
    enforcing: s.uncheckedEnforcingPaths.includes(c.path) || c.checked,
  }));
  return (
    <Card title="OCSP revocation checking" actions={<NodeLocal />}>
      <OCSPPostureFacts o={s} />
      <KeyValue
        items={[
          [
            "Fail-closed decisions",
            `Fail-closed decisions: ${String(s.failClosedTotal)}`,
          ],
          ["Revoked", `Revoked: ${String(s.revokedTotal)}`],
          ["Cached verdicts", String(s.cacheLen)],
          ["Last fail-closed", maybeTime(s.lastFailClosedAt)],
        ]}
      />
      {s.uncheckedEnforcingPaths.length > 0 && (
        <Callout variant="warning" title="Evidence limitation">
          {String(s.uncheckedEnforcingPaths.length)} enforcing handshake path
          {s.uncheckedEnforcingPaths.length === 1 ? " is" : "s are"} not
          consulted by the checker (marked Not checked below); the desired and
          runtime postures above do not cover
          {s.uncheckedEnforcingPaths.length === 1 ? " it" : " them"}.
        </Callout>
      )}
      <DataTable
        caption="Handshake paths"
        columns={[
          {
            key: "path",
            header: "Path",
            render: (r: CoverageRow) => <Mono>{r.path}</Mono>,
          },
          {
            key: "checked",
            header: "Revocation",
            render: (r) =>
              r.checked ? (
                <StatusBadge status="ok">Checked</StatusBadge>
              ) : (
                <StatusBadge status="warn">Not checked</StatusBadge>
              ),
          },
          {
            key: "enforcing",
            header: "Enforcing",
            render: (r) => (r.enforcing ? "Yes" : "No"),
          },
        ]}
        rows={rows}
        rowKey={(r) => r.path}
      />
    </Card>
  );
}

// ── Ledger + backup facts ──────────────────────────────────────────────────

function LedgerCard({ inv }: { inv: CertificateInventory }): JSX.Element {
  const l = inv.operations;
  const b = inv.backup;
  return (
    <Card title="Operation ledger and backup scope" actions={<NodeLocal />}>
      {l.degraded && (
        <Callout variant="critical" title="Operation ledger degraded">
          The ledger file is{" "}
          {l.degradedReason !== undefined ? (
            <Mono>{l.degradedReason}</Mono>
          ) : (
            "unusable"
          )}
          ; its evidence is preserved on disk and every certificate mutation and
          lookup is refused until it is repaired.
        </Callout>
      )}
      <KeyValue
        items={[
          [
            "Records",
            `Retained: ${String(l.retained)} of ${String(l.capacity)}`,
          ],
          ["Unresolved", `Unresolved intents: ${String(l.unresolved)}`],
          ["Audit", `Audit sink: ${l.auditSink}`],
        ]}
      />
      <KeyValue
        items={[
          [
            "CA bundle",
            `CA bundle: archived (${b.caBundleEncrypted ? "encrypted" : "not encrypted"})`,
          ],
          ["UI pair", "UI pair: never archived"],
          ["Ledger", "Operation ledger: never archived"],
          ["Rollback", "Config-version rollback: off"],
        ]}
      />
    </Card>
  );
}

// ── Admin operation lookup ─────────────────────────────────────────────────

type LookupOutcome =
  | { kind: "idle" }
  | { kind: "invalid" }
  | { kind: "pending" }
  | { kind: "record"; op: CertOperation }
  | { kind: "refused"; code: CertLookupRefusalCode }
  | { kind: "error"; text: string };

function OperationRecord({ op }: { op: CertOperation }): JSX.Element {
  const p = operationPosture(op);
  let head: JSX.Element;
  let explain: ReactNode;
  switch (p.kind) {
    case "pending":
      head = <StatusBadge status="info">Pending</StatusBadge>;
      explain =
        "The intent is recorded and not yet decided; a later lookup, boot or writer settles it from the object's own evidence.";
      break;
    case "committed":
      head = (
        <span>
          <StatusBadge status="ok">Committed</StatusBadge>{" "}
          <StatusBadge status="ok">Audited</StatusBadge>
        </span>
      );
      explain = "The mutation took effect and its durable audit is recorded.";
      break;
    case "committed_audit_pending":
      head = (
        <span>
          <StatusBadge status="ok">Committed</StatusBadge>{" "}
          <StatusBadge status="warn">Audit pending</StatusBadge>
        </span>
      );
      explain =
        "The mutation took effect; its durable success audit is still owed and is completed by a later settlement. This is not a failed certificate mutation.";
      break;
    case "aborted":
      head = <StatusBadge status="critical">Aborted</StatusBadge>;
      explain = "The intent did not commit; the code states why.";
      break;
    case "unknown_recoverable":
      head = (
        <StatusBadge status="unknown">
          Outcome unknown — recoverable
        </StatusBadge>
      );
      explain =
        "The evidence could not decide the outcome; it is re-decided by every later lookup, boot or writer.";
      break;
    case "unknown_unproven":
      head = (
        <StatusBadge status="unknown">Outcome unknown — unproven</StatusBadge>
      );
      explain =
        "The evidence did not prove the commit; the node does not guess.";
      break;
    case "unknown_superseded":
      head = (
        <StatusBadge status="unknown">Outcome unknown — terminal</StatusBadge>
      );
      explain = (
        <>
          A later writer superseded this intent's evidence before it could be
          decided. The node never learns whether the intent had taken effect and
          never guesses; no later settlement re-decides it. Superseded by:{" "}
          <Mono>{p.supersededBy}</Mono>
        </>
      );
      break;
  }
  const items: Array<readonly [string, ReactNode]> = [
    ["Operation", <Mono key="id">{op.operationId}</Mono>],
    ["Action", <Mono key="a">{op.action}</Mono>],
    ["Target", <Mono key="t">{op.target}</Mono>],
    ["Actor", op.actor],
    ["Fence", <Mono key="f">{op.fence}</Mono>],
    ["Started", maybeTime(op.startedAt)],
  ];
  if (op.candidateFingerprint !== undefined) {
    items.push([
      "Candidate fingerprint",
      <Mono key="c">{op.candidateFingerprint}</Mono>,
    ]);
  }
  if (op.state !== "pending") {
    items.push(["Finished", maybeTime(op.finishedAt)]);
  }
  if (op.state === "committed") {
    items.push([
      "Resulting revision",
      <Mono key="cr">{op.committedRevision}</Mono>,
    ]);
  }
  if (op.state !== "pending" && op.code !== undefined) {
    items.push(["Code", <Mono key="code">{op.code}</Mono>]);
  }
  return (
    <>
      <p>{head}</p>
      <p>{explain}</p>
      <KeyValue items={items} />
    </>
  );
}

function refusalText(code: CertLookupRefusalCode): ReactNode {
  switch (code) {
    case "not_found":
      return (
        <>
          <StatusBadge status="neutral">
            No retained operation record
          </StatusBadge>
          <p>
            The ledger retains no record under this id: it was never issued on
            this node, or it aged out of the bounded ring.
          </p>
        </>
      );
    case "operation_ledger_degraded":
      return (
        <>
          <StatusBadge status="critical">Operation ledger degraded</StatusBadge>
          <p>
            The lookup was refused with <Mono>{code}</Mono>; the ledger's
            evidence is preserved and nothing was settled.
          </p>
        </>
      );
    default:
      return (
        <>
          <StatusBadge status="warn">Lookup refused</StatusBadge>
          <p>
            The appliance refused the lookup with <Mono>{code}</Mono>.
          </p>
        </>
      );
  }
}

function OperationLookupCard(): JSX.Element {
  const [id, setId] = useState("");
  const [outcome, setOutcome] = useState<LookupOutcome>({ kind: "idle" });
  const ownerRef = useRef(createRequestRunOwner());

  // Auth boundary (FE-3 §6.4): abort the in-flight lookup, drop the typed id
  // and the rendered record — nothing admin-scoped survives the teardown.
  useEffect(() => {
    const owner = ownerRef.current;
    const cleanup = (): void => {
      owner.abort();
      setId("");
      setOutcome({ kind: "idle" });
    };
    const unregister = registerAuthCleanup(cleanup);
    return () => {
      unregister();
      owner.abort();
    };
  }, []);

  const run = (): void => {
    const target = id.trim();
    if (!isValidOperationId(target)) {
      setOutcome({ kind: "invalid" });
      return;
    }
    const signal = ownerRef.current.begin();
    setOutcome({ kind: "pending" });
    getCertOperation(target, signal)
      .then((op) => {
        if (signal.aborted) return;
        setOutcome({ kind: "record", op });
      })
      .catch((err: unknown) => {
        if (signal.aborted) return;
        if (err instanceof ApiError && err.kind === "aborted") return;
        const code = refusalCodeOf(err, CERT_LOOKUP_REFUSAL_CODES);
        if (code !== null) {
          setOutcome({ kind: "refused", code });
          return;
        }
        setOutcome({
          kind: "error",
          text: readErrorSummary(err, "operation record"),
        });
      })
      .finally(() => {
        ownerRef.current.settle(signal);
      });
  };

  let result: ReactNode = null;
  switch (outcome.kind) {
    case "idle":
      result = null;
      break;
    case "invalid":
      result = (
        <Callout variant="warning">
          The typed value is not a UUID; nothing was requested.
        </Callout>
      );
      break;
    case "pending":
      result = (
        <p>
          <Skeleton>Looking up…</Skeleton>
        </p>
      );
      break;
    case "record":
      result = <OperationRecord op={outcome.op} />;
      break;
    case "refused":
      result = refusalText(outcome.code);
      break;
    case "error":
      result = (
        <ErrorState title="Lookup not answered">{outcome.text}</ErrorState>
      );
      break;
  }

  return (
    <Card
      title="Operation lookup (admin)"
      actions={<StatusBadge status="neutral">Admin-only read</StatusBadge>}
    >
      <p className={styles.runHint}>
        Looks up one retained ledger record by its operation id. The appliance's
        lookup may settle a pending operation and complete its audit from the
        object's own evidence, so it is issued only when you press Look up —
        never automatically and never polled.
      </p>
      <div className={policyStyles.toolbar}>
        <InputField
          label="Operation ID"
          value={id}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => {
            setId(e.target.value);
          }}
        />
        <Button
          size="sm"
          variant="primary"
          onClick={run}
          disabled={outcome.kind === "pending"}
        >
          Look up
        </Button>
      </div>
      <div data-testid="operation-record" aria-live="polite">
        {result}
      </div>
    </Card>
  );
}

// ── CA Management tab ──────────────────────────────────────────────────────

function CAStatusCard({ s }: { s: CAStatus }): JSX.Element {
  return (
    <Card title="Inspection CA status" actions={<NodeLocal />}>
      {s.loadFailed && (
        <Callout variant="critical" title="Load failed">
          The persisted CA bundle could not be loaded
          {s.loadFailureClass !== undefined && (
            <>
              {" "}
              (<Mono>{s.loadFailureClass}</Mono>)
            </>
          )}
          . Inspected HTTPS is bypassed while no usable CA is installed; the
          recovery campaign below retries on a bounded schedule.
        </Callout>
      )}
      {s.rotationPersistDegraded && (
        <Callout variant="warning" title="Last rotation could not be persisted">
          The bundle write after the last rotation failed
          {s.rotationPersistClass !== undefined && (
            <>
              {" "}
              (<Mono>{s.rotationPersistClass}</Mono>)
            </>
          )}
          ; the running root is not on disk and a restart re-rotates to a
          different root.
        </Callout>
      )}
      {!s.ready ? (
        <p>
          No Root CA is installed on this node
          {s.unusableClass !== undefined && (
            <>
              {" "}
              (<Mono>{s.unusableClass}</Mono>)
            </>
          )}
          .
        </p>
      ) : (
        <KeyValue items={CAIdentityItems(s)} />
      )}
      <KeyValue
        items={[
          ["Revision", <Mono key="rev">{s.revision}</Mono>],
          [
            "Usability",
            <UsableBadge
              key="u"
              usable={s.usable}
              {...(s.unusableClass !== undefined
                ? { unusableClass: s.unusableClass }
                : {})}
            />,
          ],
          [
            "Expiry",
            s.expiresIn !== undefined ? `Expires in ${s.expiresIn}` : "—",
          ],
          ["Key provider", `Key provider: ${s.keyProvider}`],
          [
            "Persistence",
            s.persistenceConfigured
              ? "Bundle path configured"
              : "No bundle path configured (nothing persists)",
          ],
        ]}
      />
      <KeyValue
        items={[
          ["Rotation", `Auto-rotation: ${s.autoRotation ? "on" : "off"}`],
          ["Overlap", `Overlap: ${String(s.rotationOverlapDays)} days`],
          ["Rotation persist failures", String(s.rotationPersistFailures)],
          ["Leaf validity", `Leaf validity: ${s.leafValidity}`],
          [
            "Leaf cache",
            `Cache: ${String(s.cacheSize)} of ${String(s.cacheMax)}`,
          ],
          ["Cache TTL", s.cacheTTL],
        ]}
      />
      <KeyValue
        items={[
          ["Inspect blocked", `Inspect blocked: ${String(s.inspectBlocked)}`],
          ["Sign refused", `Sign refused: ${String(s.signRefused)}`],
          [
            "Inspection bypassed",
            `Inspection bypassed: ${String(s.inspectBypassed)}`,
          ],
        ]}
      />
      <KeyValue
        items={[
          [
            "Recovery campaign",
            `Recovery attempts: ${String(s.loadRecoveryAttempts)}`,
          ],
          [
            "Campaign posture",
            s.loadRecoveryGaveUp ? (
              <StatusBadge status="critical">
                Given up (bounded budget spent)
              </StatusBadge>
            ) : (
              <span>Not given up</span>
            ),
          ],
          [
            "Last recovery class",
            s.loadRecoveryClass !== undefined ? (
              <Mono>{s.loadRecoveryClass}</Mono>
            ) : (
              "—"
            ),
          ],
        ]}
      />
      {s.dualCAActive && s.secondaryCA !== undefined && (
        <Callout variant="info" title="Dual-CA overlap active">
          The previous root stays trusted until the overlap ends.
          <KeyValue
            items={[
              ["Previous subject", s.secondaryCA.subject ?? "—"],
              ["Previous not after", maybeTime(s.secondaryCA.notAfter)],
              ["Overlap ends", maybeTime(s.secondaryCA.overlapEnd)],
              [
                "Previous expiry",
                s.secondaryCA.expiresIn !== undefined
                  ? `Expires in ${s.secondaryCA.expiresIn}`
                  : "—",
              ],
            ]}
          />
        </Callout>
      )}
    </Card>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

function SnapshotCard<T>({
  title,
  loading,
  error,
  data,
  what,
  render,
}: {
  title: string;
  loading: boolean;
  error: unknown;
  data: T | undefined;
  what: string;
  render: (d: T) => ReactNode;
}): JSX.Element {
  if (data !== undefined) return <>{render(data)}</>;
  if (loading) {
    return (
      <Card title={title} actions={<NodeLocal />}>
        <p>
          <Skeleton>Loading…</Skeleton>
        </p>
      </Card>
    );
  }
  return (
    <Card title={title} actions={<NodeLocal />}>
      <ErrorState title={`${title} unavailable`}>
        {readErrorSummary(error, what)}
      </ErrorState>
    </Card>
  );
}

export function CertificatesPage(): JSX.Element {
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  const isAdmin = hasRole(role, "admin");
  const [params, setParams] = useSearchParams();
  const tab = tabFromParam(params.get("tab"));

  const inv = useSnapshot(
    ["certificates", "inventory"],
    getCertificateInventory,
  );
  const ca = useSnapshot(["certificates", "ca-status"], getCAStatus);
  const ocsp = useSnapshot(["certificates", "ocsp"], getOCSPStatus);
  const listener = useSnapshot(["certificates", "listener"], getListenerFacts);
  const all = [inv, ca, ocsp, listener];

  const updatedAt = all
    .filter((q) => q.data !== undefined)
    .reduce(
      (min, q) =>
        min === 0 ? q.dataUpdatedAt : Math.min(min, q.dataUpdatedAt),
      0,
    );
  const refreshAll = (): void => {
    for (const q of all) void q.refetch();
  };

  // PEM download (viewer GET of the PUBLIC root certificate).
  const downloads = useRef(createDownloadOwner());
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  useEffect(() => {
    const owner = downloads.current;
    const unregister = registerAuthCleanup(() => {
      owner.abortAndRevoke();
    });
    return () => {
      unregister();
      owner.abortAndRevoke();
    };
  }, []);
  const runDownload = (): void => {
    const owner = downloads.current;
    const signal = owner.begin();
    setDownloading(true);
    setDownloadError("");
    downloadCACertPEM(signal)
      .then((res) => {
        owner.deliver(signal, res.blob, res.filename);
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.kind === "aborted") return;
        setDownloadError(readErrorSummary(err, "CA certificate download"));
      })
      .finally(() => {
        owner.settle(signal);
        setDownloading(false);
      });
  };

  const selectTab = (t: Tab): void => {
    setParams(t === "CA Management" ? { tab: "ca" } : {}, { replace: true });
  };

  const caStatusView = {
    data: ca.data,
    error: ca.error,
    loading: ca.isLoading,
  };
  const listenerView = {
    data: listener.data,
    error: listener.error,
    loading: listener.isLoading,
  };

  return (
    <>
      <PageHeader
        title="Certificates & CA"
        subtitle="The inspection Root CA, the admin-listener certificate, the OCSP posture and the certificate operation ledger of THIS node — read from the appliance on demand. Node-local: nothing here is exported, rolled back or synced."
      />
      <div className={policyStyles.toolbar}>
        <div role="tablist" aria-label="Certificate sections">
          {TABS.map((t) => (
            <Button
              key={t}
              size="sm"
              variant={t === tab ? "primary" : "ghost"}
              role="tab"
              aria-selected={t === tab}
              onClick={() => {
                selectTab(t);
              }}
            >
              {t}
            </Button>
          ))}
        </div>
        <SnapshotBar
          updatedAt={updatedAt}
          fetching={all.some((q) => q.isFetching)}
          error={all.some((q) => q.isError && q.data !== undefined)}
          hasData={all.some((q) => q.data !== undefined)}
          onRefresh={refreshAll}
        />
      </div>

      {tab === "Certificates" && (
        <div className={styles.stack}>
          <InspectionCASection
            inv={{ data: inv.data, error: inv.error, loading: inv.isLoading }}
            status={caStatusView}
            download={{
              run: runDownload,
              busy: downloading,
              error: downloadError,
            }}
          />
          {inv.data !== undefined && (
            <>
              <UICertCard ui={inv.data.uiCert} listener={listenerView} />
              <MTLSCard m={inv.data.mtlsClientCert} />
              <Card title="OCSP posture" actions={<NodeLocal />}>
                <OCSPPostureFacts o={inv.data.ocsp} />
              </Card>
              <LedgerCard inv={inv.data} />
            </>
          )}
          {isAdmin && <OperationLookupCard />}
        </div>
      )}

      {tab === "CA Management" && (
        <div className={styles.stack}>
          <SnapshotCard
            title="Inspection CA status"
            loading={ca.isLoading}
            error={ca.error}
            data={ca.data}
            what="inspection CA status"
            render={(s) => <CAStatusCard s={s} />}
          />
          <SnapshotCard
            title="OCSP revocation checking"
            loading={ocsp.isLoading}
            error={ocsp.error}
            data={ocsp.data}
            what="OCSP status"
            render={(s) => <OCSPStatusCard s={s} />}
          />
        </div>
      )}
    </>
  );
}
