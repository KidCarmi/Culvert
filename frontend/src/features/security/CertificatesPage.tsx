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
//   - ACTIVATION is rendered from the SERVER-OWNED listener evidence the
//     inventory carries (`listener`: bind state, posture, served identity),
//     never from the boot-time `active` flag (FE-6B.1 correction, B1); an
//     unobserved listener is rendered UNKNOWN with no claim of any kind;
//   - the network-settings read is a CROSS-CHECK only: a disagreement between
//     the two reads, or an answer that cannot be verified as consistent
//     listener facts, is a contradiction that withholds every activation
//     claim; a read that did not happen (transport failure) is stated and
//     does not withdraw a claim that rests on the inventory's own evidence;
//   - durability is never claimed beyond the frozen contract (B2): a persist
//     failure renders its bounded class only, and a committed operation's
//     audit is qualified by the inventory's audit sink (file / memory /
//     sink evidence unavailable);
//   - the admin lookup shows a record only when it is BOUND to the requested
//     id and internally consistent, and a refusal only with its contracted
//     status, media type and shape (B3) — anything else is an unverified
//     lookup response, never a verdict;
//   - bounded classes and refusal codes only — the server's detail lines,
//     raw transport errors and filesystem paths never reach the DOM.
//
// FE-6B.2 adds the ADMIN mutation controls (rotate through the bound
// challenge, import / replace with the dry-run review, the typed delete, the
// OCSP posture set) through useCertMutations (certWrites.tsx): every write
// is fenced on the reviewed server-owned revision, identified by a marker
// written before dispatch, verified action-bound, recovered only through
// the authoritative lookup, and never retried automatically. Below admin no
// mutation control renders. The only thing persisted in the browser is the
// single NON-SECRET recovery marker (certRecovery.ts).
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
import { readErrorSummary } from "../../shared/readErrorSummary";
import { createDownloadOwner } from "../../shared/blobOwner";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { ApiError } from "../../api/client";
import {
  activationPosture,
  certLookupRefusal,
  downloadCACertPEM,
  getCAStatus,
  getCertOperation,
  getCertificateInventory,
  getListenerFacts,
  getOCSPStatus,
  isValidOperationId,
  listenerContradiction,
  listenerReadsDisagree,
  ocspAgreement,
  operationPosture,
} from "../../api/certificates";
import type {
  ActivationPosture,
  AdminListener,
  AuditSink,
  CAFacts,
  CAStatus,
  CertLookupRefusalCode,
  CertOperation,
  CertificateInventory,
  ListenerContradiction,
  ListenerFacts,
  ServedCertificate,
  MTLSClientCertFacts,
  OCSPPosture,
  OCSPStatus,
  UICertFacts,
} from "../../api/certificates";
import policyStyles from "../policy/policy.module.css";
import styles from "../diagnostics/diagnostics.module.css";
import { useCertMutations } from "./certWrites";
import type { CertMutations } from "./certWrites";

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
  writes,
}: {
  inv: ReadView<CertificateInventory>;
  status: ReadView<CAStatus>;
  download: { run: () => void; busy: boolean; error: string };
  /** admin only: the FE-6B.2 mutation controls */
  writes: CertMutations | null;
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
          {writes !== null && (
            <>
              <Button
                size="sm"
                variant="danger-quiet"
                onClick={writes.open.rotate}
                disabled={writes.blocked || !writes.can.rotate}
              >
                Rotate Root CA…
              </Button>
              <Button
                size="sm"
                onClick={writes.open.importCA}
                disabled={writes.blocked}
              >
                Import CA…
              </Button>
            </>
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

/** B2: a persist failure is rendered as the BOUNDED class the node recorded
 * and nothing more. Whether the live CA changed is decided by the operation
 * protocol (persist-before-publish: an ordinary bundle-write failure leaves
 * the previous CA in place; a post-rename sync doubt installs the candidate
 * with the outcome recorded as unproven) and is stated by the operation's own
 * ledger record — this card never infers a live/disk divergence from a
 * counter. */
function PersistDegradedCallout({
  persistClass,
}: {
  persistClass: string | undefined;
}): JSX.Element {
  return (
    <Callout variant="warning" title="Last rotation could not be persisted">
      The bundle write of the last rotation attempt failed
      {persistClass !== undefined && (
        <>
          {" "}
          (<Mono>{persistClass}</Mono>)
        </>
      )}
      . Only that bounded failure class is recorded here: the identity shown is
      what the signer holds now, the persisted bundle is what a restart loads,
      and the operation's ledger record states what the attempt installed.
    </Callout>
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
        <PersistDegradedCallout persistClass={ca.persistClass} />
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
      return "The network settings report a listener that fell back to plain HTTP while the inventory reports the persisted pair as active.";
    case "active_disagrees":
      return "The inventory and the network settings disagree about whether the persisted pair is active on the running listener.";
    case "present_disagrees":
      return "The inventory and the network settings disagree about whether a custom pair is persisted.";
    case "corrupt_disagrees":
      return "The inventory and the network settings disagree about whether the persisted pair is corrupt.";
  }
}

/** The listener evidence in the operator's words — used only to DESCRIBE the
 * two reads when they disagree, never to pick one. */
function listenerWords(l: AdminListener): string {
  if (l.state !== "serving") return "no bind observed";
  switch (l.posture) {
    case "tls_custom":
      return "serving a GUI-uploaded pair";
    case "tls_configured":
      return "serving an explicitly configured certificate";
    case "tls_self_signed":
      return "serving the self-signed certificate";
    case "plain_http":
      return "serving plain HTTP";
    case "unknown":
      return "no bind observed";
  }
}

function NotActive(): JSX.Element {
  return (
    <StatusBadge status="neutral">
      Not active on the running listener
    </StatusBadge>
  );
}

function RestartActivates(): JSX.Element {
  return (
    <p>
      Activation requires a restart: the listener loads the persisted pair only
      at boot.
    </p>
  );
}

function ServedLine({
  lead,
  served,
  tail,
}: {
  lead: string;
  served: ServedCertificate;
  tail: string;
}): JSX.Element {
  return (
    <p>
      {lead} <Mono>{served.fingerprint}</Mono>
      {tail}
    </p>
  );
}

/** B1: what the RUNNING listener serves, from the appliance's bind evidence
 * alone. Every branch names the served identity where one exists; the
 * "unknown" branch claims nothing. */
function ListenerActivation({ p }: { p: ActivationPosture }): JSX.Element {
  switch (p.kind) {
    case "unknown":
      return (
        <>
          <p>
            <StatusBadge status="unknown">
              Listener activation unknown
            </StatusBadge>
          </p>
          <p>
            The appliance has not been observed serving: no bind evidence is
            recorded (before the first bind, or while the listener is
            rebinding). Nothing is claimed about what the running listener
            serves or whether the persisted pair is in use.
          </p>
        </>
      );
    case "plain_http":
      return (
        <>
          <p>
            <NotActive />
          </p>
          <p>
            The listener serves plain HTTP; the persisted pair is not in use.
          </p>
          {p.persistedActivatesOnRestart && <RestartActivates />}
        </>
      );
    case "tls_configured":
      return (
        <>
          <p>
            <NotActive />
          </p>
          <ServedLine
            lead="Listener serves an explicitly configured certificate:"
            served={p.served}
            tail=". The persisted GUI pair is never used while an explicit certificate is configured."
          />
        </>
      );
    case "self_signed":
      return (
        <>
          <p>
            <NotActive />
          </p>
          <ServedLine
            lead="Listener serves the automatically generated self-signed certificate:"
            served={p.served}
            tail="."
          />
          {p.persistedActivatesOnRestart && <RestartActivates />}
        </>
      );
    case "custom_matches":
      return (
        <>
          <p>
            <StatusBadge status="ok">
              Active on the running listener
            </StatusBadge>
          </p>
          <ServedLine
            lead="Listener serves the persisted pair:"
            served={p.served}
            tail="."
          />
        </>
      );
    case "custom_differs":
      return (
        <>
          <p>
            <NotActive />
          </p>
          <ServedLine
            lead="Listener serves a previously persisted GUI pair:"
            served={p.served}
            tail="; the pair persisted now is a different one (its identity is below)."
          />
          <RestartActivates />
        </>
      );
    case "custom_not_persisted":
      return (
        <>
          <p>
            <NotActive />
          </p>
          <ServedLine
            lead="Listener serves a GUI pair that is no longer persisted:"
            served={p.served}
            tail="; it is not loaded again at the next boot."
          />
        </>
      );
    case "custom_persisted_unusable":
      return (
        <>
          <p>
            <NotActive />
          </p>
          <ServedLine
            lead="Listener serves a GUI pair:"
            served={p.served}
            tail={
              p.persistedState === "unavailable"
                ? "; the pair persisted now cannot be examined, so whether it is the served one is not known."
                : `; the pair persisted now is ${p.persistedState} and is never loaded.`
            }
          />
        </>
      );
  }
}

function persistedHead(ui: UICertFacts): JSX.Element {
  switch (ui.pairState) {
    case "unavailable":
      return <StatusBadge status="unknown">Evidence unavailable</StatusBadge>;
    case "incomplete":
      return <StatusBadge status="critical">Incomplete pair</StatusBadge>;
    case "absent":
      return <StatusBadge status="neutral">No persisted pair</StatusBadge>;
    case "complete":
      return ui.corrupt ? (
        <StatusBadge status="critical">Corrupt pair</StatusBadge>
      ) : (
        <StatusBadge status="ok">Complete pair persisted</StatusBadge>
      );
  }
}

function persistedBody(ui: UICertFacts): ReactNode {
  switch (ui.pairState) {
    case "unavailable":
      return (
        <p>
          The persisted pair cannot be examined or read (an unreadable path, a
          directory, or an unreadable key). This is not absent: the files may
          exist, and the evidence blocks mutations until it can be read.
        </p>
      );
    case "incomplete":
      return (
        <p>
          The pair is incomplete: exactly one of the two files (certificate or
          key) is present; the listener never loads an incomplete pair.
        </p>
      );
    case "absent":
      return <p>The pair is positively absent: neither file exists.</p>;
    case "complete":
      return ui.corrupt ? (
        <p>
          The persisted files are readable but did not parse as a matching pair;
          the listener never loads them.
        </p>
      ) : null;
  }
}

/** The network-settings read is a CROSS-CHECK of the inventory's listener
 * evidence. Three outcomes: agreement (nothing extra rendered), a
 * contradiction (every activation claim withheld), or a read that did not
 * happen (stated; the inventory's evidence-backed claim stands). An answer
 * that cannot be verified as consistent listener facts is a contradiction,
 * not an unavailability — the appliance answered, and its facts disagree. */
type CrossCheck =
  | { kind: "pending" }
  | { kind: "agree" }
  | { kind: "contradiction"; text: string }
  | { kind: "unavailable"; text: string };

function crossCheck(
  inv: CertificateInventory,
  listener: ReadView<ListenerFacts>,
): CrossCheck {
  if (listener.data !== undefined) {
    const parts: string[] = [];
    if (listenerReadsDisagree(inv, listener.data)) {
      parts.push(
        `The certificate inventory and the network settings disagree about the running listener (inventory: ${listenerWords(inv.listener)}; network settings: ${listenerWords(listener.data.listener)}).`,
      );
    }
    const legacy = listenerContradiction(inv.uiCert, listener.data);
    if (legacy !== null) parts.push(contradictionText(legacy));
    if (parts.length === 0) return { kind: "agree" };
    return {
      kind: "contradiction",
      text: `${parts.join(" ")} No activation claim is made until the two reads agree.`,
    };
  }
  if (listener.loading) return { kind: "pending" };
  const summary = readErrorSummary(listener.error, "network settings");
  if (
    listener.error instanceof ApiError &&
    (listener.error.kind === "decode" || listener.error.kind === "contenttype")
  ) {
    return {
      kind: "contradiction",
      text: `${summary} The network settings could not be verified as consistent listener facts, so no activation claim is made.`,
    };
  }
  return {
    kind: "unavailable",
    text: `${summary} The listener facts below rest on the inventory's own bind evidence and were not cross-checked against the network settings.`,
  };
}

function UICertCard({
  inv,
  listener,
  writes,
}: {
  inv: CertificateInventory;
  listener: ReadView<ListenerFacts>;
  /** admin only: the FE-6B.2 mutation controls */
  writes: CertMutations | null;
}): JSX.Element {
  const ui = inv.uiCert;
  const check = crossCheck(inv, listener);
  const posture = activationPosture(inv);
  return (
    <Card
      title="UI listener certificate"
      actions={
        <>
          <NodeLocal />
          {writes !== null && (
            <>
              <Button
                size="sm"
                onClick={writes.open.replaceUI}
                disabled={writes.blocked}
              >
                Replace UI certificate…
              </Button>
              <Button
                size="sm"
                variant="danger-quiet"
                onClick={writes.open.deleteUI}
                disabled={writes.blocked || !writes.can.deleteUI}
              >
                Delete UI certificate…
              </Button>
            </>
          )}
        </>
      }
    >
      {check.kind === "contradiction" && (
        <Callout variant="critical" title="Contradictory listener facts">
          {check.text}
        </Callout>
      )}
      {check.kind === "unavailable" && (
        <Callout variant="warning" title="Listener cross-check unavailable">
          {check.text}
        </Callout>
      )}
      <p>
        {posture.kind === "custom_not_persisted" ? (
          <StatusBadge status="warn">No persisted pair</StatusBadge>
        ) : (
          persistedHead(ui)
        )}
      </p>
      {persistedBody(ui)}
      {check.kind !== "contradiction" && <ListenerActivation p={posture} />}
      {check.kind === "pending" && (
        <p>
          <Skeleton>Cross-checking the network settings…</Skeleton>
        </p>
      )}
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
  | { kind: "error"; unverified: boolean; text: string };

/** B2: "Audited" is qualified by the inventory's audit sink. A file sink is
 * the only evidence that the success audit reached the node's audit file; a
 * memory sink means the in-memory ring only; an inventory that could not be
 * read leaves the sink unknown — and "durable" is never said without the
 * file sink. */
function auditQualifier(sink: AuditSink | undefined): {
  badge: JSX.Element;
  text: string;
} {
  switch (sink) {
    case "file":
      return {
        badge: <StatusBadge status="ok">Audited</StatusBadge>,
        text: "Audit persisted (file sink): its success audit is appended to the node's audit file.",
      };
    case "memory":
      return {
        badge: <StatusBadge status="warn">Audited (memory sink)</StatusBadge>,
        text: "Audit recorded in the in-memory ring only (memory sink): this node has no audit file, so the record does not survive a restart.",
      };
    case undefined:
      return {
        badge: <StatusBadge status="neutral">Audited</StatusBadge>,
        text: "Audit recorded; sink evidence unavailable — the inventory read that names the audit sink failed, so whether the audit reached a file is not known.",
      };
  }
}

function OperationRecord({
  op,
  auditSink,
}: {
  op: CertOperation;
  auditSink: AuditSink | undefined;
}): JSX.Element {
  const p = operationPosture(op);
  let head: JSX.Element;
  let explain: ReactNode;
  switch (p.kind) {
    case "pending":
      head = <StatusBadge status="info">Pending</StatusBadge>;
      explain =
        "The intent is recorded and not yet decided; a later lookup, boot or writer settles it from the object's own evidence.";
      break;
    case "committed": {
      const q = auditQualifier(auditSink);
      head = (
        <span>
          <StatusBadge status="ok">Committed</StatusBadge> {q.badge}
        </span>
      );
      explain = `The mutation took effect. ${q.text}`;
      break;
    }
    case "committed_audit_pending":
      head = (
        <span>
          <StatusBadge status="ok">Committed</StatusBadge>{" "}
          <StatusBadge status="warn">Audit pending</StatusBadge>
        </span>
      );
      explain =
        "The mutation took effect; its success audit is still owed and is completed by a later settlement. This is not a failed certificate mutation.";
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

function OperationLookupCard({
  auditSink,
}: {
  auditSink: AuditSink | undefined;
}): JSX.Element {
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
        // B3: a refusal is a verdict only with its contracted HTTP status,
        // the JSON media type and the bounded {error, code, current?} shape.
        const code = certLookupRefusal(err);
        if (code !== null) {
          setOutcome({ kind: "refused", code });
          return;
        }
        setOutcome({
          kind: "error",
          unverified:
            err instanceof ApiError &&
            (err.kind === "decode" || err.kind === "contenttype"),
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
      result = <OperationRecord op={outcome.op} auditSink={auditSink} />;
      break;
    case "refused":
      result = refusalText(outcome.code);
      break;
    case "error":
      result = (
        <ErrorState
          title={
            outcome.unverified
              ? "Lookup response not verified"
              : "Lookup not answered"
          }
        >
          {outcome.text}
        </ErrorState>
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
          . The recovery campaign below reports its attempts and its last
          outcome.
        </Callout>
      )}
      {s.rotationPersistDegraded && (
        <PersistDegradedCallout persistClass={s.rotationPersistClass} />
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
  // FE-6B.2: the admin mutation surfaces. The hook is unconditional (rules of
  // hooks); below admin it renders nothing and offers nothing.
  const subject = state.phase === "authenticated" ? state.user : "";
  const mutations = useCertMutations({
    subject,
    isAdmin,
    inv: inv.data,
    ocsp: ocsp.data,
    refreshAll,
  });
  const writes = isAdmin ? mutations : null;

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
        subtitle="The inspection Root CA, the admin-listener certificate, the OCSP posture and the certificate operation ledger of THIS node — read from the appliance on demand. Node-local: none of these objects ride config export, version rollback or CP→DP sync; what the backup archive carries is stated in the backup facts below."
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

      {writes?.dialog}
      {tab === "Certificates" && (
        <div className={styles.stack}>
          {writes?.notices}
          <InspectionCASection
            inv={{ data: inv.data, error: inv.error, loading: inv.isLoading }}
            status={caStatusView}
            download={{
              run: runDownload,
              busy: downloading,
              error: downloadError,
            }}
            writes={writes}
          />
          {inv.data !== undefined && (
            <>
              <UICertCard
                inv={inv.data}
                listener={listenerView}
                writes={writes}
              />
              <MTLSCard m={inv.data.mtlsClientCert} />
              <Card
                title="OCSP posture"
                actions={
                  <>
                    <NodeLocal />
                    {writes !== null && (
                      <Button
                        size="sm"
                        onClick={writes.open.ocsp}
                        disabled={writes.blocked}
                      >
                        Set OCSP posture…
                      </Button>
                    )}
                  </>
                }
              >
                <OCSPPostureFacts o={inv.data.ocsp} />
              </Card>
              <LedgerCard inv={inv.data} />
            </>
          )}
          {isAdmin && (
            <OperationLookupCard auditSink={inv.data?.operations.auditSink} />
          )}
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
