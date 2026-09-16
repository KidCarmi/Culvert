// FE-6A.1 — Identity Providers (FE-V27) READ surface at
// /objects/identity-providers (viewer floor: uiRoutes GET /api/idp = viewer).
//
// This slice is READ-ONLY by directive: no create, update, delete, repair,
// test-provider, cutover, import or credential control is rendered — not
// even a disabled one — and the only interactive control is Refresh. Every
// fact is a SERVER fact rendered as supplied (bounded states and codes, never
// re-worded, never converted into a success/failure guess):
//   • registry: persisted / degraded posture (bounded reason; quarantine
//     evidence reported as RECORDED, never its file name), the content-
//     derived DOCUMENT revision, the cluster-synced scope;
//   • fleet: the publication result (published + config version, or pending
//     with the bounded last-rejection class);
//   • operation ledger: retained / unresolved / capacity / audit sink /
//     degraded posture;
//   • per profile: identity, type, enabled state, ENTRY revision, priority,
//     the write-only-secret INDICATOR (configured / not configured — never a
//     value), the authentication rules whose SSORequired providerRefs would
//     block a delete (409 referenced), and the create provenance
//     (operationId);
//   • legacy YAML LDAP (node-local): presence, active, retired, shadowed,
//     directory identity + bind-credential indicator, the bounded
//     cutoverDurability word, the operation-identified cutover record and —
//     for an ADMIN only (the ledger lookup names the actor) — the
//     authoritative operation record: pending / committed (+ owed audit) /
//     aborted (+ code) / outcome_unknown (+ code).
// Snapshot doctrine (ADR-FE-002): manual Refresh, no polling. The auth
// boundary clears the query cache (authBoundaryTeardown); this surface keeps
// no other subject-bound state and persists nothing.
import { useEffect, useRef, useState } from "react";
import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
  Timestamp,
} from "../../design-system/primitives";
import type { ConfirmResult } from "../../design-system/dialog";
import { DataTable } from "../../design-system/table";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import { readErrorSummary, refusalCodeOf } from "../../shared/readErrorSummary";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { ApiError } from "../../api/client";
import {
  IDP_LOOKUP_REFUSAL_CODES,
  asIdPRefusal,
  candidateDigest,
  createIdP,
  deleteIdP,
  discoverOIDC,
  getIdPList,
  getIdPOperation,
  getIdPReferences,
  getLegacyLDAP,
  IMPORT_SOURCE_UNAVAILABLE,
  importCandidateDigest,
  importLegacyLDAP,
  repairIdPRegistry,
  specCarriesSecret,
  testIdP,
  updateIdP,
} from "../../api/idp";
import type {
  IdPList,
  IdPOperation,
  IdPProfile,
  IdPRefusal,
  IdPRefusalCode,
  IdPWriteSpec,
  LegacyLDAP,
} from "../../api/idp";
import type { ObjectRefConsumer } from "../../api/policy";
import { useObjectPage } from "./useObjectPage";
import {
  clearIdPRecovery,
  readIdPRecovery,
  writeIdPRecovery,
} from "./idpRecovery";
import type { IdPRecoveryMarker, IdPRecoveryRead } from "./idpRecovery";
import {
  AbandonCeremony,
  CutoverCeremony,
  DeleteProviderCeremony,
  IdPFenceCallout,
  IdPRefusalCallout,
  IdPUnprovenCallout,
  ImportCeremony,
  ProviderEditorDialog,
  RepairCeremony,
  ReviewCeremony,
  carriesCutover,
  draftDirty,
  draftFrom,
  draftToSpec,
  stripSecrets,
} from "./idpWrites";
import type { DiscoverState, ProviderDraft, TestState } from "./idpWrites";
import styles from "../diagnostics/diagnostics.module.css";

/** null = the where-used read for this profile did not succeed (unknown —
 * never rendered as "not referenced"). */
type ReferenceMap = ReadonlyMap<string, readonly ObjectRefConsumer[] | null>;

interface RegistrySnapshot {
  list: IdPList;
  references: ReferenceMap;
}

async function fetchRegistry(signal: AbortSignal): Promise<RegistrySnapshot> {
  const list = await getIdPList(signal);
  const entries = await Promise.all(
    list.profiles.map(
      async (p): Promise<[string, readonly ObjectRefConsumer[] | null]> => {
        try {
          const refs = await getIdPReferences(p.id, signal);
          return [p.id, refs.referencedBy];
        } catch (err) {
          // An aborted snapshot must not settle a stale partial answer.
          if (err instanceof ApiError && err.kind === "aborted") throw err;
          return [p.id, null];
        }
      },
    ),
  );
  return { list, references: new Map(entries) };
}

// The decoder guarantees exactly the type's own sub-config is present, so
// the indicator is read from a fact the server stated — never invented from
// a missing object.
function materialIndicator(p: IdPProfile): string {
  const word = (configured: boolean): string =>
    configured ? "configured" : "not configured";
  switch (p.type) {
    case "oidc":
      return `Client secret: ${word(p.oidc.clientSecretConfigured)}`;
    case "saml":
      return `Inline metadata: ${word(p.saml.inlineMetadataConfigured)}`;
    case "ldap":
      return `Bind credential: ${word(p.ldap.bindCredentialConfigured)}`;
  }
}

function ReferencesCell({
  refs,
}: {
  refs: readonly ObjectRefConsumer[] | null | undefined;
}): JSX.Element {
  if (refs === null || refs === undefined) {
    return <StatusBadge status="unknown">References unavailable</StatusBadge>;
  }
  if (refs.length === 0) {
    return <span>Not referenced</span>;
  }
  return (
    <div>
      <div>
        Referenced by {String(refs.length)} authentication rule
        {refs.length === 1 ? "" : "s"} — a delete would be refused
      </div>
      <ul>
        {refs.map((r) => (
          <li key={`${r.consumerType}:${r.id}:${r.name}`}>{r.name}</li>
        ))}
      </ul>
    </div>
  );
}

function RegistryCard({ list }: { list: IdPList }): JSX.Element {
  const fleet =
    list.cluster.state === "published" ? (
      <StatusBadge status="ok">
        Published (config version {String(list.cluster.publishedVersion)})
      </StatusBadge>
    ) : (
      <span>
        <StatusBadge status="warn">Pending publication</StatusBadge>
        {list.cluster.lastRejection !== undefined && (
          <span>
            {" "}
            — last rejection <Mono>
              {list.cluster.lastRejection.reason}
            </Mono> at <Timestamp iso={list.cluster.lastRejection.at} />
          </span>
        )}
      </span>
    );
  return (
    <Card title="Registry">
      <KeyValue
        items={[
          [
            "Scope",
            <StatusBadge key="scope" status="info">
              Cluster-synced
            </StatusBadge>,
          ],
          [
            "Persistence",
            list.persisted ? (
              <StatusBadge status="ok">Persisted</StatusBadge>
            ) : (
              <StatusBadge status="warn">
                Not persisted — no registry persistence path on this node;
                administrative changes are refused
              </StatusBadge>
            ),
          ],
          ["Document revision", <Mono key="rev">{list.revision}</Mono>],
          ["Profiles", String(list.profiles.length)],
          ["Fleet publication", fleet],
        ]}
      />
    </Card>
  );
}

function LedgerCard({ list }: { list: IdPList }): JSX.Element {
  const ops = list.operations;
  return (
    <Card title="Operation ledger">
      {ops.degraded && ops.degradedReason !== undefined && (
        <Callout
          variant="critical"
          title="Operation ledger degraded"
          role="alert"
        >
          Reason: <Mono>{ops.degradedReason}</Mono>. Operation-identified writes
          and lookups are refused until the ledger is restored and the node
          restarted (server posture).
        </Callout>
      )}
      <ul>
        <li>Unresolved intents: {String(ops.unresolved)}</li>
        <li>
          Retained: {String(ops.retained)} of {String(ops.capacity)}
        </li>
        <li>Audit sink: {ops.auditSink}</li>
      </ul>
    </Card>
  );
}

interface RowActions {
  canMutate: boolean;
  onEdit: (p: IdPProfile) => void;
  onDelete: (p: IdPProfile) => void;
}

function ProvidersCard({
  snap,
  actions,
}: {
  snap: RegistrySnapshot;
  /** admin only — never rendered below the role */
  actions: RowActions | null;
}): JSX.Element {
  const rows = snap.list.profiles;
  return (
    <Card title="Providers">
      {rows.length === 0 ? (
        <EmptyState title="No identity providers">
          The registry holds no provider profiles.
        </EmptyState>
      ) : (
        <DataTable
          caption="Identity-provider profiles"
          columns={[
            { key: "name", header: "Name", render: (p: IdPProfile) => p.name },
            {
              key: "type",
              header: "Type",
              render: (p) => <Mono>{p.type}</Mono>,
            },
            {
              key: "state",
              header: "State",
              render: (p) =>
                p.enabled ? (
                  <StatusBadge status="ok">Enabled</StatusBadge>
                ) : (
                  <StatusBadge status="neutral">Disabled</StatusBadge>
                ),
            },
            {
              key: "priority",
              header: "Priority",
              numeric: true,
              render: (p) => String(p.priority),
            },
            {
              key: "revision",
              header: "Revision",
              numeric: true,
              render: (p) => String(p.revision),
            },
            {
              key: "material",
              header: "Write-only material",
              render: (p) => materialIndicator(p),
            },
            {
              key: "refs",
              header: "Referenced by",
              render: (p) => (
                <ReferencesCell refs={snap.references.get(p.id)} />
              ),
            },
            {
              key: "prov",
              header: "Provenance",
              render: (p) =>
                p.operationId !== undefined ? (
                  <Mono>{p.operationId}</Mono>
                ) : (
                  "—"
                ),
            },
            ...(actions !== null
              ? [
                  {
                    key: "actions",
                    header: "Actions",
                    render: (p: IdPProfile) => (
                      <span>
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={!actions.canMutate}
                          onClick={() => actions.onEdit(p)}
                        >
                          Edit
                        </Button>{" "}
                        <Button
                          size="sm"
                          variant="danger-quiet"
                          disabled={!actions.canMutate}
                          onClick={() => actions.onDelete(p)}
                        >
                          Delete
                        </Button>
                      </span>
                    ),
                  },
                ]
              : []),
          ]}
          rows={rows}
          rowKey={(p) => p.id}
        />
      )}
    </Card>
  );
}

function durabilityBadge(l: LegacyLDAP): JSX.Element {
  switch (l.cutoverDurability) {
    case "durable":
      return <StatusBadge status="ok">Durable</StatusBadge>;
    case "pending_reconciliation":
      return (
        <StatusBadge status="warn">
          Pending reconciliation — active at runtime, not yet durable
        </StatusBadge>
      );
    case "not_retired":
      return <StatusBadge status="neutral">Not retired</StatusBadge>;
  }
}

function operationStateView(op: IdPOperation): JSX.Element {
  switch (op.state) {
    case "committed":
      return (
        <span>
          <StatusBadge status="ok">Committed</StatusBadge>{" "}
          {op.audited
            ? "— success audit durable"
            : op.auditState === "pending"
              ? "— success audit still owed (recoverable)"
              : ""}
          {op.committedRevision !== undefined && (
            <span>
              {" "}
              · registry revision <Mono>{op.committedRevision}</Mono>
            </span>
          )}
        </span>
      );
    case "pending":
      return <StatusBadge status="warn">Pending — not yet settled</StatusBadge>;
    case "aborted":
      return (
        <span>
          <StatusBadge status="critical">Aborted</StatusBadge>
          {op.code !== undefined && (
            <span>
              {" "}
              — <Mono>{op.code}</Mono>
            </span>
          )}
        </span>
      );
    case "outcome_unknown":
      return (
        <span>
          <StatusBadge status="unknown">Outcome unknown</StatusBadge>
          {op.code !== undefined && (
            <span>
              {" "}
              — <Mono>{op.code}</Mono>
            </span>
          )}{" "}
          · settled by a later lookup, a later writer on the profile, or the
          next boot
        </span>
      );
  }
}

function OperationRecord({
  operationId,
  isAdmin,
}: {
  operationId: string;
  isAdmin: boolean;
}): JSX.Element {
  const q = useQuery({
    queryKey: ["objects", "idp", "operation", operationId],
    queryFn: ({ signal }) => getIdPOperation(operationId, signal),
    enabled: isAdmin,
    staleTime: Infinity,
    retry: false,
  });
  if (!isAdmin) {
    return <span>Operation record lookup is admin-only.</span>;
  }
  if (q.data !== undefined) return operationStateView(q.data);
  if (q.isError) {
    const err: unknown = q.error;
    if (err instanceof ApiError && err.status === 404) {
      return (
        <StatusBadge status="neutral">No retained operation record</StatusBadge>
      );
    }
    // A refusal is a verdict only inside the lookup's contracted vocabulary;
    // an unrecognised code is reported as a refusal WITHOUT echoing it.
    const code = refusalCodeOf(err, IDP_LOOKUP_REFUSAL_CODES);
    if (code !== null) {
      return <StatusBadge status="unknown">Lookup refused: {code}</StatusBadge>;
    }
    if (err instanceof ApiError && err.kind === "http") {
      return (
        <StatusBadge status="unknown">
          Lookup refused (HTTP {String(err.status ?? 0)}, unrecognised refusal
          code)
        </StatusBadge>
      );
    }
    return (
      <StatusBadge status="unknown">
        {readErrorSummary(err, "operation record")}
      </StatusBadge>
    );
  }
  return <span>Looking up the operation record…</span>;
}

// The cutover record carries its OWN identity (server-minted at the cutover);
// the operation LEDGER is keyed on the enabling create's client operationId,
// which the registry co-writes as that profile's provenance. The lookup is
// therefore keyed on the enabling profile's provenance — a join over two
// server facts, never a guess; without it (profile gone, or created without
// an operationId) no lookup is issued and that is said.
type LedgerKey =
  | { kind: "known"; operationId: string }
  | { kind: "absent" } // registry read, enabling profile gone or without provenance
  | { kind: "registry_unavailable" }; // the registry snapshot itself could not be read

function LegacyCard({
  legacy,
  isAdmin,
  ledgerKey,
  onImport,
}: {
  legacy: LegacyLDAP;
  isAdmin: boolean;
  ledgerKey: LedgerKey;
  /** admin only, present block only; null ⇒ no control rendered */
  onImport: (() => void) | null;
}): JSX.Element {
  const yesNo = (b: boolean): string => (b ? "yes" : "no");
  const items: Array<readonly [string, JSX.Element | string]> = [
    [
      "Scope",
      <StatusBadge key="scope" status="info">
        Node-local
      </StatusBadge>,
    ],
    ["Block", legacy.present ? "Present" : "Not present"],
  ];
  if (legacy.present) {
    items.push(["Active for proxy authentication", yesNo(legacy.active)]);
    items.push(["Shadowed by the registry", yesNo(legacy.shadowed)]);
    items.push(["Directory", <Mono key="url">{legacy.url}</Mono>]);
    items.push(["Base DN", <Mono key="base">{legacy.baseDn}</Mono>]);
    items.push(["Bind DN", <Mono key="bind">{legacy.bindDn}</Mono>]);
    items.push([
      "Write-only material",
      `Bind credential: ${legacy.bindCredentialConfigured ? "configured" : "not configured"}`,
    ]);
    // The security-effective legacy configuration, verbatim from the wire
    // (correction round 2, DP1): "" is a configured value and is said so.
    items.push([
      "User filter",
      legacy.userFilter === "" ? (
        "(empty)"
      ) : (
        <Mono key="filter">{legacy.userFilter}</Mono>
      ),
    ]);
    items.push([
      "Required group",
      legacy.requiredGroup === "" ? (
        "(none)"
      ) : (
        <Mono key="group">{legacy.requiredGroup}</Mono>
      ),
    ]);
    items.push(["StartTLS", legacy.startTls ? "Negotiated" : "Not negotiated"]);
    items.push([
      "TLS certificate verification",
      legacy.tlsSkipVerify ? (
        <StatusBadge key="tls" status="critical">
          Skipped (tlsSkipVerify)
        </StatusBadge>
      ) : (
        "Enforced"
      ),
    ]);
    items.push(["Result cache TTL", `${String(legacy.cacheTtlSeconds)} s`]);
  }
  items.push(["Legacy authority", legacy.retired ? "Retired" : "Not retired"]);
  items.push(["Authority cutover", durabilityBadge(legacy)]);
  const c = legacy.cutover;
  return (
    <Card
      title="Legacy YAML LDAP"
      {...(onImport !== null && legacy.present
        ? {
            actions: (
              <Button size="sm" variant="secondary" onClick={onImport}>
                Import legacy configuration
              </Button>
            ),
          }
        : {})}
    >
      <KeyValue items={items} />
      {c !== undefined && (
        <div>
          <h3>Cutover record</h3>
          <KeyValue
            items={[
              ["Cutover identity", <Mono key="op">{c.operationId}</Mono>],
              [
                "Enabling profile",
                c.profileName !== undefined || c.profileId !== undefined
                  ? `${c.profileName ?? ""}${c.profileId !== undefined ? ` (${c.profileId})` : ""}`
                  : "—",
              ],
              [
                "Registry revision",
                c.registryRevision !== undefined ? (
                  <Mono key="rr">{c.registryRevision}</Mono>
                ) : (
                  "—"
                ),
              ],
              ["Actor", c.actor],
              ["Trigger", <Mono key="trig">{c.trigger}</Mono>],
              ["At", <Timestamp key="at" iso={c.at} />],
              ["Record durable", c.durable ? "yes" : "no"],
              [
                "Ledger key (enabling create)",
                ledgerKey.kind === "known" ? (
                  <Mono key="lk">{ledgerKey.operationId}</Mono>
                ) : (
                  "—"
                ),
              ],
              [
                "Operation record",
                ledgerKey.kind === "known" ? (
                  <OperationRecord
                    key="rec"
                    operationId={ledgerKey.operationId}
                    isAdmin={isAdmin}
                  />
                ) : ledgerKey.kind === "absent" ? (
                  <span key="nolk">
                    No ledger key: the enabling profile is not in the registry
                    or carries no create provenance.
                  </span>
                ) : (
                  <span key="nolk">
                    Ledger key unavailable: the registry could not be read.
                  </span>
                ),
              ],
            ]}
          />
        </div>
      )}
    </Card>
  );
}

// The registry (cluster-synced) and the legacy YAML block (node-local) are
// INDEPENDENT authoritative snapshots (correction, blocker 4): each renders
// its own loading / error / data state, so a failed or refused registry
// read never blanks a valid legacy snapshot and vice versa.
type Ceremony =
  | { kind: "closed" }
  | {
      kind: "editor";
      mode: "create" | "edit";
      initial: IdPProfile | null;
      draft: ProviderDraft;
      base: ProviderDraft;
      /** a re-send bound to an unresolved operation's identity */
      boundOperationId?: string;
      error: string | null;
    }
  | {
      kind: "review";
      mode: "create" | "edit";
      initial: IdPProfile | null;
      spec: IdPWriteSpec;
      draft: ProviderDraft;
      operationId: string;
    }
  | {
      kind: "cutover";
      mode: "create" | "edit";
      initial: IdPProfile | null;
      spec: IdPWriteSpec;
      draft: ProviderDraft;
      operationId: string;
      legacy: LegacyLDAP & { present: true };
    }
  | { kind: "delete"; profile: IdPProfile }
  | { kind: "repair"; evidence: string }
  | {
      kind: "import";
      legacy: LegacyLDAP & { present: true };
      /** a re-send of an unresolved import keeps its operation identity */
      boundOperationId?: string;
    }
  | { kind: "abandon"; marker: IdPRecoveryMarker };

type RecoveryView =
  | { kind: "none" }
  | { kind: "looking" }
  | { kind: "op"; op: IdPOperation }
  | { kind: "never_recorded" }
  | { kind: "refused"; code: string }
  | { kind: "unproven" };

/** Refusal codes that PROVE nothing was written — the marker may be cleared. */
const TERMINAL_NOTHING_WRITTEN: readonly IdPRefusalCode[] = [
  "invalid_input",
  "forbidden",
  "not_found",
  "vanished",
  "stale",
  "precondition_required",
  "persistence_not_configured",
  "provider_compile_failed",
  "operation_id_required",
  "cutover_confirm_required",
  "confirm_mismatch",
  "operation_aborted",
  "operation_ledger_degraded",
  "operation_ledger_full",
  // FE-6A.2 correction (Blocker 3): the write-boundary preflight is decided
  // BEFORE the ledger intent, so a preflight refusal has no record to settle.
  "preflight_failed",
  // Round 3 (Blocker 1): the reviewed-source check is decided before the
  // fence and the intent — nothing to settle, the source is re-read.
  "import_source_required",
  "import_source_stale",
  "operation_unsettled",
  "persist_failed",
  "registry_degraded",
  "method_not_allowed",
];

function mintOperationId(): string {
  return crypto.randomUUID();
}

export function IdentityProvidersPage(): JSX.Element {
  const { state } = useAuth();
  const isAdmin = hasRole(state.role ?? "viewer", "admin");
  const subject = state.phase === "authenticated" ? state.user : "";
  const page = useObjectPage(["objects", "idp", "registry"], fetchRegistry);
  const registry = page.q;
  const legacy = useSnapshot(["objects", "idp", "legacy-ldap"], getLegacyLDAP);
  const snap = registry.data;

  const [ceremony, setCeremony] = useState<Ceremony>({ kind: "closed" });
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState<string | undefined>(undefined);
  const [notice, setNotice] = useState<string | null>(null);
  const [fence, setFence] = useState<IdPRefusal | null>(null);
  const [refusal, setRefusal] = useState<IdPRefusal | null>(null);
  const [unproven, setUnproven] = useState<{
    action: string;
    status: number | undefined;
  } | null>(null);
  const [forbidden, setForbidden] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<IdPRecoveryRead>({
    kind: "unresolved",
  });
  const [recoveryView, setRecoveryView] = useState<RecoveryView>({
    kind: "none",
  });
  const [test, setTest] = useState<TestState>({ kind: "idle" });
  const [discover, setDiscover] = useState<DiscoverState>({ kind: "idle" });
  /** the NON-SECRET draft of the last dispatched candidate, for a re-send prefill */
  const lastCandidate = useRef<{
    operationId: string;
    draft: ProviderDraft;
  } | null>(null);

  useEffect(() => {
    setRecovery(readIdPRecovery(subject));
  }, [subject]);

  const dirty =
    ceremony.kind === "editor" && draftDirty(ceremony.draft, ceremony.base);
  const guard = useDirtyGuard(dirty, "the provider editor");

  const blocked = page.unknown !== null || recovery.kind !== "none";
  const canMutate =
    isAdmin && snap !== undefined && !blocked && result !== "pending";

  const clearOutcome = (): void => {
    setNotice(null);
    setFence(null);
    setRefusal(null);
    setUnproven(null);
    setForbidden(null);
  };
  const close = (): void => {
    setCeremony({ kind: "closed" });
    setResult("idle");
    setErrorText(undefined);
    setTest({ kind: "idle" });
    setDiscover({ kind: "idle" });
  };
  const refreshAll = (): void => {
    page.refreshToResolve();
    void legacy.refetch();
  };
  const rereadRecovery = (): void => {
    setRecovery(readIdPRecovery(subject));
  };

  const markUnproven = (action: string, err: unknown): void => {
    close(); // drops every secret with the dialog tree
    setUnproven({
      action,
      status: err instanceof ApiError ? err.status : undefined,
    });
    page.latchUnknown("edit");
    const transport =
      err instanceof ApiError &&
      (err.kind === "network" ||
        err.kind === "timeout" ||
        err.kind === "aborted");
    if (!transport) refreshAll();
  };

  const fail = (
    err: unknown,
    action: string,
    marker: IdPRecoveryMarker | null,
  ): void => {
    const r = asIdPRefusal(err);
    if (r !== null) {
      close();
      if (r.code === "stale" || r.code === "precondition_required") setFence(r);
      else setRefusal(r);
      if (marker !== null && TERMINAL_NOTHING_WRITTEN.includes(r.code))
        clearIdPRecovery(marker.operationId);
      rereadRecovery();
      refreshAll();
      return;
    }
    if (err instanceof ApiError && err.forbidden) {
      close();
      setForbidden(action);
      if (marker !== null) clearIdPRecovery(marker.operationId);
      rereadRecovery();
      refreshAll();
      return;
    }
    // UNPROVEN: the marker (if any) is KEPT — the ledger settles it.
    markUnproven(action, err);
    rereadRecovery();
  };

  /** A re-send dispatches under the RECORDED marker (same start instant —
   * the evidence is immutable, and a freshly stamped copy of it would be
   * refused by the store as a second unresolved operation). A first dispatch
   * records the fresh marker. */
  const adoptOrRecordMarker = (fresh: IdPRecoveryMarker): boolean => {
    const stored = readIdPRecovery(subject);
    const marker =
      stored.kind === "valid" && stored.marker.operationId === fresh.operationId
        ? stored.marker
        : fresh;
    return writeIdPRecovery(subject, marker);
  };

  // ── dispatch ──────────────────────────────────────────────────────────────
  const dispatchWrite = async (
    mode: "create" | "edit",
    initial: IdPProfile | null,
    spec: IdPWriteSpec,
    draft: ProviderDraft,
    operationId: string,
    cutoverConfirm: string | undefined,
  ): Promise<void> => {
    if (snap === undefined) return;
    clearOutcome();
    const needsOperation = mode === "create" || cutoverConfirm !== undefined;
    let marker: IdPRecoveryMarker | null = null;
    if (needsOperation) {
      marker = {
        operationId,
        action: mode === "create" ? "create" : "update",
        profileId: initial?.id ?? "",
        name: spec.name,
        type: spec.type,
        candidateDigest: candidateDigest(spec),
        fence:
          mode === "create"
            ? snap.list.revision
            : String(initial?.revision ?? 0),
        cutover: cutoverConfirm !== undefined,
        startedAt: Date.now(),
      };
      if (!adoptOrRecordMarker(marker)) {
        setResult("failed");
        setErrorText(
          readIdPRecovery(subject).kind === "valid"
            ? "Another provider operation is still unresolved in this browser; nothing was sent."
            : "The operation identity could not be persisted in this browser; nothing was sent.",
        );
        rereadRecovery();
        return;
      }
      lastCandidate.current = { operationId, draft: stripSecrets(draft) };
    }
    setResult("pending");
    const signal = page.owner.begin();
    try {
      const out =
        mode === "create"
          ? await createIdP(
              spec,
              {
                documentRevision: snap.list.revision,
                operationId,
                ...(cutoverConfirm !== undefined ? { cutoverConfirm } : {}),
              },
              signal,
            )
          : await updateIdP(
              initial?.id ?? "",
              spec,
              {
                revision: initial?.revision ?? 0,
                ...(needsOperation ? { operationId } : {}),
                ...(cutoverConfirm !== undefined ? { cutoverConfirm } : {}),
              },
              signal,
            );
      if (marker !== null) clearIdPRecovery(marker.operationId);
      lastCandidate.current = null;
      close();
      setNotice(
        out.kind === "replayed"
          ? `Provider ${mode === "create" ? "create" : "update"} replayed from the appliance's ledger (operation ${out.operationId}); nothing was written twice`
          : mode === "create"
            ? `Provider created (${out.profile.name}, revision ${String(out.profile.revision)})${out.auditState === "pending" ? " — success audit still owed by the appliance" : ""}`
            : `Provider updated (${out.profile.name}, revision ${String(out.profile.revision)})${cutoverConfirm !== undefined ? " — legacy authenticator retired" : ""}`,
      );
      rereadRecovery();
      refreshAll();
    } catch (err) {
      fail(
        err,
        mode === "create" ? "create provider" : "update provider",
        marker,
      );
    } finally {
      page.owner.settle(signal);
    }
  };

  const review = (): void => {
    if (ceremony.kind !== "editor") return;
    const spec = draftToSpec(ceremony.draft, ceremony.mode, ceremony.initial);
    if (typeof spec === "string") {
      setCeremony({ ...ceremony, error: spec });
      return;
    }
    const operationId = ceremony.boundOperationId ?? mintOperationId();
    if (
      ceremony.boundOperationId !== undefined &&
      recovery.kind === "valid" &&
      recovery.marker.candidateDigest !== candidateDigest(spec)
    ) {
      setCeremony({
        ...ceremony,
        error:
          "This re-send is bound to the unresolved operation's candidate; re-enter the same candidate or abandon the operation first.",
      });
      return;
    }
    const cut = carriesCutover(spec, legacy.data);
    if (cut !== null) {
      setCeremony({
        kind: "cutover",
        mode: ceremony.mode,
        initial: ceremony.initial,
        spec,
        draft: ceremony.draft,
        operationId,
        legacy: cut,
      });
      return;
    }
    if (specCarriesSecret(spec)) {
      setCeremony({
        kind: "review",
        mode: ceremony.mode,
        initial: ceremony.initial,
        spec,
        draft: ceremony.draft,
        operationId,
      });
      return;
    }
    void dispatchWrite(
      ceremony.mode,
      ceremony.initial,
      spec,
      ceremony.draft,
      operationId,
      undefined,
    );
  };

  const runDelete = async (profile: IdPProfile): Promise<void> => {
    clearOutcome();
    setResult("pending");
    const signal = page.owner.begin();
    try {
      await deleteIdP(profile.id, profile.revision, signal);
      close();
      setNotice(`Provider deleted (${profile.name})`);
      refreshAll();
    } catch (err) {
      fail(err, "delete provider", null);
    } finally {
      page.owner.settle(signal);
    }
  };
  const runRepair = async (evidence: string): Promise<void> => {
    clearOutcome();
    setResult("pending");
    const signal = page.owner.begin();
    try {
      await repairIdPRegistry(evidence, signal);
      close();
      setNotice(
        "Registry repaired — it is empty and accepts writes again; the quarantined copy stays on disk",
      );
      refreshAll();
    } catch (err) {
      fail(err, "repair registry", null);
    } finally {
      page.owner.settle(signal);
    }
  };
  const runImport = async (): Promise<void> => {
    if (ceremony.kind !== "import" || snap === undefined) return;
    clearOutcome();
    // FE-6A.2 correction (Blocker 1): the import is an operation-identified,
    // fenced write and rides the recovery marker like a create — persisted
    // BEFORE dispatch, so an unproven answer can never become a second import.
    if (ceremony.legacy.importSourceRevision === IMPORT_SOURCE_UNAVAILABLE) {
      // The appliance cannot bind the import to the reviewed source (no
      // usable ledger key): nothing is sent — the server would refuse it as
      // operation_ledger_degraded anyway.
      setResult("failed");
      setErrorText(
        "The appliance cannot bind this import to the reviewed legacy source (operation ledger unavailable); nothing was sent.",
      );
      return;
    }
    const operationId = ceremony.boundOperationId ?? mintOperationId();
    const marker: IdPRecoveryMarker = {
      operationId,
      action: "import",
      profileId: "",
      name: "Imported legacy LDAP",
      type: "ldap",
      candidateDigest: importCandidateDigest(ceremony.legacy),
      fence: snap.list.revision,
      cutover: false,
      startedAt: Date.now(),
    };
    if (
      ceremony.boundOperationId !== undefined &&
      recovery.kind === "valid" &&
      recovery.marker.candidateDigest !== marker.candidateDigest
    ) {
      // The legacy block changed since the unresolved import was reviewed:
      // the appliance would refuse it as operation_mismatch; say so first.
      setResult("failed");
      setErrorText(
        "This re-send is bound to the unresolved import's legacy configuration, which has changed; abandon the operation first.",
      );
      return;
    }
    if (!adoptOrRecordMarker(marker)) {
      setResult("failed");
      setErrorText(
        readIdPRecovery(subject).kind === "valid"
          ? "Another provider operation is still unresolved in this browser; nothing was sent."
          : "The operation identity could not be persisted in this browser; nothing was sent.",
      );
      rereadRecovery();
      return;
    }
    setResult("pending");
    const signal = page.owner.begin();
    try {
      const out = await importLegacyLDAP(
        {
          documentRevision: snap.list.revision,
          operationId,
          // Round 3 (Blocker 1): the token of the source the operator
          // REVIEWED in this ceremony — the appliance refuses a changed
          // source and the decoder refuses an answer for another one.
          importSourceRevision: ceremony.legacy.importSourceRevision,
        },
        signal,
      );
      clearIdPRecovery(operationId);
      close();
      setNotice(
        out.kind === "replayed"
          ? `Legacy import replayed from the appliance's ledger (operation ${out.operationId}); nothing was imported twice`
          : `Legacy configuration imported as the disabled provider ${out.name} (revision ${String(out.revision)})${out.auditState === "pending" ? " — success audit still owed by the appliance" : ""}`,
      );
      rereadRecovery();
      refreshAll();
    } catch (err) {
      fail(err, "import legacy configuration", marker);
    } finally {
      page.owner.settle(signal);
    }
  };
  const runTest = async (cred: {
    username: string;
    password: string;
  }): Promise<void> => {
    if (ceremony.kind !== "editor") return;
    const spec = draftToSpec(ceremony.draft, ceremony.mode, ceremony.initial);
    if (typeof spec === "string") {
      setCeremony({ ...ceremony, error: spec });
      return;
    }
    setTest({ kind: "running" });
    try {
      const report = await testIdP(
        {
          ...spec,
          ...(ceremony.initial !== null ? { id: ceremony.initial.id } : {}),
        },
        cred,
      );
      setTest({ kind: "report", report });
    } catch (err) {
      const r = asIdPRefusal(err);
      setTest(
        r !== null
          ? { kind: "refused", refusal: r }
          : {
              kind: "unproven",
              status: err instanceof ApiError ? err.status : undefined,
            },
      );
    }
  };
  const runDiscover = async (issuer: string): Promise<void> => {
    setDiscover({ kind: "running" });
    try {
      const d = await discoverOIDC(issuer);
      setCeremony((c) =>
        c.kind === "editor"
          ? {
              ...c,
              draft: {
                ...c.draft,
                oidc: {
                  ...c.draft.oidc,
                  authorizationEndpoint:
                    d.authorizationEndpoint ??
                    c.draft.oidc.authorizationEndpoint,
                  tokenEndpoint: d.tokenEndpoint ?? c.draft.oidc.tokenEndpoint,
                  introspectionEndpoint:
                    d.introspectionEndpoint ??
                    c.draft.oidc.introspectionEndpoint,
                  userinfoEndpoint:
                    d.userinfoEndpoint ?? c.draft.oidc.userinfoEndpoint,
                  jwksUri: d.jwksUri ?? c.draft.oidc.jwksUri,
                },
              },
            }
          : c,
      );
      setDiscover({ kind: "done", found: Object.keys(d).length });
    } catch (err) {
      const r = asIdPRefusal(err);
      setDiscover(
        r !== null
          ? { kind: "refused", refusal: r }
          : {
              kind: "unproven",
              status: err instanceof ApiError ? err.status : undefined,
            },
      );
    }
  };

  // ── recovery ──────────────────────────────────────────────────────────────
  const recover = async (marker: IdPRecoveryMarker): Promise<void> => {
    setRecoveryView({ kind: "looking" });
    try {
      const op = await getIdPOperation(marker.operationId);
      setRecoveryView({ kind: "op", op });
      if (op.state === "committed") {
        clearIdPRecovery(marker.operationId);
        lastCandidate.current = null;
        setNotice(
          `Operation ${marker.operationId} is committed on the appliance${op.audited ? "" : " (success audit still owed)"}`,
        );
        rereadRecovery();
        refreshAll();
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setRecoveryView({ kind: "never_recorded" });
        return;
      }
      const code = refusalCodeOf(err, IDP_LOOKUP_REFUSAL_CODES);
      setRecoveryView(
        code !== null ? { kind: "refused", code } : { kind: "unproven" },
      );
    }
  };
  const resend = (marker: IdPRecoveryMarker): void => {
    if (marker.action === "import") {
      // The SAME import operation is re-sent (never a new one); it needs
      // the legacy block that was reviewed to still be present.
      if (legacy.data?.present === true)
        setCeremony({
          kind: "import",
          legacy: legacy.data,
          boundOperationId: marker.operationId,
        });
      return;
    }
    const initial =
      marker.action === "update"
        ? (snap?.list.profiles.find((p) => p.id === marker.profileId) ?? null)
        : null;
    const remembered =
      lastCandidate.current?.operationId === marker.operationId
        ? lastCandidate.current.draft
        : null;
    const base = remembered ?? {
      ...draftFrom(initial),
      type: marker.type,
      name: marker.name,
    };
    setCeremony({
      kind: "editor",
      mode: marker.action === "create" ? "create" : "edit",
      initial,
      draft: base,
      base,
      boundOperationId: marker.operationId,
      error: null,
    });
  };
  const abandon = (marker: IdPRecoveryMarker): void => {
    clearIdPRecovery(marker.operationId);
    lastCandidate.current = null;
    close();
    setRecoveryView({ kind: "none" });
    rereadRecovery();
  };

  const ledgerKeyFor = (l: LegacyLDAP): LedgerKey => {
    if (snap === undefined) return { kind: "registry_unavailable" };
    const key = snap.list.profiles.find(
      (p) => p.id === l.cutover?.profileId,
    )?.operationId;
    return key !== undefined
      ? { kind: "known", operationId: key }
      : { kind: "absent" };
  };

  const openCreate = (): void => {
    clearOutcome();
    const base = draftFrom(null);
    setCeremony({
      kind: "editor",
      mode: "create",
      initial: null,
      draft: base,
      base,
      error: null,
    });
  };
  const openEdit = (p: IdPProfile): void => {
    clearOutcome();
    const base = draftFrom(p);
    setCeremony({
      kind: "editor",
      mode: "edit",
      initial: p,
      draft: base,
      base,
      error: null,
    });
  };

  const rowActions = isAdmin
    ? {
        canMutate,
        onEdit: openEdit,
        onDelete: (p: IdPProfile) => {
          clearOutcome();
          setCeremony({ kind: "delete", profile: p });
        },
      }
    : null;

  return (
    <>
      <PageHeader
        title="Identity Providers"
        subtitle="Registry — identity, state, revisions, fleet publication, the legacy LDAP cutover posture; admin writes are fenced and ceremonied"
        actions={
          <>
            {isAdmin && snap !== undefined && (
              <Button
                variant="primary"
                size="sm"
                disabled={!canMutate}
                onClick={openCreate}
              >
                Add provider
              </Button>
            )}
            <SnapshotBar
              updatedAt={Math.max(registry.dataUpdatedAt, legacy.dataUpdatedAt)}
              fetching={registry.isFetching || legacy.isFetching}
              error={registry.isError || legacy.isError}
              hasData={snap !== undefined || legacy.data !== undefined}
              onRefresh={refreshAll}
            />
          </>
        }
      />
      <div className={styles.stack}>
        {notice !== null && (
          <Callout variant="success" role="status">
            {notice}
          </Callout>
        )}
        {fence !== null && <IdPFenceCallout refusal={fence} />}
        {refusal !== null && <IdPRefusalCallout refusal={refusal} />}
        {unproven !== null && (
          <IdPUnprovenCallout
            action={unproven.action}
            status={unproven.status}
          />
        )}
        {forbidden !== null && (
          <Callout
            variant="warning"
            title="Refused — insufficient role"
            role="alert"
          >
            The appliance refused to {forbidden} (HTTP 403); nothing was
            changed.
          </Callout>
        )}
        {isAdmin && recovery.kind === "valid" && (
          <Callout
            variant="unknown"
            title="Unresolved provider operation"
            role="alert"
          >
            <p>
              {recovery.marker.action === "import"
                ? "An import"
                : `A ${recovery.marker.action}`}{" "}
              of <strong>{recovery.marker.name}</strong> (
              <Mono>{recovery.marker.type}</Mono>
              {recovery.marker.cutover ? ", carrying the legacy cutover" : ""})
              was dispatched as operation{" "}
              <Mono>{recovery.marker.operationId}</Mono> and its answer was not
              verified. Every mutation stays blocked until the appliance's
              ledger settles it; nothing is re-sent automatically.
            </p>
            <div>
              <Button
                size="sm"
                variant="primary"
                disabled={recoveryView.kind === "looking"}
                onClick={() => void recover(recovery.marker)}
              >
                Recover
              </Button>{" "}
              {recoveryView.kind === "never_recorded" && (
                <>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => resend(recovery.marker)}
                  >
                    Re-send
                  </Button>{" "}
                </>
              )}
              {(recoveryView.kind === "never_recorded" ||
                (recoveryView.kind === "op" &&
                  recoveryView.op.state === "aborted")) && (
                <Button
                  size="sm"
                  variant="danger-quiet"
                  onClick={() =>
                    setCeremony({ kind: "abandon", marker: recovery.marker })
                  }
                >
                  Abandon
                </Button>
              )}
            </div>
            <div>
              {recoveryView.kind === "looking" && "Looking the operation up…"}
              {recoveryView.kind === "op" &&
                operationStateView(recoveryView.op)}
              {recoveryView.kind === "never_recorded" && (
                <span>
                  The appliance never recorded this operation: the write did not
                  start. The same candidate may be re-sent under the same
                  operation identity, or the marker abandoned.
                </span>
              )}
              {recoveryView.kind === "refused" && (
                <StatusBadge status="unknown">
                  Lookup refused: {recoveryView.code}
                </StatusBadge>
              )}
              {recoveryView.kind === "unproven" && (
                <StatusBadge status="unknown">
                  Lookup outcome unproven — try Recover again
                </StatusBadge>
              )}
            </div>
          </Callout>
        )}
        {isAdmin && recovery.kind === "none" && recoveryView.kind === "op" && (
          <Callout
            variant="success"
            title="Operation resolved from the appliance's ledger"
            role="status"
          >
            <Mono>{recoveryView.op.operationId}</Mono> ·{" "}
            {operationStateView(recoveryView.op)}
          </Callout>
        )}
        {isAdmin &&
          (recovery.kind === "unavailable" ||
            recovery.kind === "unreadable") && (
            <Callout
              variant="unknown"
              title="Recovery marker store unusable"
              role="alert"
            >
              This browser cannot{" "}
              {recovery.kind === "unavailable" ? "reach" : "read"} its operation
              recovery store, so no provider write is dispatched from it.
            </Callout>
          )}
        {snap === undefined && registry.isPending && (
          <Skeleton>Loading the identity-provider registry…</Skeleton>
        )}
        {snap === undefined && registry.isError && (
          <ErrorState title="Identity-provider registry unavailable">
            {readErrorSummary(registry.error, "identity-provider registry")}
          </ErrorState>
        )}
        {snap !== undefined && (
          <>
            {snap.list.degraded && snap.list.degradedReason !== undefined && (
              <Callout
                variant="critical"
                title="Registry degraded"
                role="alert"
              >
                Reason: <Mono>{snap.list.degradedReason}</Mono>. Quarantine
                evidence:{" "}
                {snap.list.quarantineEvidence !== undefined
                  ? "recorded"
                  : "not recorded"}
                . The registry is empty and refuses changes until it is repaired
                (server posture).{" "}
                {isAdmin && snap.list.quarantineEvidence !== undefined && (
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={
                      !isAdmin || page.unknown !== null || result === "pending"
                    }
                    onClick={() => {
                      clearOutcome();
                      setCeremony({
                        kind: "repair",
                        evidence: snap.list.quarantineEvidence ?? "",
                      });
                    }}
                  >
                    Repair registry
                  </Button>
                )}
              </Callout>
            )}
            <RegistryCard list={snap.list} />
            <ProvidersCard snap={snap} actions={rowActions} />
            <LedgerCard list={snap.list} />
          </>
        )}
        {legacy.data === undefined && legacy.isPending && (
          <Skeleton>Loading the legacy YAML LDAP posture…</Skeleton>
        )}
        {legacy.data === undefined && legacy.isError && (
          <ErrorState title="Legacy YAML LDAP posture unavailable">
            {readErrorSummary(legacy.error, "legacy LDAP read model")}
          </ErrorState>
        )}
        {legacy.data !== undefined && (
          <LegacyCard
            legacy={legacy.data}
            isAdmin={isAdmin}
            ledgerKey={ledgerKeyFor(legacy.data)}
            onImport={
              isAdmin &&
              legacy.data.present &&
              canMutate &&
              legacy.data.importSourceRevision !== IMPORT_SOURCE_UNAVAILABLE
                ? () => {
                    clearOutcome();
                    if (legacy.data?.present === true)
                      setCeremony({ kind: "import", legacy: legacy.data });
                  }
                : null
            }
          />
        )}
      </div>
      {guard.element}
      {ceremony.kind === "editor" && (
        <ProviderEditorDialog
          mode={ceremony.mode}
          initial={ceremony.initial}
          draft={ceremony.draft}
          onChange={(d) => setCeremony({ ...ceremony, draft: d, error: null })}
          onReview={review}
          onCancel={close}
          pending={result === "pending"}
          error={ceremony.error}
          test={test}
          onTest={(cred) => void runTest(cred)}
          discover={discover}
          onDiscover={(issuer) => void runDiscover(issuer)}
        />
      )}
      {ceremony.kind === "review" && (
        <ReviewCeremony
          mode={ceremony.mode}
          initial={ceremony.initial}
          spec={ceremony.spec}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() =>
            void dispatchWrite(
              ceremony.mode,
              ceremony.initial,
              ceremony.spec,
              ceremony.draft,
              ceremony.operationId,
              undefined,
            )
          }
          onCancel={() =>
            setCeremony({
              kind: "editor",
              mode: ceremony.mode,
              initial: ceremony.initial,
              draft: ceremony.draft,
              base: draftFrom(ceremony.initial),
              error: null,
            })
          }
        />
      )}
      {ceremony.kind === "cutover" && (
        <CutoverCeremony
          spec={ceremony.spec}
          initial={ceremony.initial}
          fence={
            ceremony.mode === "create"
              ? (snap?.list.revision ?? "")
              : String(ceremony.initial?.revision ?? 0)
          }
          operationId={ceremony.operationId}
          legacy={ceremony.legacy}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() =>
            void dispatchWrite(
              ceremony.mode,
              ceremony.initial,
              ceremony.spec,
              ceremony.draft,
              ceremony.operationId,
              ceremony.legacy.cutoverConfirmValue,
            )
          }
          onCancel={() =>
            setCeremony({
              kind: "editor",
              mode: ceremony.mode,
              initial: ceremony.initial,
              draft: ceremony.draft,
              base: draftFrom(ceremony.initial),
              error: null,
            })
          }
        />
      )}
      {ceremony.kind === "delete" && (
        <DeleteProviderCeremony
          profile={ceremony.profile}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() => void runDelete(ceremony.profile)}
          onCancel={close}
        />
      )}
      {ceremony.kind === "repair" && (
        <RepairCeremony
          evidence={ceremony.evidence}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() => void runRepair(ceremony.evidence)}
          onCancel={close}
        />
      )}
      {ceremony.kind === "import" && (
        <ImportCeremony
          legacy={ceremony.legacy}
          {...(ceremony.boundOperationId !== undefined
            ? { boundOperationId: ceremony.boundOperationId }
            : {})}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() => void runImport()}
          onCancel={close}
        />
      )}
      {ceremony.kind === "abandon" && (
        <AbandonCeremony
          marker={ceremony.marker}
          result={result}
          onConfirm={() => abandon(ceremony.marker)}
          onCancel={close}
        />
      )}
    </>
  );
}
