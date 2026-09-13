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
import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../layouts/AppShell";
import {
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
import { DataTable } from "../../design-system/table";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { readErrorSummary, refusalCodeOf } from "../../shared/readErrorSummary";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { ApiError } from "../../api/client";
import {
  IDP_LOOKUP_REFUSAL_CODES,
  getIdPList,
  getIdPOperation,
  getIdPReferences,
  getLegacyLDAP,
} from "../../api/idp";
import type {
  IdPList,
  IdPOperation,
  IdPProfile,
  LegacyLDAP,
} from "../../api/idp";
import type { ObjectRefConsumer } from "../../api/policy";
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

function ProvidersCard({ snap }: { snap: RegistrySnapshot }): JSX.Element {
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
}: {
  legacy: LegacyLDAP;
  isAdmin: boolean;
  ledgerKey: LedgerKey;
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
    items.push(["Bind DN", <Mono key="bind">{legacy.bindDn}</Mono>]);
    items.push([
      "Write-only material",
      `Bind credential: ${legacy.bindCredentialConfigured ? "configured" : "not configured"}`,
    ]);
  }
  items.push(["Legacy authority", legacy.retired ? "Retired" : "Not retired"]);
  items.push(["Authority cutover", durabilityBadge(legacy)]);
  const c = legacy.cutover;
  return (
    <Card title="Legacy YAML LDAP">
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
export function IdentityProvidersPage(): JSX.Element {
  const { state } = useAuth();
  const isAdmin = hasRole(state.role ?? "viewer", "admin");
  const registry = useSnapshot(["objects", "idp", "registry"], fetchRegistry);
  const legacy = useSnapshot(["objects", "idp", "legacy-ldap"], getLegacyLDAP);
  const snap = registry.data;
  const ledgerKeyFor = (l: LegacyLDAP): LedgerKey => {
    if (snap === undefined) return { kind: "registry_unavailable" };
    const key = snap.list.profiles.find(
      (p) => p.id === l.cutover?.profileId,
    )?.operationId;
    return key !== undefined
      ? { kind: "known", operationId: key }
      : { kind: "absent" };
  };
  return (
    <>
      <PageHeader
        title="Identity Providers"
        subtitle="Registry read model — identity, state, revisions, fleet publication and the legacy LDAP cutover posture (read-only)"
        actions={
          <SnapshotBar
            updatedAt={Math.max(registry.dataUpdatedAt, legacy.dataUpdatedAt)}
            fetching={registry.isFetching || legacy.isFetching}
            error={registry.isError || legacy.isError}
            hasData={snap !== undefined || legacy.data !== undefined}
            onRefresh={() => {
              void registry.refetch();
              void legacy.refetch();
            }}
          />
        }
      />
      <div className={styles.stack}>
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
                (server posture).
              </Callout>
            )}
            <RegistryCard list={snap.list} />
            <ProvidersCard snap={snap} />
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
          />
        )}
      </div>
    </>
  );
}
