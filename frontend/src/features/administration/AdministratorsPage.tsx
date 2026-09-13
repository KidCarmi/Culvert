// FE-6A.1 — Administrators (FE-V37) READ surface at /administrators
// (admin only: uiRoutes GET /api/auth/users = admin, GET /api/auth/lockouts =
// admin — the server is the role authority; a 403 renders as a bounded state).
//
// READ-ONLY by directive: no create / update / delete / password / TOTP /
// lockout-reset control is rendered — not even a disabled one; Refresh is the
// only control. Every fact is the server's:
//   • roster (node-local): authoritative username and DURABLE role, per-user
//     security generation (the session-binding fact: a role or credential
//     change advances it inside the roster commit and invalidates sessions
//     issued under the previous value), TOTP enrollment PRESENCE (never the
//     seed), the roster revision;
//   • derived over the roster only: administrator count and the last-admin
//     posture (exactly one admin — the appliance refuses demoting or
//     deleting it);
//   • login lock set (node-local): tier, username, source IP, seconds
//     remaining, the lock-set generation.
// The roster and the lock set are INDEPENDENT snapshots: a failed lockouts
// read never blanks the roster and never renders as "no lockouts".
// Recorded backend truth gaps (not patched with copy): the roster read model
// carries neither a persistence posture nor the legacy single-user mirror
// identity; neither is rendered.
import type { JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import {
  Card,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { DataTable } from "../../design-system/table";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { readErrorSummary } from "../../shared/readErrorSummary";
import { ApiError } from "../../api/client";
import { getAdminRoster, getLockouts, rosterFacts } from "../../api/admins";
import type { AdminUser, Lockout } from "../../api/admins";
import styles from "../diagnostics/diagnostics.module.css";

function forbiddenOr(err: unknown, what: string): string {
  if (err instanceof ApiError && err.forbidden) {
    return `This surface requires the admin role; the appliance refused the ${what} read (HTTP 403).`;
  }
  return readErrorSummary(err, what);
}

export function AdministratorsPage(): JSX.Element {
  const roster = useSnapshot(["administration", "roster"], getAdminRoster);
  const locks = useSnapshot(["administration", "lockouts"], getLockouts);
  const r = roster.data;
  const facts = r !== undefined ? rosterFacts(r) : undefined;
  return (
    <>
      <PageHeader
        title="Administrators"
        subtitle="Node-local admin roster and login lock set (read-only)"
        actions={
          <SnapshotBar
            updatedAt={roster.dataUpdatedAt}
            fetching={roster.isFetching || locks.isFetching}
            error={roster.isError || locks.isError}
            hasData={r !== undefined}
            onRefresh={() => {
              void roster.refetch();
              void locks.refetch();
            }}
          />
        }
      />
      {r === undefined && roster.isPending && (
        <Skeleton>Loading the admin roster…</Skeleton>
      )}
      {r === undefined && roster.isError && (
        <ErrorState title="Administrators roster unavailable">
          {forbiddenOr(roster.error, "admin roster")}
        </ErrorState>
      )}
      {r !== undefined && facts !== undefined && (
        <div className={styles.stack}>
          <Card title="Roster">
            <KeyValue
              items={[
                [
                  "Scope",
                  <StatusBadge key="scope" status="info">
                    Node-local
                  </StatusBadge>,
                ],
                ["Revision", `Roster revision ${String(r.revision)}`],
                ["Accounts", String(facts.total)],
                [
                  "Administrators",
                  `${String(facts.adminCount)} administrator account${facts.adminCount === 1 ? "" : "s"}`,
                ],
                [
                  "Administrator posture",
                  // Three EXPLICIT states (correction, blocker 5) — the read
                  // model never assumes the backend's at-least-one-admin rule.
                  facts.posture === "none" ? (
                    <StatusBadge status="critical">
                      No administrator accounts
                    </StatusBadge>
                  ) : facts.posture === "last_admin" ? (
                    <StatusBadge status="warn">
                      Last admin: {facts.lastAdmin ?? ""} — the appliance
                      refuses demoting or deleting it
                    </StatusBadge>
                  ) : (
                    "More than one administrator"
                  ),
                ],
                [
                  "Sessions",
                  "Bound to each account's security generation; a role or credential change advances it and invalidates sessions issued under the previous value",
                ],
              ]}
            />
            <DataTable
              caption="Administrator accounts"
              columns={[
                {
                  key: "u",
                  header: "Username",
                  render: (u: AdminUser) => u.username,
                },
                {
                  key: "r",
                  header: "Role",
                  render: (u) => <Mono>{u.role}</Mono>,
                },
                {
                  key: "g",
                  header: "Security generation",
                  numeric: true,
                  render: (u) => String(u.securityGeneration),
                },
                {
                  key: "t",
                  header: "TOTP",
                  render: (u) =>
                    u.totpEnabled ? "configured" : "not configured",
                },
              ]}
              rows={r.users}
              rowKey={(u) => u.username}
            />
          </Card>
          <Card title="Login lockouts">
            {locks.data === undefined && locks.isPending && (
              <Skeleton>Loading the lock set…</Skeleton>
            )}
            {locks.data === undefined && locks.isError && (
              <ErrorState title="Lockouts unavailable">
                {forbiddenOr(locks.error, "lock set")}
              </ErrorState>
            )}
            {locks.data !== undefined && (
              <>
                <KeyValue
                  items={[
                    [
                      "Scope",
                      <StatusBadge key="scope" status="info">
                        Node-local
                      </StatusBadge>,
                    ],
                    [
                      "Generation",
                      `Lock-set generation ${String(locks.data.generation)}`,
                    ],
                  ]}
                />
                {locks.data.lockouts.length === 0 ? (
                  <EmptyState title="No active lockouts" />
                ) : (
                  <DataTable
                    caption="Active login lockouts"
                    columns={[
                      {
                        key: "tier",
                        header: "Tier",
                        render: (l: Lockout) => <Mono>{l.tier}</Mono>,
                      },
                      {
                        key: "u",
                        header: "Username",
                        render: (l) => l.username,
                      },
                      {
                        key: "ip",
                        header: "Source IP",
                        render: (l) => l.ip ?? "—",
                      },
                      {
                        key: "s",
                        header: "Seconds remaining",
                        numeric: true,
                        render: (l) => String(l.secondsRemaining),
                      },
                    ]}
                    rows={locks.data.lockouts}
                    rowKey={(l) => `${l.tier}:${l.username}:${l.ip ?? ""}`}
                  />
                )}
              </>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
