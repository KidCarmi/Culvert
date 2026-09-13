// FE-6A.1 read surface + FE-6A.2 WRITE surface for the node-local admin
// roster and login lock set (admin-only route; GET /api/auth/users and
// /api/auth/lockouts = admin). Writes: create / update / delete an account
// under the roster revision fence, clear a lockout under the lock-set
// generation, and the self-service password change (fenced on the caller's
// security generation). A mutation that reports selfAffected:true completes
// the auth teardown — nothing privileged stays visible.
import { useState } from "react";
import type { JSX } from "react";
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
} from "../../design-system/primitives";
import type { ConfirmResult } from "../../design-system/dialog";
import { DataTable } from "../../design-system/table";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import { readErrorSummary } from "../../shared/readErrorSummary";
import { useAuth } from "../../auth/AuthProvider";
import { ApiError } from "../../api/client";
import {
  asAdminRefusal,
  clearLockout,
  createAdminUser,
  deleteAdminUser,
  getAdminRoster,
  getLockouts,
  rosterFacts,
  updateAdminUser,
} from "../../api/admins";
import type { AdminRefusal, AdminUser, Lockout } from "../../api/admins";
import { useObjectPage } from "../objects/useObjectPage";
import {
  AccountEditorDialog,
  AccountReviewCeremony,
  AdminFenceCallout,
  AdminRefusalCallout,
  AdminUnprovenCallout,
  ClearLockoutCeremony,
  DeleteAccountCeremony,
  draftFromUser,
  draftToCandidate,
} from "./adminWrites";
import type { AccountCandidate, AccountDraft } from "./adminWrites";
import { ChangePasswordDialog } from "./ChangePasswordDialog";
import styles from "../diagnostics/diagnostics.module.css";

function forbiddenOr(err: unknown, what: string): string {
  if (err instanceof ApiError && err.forbidden) {
    return `This surface requires the admin role; the appliance refused the ${what} read (HTTP 403).`;
  }
  return readErrorSummary(err, what);
}

type Ceremony =
  | { kind: "closed" }
  | {
      kind: "editor";
      mode: "create" | "edit";
      initial: AdminUser | null;
      draft: AccountDraft;
      error: string | null;
    }
  | {
      kind: "review";
      mode: "create" | "edit";
      initial: AdminUser | null;
      candidate: AccountCandidate;
      draft: AccountDraft;
    }
  | { kind: "delete"; user: AdminUser }
  | { kind: "clear"; lock: Lockout; generation: number }
  | { kind: "password" };

export function AdministratorsPage(): JSX.Element {
  const { state, machine } = useAuth();
  const authenticated = state.phase === "authenticated";
  const self = state.user;
  const page = useObjectPage(["administration", "roster"], getAdminRoster);
  const roster = page.q;
  const locks = useSnapshot(["administration", "lockouts"], getLockouts);
  const r = roster.data;
  const facts = r !== undefined ? rosterFacts(r) : undefined;

  const [ceremony, setCeremony] = useState<Ceremony>({ kind: "closed" });
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState<string | undefined>(undefined);
  const [notice, setNotice] = useState<string | null>(null);
  const [fence, setFence] = useState<AdminRefusal | null>(null);
  const [refusal, setRefusal] = useState<AdminRefusal | null>(null);
  const [unproven, setUnproven] = useState<{
    action: string;
    status: number | undefined;
  } | null>(null);
  const [forbidden, setForbidden] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);

  const dirty =
    ceremony.kind === "editor" &&
    (ceremony.draft.username !== (ceremony.initial?.username ?? "") ||
      ceremony.draft.role !== (ceremony.initial?.role ?? "viewer") ||
      ceremony.draft.password !== "");
  const guard = useDirtyGuard(dirty, "the account editor");

  const blocked = page.unknown !== null || signingOut;
  const canMutate = r !== undefined && !blocked && result !== "pending";

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
  };
  const refreshAll = (): void => {
    page.refreshToResolve();
    void locks.refetch();
  };
  const teardown = (why: string): void => {
    // selfAffected: the appliance revoked THIS session's authority; nothing
    // privileged may stay visible — complete the auth teardown now.
    setSigningOut(true);
    setNotice(why);
    void machine.logout();
  };
  const fail = (
    err: unknown,
    action: string,
    endpoint: Parameters<typeof asAdminRefusal>[1],
  ): void => {
    const f = asAdminRefusal(err, endpoint);
    if (f !== null) {
      close();
      if (f.code === "stale" || f.code === "precondition_required") setFence(f);
      else setRefusal(f);
      refreshAll();
      return;
    }
    if (err instanceof ApiError && err.forbidden) {
      close();
      setForbidden(action);
      refreshAll();
      return;
    }
    close();
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

  const runAccount = async (
    mode: "create" | "edit",
    candidate: AccountCandidate,
  ): Promise<void> => {
    if (r === undefined) return;
    clearOutcome();
    setResult("pending");
    const signal = page.owner.begin();
    try {
      if (mode === "create") {
        const out = await createAdminUser(
          {
            username: candidate.username,
            password: candidate.password ?? "",
            role: candidate.role,
          },
          r.revision,
          signal,
        );
        close();
        setNotice(
          `Account ${out.user.username} created (${out.user.role}, roster revision ${String(out.revision)})`,
        );
        refreshAll();
        return;
      }
      const out = await updateAdminUser(
        {
          username: candidate.username,
          ...(candidate.roleChanged ? { role: candidate.role } : {}),
          ...(candidate.password !== undefined
            ? { password: candidate.password }
            : {}),
        },
        r.revision,
        signal,
      );
      close();
      if (out.selfAffected) {
        teardown("Your own account changed — signing out.");
        return;
      }
      setNotice(
        `Account ${out.user.username} saved (${out.user.role}, security generation ${String(out.securityGeneration)}, roster revision ${String(out.revision)}). ${out.sessionsRevoked ? "Sessions revoked." : "No session was revoked."}`,
      );
      refreshAll();
    } catch (err) {
      fail(
        err,
        mode === "create" ? "create account" : "save account",
        mode === "create" ? "users.create" : "users.update",
      );
    } finally {
      page.owner.settle(signal);
    }
  };
  const runDelete = async (user: AdminUser): Promise<void> => {
    if (r === undefined) return;
    clearOutcome();
    setResult("pending");
    const signal = page.owner.begin();
    try {
      const out = await deleteAdminUser(user.username, r.revision, signal);
      close();
      if (out.selfAffected) {
        teardown("Your own account was deleted — signing out.");
        return;
      }
      setNotice(
        `Account ${out.username} deleted (roster revision ${String(out.revision)}). ${out.sessionsRevoked ? "Sessions revoked." : ""}`,
      );
      refreshAll();
    } catch (err) {
      fail(err, "delete account", "users.delete");
    } finally {
      page.owner.settle(signal);
    }
  };
  const runClear = async (lock: Lockout, generation: number): Promise<void> => {
    clearOutcome();
    setResult("pending");
    const signal = page.owner.begin();
    try {
      const out = await clearLockout(lock.username, generation, signal);
      close();
      setNotice(
        `Lockouts cleared for ${out.username} (lock-set generation ${String(out.generation)})`,
      );
      refreshAll();
    } catch (err) {
      fail(err, "clear lockouts", "lockouts.clear");
    } finally {
      page.owner.settle(signal);
    }
  };
  const review = (): void => {
    if (ceremony.kind !== "editor") return;
    const c = draftToCandidate(ceremony.draft, ceremony.mode, ceremony.initial);
    if (typeof c === "string") {
      setCeremony({ ...ceremony, error: c });
      return;
    }
    setCeremony({
      kind: "review",
      mode: ceremony.mode,
      initial: ceremony.initial,
      candidate: c,
      draft: ceremony.draft,
    });
  };

  if (!authenticated) {
    return (
      <>
        <PageHeader title="Administrators" subtitle="Signed out" />
        <Callout variant="info" role="status">
          {notice ?? "This session has ended; sign in again."}
        </Callout>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Administrators"
        subtitle="Node-local admin roster and login lock set; writes are fenced and ceremonied"
        actions={
          <>
            {r !== undefined && (
              <Button
                variant="primary"
                size="sm"
                disabled={!canMutate}
                onClick={() => {
                  clearOutcome();
                  setCeremony({
                    kind: "editor",
                    mode: "create",
                    initial: null,
                    draft: draftFromUser(null),
                    error: null,
                  });
                }}
              >
                Add account
              </Button>
            )}
            {r !== undefined && (
              <Button
                variant="secondary"
                size="sm"
                disabled={blocked || result === "pending"}
                onClick={() => {
                  clearOutcome();
                  setCeremony({ kind: "password" });
                }}
              >
                Change my password
              </Button>
            )}
            <SnapshotBar
              updatedAt={roster.dataUpdatedAt}
              fetching={roster.isFetching || locks.isFetching}
              error={roster.isError || locks.isError}
              hasData={r !== undefined}
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
        {fence !== null && <AdminFenceCallout refusal={fence} />}
        {refusal !== null && <AdminRefusalCallout refusal={refusal} />}
        {unproven !== null && (
          <AdminUnprovenCallout
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
        {r === undefined && roster.isPending && (
          <Skeleton>Loading the admin roster…</Skeleton>
        )}
        {r === undefined && roster.isError && (
          <ErrorState title="Administrators roster unavailable">
            {forbiddenOr(roster.error, "admin roster")}
          </ErrorState>
        )}
        {r !== undefined && facts !== undefined && !signingOut && (
          <>
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
                  {
                    key: "actions",
                    header: "Actions",
                    render: (u) => (
                      <span>
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={!canMutate}
                          onClick={() => {
                            clearOutcome();
                            setCeremony({
                              kind: "editor",
                              mode: "edit",
                              initial: u,
                              draft: draftFromUser(u),
                              error: null,
                            });
                          }}
                        >
                          Edit
                        </Button>{" "}
                        <Button
                          size="sm"
                          variant="danger-quiet"
                          disabled={!canMutate}
                          onClick={() => {
                            clearOutcome();
                            setCeremony({ kind: "delete", user: u });
                          }}
                        >
                          Delete
                        </Button>
                      </span>
                    ),
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
                        {
                          key: "actions",
                          header: "Actions",
                          render: (l) => {
                            const gen = locks.data?.generation;
                            return (
                              <Button
                                size="sm"
                                variant="secondary"
                                disabled={!canMutate || gen === undefined}
                                onClick={() => {
                                  if (gen === undefined) return;
                                  clearOutcome();
                                  setCeremony({
                                    kind: "clear",
                                    lock: l,
                                    generation: gen,
                                  });
                                }}
                              >
                                Clear
                              </Button>
                            );
                          },
                        },
                      ]}
                      rows={locks.data.lockouts}
                      rowKey={(l) => `${l.tier}:${l.username}:${l.ip ?? ""}`}
                    />
                  )}
                </>
              )}
            </Card>
          </>
        )}
      </div>
      {guard.element}
      {ceremony.kind === "editor" && r !== undefined && (
        <AccountEditorDialog
          mode={ceremony.mode}
          initial={ceremony.initial}
          draft={ceremony.draft}
          onChange={(d) => setCeremony({ ...ceremony, draft: d, error: null })}
          onReview={review}
          onCancel={close}
          pending={result === "pending"}
          error={ceremony.error}
          rosterRevision={r.revision}
        />
      )}
      {ceremony.kind === "review" && r !== undefined && (
        <AccountReviewCeremony
          mode={ceremony.mode}
          candidate={ceremony.candidate}
          initial={ceremony.initial}
          rosterRevision={r.revision}
          self={ceremony.candidate.username === self}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() => void runAccount(ceremony.mode, ceremony.candidate)}
          onCancel={() =>
            setCeremony({
              kind: "editor",
              mode: ceremony.mode,
              initial: ceremony.initial,
              draft: ceremony.draft,
              error: null,
            })
          }
        />
      )}
      {ceremony.kind === "delete" && r !== undefined && (
        <DeleteAccountCeremony
          user={ceremony.user}
          rosterRevision={r.revision}
          self={ceremony.user.username === self}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() => void runDelete(ceremony.user)}
          onCancel={close}
        />
      )}
      {ceremony.kind === "clear" && (
        <ClearLockoutCeremony
          lock={ceremony.lock}
          generation={ceremony.generation}
          result={result}
          {...(errorText !== undefined ? { errorText } : {})}
          onConfirm={() => void runClear(ceremony.lock, ceremony.generation)}
          onCancel={close}
        />
      )}
      {ceremony.kind === "password" && (
        <ChangePasswordDialog
          user={self}
          generation={state.securityGeneration}
          onCancel={close}
          onOutcome={(o) => {
            close();
            if (o.kind === "changed") {
              teardown(
                "Your password changed — every session of your account was revoked; signing out.",
              );
              return;
            }
            setUnproven({ action: "change my password", status: o.status });
            page.latchUnknown("edit");
            void machine.revalidateAuthenticatedSession();
          }}
        />
      )}
    </>
  );
}
