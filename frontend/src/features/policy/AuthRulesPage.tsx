// 2C.2/2C.3 — Authentication Rules (Stage-1). A DEDICATED surface for the
// auth rulebase (/api/authpolicy): viewer+ read; ADMIN-only writes — the
// backend is deliberately stricter than the Stage-2 operator surface and this
// page never renders a control the server would refuse (§10).
//
// Domain truth (§2): Stage-1 rules affect the RUNNING policy immediately.
// Nothing here stages into the Access-Policy Draft, Require Commit is never
// mentioned as governing these writes, and every mutation is fenced on the
// RUNNING generation served by GET /api/authpolicy. When an Access-Policy
// Draft is active, the editor warns (§9) that saving invalidates that draft's
// baseline — the DraftBar on the Access Rules page then reports baseStale.
//
// Exempt is NOT Allow (§12): the server's contract note renders verbatim,
// and the Exempt outcome is presented as a warning-class waiver — never with
// green "allowed" semantics.
import { useEffect, useMemo, useState, type JSX, type ReactNode } from "react";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  ErrorState,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { SnapshotBar } from "../../shared/snapshot";
import type { AuthRuleView, AuthRuleWrite } from "../../api/policyAuth";
import {
  authRuleEditable,
  createAuthRule,
  deleteAuthRule,
  reorderAuthRules,
  updateAuthRule,
} from "../../api/policyAuth";
import {
  asPolicyConflict,
  getCategoryGroupNames,
  getURLCategoryNames,
} from "../../api/policyWrite";
import type { PolicyConflict } from "../../api/policyWrite";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import { AuthRuleEditor } from "./AuthRuleEditor";
import type { AuthRuleEditorMode } from "./AuthRuleEditor";
import { DefaultAuthOutcomeControl } from "./DefaultAuthOutcomeControl";
import { useAuthPolicyWrites } from "./useAuthPolicyWrites";
import styles from "./policy.module.css";

function outcomeBadge(rule: AuthRuleView): JSX.Element {
  const spec = rule.authSpec;
  if (spec === undefined) {
    return <StatusBadge status="neutral">no spec</StatusBadge>;
  }
  switch (spec.outcomeKnown) {
    case "Exempt":
      // A waiver, deliberately warning-class — never green "allowed".
      return <StatusBadge status="warn">Exempt</StatusBadge>;
    case "CredentialRequired":
      return <StatusBadge status="info">CredentialRequired</StatusBadge>;
    case "SSORequired":
      return <StatusBadge status="info">SSORequired</StatusBadge>;
    case null:
      return <StatusBadge status="neutral">{spec.outcome}</StatusBadge>;
  }
}

function subjectSummary(rule: AuthRuleView): string {
  const sm = rule.subjectMatch;
  if (sm === undefined) return "—";
  return sm.all
    .map((p) =>
      p.known ? p.values.join(", ") : `[unrecognized: ${p.type}]`,
    )
    .join(" AND ");
}

function authDestinationSummary(rule: AuthRuleView): string {
  const parts: string[] = [];
  if (rule.destFQDN !== "") parts.push(rule.destFQDN);
  if (rule.destCategory !== "") parts.push(`cat: ${rule.destCategory}`);
  if (rule.destCategoryGroup !== "")
    parts.push(`catgroup: ${rule.destCategoryGroup}`);
  if (parts.length === 0) {
    return rule.authSpec?.broadExemption === true
      ? "ALL destinations (broad exemption)"
      : "—";
  }
  return parts.join(" · ");
}

function AuthRuleDetail({
  r,
  danglingRefs,
}: {
  r: AuthRuleView;
  danglingRefs: readonly string[];
}): JSX.Element {
  const spec = r.authSpec;
  const items: Array<readonly [string, ReactNode]> = [
    ["Rule ID", r.id === "" ? "—" : <Mono key="id">{r.id}</Mono>],
    [
      "Source scope",
      r.subjectMatch === undefined ? (
        "—"
      ) : (
        <span key="sm">
          {subjectSummary(r)} (schema v
          {String(r.subjectMatch.schemaVersion)})
        </span>
      ),
    ],
    ["Protocol", spec?.protocol === "" || spec === undefined ? "any" : spec.protocol],
    ["Method", spec?.method === "" || spec === undefined ? "any" : spec.method],
    ["Owner", spec?.owner ?? "—"],
    ["Reason", spec?.reason ?? "—"],
    ["Expires", spec?.expiresAt === "" || spec === undefined ? "no expiry" : spec.expiresAt],
    [
      "Providers",
      spec === undefined || spec.providerRefs.length === 0 ? (
        spec?.outcomeKnown === "SSORequired" ? (
          "any compatible enabled interactive IdP"
        ) : (
          "—"
        )
      ) : (
        <span key="refs">
          {spec.providerRefs.map((ref) => (
            <span key={ref}>
              <Mono>{ref}</Mono>
              {danglingRefs.includes(ref) && (
                <StatusBadge status="warn">unresolved</StatusBadge>
              )}{" "}
            </span>
          ))}
        </span>
      ),
    ],
    ["Created", r.createdAt === "" ? "—" : r.createdAt],
    [
      "Modified",
      r.modifiedAt === ""
        ? "—"
        : `${r.modifiedAt}${r.modifiedBy !== "" ? ` by ${r.modifiedBy}` : ""}`,
    ],
    ["Comment", r.comment === "" ? "—" : r.comment],
  ];
  return (
    <div className={styles.rowDetail}>
      <dl className={styles.kvGrid}>
        {items.map(([k, v]) => (
          <div key={k}>
            <dt className={styles.refDetail}>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      {r.warnings.length > 0 && (
        <Callout variant="warning" title="Appliance risk flags">
          <ul>
            {r.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </Callout>
      )}
      {!authRuleEditable(r) && (
        <Callout variant="unknown" title="Read-only rule">
          This rule carries fields this console does not recognize (a newer
          outcome or subject predicate type). It stays enforced as stored, but
          it cannot be edited here — editing would destroy semantics this
          console cannot represent. It can still be deleted.
        </Callout>
      )}
    </div>
  );
}

export function AuthRulesPage(): JSX.Element {
  const ap = useAuthPolicyWrites();
  const q = ap.authQ;
  const snap = q.data;
  const { state } = useAuth();
  const isAdmin = hasRole(state.role ?? "viewer", "admin");
  const [openId, setOpenId] = useState<string | null>(null);

  // ── editor state ─────────────────────────────────────────────────────────
  const [editor, setEditor] = useState<AuthRuleEditorMode | null>(null);
  const [editorPending, setEditorPending] = useState(false);
  const [editorConflict, setEditorConflict] = useState<PolicyConflict | null>(
    null,
  );
  const [editorServerError, setEditorServerError] = useState("");
  const [editorDirty, setEditorDirty] = useState(false);

  // ── delete ceremony state ────────────────────────────────────────────────
  const [deleting, setDeleting] = useState<AuthRuleView | null>(null);
  const [deleteResult, setDeleteResult] = useState<ConfirmResult>("idle");
  const [deleteError, setDeleteError] = useState("");

  // ── staged reorder (2B model): LOCAL permutation until Apply ─────────────
  const [reorder, setReorder] = useState<readonly AuthRuleView[] | null>(null);
  const [reorderNotice, setReorderNotice] = useState("");
  const [reorderPending, setReorderPending] = useState(false);
  const [reorderAnnounce, setReorderAnnounce] = useState("");

  // Option sources for the editor (categories/groups + IdP providers).
  const wantOptions = editor !== null;
  const optQ = useQuery({
    queryKey: ["authpolicy", "rule-editor-options"],
    enabled: wantOptions,
    staleTime: Infinity,
    retry: false,
    queryFn: async ({ signal }) => {
      const [categories, categoryGroups] = await Promise.all([
        getURLCategoryNames(signal),
        getCategoryGroupNames(signal),
      ]);
      return { categories, categoryGroups };
    },
  });

  const closeAllWriteState = (): void => {
    setEditor(null);
    setEditorPending(false);
    setEditorConflict(null);
    setEditorServerError("");
    setEditorDirty(false);
    setDeleting(null);
    setDeleteResult("idle");
    setDeleteError("");
    setReorder(null);
    setReorderNotice("");
    setReorderPending(false);
    setReorderAnnounce("");
  };
  ap.setBoundaryCleanup(closeAllWriteState);

  // A fresh snapshot resolves a stale-version conflict for deliberate resubmit.
  useEffect(() => {
    setEditorConflict(null);
  }, [q.dataUpdatedAt]);

  const rules = useMemo(() => snap?.rules ?? [], [snap]);

  // Staged-reorder integrity: membership changed under the staging ⇒ discard
  // VISIBLY (never rebase automatically).
  useEffect(() => {
    if (reorder === null) return;
    const ids = new Set(rules.map((r) => r.id));
    const stale =
      reorder.length !== rules.length || reorder.some((r) => !ids.has(r.id));
    if (stale) {
      setReorder(null);
      setReorderNotice(
        "The auth rulebase changed while you were reordering. Review the current order and try again.",
      );
    }
  }, [rules, reorder]);

  const reorderChanged =
    reorder !== null &&
    (reorder.length !== rules.length ||
      reorder.some((r, i) => rules[i]?.id !== r.id));
  const guard = useDirtyGuard(
    editorDirty || reorderChanged,
    editorDirty
      ? "the unsaved authentication-rule changes in the editor"
      : "the staged authentication-rule reorder",
  );

  const blocked = ap.unknown !== null;
  const draftActive = ap.draftQ.data?.active === true;
  const providers = ap.providersQ.data?.profiles ?? [];
  const enabledInteractiveIds = new Set(
    providers.filter((p) => p.interactive && p.enabled).map((p) => p.id),
  );

  // ── mutation flows ───────────────────────────────────────────────────────
  const submitEditor = (write: AuthRuleWrite): void => {
    if (snap === undefined || editor === null) return;
    const version = snap.version;
    const signal = ap.owner.begin();
    setEditorPending(true);
    setEditorServerError("");
    const call =
      editor.kind === "create"
        ? createAuthRule(write, version, signal).then(() => undefined)
        : updateAuthRule(editor.rule.id, write, version, signal);
    call
      .then(() => {
        setEditor(null);
        setEditorDirty(false);
        setEditorConflict(null);
        ap.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          ap.latchUnknown(editor.kind === "create" ? "create" : "edit");
          return;
        }
        const conflict = asPolicyConflict(err);
        if (conflict !== null) {
          setEditorConflict(conflict);
          return;
        }
        setEditorServerError(
          serverErrorText(err, "The appliance rejected the rule."),
        );
      })
      .finally(() => {
        ap.owner.settle(signal);
        setEditorPending(false);
      });
  };

  const moveStaged = (fromIdx: number, toIdx: number): void => {
    if (reorder === null) return;
    if (toIdx < 0 || toIdx >= reorder.length || fromIdx === toIdx) return;
    const next = [...reorder];
    const moved = next.splice(fromIdx, 1)[0];
    if (moved === undefined) return;
    next.splice(toIdx, 0, moved);
    setReorder(next);
    setReorderAnnounce(
      `Rule ${moved.name} moved to position ${String(toIdx + 1)} of ${String(next.length)}. Staged locally — not applied yet.`,
    );
  };

  const applyReorder = (): void => {
    if (snap === undefined || reorder === null) return;
    const version = snap.version;
    const signal = ap.owner.begin();
    setReorderPending(true);
    setReorderNotice("");
    // Stable-ID shape (§16): every auth rule's ULID, in the new order.
    reorderAuthRules(
      reorder.map((r) => r.id),
      version,
      signal,
    )
      .then(() => {
        setReorder(null);
        setReorderAnnounce("");
        ap.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setReorder(null);
          setReorderAnnounce("");
          ap.latchUnknown("reorder");
          return;
        }
        const conflict = asPolicyConflict(err);
        if (conflict !== null) {
          setReorder(null);
          setReorderAnnounce("");
          setReorderNotice(
            "The auth rulebase changed while you were reordering. Review the current order and try again.",
          );
          ap.refetchAll();
          return;
        }
        setReorderNotice(
          serverErrorText(err, "The appliance refused the reorder."),
        );
      })
      .finally(() => {
        ap.owner.settle(signal);
        setReorderPending(false);
      });
  };

  const confirmDelete = (): void => {
    if (snap === undefined || deleting === null) return;
    const version = snap.version;
    const signal = ap.owner.begin();
    setDeleteResult("pending");
    deleteAuthRule(deleting.id, version, signal)
      .then(() => {
        setDeleting(null);
        setDeleteResult("idle");
        setDeleteError("");
        ap.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setDeleting(null);
          setDeleteResult("idle");
          ap.latchUnknown("delete");
          return;
        }
        const conflict = asPolicyConflict(err);
        setDeleteResult("failed");
        setDeleteError(
          conflict !== null
            ? conflict.error
            : serverErrorText(err, "The appliance refused the delete."),
        );
      })
      .finally(() => {
        ap.owner.settle(signal);
      });
  };

  const displayRules = reorder ?? rules;

  return (
    <>
      <PageHeader
        title="Authentication Rules"
        subtitle="Stage-1 authentication policy — decides HOW a client must authenticate (or is exempted) BEFORE Stage-2 access policy decides WHAT it may reach. Changes are live immediately."
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={snap !== undefined}
            onRefresh={ap.refreshToResolve}
          />
        }
      />
      <span role="status" aria-live="polite" className={styles.srOnly}>
        {reorderAnnounce}
      </span>

      {ap.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the change may or may not have been applied. Refresh the rulebase
            and review the current state before making further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={ap.refreshToResolve}>
                Refresh rulebase
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {reorderNotice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Reorder not applied" role="alert">
            {reorderNotice}
          </Callout>
        </div>
      )}

      <DefaultAuthOutcomeControl
        isAdmin={isAdmin}
        blocked={blocked}
        owner={ap.owner}
      />

      {snap !== undefined && snap.note !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="info" title="Exempt is not Allow">
            {snap.note}
          </Callout>
        </div>
      )}

      {snap === undefined && q.isPending && <Skeleton>Loading rules…</Skeleton>}
      {snap === undefined && q.isError && (
        <ErrorState title="Auth rulebase unavailable">
          The authentication-policy snapshot could not be loaded. Refresh to
          try again.
        </ErrorState>
      )}

      {snap !== undefined && (
        <>
          <div className={styles.toolbar}>
            {isAdmin && reorder === null && (
              <div className={styles.toolbarActions}>
                <Button
                  disabled={blocked}
                  onClick={() => {
                    setEditor({ kind: "create" });
                    setEditorConflict(null);
                    setEditorServerError("");
                  }}
                >
                  New authentication rule…
                </Button>
                <Button
                  variant="ghost"
                  disabled={blocked || rules.length < 2}
                  onClick={() => {
                    setReorder(rules);
                    setReorderNotice("");
                  }}
                >
                  Reorder rules…
                </Button>
              </div>
            )}
            {isAdmin && reorder !== null && (
              <div className={styles.toolbarActions}>
                {reorderChanged && (
                  <StatusBadge status="warn">Reorder staged</StatusBadge>
                )}
                <Button
                  disabled={blocked || !reorderChanged || reorderPending}
                  onClick={applyReorder}
                >
                  Apply reorder (live)
                </Button>
                <Button
                  variant="ghost"
                  disabled={reorderPending}
                  onClick={() => {
                    setReorder(null);
                    setReorderNotice("");
                    setReorderAnnounce("");
                  }}
                >
                  Discard reorder
                </Button>
              </div>
            )}
            <span className={styles.counts}>
              {String(rules.length)} authentication{" "}
              {rules.length === 1 ? "rule" : "rules"}
            </span>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">
                Authentication rules in evaluation order
              </caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Details" />
                  <th scope="col" className={styles.numeric}>
                    Priority
                  </th>
                  <th scope="col">Name</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Source scope</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Flags</th>
                  {isAdmin && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {displayRules.length === 0 && (
                  <tr>
                    <td colSpan={isAdmin ? 10 : 9}>
                      No authentication rules are defined. Every request
                      follows the global default authentication above.
                    </td>
                  </tr>
                )}
                {displayRules.map((r, idx) => {
                  const rowKey = r.id !== "" ? r.id : `p${String(r.priority)}`;
                  const open = openId === rowKey;
                  const staging = reorder !== null;
                  const last = displayRules.length - 1;
                  const editable = authRuleEditable(r);
                  const dangling = (r.authSpec?.providerRefs ?? []).filter(
                    (ref) => !enabledInteractiveIds.has(ref),
                  );
                  return (
                    <AuthRuleRowGroup
                      key={rowKey}
                      r={r}
                      open={open}
                      danglingRefs={
                        ap.providersQ.data !== undefined ? dangling : []
                      }
                      onToggle={() => {
                        setOpenId(open ? null : rowKey);
                      }}
                      isAdmin={isAdmin}
                      actions={
                        isAdmin && staging ? (
                          <span className={styles.rowActions}>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={idx === 0 || reorderPending}
                              aria-label={`Move rule ${r.name} up`}
                              onClick={() => {
                                moveStaged(idx, idx - 1);
                              }}
                            >
                              ↑
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={idx === last || reorderPending}
                              aria-label={`Move rule ${r.name} down`}
                              onClick={() => {
                                moveStaged(idx, idx + 1);
                              }}
                            >
                              ↓
                            </Button>
                          </span>
                        ) : isAdmin ? (
                          <span className={styles.rowActions}>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={blocked || !editable}
                              title={
                                editable
                                  ? undefined
                                  : "This rule carries unrecognized fields and is read-only here."
                              }
                              onClick={() => {
                                if (!editable) return;
                                setEditor({ kind: "edit", rule: r });
                                setEditorConflict(null);
                                setEditorServerError("");
                              }}
                            >
                              Edit
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={blocked}
                              onClick={() => {
                                setDeleting(r);
                                setDeleteResult("idle");
                                setDeleteError("");
                              }}
                            >
                              Delete
                            </Button>
                          </span>
                        ) : undefined
                      }
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {editor !== null && isAdmin && (
        <AuthRuleEditor
          mode={editor}
          options={{
            categories: optQ.data?.categories ?? [],
            categoryGroups: optQ.data?.categoryGroups ?? [],
            providers,
          }}
          exemptNote={snap?.note ?? ""}
          draftActive={draftActive}
          blocked={blocked}
          pending={editorPending}
          conflict={editorConflict}
          serverError={editorServerError}
          onSubmit={submitEditor}
          onCancel={() => {
            setEditor(null);
            setEditorDirty(false);
            setEditorConflict(null);
            setEditorServerError("");
          }}
          onDirtyChange={setEditorDirty}
        />
      )}

      {deleting !== null && isAdmin && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Delete authentication rule: ${deleting.name}`}
          body={
            <>
              This deletes the {deleting.authSpec?.outcome ?? "authentication"}{" "}
              rule <strong>{deleting.name}</strong> (source{" "}
              {subjectSummary(deleting)} → {authDestinationSummary(deleting)}).
              The deletion takes effect IMMEDIATELY in the running policy:
              matching clients revert to lower-priority rules or the global
              default authentication.
            </>
          }
          impact="Live Stage-1 behavior changes the moment this is confirmed."
          rollback="Re-create the rule (its stable ID will differ), or restore a config version."
          confirmLabel="Delete rule"
          destructive
          result={deleteResult}
          errorText={deleteError}
          onConfirm={() => {
            if (deleteResult !== "pending") confirmDelete();
          }}
          onCancel={() => {
            if (deleteResult !== "pending") {
              setDeleting(null);
              setDeleteResult("idle");
              setDeleteError("");
            }
          }}
        />
      )}
      {guard.element}
    </>
  );
}

function AuthRuleRowGroup({
  r,
  open,
  danglingRefs,
  onToggle,
  isAdmin,
  actions,
}: {
  r: AuthRuleView;
  open: boolean;
  danglingRefs: readonly string[];
  onToggle: () => void;
  isAdmin: boolean;
  actions: ReactNode;
}): JSX.Element {
  const flagCount = r.warnings.length + danglingRefs.length;
  return (
    <>
      <tr>
        <td>
          <Button
            size="sm"
            variant="ghost"
            aria-expanded={open}
            aria-label={`Details for rule ${r.name}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </Button>
        </td>
        <td className={styles.numeric}>{r.priority}</td>
        <td>{r.name}</td>
        <td>
          {r.enabled ? (
            <StatusBadge status="ok">on</StatusBadge>
          ) : (
            <StatusBadge status="neutral">off</StatusBadge>
          )}
        </td>
        <td>{outcomeBadge(r)}</td>
        <td>{subjectSummary(r)}</td>
        <td>{authDestinationSummary(r)}</td>
        <td>{r.authSpec?.owner ?? "—"}</td>
        <td>
          {flagCount > 0 ? (
            <StatusBadge status="warn">
              {String(flagCount)} {flagCount === 1 ? "flag" : "flags"}
            </StatusBadge>
          ) : (
            "—"
          )}
        </td>
        {isAdmin && <td>{actions}</td>}
      </tr>
      {open && (
        <tr>
          <td colSpan={isAdmin ? 10 : 9}>
            <AuthRuleDetail r={r} danglingRefs={danglingRefs} />
          </td>
        </tr>
      )}
    </>
  );
}
