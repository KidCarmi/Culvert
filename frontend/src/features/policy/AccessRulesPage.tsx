// Access Rules (FE-V16): the Stage-2 rulebase. Slice 2A built the READ
// surface (server priority order, snapshot/refresh per ADR-FE-002, deep links
// by data equality); Slice 2B adds the WRITE surface — create/edit/delete
// through the fenced mutation contract (every mutation asserts ifVersion; the
// server checks + mutates atomically after 2B.0), with the 2A-M unknown-
// outcome doctrine at page level and a targeted dirty-route guard.
//
// RBAC: viewer mounts NO mutation controls (absent, not disabled); operator+
// gets create/edit/delete; the server stays authoritative (403 tests).
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
  type ReactNode,
  type Ref,
} from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
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
import { InputField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { isPlausibleRuleID } from "../../api/policy";
import type { PolicyRuleView, PolicySnapshot } from "../../api/policy";
import {
  asPolicyConflict,
  createRule,
  deleteRule,
  getCategoryGroupNames,
  getDecryptionProfileNames,
  getFileProfileNames,
  getURLCategoryNames,
  reorderRules,
  updateRule,
} from "../../api/policyWrite";
import type { AccessRuleWrite, PolicyConflict } from "../../api/policyWrite";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import { WhereUsed } from "./WhereUsed";
import { CommitReview } from "./CommitReview";
import { DefaultActionControl } from "./DefaultActionControl";
import { DraftBar } from "./DraftBar";
import { RuleEditor } from "./RuleEditor";
import type { RuleEditorMode } from "./RuleEditor";
import { useRulebaseWrites } from "./useRulebaseWrites";
import styles from "./policy.module.css";

function actionBadge(action: string): JSX.Element {
  const map: Record<string, "ok" | "critical" | "warn" | "info"> = {
    Allow: "ok",
    Drop: "critical",
    Block_Page: "critical",
    Redirect: "warn",
  };
  return <StatusBadge status={map[action] ?? "neutral"}>{action}</StatusBadge>;
}

function joinNonEmpty(parts: ReadonlyArray<readonly [string, string]>): string {
  const out = parts
    .filter(([, v]) => v !== "")
    .map(([k, v]) => (k === "" ? v : `${k} ${v}`));
  return out.length === 0 ? "—" : out.join(" · ");
}

function sourceSummary(r: PolicyRuleView): string {
  return joinNonEmpty([
    ["", r.sourceIP],
    ["id:", r.sourceIdentity],
    ["group:", r.sourceGroup],
    ["auth:", r.authSource],
  ]);
}

function destinationSummary(r: PolicyRuleView): string {
  return joinNonEmpty([
    ["", r.destFQDN],
    ["cat:", r.destCategory],
    ["catgroup:", r.destCategoryGroup],
    ["geo:", r.destCountry.join(",")],
  ]);
}

function tlsSummary(r: PolicyRuleView): string {
  return joinNonEmpty([
    ["", r.sslAction],
    ["profile:", r.decryptionProfile],
  ]);
}

function scheduleSummary(r: PolicyRuleView): string {
  const s = r.schedule;
  if (s === undefined) return "—";
  const days = s.days.length > 0 ? s.days.join(",") : "any day";
  const window =
    s.timeStart !== "" || s.timeEnd !== ""
      ? ` ${s.timeStart !== "" ? s.timeStart : "…"}–${s.timeEnd !== "" ? s.timeEnd : "…"}`
      : "";
  const tz = s.timezone !== "" ? ` (${s.timezone})` : "";
  return `${days}${window}${tz}`;
}

function ruleMatchesFilter(r: PolicyRuleView, needle: string): boolean {
  const n = needle.toLowerCase();
  return (
    r.name.toLowerCase().includes(n) ||
    r.id.toLowerCase().includes(n) ||
    r.action.toLowerCase().includes(n) ||
    sourceSummary(r).toLowerCase().includes(n) ||
    destinationSummary(r).toLowerCase().includes(n)
  );
}

function RuleDetail({ r }: { r: PolicyRuleView }): JSX.Element {
  const items: Array<readonly [string, ReactNode]> = [
    ["Rule ID", r.id === "" ? "—" : <Mono key="id">{r.id}</Mono>],
    ["Countries", r.destCountry.length === 0 ? "—" : r.destCountry.join(", ")],
    ["Category", r.destCategory === "" ? "—" : r.destCategory],
    [
      "Category group",
      r.destCategoryGroup === "" ? (
        "—"
      ) : (
        <span key="cg">
          {r.destCategoryGroup}
          {r.destCategoryGroupId !== "" && (
            <>
              {" "}
              <Mono>{r.destCategoryGroupId}</Mono>
            </>
          )}
        </span>
      ),
    ],
    [
      "File profile",
      r.fileProfile === ""
        ? r.fileFiltering
          ? "(file filtering on, default profile)"
          : "—"
        : r.fileProfile,
    ],
    [
      "Decryption profile",
      r.decryptionProfile === "" ? (
        "—"
      ) : (
        <span key="dp">
          {r.decryptionProfile}
          {r.decryptionProfileId !== "" && (
            <>
              {" "}
              <Mono>{r.decryptionProfileId}</Mono>
            </>
          )}
        </span>
      ),
    ],
    ["Redirect URL", r.redirectURL === "" ? "—" : r.redirectURL],
    ["Logging", logSummary(r)],
    ["Schedule", scheduleSummary(r)],
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
      <div className={styles.whereUsedBar}>
        {r.destCategory !== "" && (
          <WhereUsed type="category" name={r.destCategory} />
        )}
        {r.destCategoryGroup !== "" && (
          <WhereUsed type="category-group" name={r.destCategoryGroup} />
        )}
        {r.fileProfile !== "" && (
          <WhereUsed type="file-profile" name={r.fileProfile} />
        )}
        {r.decryptionProfile !== "" && (
          <WhereUsed type="decryption-profile" name={r.decryptionProfile} />
        )}
      </div>
    </div>
  );
}

function logSummary(r: PolicyRuleView): string {
  return r.logFullUri ? "full URI" : "standard";
}

export function AccessRulesPage(): JSX.Element {
  const rb = useRulebaseWrites();
  const q = rb.policyQ;
  const snap: PolicySnapshot | undefined = q.data;
  const { state } = useAuth();
  const canWrite = hasRole(state.role ?? "viewer", "operator");
  const isAdmin = hasRole(state.role ?? "viewer", "admin");
  const [filter, setFilter] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
  const ruleParam = searchParams.get("rule") ?? "";

  // ── editor state ─────────────────────────────────────────────────────────
  const [editor, setEditor] = useState<RuleEditorMode | null>(null);
  const [editorPending, setEditorPending] = useState(false);
  const [editorConflict, setEditorConflict] = useState<PolicyConflict | null>(
    null,
  );
  const [editorServerError, setEditorServerError] = useState("");
  const [editorDirty, setEditorDirty] = useState(false);

  // ── delete ceremony state ────────────────────────────────────────────────
  const [deleting, setDeleting] = useState<PolicyRuleView | null>(null);
  const [deleteResult, setDeleteResult] = useState<ConfirmResult>("idle");
  const [deleteError, setDeleteError] = useState("");

  // ── staged reorder (§22): LOCAL permutation, no server mutation until
  // Apply; never persisted; cleared at the auth boundary. While staged,
  // create/edit/delete on this view are blocked so nothing composes against
  // a permutation the server does not know.
  const [reorder, setReorder] = useState<readonly PolicyRuleView[] | null>(
    null,
  );
  const [reorderNotice, setReorderNotice] = useState("");
  const [reorderPending, setReorderPending] = useState(false);
  const [reorderAnnounce, setReorderAnnounce] = useState("");

  // ── commit review (2B.5) ─────────────────────────────────────────────────
  const [commitOpen, setCommitOpen] = useState(false);

  // Reference option sources (§12): loaded once a write control asks for the
  // editor; read-only, never managed here.
  const wantOptions = editor !== null;
  const optQ = useQuery({
    queryKey: ["policy", "rule-editor-options"],
    enabled: wantOptions,
    staleTime: Infinity,
    retry: false,
    queryFn: async ({ signal }) => {
      const [categories, categoryGroups, fileProfiles, decryptionProfiles] =
        await Promise.all([
          getURLCategoryNames(signal),
          getCategoryGroupNames(signal),
          getFileProfileNames(signal),
          getDecryptionProfileNames(signal),
        ]);
      return { categories, categoryGroups, fileProfiles, decryptionProfiles };
    },
  });

  // Auth boundary / unmount: clear every write intent belonging to this
  // identity (the run owner is aborted by the hook itself).
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
    setCommitOpen(false);
  };
  // Installed every render so the boundary always runs the LATEST closure
  // (single-slot ref inside the hook — no accumulation, no stale state).
  rb.setBoundaryCleanup(closeAllWriteState);

  // A fresh policy snapshot resolves a stale-version conflict: the operator
  // can now review current truth and resubmit deliberately.
  useEffect(() => {
    setEditorConflict(null);
  }, [q.dataUpdatedAt]);

  const accessRulesForDirty = snap?.accessRules ?? [];
  const reorderChanged =
    reorder !== null &&
    (reorder.length !== accessRulesForDirty.length ||
      reorder.some((r, i) => accessRulesForDirty[i]?.id !== r.id));
  const guard = useDirtyGuard(
    editorDirty || reorderChanged,
    editorDirty
      ? "the unsaved rule changes in the editor"
      : "the staged reorder",
  );

  const accessRules = useMemo(() => snap?.accessRules ?? [], [snap]);
  const filtered = useMemo(() => {
    const needle = filter.trim();
    if (needle === "") return accessRules;
    return accessRules.filter((r) => ruleMatchesFilter(r, needle));
  }, [accessRules, filter]);

  // Staged-reorder integrity: if a refetch shows the rulebase membership
  // changed under the staged permutation, discard it VISIBLY — the local
  // order can no longer be rebased safely (§23: never rebase automatically).
  useEffect(() => {
    if (reorder === null) return;
    const ids = new Set(accessRules.map((r) => r.id));
    const stale =
      reorder.length !== accessRules.length ||
      reorder.some((r) => !ids.has(r.id));
    if (stale) {
      setReorder(null);
      setReorderNotice(
        "The rulebase changed while you were reordering. Review the current order and try again.",
      );
    }
  }, [accessRules, reorder]);

  // Deep-link resolution (§10): pure data equality against the decoded
  // snapshot; the raw parameter never reaches the DOM as a selector.
  const paramValid = ruleParam === "" || isPlausibleRuleID(ruleParam);
  const target =
    paramValid && ruleParam !== ""
      ? accessRules.find((r) => r.id === ruleParam)
      : undefined;
  const targetVisible =
    target !== undefined && filtered.some((r) => r.id === target.id);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [announce, setAnnounce] = useState("");
  const targetRowRef = useRef<HTMLTableRowElement | null>(null);
  // The ?rule= value this component has FINISHED locating (row existed,
  // scrolled, focused, highlighted, announced). Reset whenever the parameter
  // changes so A → B → A locates A again; never set before the row exists.
  const handledParam = useRef<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (highlightTimer.current !== null) clearTimeout(highlightTimer.current);
    },
    [],
  );
  useEffect(() => {
    if (snap === undefined) return;
    if (ruleParam === "" || !paramValid || target === undefined) {
      // Empty / malformed / not-in-snapshot: any previous target-specific
      // state (highlight, announcement, handled marker) must not survive —
      // a stale highlight next to an invalid/historical callout would lie.
      handledParam.current = null;
      if (highlightTimer.current !== null) {
        clearTimeout(highlightTimer.current);
        highlightTimer.current = null;
      }
      setHighlightId(null);
      setAnnounce("");
      return;
    }
    if (handledParam.current === ruleParam) return; // located; user owns the filter again
    if (!targetVisible) {
      // A NEW valid deep-link navigation is authoritative over the temporary
      // in-memory display filter: reset it so the target row can exist. The
      // effect re-runs once the unfiltered rows have rendered.
      setFilter("");
      return;
    }
    const row = targetRowRef.current;
    if (row === null) return; // row not committed yet; re-runs on `filtered`
    handledParam.current = ruleParam;
    if (highlightTimer.current !== null) clearTimeout(highlightTimer.current);
    setHighlightId(target.id);
    row.scrollIntoView({ block: "center" });
    row.focus();
    // Announced only AFTER the row exists, is scrolled, and holds focus.
    setAnnounce(
      `Rule ${target.name} (priority ${String(target.priority)}) located.`,
    );
    highlightTimer.current = setTimeout(() => {
      setHighlightId(null);
      highlightTimer.current = null;
    }, 4000);
  }, [ruleParam, paramValid, target, targetVisible, filtered, snap]);

  const draft = snap?.draft === true;
  const blocked = rb.unknown !== null;
  // Whether the NEXT write will stage into the draft (server-authoritative
  // signal: Require Commit is armed on the draft surface).
  const nextWriteStaged =
    rb.draftQ.data !== undefined ? rb.draftQ.data.requireCommit : draft;

  // ── mutation flows ───────────────────────────────────────────────────────
  const submitEditor = (write: AccessRuleWrite): void => {
    if (snap === undefined || editor === null) return;
    const version = snap.version;
    const signal = rb.owner.begin();
    setEditorPending(true);
    setEditorServerError("");
    const call =
      editor.kind === "create"
        ? createRule(write, version, signal).then(() => undefined)
        : updateRule(editor.rule.id, write, version, signal);
    call
      .then(() => {
        // Confirmed success: render server truth, never the form echo.
        setEditor(null);
        setEditorDirty(false);
        setEditorConflict(null);
        rb.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          // Outcome unconfirmed: keep the form content for review, block
          // every mutation until a fresh refetch confirms server state.
          rb.latchUnknown(editor.kind === "create" ? "create" : "edit");
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
        rb.owner.settle(signal);
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
      `Rule ${moved.name} moved to position ${String(toIdx + 1)} of ${String(next.length)}. Reorder staged, not applied.`,
    );
  };

  const applyReorder = (): void => {
    if (snap === undefined || reorder === null) return;
    const version = snap.version;
    const signal = rb.owner.begin();
    setReorderPending(true);
    setReorderNotice("");
    // The permutation: every current access rule's OLD priority, in the NEW
    // display order — exactly once each (Stage-1 auth priorities are never
    // present; accessRules structurally excludes them).
    reorderRules(
      reorder.map((r) => r.priority),
      version,
      signal,
    )
      .then(() => {
        setReorder(null);
        setReorderAnnounce("");
        rb.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          // The permutation may or may not have applied — the local staging
          // is no longer trustworthy. Discard it visibly and latch.
          setReorder(null);
          setReorderAnnounce("");
          rb.latchUnknown("reorder");
          return;
        }
        const conflict = asPolicyConflict(err);
        if (conflict !== null) {
          // §23: the staged permutation is stale. Never rebase automatically —
          // discard visibly and refetch server truth.
          setReorder(null);
          setReorderAnnounce("");
          setReorderNotice(
            "The rulebase changed while you were reordering. Review the current order and try again.",
          );
          rb.refetchAll();
          return;
        }
        setReorderNotice(
          serverErrorText(err, "The appliance refused the reorder."),
        );
      })
      .finally(() => {
        rb.owner.settle(signal);
        setReorderPending(false);
      });
  };

  const confirmDelete = (): void => {
    if (snap === undefined || deleting === null) return;
    const version = snap.version;
    const signal = rb.owner.begin();
    setDeleteResult("pending");
    deleteRule(deleting.id, version, signal)
      .then(() => {
        setDeleting(null);
        setDeleteResult("idle");
        setDeleteError("");
        rb.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          // Never blindly repeat DELETE: close into the page-level latch.
          setDeleting(null);
          setDeleteResult("idle");
          rb.latchUnknown("delete");
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
        rb.owner.settle(signal);
      });
  };

  return (
    <>
      <PageHeader
        title="Access Rules"
        subtitle="Stage-2 access policy — first match in priority order decides; unmatched traffic gets the default action."
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={snap !== undefined}
            onRefresh={rb.refreshToResolve}
          />
        }
      />
      <span role="status" aria-live="polite" className={styles.srOnly}>
        {announce}
      </span>

      {rb.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout
            variant="unknown"
            title={`${rb.unknown === "delete" ? "Delete" : rb.unknown === "create" ? "Create" : "Save"} outcome unconfirmed`}
            role="alert"
          >
            The connection was lost before the appliance&apos;s answer arrived —
            the change may or may not have been applied. Refresh the rulebase
            and review the current state before making further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={rb.refreshToResolve}>
                Refresh rulebase
              </Button>
            </div>
          </Callout>
        </div>
      )}

      <span role="status" aria-live="polite" className={styles.srOnly}>
        {reorderAnnounce}
      </span>
      {reorderNotice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Reorder not applied" role="alert">
            {reorderNotice}
          </Callout>
        </div>
      )}

      {snap !== undefined && (
        <DraftBar
          draft={rb.draftQ.data}
          draftError={rb.draftQ.isError}
          snapshotIsDraft={draft}
          isAdmin={isAdmin}
          canWrite={canWrite}
          currentUser={state.user}
          blocked={blocked}
          owner={rb.owner}
          refetchAll={rb.refetchAll}
          latchUnknown={rb.latchUnknown}
          onOpenCommit={() => {
            setCommitOpen(true);
          }}
        />
      )}

      {snap !== undefined && (
        <DefaultActionControl
          canWrite={canWrite}
          blocked={blocked}
          owner={rb.owner}
        />
      )}

      {commitOpen && canWrite && (
        <CommitReview
          owner={rb.owner}
          blocked={blocked}
          refetchAll={rb.refetchAll}
          latchUnknown={rb.latchUnknown}
          onClose={() => {
            setCommitOpen(false);
          }}
        />
      )}
      {snap !== undefined && snap.unknownKindCount > 0 && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Unrecognized rule entries">
            {String(snap.unknownKindCount)} rulebase{" "}
            {snap.unknownKindCount === 1 ? "entry uses" : "entries use"} a rule
            type this console does not recognize. They are not shown here and
            are NOT access rules; upgrade the console to manage them.
          </Callout>
        </div>
      )}
      {ruleParam !== "" && !paramValid && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Invalid rule reference">
            The rule reference in this link is not a valid rule identifier.
          </Callout>
        </div>
      )}
      {snap !== undefined &&
        paramValid &&
        ruleParam !== "" &&
        target === undefined && (
          <div className={styles.calloutSpace}>
            <Callout
              variant="info"
              title="Referenced rule not in this snapshot"
            >
              The referenced Rule ID is not present in the current Access Rules
              snapshot. It may represent historical data or a rule outside the
              current effective Access Rules view.
            </Callout>
          </div>
        )}

      {snap === undefined && q.isPending && <Skeleton>Loading rules…</Skeleton>}
      {snap === undefined && q.isError && (
        <ErrorState title="Rulebase unavailable">
          The policy snapshot could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {snap !== undefined && (
        <>
          <div className={styles.toolbar}>
            <InputField
              label="Filter"
              help={
                reorder !== null
                  ? "Filtering is paused while a reorder is staged — the full evaluation order must stay visible."
                  : "Matches name, source, destination, action, and rule ID. Display only — priority order is preserved."
              }
              value={filter}
              disabled={reorder !== null}
              onChange={(e) => {
                setFilter(e.target.value);
              }}
            />
            {canWrite && reorder === null && (
              <div className={styles.toolbarActions}>
                <Button
                  disabled={blocked}
                  onClick={() => {
                    setEditor({ kind: "create" });
                    setEditorConflict(null);
                    setEditorServerError("");
                  }}
                >
                  New rule…
                </Button>
                <Button
                  variant="ghost"
                  disabled={blocked || accessRules.length < 2}
                  onClick={() => {
                    setFilter("");
                    setReorder(accessRules);
                    setReorderNotice("");
                  }}
                >
                  Reorder rules…
                </Button>
              </div>
            )}
            {canWrite && reorder !== null && (
              <div className={styles.toolbarActions}>
                {reorderChanged && (
                  <StatusBadge status="warn">Reorder staged</StatusBadge>
                )}
                <Button
                  disabled={blocked || !reorderChanged || reorderPending}
                  onClick={applyReorder}
                >
                  Apply reorder
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
              {String(filtered.length)} of {String(accessRules.length)} access
              rules
              {snap.authRuleCount > 0 &&
                ` · ${String(snap.authRuleCount)} authentication ${
                  snap.authRuleCount === 1 ? "rule" : "rules"
                } managed on the Authentication Rules surface`}
            </span>
          </div>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">
                Access rules in evaluation order
              </caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Details" />
                  <th scope="col" className={styles.numeric}>
                    Priority
                  </th>
                  <th scope="col">Name</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Source</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Action</th>
                  <th scope="col">TLS / Decryption</th>
                  <th scope="col" className={styles.numeric}>
                    Hits
                  </th>
                  <th scope="col">Last hit</th>
                  {canWrite && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {(reorder ?? filtered).length === 0 && (
                  <tr>
                    <td colSpan={canWrite ? 11 : 10}>
                      {accessRules.length === 0
                        ? "No access rules are defined. Unmatched traffic receives the default action."
                        : "No rules match the filter."}
                    </td>
                  </tr>
                )}
                {(reorder ?? filtered).map((r, idx) => {
                  const rowKey = r.id !== "" ? r.id : `p${String(r.priority)}`;
                  const isTarget = target !== undefined && r.id === target.id;
                  const open = openId === rowKey;
                  const staging = reorder !== null;
                  const last = (reorder ?? filtered).length - 1;
                  return (
                    <RuleRow
                      key={rowKey}
                      r={r}
                      open={open}
                      highlighted={highlightId !== null && r.id === highlightId}
                      rowRef={isTarget ? targetRowRef : undefined}
                      onToggle={() => {
                        setOpenId(open ? null : rowKey);
                      }}
                      actions={
                        canWrite && staging ? (
                          <span className={styles.rowActions}>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={idx === 0 || reorderPending}
                              aria-label={`Move rule ${r.name} first`}
                              onClick={() => {
                                moveStaged(idx, 0);
                              }}
                            >
                              ⇤
                            </Button>
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
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={idx === last || reorderPending}
                              aria-label={`Move rule ${r.name} last`}
                              onClick={() => {
                                moveStaged(idx, last);
                              }}
                            >
                              ⇥
                            </Button>
                          </span>
                        ) : canWrite ? (
                          <span className={styles.rowActions}>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={blocked || r.id === ""}
                              aria-label={`Edit rule ${r.name}`}
                              onClick={() => {
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
                              disabled={blocked || r.id === ""}
                              aria-label={`Delete rule ${r.name}`}
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

      {guard.element}

      {editor !== null && snap !== undefined && (
        <>
          {optQ.isPending && (
            <div className={styles.calloutSpace}>
              <Skeleton>Loading reference lists…</Skeleton>
            </div>
          )}
          {optQ.isError && (
            <div className={styles.calloutSpace}>
              <Callout variant="critical" title="Reference lists unavailable">
                The category / profile option lists could not be loaded, so the
                editor cannot open safely.
                <div className={styles.fallbackAction}>
                  <Button
                    size="sm"
                    onClick={() => {
                      void optQ.refetch();
                    }}
                  >
                    Retry
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      setEditor(null);
                      setEditorDirty(false);
                    }}
                  >
                    Cancel
                  </Button>
                </div>
              </Callout>
            </div>
          )}
          {optQ.data !== undefined && (
            <RuleEditor
              mode={editor}
              staged={nextWriteStaged}
              options={optQ.data}
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
        </>
      )}

      {canWrite && deleting !== null && (
        <ConfirmationDialog
          open
          tier={1}
          title="Delete access rule"
          body={
            <>
              Delete rule <strong>{deleting.name}</strong> (priority{" "}
              {deleting.priority}, action {deleting.action})?{" "}
              {nextWriteStaged
                ? "The delete will be STAGED in the shared Policy Draft and takes effect only when the draft is committed."
                : "The delete is LIVE immediately."}
            </>
          }
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
    </>
  );
}

function RuleRow({
  r,
  open,
  highlighted,
  rowRef,
  onToggle,
  actions,
}: {
  r: PolicyRuleView;
  open: boolean;
  highlighted: boolean;
  rowRef: Ref<HTMLTableRowElement> | undefined;
  onToggle: () => void;
  actions: ReactNode | undefined;
}): JSX.Element {
  const cols = actions !== undefined ? 11 : 10;
  return (
    <>
      <tr
        ref={rowRef}
        tabIndex={-1}
        className={`${styles.ruleRow}${r.enabled ? "" : ` ${styles.disabledRule}`}`}
        data-highlight={highlighted || undefined}
      >
        <td>
          <button
            type="button"
            className={styles.expandBtn}
            aria-expanded={open}
            aria-label={`Details for rule ${r.name}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </button>
        </td>
        <td className={styles.numeric}>{r.priority}</td>
        <td className={styles.nameCell}>{r.name}</td>
        <td>
          {r.enabled ? (
            <StatusBadge status="ok">On</StatusBadge>
          ) : (
            <StatusBadge status="neutral">Off</StatusBadge>
          )}
        </td>
        <td className={styles.matchCell}>{sourceSummary(r)}</td>
        <td className={styles.matchCell}>{destinationSummary(r)}</td>
        <td>{actionBadge(r.action)}</td>
        <td className={styles.matchCell}>{tlsSummary(r)}</td>
        <td className={styles.numeric}>{r.hitCount}</td>
        <td className={styles.mono}>{r.lastHit === "" ? "—" : r.lastHit}</td>
        {actions !== undefined && <td>{actions}</td>}
      </tr>
      {open && (
        <tr className={styles.detailRow}>
          <td colSpan={cols}>
            <RuleDetail r={r} />
          </td>
        </tr>
      )}
    </>
  );
}
