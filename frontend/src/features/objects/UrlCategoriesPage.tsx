// 2D-B — URL Categories + signed SaaS taxonomy: one coherent product surface
// with five sections (Categories / Lookup / Feed Status / Signed SaaS Feed /
// Overrides).
//
// Ownership layers (§2 — deliberately NOT one homogeneous store):
//   - catStore rows (this page's Categories tab): admin-created + built-in
//     baseline categories, NAME-authoritative (no IDs, no rename — §3).
//   - UT1 community DB: node-local, feed-derived, READ-ONLY here. The
//     `feedBacked` flag means "UT1 community feed name mapping" — never the
//     signed SaaS corpus.
//   - Signed SaaS effective view: immutable generation, server-composed —
//     never reconstructed in the browser (§17/§39).
//   - Admin SaaS overrides: layered over the signed view (Overrides tab).
//
// Concurrency: every mutation asserts the server-owned semantic revision from
// GET /api/urlcat/state (?ifRevision=); a stale token is the structured 409
// and never a silent overwrite. Create is STRICT. Confirmed 2xx =
// restart-durable (2D-B.0a).
import { useMemo, useState, type JSX } from "react";
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
import { InputField, TextareaField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  MAX_HOSTS_PER_CATEGORY,
  asRevisionConflict,
  createUrlCategory,
  getUrlCategoryState,
  replaceUrlCategoryHosts,
} from "../../api/urlcat";
import type { BuiltInAuthority, UrlCategoryRow } from "../../api/urlcat";
import { WhereUsed } from "../policy/WhereUsed";
import { UrlCategoryDeleteDialog } from "./UrlCategoryDeleteDialog";
import { UrlCatLookupTab } from "./UrlCatLookupTab";
import { SaasFeedStatusTab, SignedSaasFeedTab } from "./SaasFeedTabs";
import { SaasOverridesTab } from "./SaasOverridesTab";
import { useObjectPage } from "./useObjectPage";
import styles from "../policy/policy.module.css";

const TABS = [
  "Categories",
  "Lookup",
  "Feed Status",
  "Signed SaaS Feed",
  "Overrides",
] as const;
type Tab = (typeof TABS)[number];

type EditorMode = { kind: "create" } | { kind: "edit"; row: UrlCategoryRow };

export function UrlCategoriesPage(): JSX.Element {
  const [tab, setTab] = useState<Tab>("Categories");
  const page = useObjectPage(["objects", "urlcat-state"], getUrlCategoryState);
  const q = page.q;
  const snap = q.data;
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  const canWrite = hasRole(role, "operator");
  const isAdmin = hasRole(role, "admin");

  const [editor, setEditor] = useState<EditorMode | null>(null);
  const [editorDirty, setEditorDirty] = useState(false);
  const [deleting, setDeleting] = useState<UrlCategoryRow | null>(null);
  const [notice, setNotice] = useState("");

  const closeAllWriteState = (): void => {
    setEditor(null);
    setEditorDirty(false);
    setDeleting(null);
    setNotice("");
  };
  page.setBoundaryCleanup(closeAllWriteState);

  const guard = useDirtyGuard(
    editorDirty,
    "the unsaved URL-category changes in the editor",
  );

  const blocked = page.unknown !== null;
  const categories = snap?.categories ?? [];
  const revision = snap?.revision ?? "";
  // Server-owned ownership truth (Blocker D): the browser renders it, never
  // derives it from builtIn/provenance/state.
  const builtInAuthority = snap?.builtInAuthority ?? "local";

  const onConflict = (text: string): void => {
    setEditor(null);
    setEditorDirty(false);
    setDeleting(null);
    setNotice(text);
    page.refreshToResolve();
  };

  return (
    <>
      <PageHeader
        title="URL Categories"
        subtitle="Named URL categories referenced by Access Rules and Category Groups. Category NAMES are the authoritative identity — there is no rename. UT1 community and signed SaaS taxonomy layers are separate, read-only sources."
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

      {guard.element}

      <div
        role="tablist"
        aria-label="URL category sections"
        className={styles.calloutSpace}
      >
        {TABS.map((t) => (
          <Button
            key={t}
            size="sm"
            variant={t === tab ? "primary" : "ghost"}
            role="tab"
            aria-selected={t === tab}
            onClick={() => {
              setTab(t);
            }}
          >
            {t}
          </Button>
        ))}
      </div>

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the {page.unknown} may or may not have been applied. Refresh and
            review the current taxonomy before writing again.
            <div className={styles.calloutAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh to resolve
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

      {tab === "Categories" && (
        <CategoriesTab
          rows={categories}
          loading={q.isPending}
          error={q.isError}
          blocked={blocked}
          canWrite={canWrite}
          builtInAuthority={builtInAuthority}
          onManageOverrides={() => {
            setNotice("");
            setTab("Overrides");
          }}
          onCreate={() => {
            setNotice("");
            setEditor({ kind: "create" });
          }}
          onEdit={(row) => {
            setNotice("");
            setEditor({ kind: "edit", row });
          }}
          onDelete={(row) => {
            setNotice("");
            setDeleting(row);
          }}
        />
      )}
      {tab === "Lookup" && <UrlCatLookupTab />}
      {tab === "Feed Status" && <SaasFeedStatusTab />}
      {tab === "Signed SaaS Feed" && <SignedSaasFeedTab isAdmin={isAdmin} />}
      {tab === "Overrides" && <SaasOverridesTab isAdmin={isAdmin} />}

      {editor !== null && (
        <CategoryEditorDialog
          mode={editor}
          revision={revision}
          page={page}
          onDirty={setEditorDirty}
          onDone={() => {
            setEditor(null);
            setEditorDirty(false);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setEditor(null);
            setEditorDirty(false);
          }}
          onConflictNotice={onConflict}
        />
      )}
      {deleting !== null && (
        <UrlCategoryDeleteDialog
          row={deleting}
          revision={revision}
          page={page}
          onDone={() => {
            setDeleting(null);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setDeleting(null);
          }}
          onConflictNotice={onConflict}
        />
      )}
    </>
  );
}

function CategoriesTab({
  rows,
  loading,
  error,
  blocked,
  canWrite,
  builtInAuthority,
  onManageOverrides,
  onCreate,
  onEdit,
  onDelete,
}: {
  rows: readonly UrlCategoryRow[];
  loading: boolean;
  error: boolean;
  blocked: boolean;
  canWrite: boolean;
  builtInAuthority: BuiltInAuthority;
  onManageOverrides: () => void;
  onCreate: () => void;
  onEdit: (row: UrlCategoryRow) => void;
  onDelete: (row: UrlCategoryRow) => void;
}): JSX.Element {
  const [openName, setOpenName] = useState<string | null>(null);
  if (loading) return <Skeleton>Loading URL categories…</Skeleton>;
  if (error) return <ErrorState title="Could not load URL categories" />;
  return (
    <section aria-label="URL categories">
      {builtInAuthority === "signed-feed" && (
        <div className={styles.calloutSpace}>
          <Callout
            variant="info"
            title="Built-in categories are signed-feed owned"
          >
            An active signed SaaS feed generation currently serves the built-in
            categories, so their local definitions are read-only here — a local
            edit would be stored but never enforced. Adjust signed-feed content
            with SaaS Overrides; admin-created categories stay fully editable.
          </Callout>
        </div>
      )}
      {canWrite && (
        <div className={styles.calloutSpace}>
          <Button onClick={onCreate} disabled={blocked}>
            Create category
          </Button>
        </div>
      )}
      <table className={styles.table}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Hosts</th>
            <th>Community</th>
            <th aria-label="actions" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name}>
              <td>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setOpenName(openName === row.name ? null : row.name);
                  }}
                >
                  {row.name}
                </Button>
                {openName === row.name && (
                  <div className={styles.refDetail}>
                    <WhereUsed type="category" name={row.name} />
                  </div>
                )}
              </td>
              <td>
                {row.builtIn ? (
                  <StatusBadge status="neutral">
                    Baseline / built-in
                  </StatusBadge>
                ) : (
                  <StatusBadge status="ok">Admin</StatusBadge>
                )}
              </td>
              <td>
                <Mono>{String(row.hosts.length)}</Mono>
              </td>
              <td>
                {row.feedBacked ? (
                  <StatusBadge status="neutral">UT1 community feed</StatusBadge>
                ) : (
                  <span aria-hidden="true">—</span>
                )}
              </td>
              <td>
                {!row.writable ? (
                  // Server-owned truth: this row's classes are served from
                  // the active signed feed generation — no Edit/Delete.
                  <>
                    <StatusBadge status="info">Signed-feed owned</StatusBadge>
                    {canWrite && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={onManageOverrides}
                      >
                        Manage with Overrides
                      </Button>
                    )}
                  </>
                ) : (
                  canWrite && (
                    <>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={blocked}
                        onClick={() => {
                          onEdit(row);
                        }}
                      >
                        Edit hosts
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={blocked}
                        onClick={() => {
                          onDelete(row);
                        }}
                      >
                        Delete
                      </Button>
                    </>
                  )
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && (
        <Callout variant="info" title="No categories">
          The taxonomy is empty — create a category or load the defaults.
        </Callout>
      )}
    </section>
  );
}

// ── Editor (bounded text-oriented — one host/pattern per line, §18) ─────────

function parseHostLines(text: string): readonly string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

function CategoryEditorDialog({
  mode,
  revision,
  page,
  onDirty,
  onDone,
  onCancel,
  onConflictNotice,
}: {
  mode: EditorMode;
  revision: string;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getUrlCategoryState>>>
  >;
  onDirty: (d: boolean) => void;
  onDone: () => void;
  onCancel: () => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const isCreate = mode.kind === "create";
  const [name, setName] = useState(isCreate ? "" : mode.row.name);
  // Server-returned ordering/content preserved unless deliberately changed.
  const [hostText, setHostText] = useState(
    isCreate ? "" : mode.row.hosts.join("\n"),
  );
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");

  const hosts = useMemo(() => parseHostLines(hostText), [hostText]);
  const overCap = hosts.length > MAX_HOSTS_PER_CATEGORY;

  const markDirty = (): void => {
    onDirty(true);
  };

  const save = (): void => {
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    const run = isCreate
      ? createUrlCategory(name.trim(), hosts, revision, signal)
      : replaceUrlCategoryHosts(mode.row.name, hosts, revision, signal);
    run
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown(isCreate ? "create" : "edit");
          onConflictNotice(
            "The save's outcome is unconfirmed — refresh before retrying.",
          );
          return;
        }
        const conflict = asRevisionConflict(err);
        if (conflict !== null) {
          onConflictNotice(
            "The taxonomy changed since this editor was opened (stale revision). Nothing was written — refresh and re-apply your change on the current state.",
          );
          return;
        }
        setServerError(serverErrorText(err, "The appliance refused the save."));
      })
      .finally(() => {
        setPending(false);
      });
  };

  return (
    <Dialog
      open
      onClose={onCancel}
      title={isCreate ? "Create category" : `Edit hosts — ${mode.row.name}`}
    >
      <DialogBody>
        {isCreate ? (
          <InputField
            label="Category name"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              markDirty();
            }}
            placeholder="e.g. Streaming Media"
          />
        ) : (
          <p className={styles.refDetail}>
            Category names are the authoritative identity — this editor never
            renames. Editing hosts of <Mono>{mode.row.name}</Mono>
            {mode.row.builtIn ? " (baseline/built-in)" : ""}.
          </p>
        )}
        <TextareaField
          label="Hosts / patterns — one per line"
          value={hostText}
          rows={14}
          onChange={(e) => {
            setHostText(e.target.value);
            markDirty();
          }}
        />
        <p className={styles.refDetail} aria-live="polite">
          {String(hosts.length)} host{hosts.length === 1 ? "" : "s"} · server
          limit {String(MAX_HOSTS_PER_CATEGORY)} per category
        </p>
        {overCap && (
          <Callout variant="critical" title="Over the host limit">
            This category would exceed the {String(MAX_HOSTS_PER_CATEGORY)}-host
            limit; the appliance will refuse the save.
          </Callout>
        )}
        {serverError !== "" && (
          <Callout variant="critical" title="Not saved" role="alert">
            {serverError}
          </Callout>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button
          onClick={save}
          disabled={pending || overCap || (isCreate && name.trim() === "")}
        >
          {isCreate ? "Create" : "Save hosts"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
