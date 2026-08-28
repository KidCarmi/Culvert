// 2D-A.2 — Category Groups: the first v2 shared-object management surface.
//
// Reference model (§2): the stable object ID is the authoritative link; the
// denormalized name on referencing rules is a display/export cache the SERVER
// maintains (rename cascade). This page addresses every mutation by stable ID
// and never touches policy rules.
//
// Membership truth (§12): URL categories are deliberately NAME-authoritative
// (community feed resolution and group membership both store names), so the
// membership editor selects category NAMES from the authoritative URL-category
// read surface. A member name no longer present renders as unresolved/dangling
// and is preserved unless explicitly removed.
//
// Delete integrity (§3/§13): the server's reference walk (running rules AND an
// active draft candidate) is authoritative — the dialog pre-fetches Where Used
// for clarity, but a concurrent reference still fails safely as the server's
// structured 409, rendered with the real consumers.
import { useEffect, useMemo, useState, type JSX } from "react";
import { useQuery } from "@tanstack/react-query";
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
import { Checkbox, InputField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  createCategoryGroup,
  deleteCategoryGroup,
  updateCategoryGroup,
} from "../../api/objects";
import type { CategoryGroupView } from "../../api/objects";
import { getCategoryGroups } from "../../api/objects";
import { getURLCategoryNames } from "../../api/policyWrite";
import { asPolicyConflict } from "../../api/policyWrite";
import { WhereUsed } from "../policy/WhereUsed";
import { useObjectPage } from "./useObjectPage";
import { ObjectDeleteDialog } from "./ObjectDeleteDialog";
import styles from "../policy/policy.module.css";

type EditorMode =
  { kind: "create" } | { kind: "edit"; group: CategoryGroupView };

export function CategoryGroupsPage(): JSX.Element {
  const page = useObjectPage(["objects", "category-groups"], getCategoryGroups);
  const q = page.q;
  const snap = q.data;
  const { state } = useAuth();
  const canWrite = hasRole(state.role ?? "viewer", "operator");
  const [openId, setOpenId] = useState<string | null>(null);
  const [params] = useSearchParams();

  // Authoritative category-name read surface for membership + dangling
  // detection — refreshed with the page snapshot (manual, never polled).
  const catsQ = useQuery({
    queryKey: ["objects", "urlcat-names"],
    staleTime: Infinity,
    retry: false,
    queryFn: ({ signal }) => getURLCategoryNames(signal),
  });
  const knownCats = useMemo(
    () => new Set((catsQ.data ?? []).map((c) => c.toLowerCase())),
    [catsQ.data],
  );

  // ── editor / delete / notice state ──────────────────────────────────────
  const [editor, setEditor] = useState<EditorMode | null>(null);
  const [editorDirty, setEditorDirty] = useState(false);
  const [deleting, setDeleting] = useState<CategoryGroupView | null>(null);
  const [notice, setNotice] = useState("");

  const closeAllWriteState = (): void => {
    setEditor(null);
    setEditorDirty(false);
    setDeleting(null);
    setNotice("");
  };
  page.setBoundaryCleanup(closeAllWriteState);

  const blocked = page.unknown !== null;
  const groups = snap?.groups ?? [];
  const version = snap?.version ?? 0;

  const refreshAll = (): void => {
    page.refreshToResolve();
    void catsQ.refetch();
  };

  const guard = useDirtyGuard(
    editorDirty,
    "the unsaved category-group changes in the editor",
  );

  // Deep link (?id=): open the row detail for a stable-ID consumer link.
  const linkedId = params.get("id");
  useEffect(() => {
    if (linkedId !== null && linkedId !== "") setOpenId(linkedId);
  }, [linkedId]);

  return (
    <>
      <PageHeader
        title="Category Groups"
        subtitle="Named bundles of URL categories that Access Rules reference as one destination object. Rules link by the stable object ID — renames follow the same object."
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={snap !== undefined}
            onRefresh={refreshAll}
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
              <Button size="sm" onClick={refreshAll}>
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
        <Skeleton>Loading category groups…</Skeleton>
      )}
      {snap === undefined && q.isError && (
        <ErrorState title="Category groups unavailable">
          The category-group snapshot could not be loaded. Refresh to try again.
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
                  New category group…
                </Button>
              </div>
            )}
            <span className={styles.counts}>
              {String(groups.length)} category{" "}
              {groups.length === 1 ? "group" : "groups"}
            </span>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">Category groups</caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Details" />
                  <th scope="col">Name</th>
                  <th scope="col">Object ID</th>
                  <th scope="col" className={styles.numeric}>
                    Categories
                  </th>
                  <th scope="col">Updated</th>
                  {canWrite && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {groups.length === 0 && (
                  <tr>
                    <td colSpan={canWrite ? 6 : 5}>
                      No category groups are defined.
                    </td>
                  </tr>
                )}
                {groups.map((g) => {
                  const open = openId === g.id;
                  const dangling =
                    catsQ.data === undefined
                      ? []
                      : g.categories.filter((c) => !knownCats.has(c));
                  return (
                    <GroupRow
                      key={g.id}
                      g={g}
                      open={open}
                      dangling={dangling}
                      canWrite={canWrite}
                      blocked={blocked}
                      highlighted={linkedId === g.id}
                      onToggle={() => {
                        setOpenId(open ? null : g.id);
                      }}
                      onEdit={() => {
                        setEditor({ kind: "edit", group: g });
                        setNotice("");
                      }}
                      onDelete={() => {
                        setDeleting(g);
                        setNotice("");
                      }}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {editor !== null && canWrite && snap !== undefined && (
        <GroupEditor
          mode={editor}
          version={version}
          knownCategories={catsQ.data ?? []}
          categoriesUnavailable={catsQ.isError}
          blocked={blocked}
          page={page}
          onDone={() => {
            setEditor(null);
            setEditorDirty(false);
            refreshAll();
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
          objType="category-group"
          objName={deleting.name}
          objId={deleting.id}
          body={
            <>
              This deletes the category group <strong>{deleting.name}</strong> (
              <Mono>{deleting.id}</Mono>, {String(deleting.categories.length)}{" "}
              {deleting.categories.length === 1 ? "category" : "categories"}).
              The delete is refused while any Access Rule — running or staged in
              an active Policy Draft — references it.
            </>
          }
          doDelete={(signal) =>
            deleteCategoryGroup(deleting.id, version, signal)
          }
          page={page}
          onDone={() => {
            setDeleting(null);
            refreshAll();
          }}
          onCancel={() => {
            setDeleting(null);
          }}
          onConflictNotice={(text) => {
            setDeleting(null);
            setNotice(text);
            refreshAll();
          }}
        />
      )}
      {guard.element}
    </>
  );
}

function GroupRow({
  g,
  open,
  dangling,
  canWrite,
  blocked,
  highlighted,
  onToggle,
  onEdit,
  onDelete,
}: {
  g: CategoryGroupView;
  open: boolean;
  dangling: readonly string[];
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
            aria-label={`Details for group ${g.name}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </Button>
        </td>
        <td>{g.name}</td>
        <td>
          <Mono>{g.id}</Mono>
        </td>
        <td className={styles.numeric}>
          {String(g.categories.length)}
          {dangling.length > 0 && (
            <>
              {" "}
              <StatusBadge status="warn">
                {String(dangling.length)} unresolved
              </StatusBadge>
            </>
          )}
        </td>
        <td>{g.updatedAt === "" ? "—" : g.updatedAt}</td>
        {canWrite && (
          <td>
            <span className={styles.rowActions}>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                aria-label={`Edit group ${g.name}`}
                onClick={onEdit}
              >
                Edit
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                aria-label={`Delete group ${g.name}`}
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
          <td colSpan={canWrite ? 6 : 5}>
            <div className={styles.rowDetail}>
              <dl className={styles.kvGrid}>
                <div>
                  <dt className={styles.refDetail}>Object ID</dt>
                  <dd>
                    <Mono>{g.id}</Mono>
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Created</dt>
                  <dd>{g.createdAt === "" ? "—" : g.createdAt}</dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Member categories</dt>
                  <dd>
                    {g.categories.length === 0
                      ? "none"
                      : g.categories.map((c) => (
                          <span key={c}>
                            {c}
                            {dangling.includes(c) && (
                              <StatusBadge status="warn">
                                unresolved
                              </StatusBadge>
                            )}{" "}
                          </span>
                        ))}
                  </dd>
                </div>
              </dl>
              {dangling.length > 0 && (
                <Callout variant="warning" title="Unresolved member categories">
                  These member names do not match any current URL category. They
                  are preserved as stored (matching simply never fires for them)
                  until explicitly removed in the editor.
                </Callout>
              )}
              <WhereUsed type="category-group" name={g.name} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Editor ──────────────────────────────────────────────────────────────────

function GroupEditor({
  mode,
  version,
  knownCategories,
  categoriesUnavailable,
  blocked,
  page,
  onDone,
  onCancel,
  onDirtyChange,
  onConflictNotice,
}: {
  mode: EditorMode;
  version: number;
  knownCategories: readonly string[];
  categoriesUnavailable: boolean;
  blocked: boolean;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getCategoryGroups>>>
  >;
  onDone: () => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const emptyInitial: {
    id: string;
    name: string;
    categories: readonly string[];
  } = { id: "", name: "", categories: [] };
  const initial = mode.kind === "edit" ? mode.group : emptyInitial;
  const [name, setName] = useState(initial.name);
  const [members, setMembers] = useState<readonly string[]>(initial.categories);
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");

  const dirty =
    name !== initial.name ||
    members.length !== initial.categories.length ||
    members.some((m) => !initial.categories.includes(m));
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);

  const renaming =
    mode.kind === "edit" &&
    name.trim() !== "" &&
    name.trim().toLowerCase() !== mode.group.name.toLowerCase();

  // The selectable universe: authoritative names, PLUS any stored members not
  // (or no longer) in it — preserved as dangling entries (§12: never silently
  // dropped by editing another field).
  const universe = useMemo(() => {
    const seen = new Set(knownCategories.map((c) => c.toLowerCase()));
    const extra = members.filter((m) => !seen.has(m));
    return { known: knownCategories, dangling: extra };
  }, [knownCategories, members]);
  const memberSet = useMemo(
    () => new Set(members.map((m) => m.toLowerCase())),
    [members],
  );

  const toggle = (catName: string, lower: string): void => {
    setMembers((cur) =>
      cur.some((m) => m.toLowerCase() === lower)
        ? cur.filter((m) => m.toLowerCase() !== lower)
        : [...cur, catName],
    );
  };

  const submit = (): void => {
    if (name.trim() === "") {
      setServerError("A group name is required.");
      return;
    }
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    const write = { name: name.trim(), categories: members };
    const call =
      mode.kind === "create"
        ? createCategoryGroup(write, version, signal)
        : updateCategoryGroup(mode.group.id, write, version, signal);
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
            "The category groups changed since you loaded them. The change was not applied — review the refreshed objects and reapply.",
          );
          onCancel();
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance rejected the group."),
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
          ? "New category group"
          : `Edit category group: ${mode.group.name}`
      }
    >
      <DialogBody>
        {mode.kind === "edit" && (
          <p className={styles.refDetail}>
            Object ID <Mono>{mode.group.id}</Mono> — stable across renames;
            referencing Access Rules follow this ID.
          </p>
        )}
        <InputField
          label="Group name"
          required
          value={name}
          disabled={pending}
          onChange={(e) => {
            setName(e.target.value);
          }}
        />
        {renaming && (
          <Callout variant="info" title="This is a rename">
            The stable object ID is preserved, so every referencing Access Rule
            keeps pointing at this same group. The appliance updates the display
            name on referencing rules — in the running policy and in any open
            Policy Draft candidate. A name already used by another group is
            refused.
          </Callout>
        )}
        <fieldset className={styles.editorGroup}>
          <legend>Member categories</legend>
          {categoriesUnavailable && (
            <Callout variant="warning" title="Category list unavailable">
              The authoritative URL-category list could not be loaded. Current
              members are shown and can be removed, but new members cannot be
              selected until it loads.
            </Callout>
          )}
          {universe.known.map((c) => (
            <Checkbox
              key={c}
              label={c}
              checked={memberSet.has(c.toLowerCase())}
              disabled={pending}
              onChange={() => {
                toggle(c, c.toLowerCase());
              }}
            />
          ))}
          {universe.dangling.map((c) => (
            <span key={c}>
              <Checkbox
                label={`${c} (unresolved)`}
                checked
                disabled={pending}
                onChange={() => {
                  toggle(c, c.toLowerCase());
                }}
              />
            </span>
          ))}
        </fieldset>
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
          {mode.kind === "create" ? "Create group" : "Save changes"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
