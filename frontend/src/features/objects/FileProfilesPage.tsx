// 2D-C.1 — File Profiles: named file-extension block sets Access Rules
// reference for per-rule file-type control.
//
// Reference model (2D-C): the stable object ID is the authoritative link —
// PolicyRule.fileProfileId is stamped SERVER-side from the submitted name and
// a rename cascades the display name (running + draft candidate) while every
// rule keeps enforcing the SAME profile identity. This page addresses every
// mutation by stable ID and never touches policy rules.
//
// Fence: the content-derived revision from GET /api/fileblock/profiles/state
// is echoed on every mutation; comparison happens inside the store's critical
// section and a mismatch is the shared structured revision 409.
//
// Delete integrity: the server's reference walk (running rules AND an active
// draft candidate) is authoritative — the dialog pre-fetches Where Used for
// clarity, but a concurrent reference still fails safely as the structured
// 409 rendered with the real consumers.
import { useEffect, useState, type JSX } from "react";
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
import { InputField, TextareaField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  createFileProfile,
  deleteFileProfile,
  getFileProfileState,
  previewNormalizedExtensions,
  updateFileProfile,
} from "../../api/dcobjects";
import type { FileProfileView } from "../../api/dcobjects";
import { asRevisionConflict } from "../../api/urlcat";
import { WhereUsed } from "../policy/WhereUsed";
import { useObjectPage } from "./useObjectPage";
import { ObjectDeleteDialog } from "./ObjectDeleteDialog";
import styles from "../policy/policy.module.css";

type EditorMode =
  { kind: "create" } | { kind: "edit"; profile: FileProfileView };

export function FileProfilesPage(): JSX.Element {
  const page = useObjectPage(["objects", "file-profiles"], getFileProfileState);
  const q = page.q;
  const snap = q.data;
  const { state } = useAuth();
  const canWrite = hasRole(state.role ?? "viewer", "operator");
  const [openId, setOpenId] = useState<string | null>(null);
  const [params] = useSearchParams();

  const [editor, setEditor] = useState<EditorMode | null>(null);
  const [editorDirty, setEditorDirty] = useState(false);
  const [deleting, setDeleting] = useState<FileProfileView | null>(null);
  const [notice, setNotice] = useState("");

  const closeAllWriteState = (): void => {
    setEditor(null);
    setEditorDirty(false);
    setDeleting(null);
    setNotice("");
  };
  page.setBoundaryCleanup(closeAllWriteState);

  const blocked = page.unknown !== null;
  const profiles = snap?.profiles ?? [];
  const revision = snap?.revision ?? "";

  const guard = useDirtyGuard(
    editorDirty,
    "the unsaved file-profile changes in the editor",
  );

  const linkedId = params.get("id");
  useEffect(() => {
    if (linkedId !== null && linkedId !== "") setOpenId(linkedId);
  }, [linkedId]);

  return (
    <>
      <PageHeader
        title="File Profiles"
        subtitle="Named file-extension sets that Access Rules enforce as per-rule file-type blocking. Rules link by the stable object ID — renames follow the same object."
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

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the {page.unknown} may or may not have been applied. Refresh and
            review the current profiles before making further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh profiles
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
        <Skeleton>Loading file profiles…</Skeleton>
      )}
      {snap === undefined && q.isError && (
        <ErrorState title="File profiles unavailable">
          The file-profile snapshot could not be loaded. Refresh to try again.
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
                  New file profile…
                </Button>
              </div>
            )}
            <span className={styles.counts}>
              {String(profiles.length)} file{" "}
              {profiles.length === 1 ? "profile" : "profiles"}
            </span>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">File profiles</caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Details" />
                  <th scope="col">Name</th>
                  <th scope="col">Type</th>
                  <th scope="col" className={styles.numeric}>
                    Extensions
                  </th>
                  {canWrite && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {profiles.length === 0 && (
                  <tr>
                    <td colSpan={canWrite ? 5 : 4}>
                      No file profiles are defined.
                    </td>
                  </tr>
                )}
                {profiles.map((p) => (
                  <ProfileRow
                    key={p.id}
                    p={p}
                    open={openId === p.id}
                    canWrite={canWrite}
                    blocked={blocked}
                    highlighted={linkedId === p.id}
                    onToggle={() => {
                      setOpenId(openId === p.id ? null : p.id);
                    }}
                    onEdit={() => {
                      setEditor({ kind: "edit", profile: p });
                      setNotice("");
                    }}
                    onDelete={() => {
                      setDeleting(p);
                      setNotice("");
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {editor !== null && canWrite && snap !== undefined && (
        <ProfileEditor
          mode={editor}
          revision={revision}
          blocked={blocked}
          page={page}
          onDone={() => {
            setEditor(null);
            setEditorDirty(false);
            page.refreshToResolve();
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
          objType="file-profile"
          objName={deleting.name}
          objId={deleting.id}
          body={
            <>
              This deletes the file profile <strong>{deleting.name}</strong> (
              <Mono>{deleting.id}</Mono>, {String(deleting.extensions.length)}{" "}
              {deleting.extensions.length === 1 ? "extension" : "extensions"}).
              The delete is refused while any Access Rule — running or staged in
              an active Policy Draft — references it.
            </>
          }
          doDelete={(signal) =>
            deleteFileProfile(deleting.id, revision, signal)
          }
          page={page}
          onDone={() => {
            setDeleting(null);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setDeleting(null);
          }}
          onConflictNotice={(text) => {
            setDeleting(null);
            setNotice(text);
            page.refreshToResolve();
          }}
        />
      )}
      {guard.element}
    </>
  );
}

function ProfileRow({
  p,
  open,
  canWrite,
  blocked,
  highlighted,
  onToggle,
  onEdit,
  onDelete,
}: {
  p: FileProfileView;
  open: boolean;
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
            aria-label={`Details for profile ${p.name}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </Button>
        </td>
        <td>{p.name}</td>
        <td>
          {p.builtIn ? (
            <StatusBadge status="info">Built-in</StatusBadge>
          ) : (
            "Custom"
          )}
        </td>
        <td className={styles.numeric}>{String(p.extensions.length)}</td>
        {canWrite && (
          <td>
            <span className={styles.rowActions}>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                aria-label={`Edit profile ${p.name}`}
                onClick={onEdit}
              >
                Edit
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                aria-label={`Delete profile ${p.name}`}
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
          <td colSpan={canWrite ? 5 : 4}>
            <div className={styles.rowDetail}>
              <dl className={styles.kvGrid}>
                <div>
                  <dt className={styles.refDetail}>Object ID</dt>
                  <dd>
                    <Mono>{p.id}</Mono>
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Blocked extensions</dt>
                  <dd>
                    <Mono>
                      {p.extensions.length === 0
                        ? "none"
                        : p.extensions.join(" ")}
                    </Mono>
                  </dd>
                </div>
              </dl>
              {p.builtIn && (
                <Callout variant="info" title="Seeded built-in profile">
                  This profile was seeded at first run. It can be edited,
                  renamed, or deleted like any profile — referencing rules
                  follow its stable object ID, and legacy rules naming a removed
                  built-in fall back to the compiled extension set.
                </Callout>
              )}
              <WhereUsed type="file-profile" name={p.name} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Editor ──────────────────────────────────────────────────────────────────

function ProfileEditor({
  mode,
  revision,
  blocked,
  page,
  onDone,
  onCancel,
  onDirtyChange,
  onConflictNotice,
}: {
  mode: EditorMode;
  revision: string;
  blocked: boolean;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getFileProfileState>>>
  >;
  onDone: () => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const emptyInitial: Pick<FileProfileView, "id" | "name" | "extensions"> = {
    id: "",
    name: "",
    extensions: [],
  };
  const initial = mode.kind === "edit" ? mode.profile : emptyInitial;
  const [name, setName] = useState(initial.name);
  const [extText, setExtText] = useState(initial.extensions.join("\n"));
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");

  const lines = extText.split("\n");
  const normalized = previewNormalizedExtensions(lines);
  const dirty =
    name !== initial.name || extText !== initial.extensions.join("\n");
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);

  const renaming =
    mode.kind === "edit" &&
    name.trim() !== "" &&
    name.trim().toLowerCase() !== mode.profile.name.toLowerCase();

  const submit = (): void => {
    if (name.trim() === "") {
      setServerError("A profile name is required.");
      return;
    }
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    const write = { name: name.trim(), extensions: normalized };
    const call =
      mode.kind === "create"
        ? createFileProfile(write, revision, signal).then(() => undefined)
        : updateFileProfile(mode.profile.id, write, revision, signal);
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
        if (asRevisionConflict(err) !== null) {
          onConflictNotice(
            "The file profiles changed since you loaded them. The change was not applied — review the refreshed profiles and reapply.",
          );
          onCancel();
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance rejected the profile."),
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
          ? "New file profile"
          : `Edit file profile: ${mode.profile.name}`
      }
    >
      <DialogBody>
        {mode.kind === "edit" && (
          <p className={styles.refDetail}>
            Object ID <Mono>{mode.profile.id}</Mono> — stable across renames;
            referencing Access Rules follow this ID.
          </p>
        )}
        <InputField
          label="Profile name"
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
            keeps enforcing this same profile. The appliance updates the display
            name on referencing rules — in the running policy and in any open
            Policy Draft candidate. A name already used by another profile is
            refused.
          </Callout>
        )}
        <TextareaField
          label="Blocked extensions (one per line)"
          value={extText}
          rows={8}
          disabled={pending}
          onChange={(e) => {
            setExtText(e.target.value);
          }}
        />
        <p className={styles.refDetail}>
          Saved as {String(normalized.length)} normalized{" "}
          {normalized.length === 1 ? "extension" : "extensions"}
          {normalized.length > 0 && (
            <>
              : <Mono>{normalized.join(" ")}</Mono>
            </>
          )}
          . The appliance lowercases, adds the leading dot, and de-duplicates —
          the list above previews that result; the saved profile shows the
          appliance&apos;s normalization.
        </p>
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
          {mode.kind === "create" ? "Create profile" : "Save changes"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
