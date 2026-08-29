// 2D-C.2 — Header Rewrite: per-host HTTP header rewrite rules applied on the
// forward path (request headers before dispatch, response headers before the
// client copy).
//
// Identity model (2D-C): the durable identity is the server-owned `stableId`
// (UUID) — the legacy integer id is process-local compatibility metadata and
// is shown only inside the row detail, never used for addressing or fencing.
//
// ORDER IS SEMANTICS: the table renders the rules in the appliance's actual
// evaluation order — multiple matching rules are applied top-to-bottom. The
// legacy product has no reorder primitive, so this page truthfully renders
// the current order and deliberately offers none (no invented reorder).
//
// Mutations: Create and Delete only — the backend has no rewrite update
// primitive, so no Edit is offered. Every mutation echoes the content-derived
// revision from GET /api/rewrite/state; a mismatch is the shared structured
// revision 409 and nothing was applied.
import { useEffect, useState, type JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  ErrorState,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { InputField, TextareaField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  asRewriteIdentityDegraded,
  createRewriteRule,
  deleteRewriteRule,
  getRewriteState,
  summarizeOps,
} from "../../api/dcobjects";
import type { RewriteRuleView, RewriteRuleWrite } from "../../api/dcobjects";
import { asRevisionConflict } from "../../api/urlcat";
import { useObjectPage } from "../objects/useObjectPage";
import styles from "./policy.module.css";

export function HeaderRewritePage(): JSX.Element {
  const page = useObjectPage(["policies", "header-rewrite"], getRewriteState);
  const q = page.q;
  const snap = q.data;
  const { state } = useAuth();
  const canWrite = hasRole(state.role ?? "viewer", "operator");
  const [openId, setOpenId] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [editorDirty, setEditorDirty] = useState(false);
  const [deleting, setDeleting] = useState<RewriteRuleView | null>(null);
  const [notice, setNotice] = useState("");

  const closeAllWriteState = (): void => {
    setCreating(false);
    setEditorDirty(false);
    setDeleting(null);
    setNotice("");
  };
  page.setBoundaryCleanup(closeAllWriteState);

  const blocked = page.unknown !== null;
  const rules = snap?.rules ?? [];
  const revision = snap?.revision ?? "";
  // Recovery correction: the appliance answers a structured 503 while rewrite
  // MANAGEMENT identity is not durable — the ephemeral StableIDs are never
  // exposed, so no snapshot (and no write controls) render; the page states
  // the truth instead of a generic load failure.
  const identityDegraded =
    snap === undefined && q.isError ? asRewriteIdentityDegraded(q.error) : null;

  const guard = useDirtyGuard(
    editorDirty,
    "the unsaved header-rewrite rule in the editor",
  );

  return (
    <>
      <PageHeader
        title="Header Rewrite"
        subtitle="Per-host HTTP header rewrite rules. Rules are applied in the order shown — every matching rule applies, top to bottom."
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
            review the current rules before making further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh rules
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
        <Skeleton>Loading header-rewrite rules…</Skeleton>
      )}
      {snap === undefined && q.isError && identityDegraded !== null && (
        <ErrorState title="Rewrite management identity is not durable">
          Traffic rewrite enforcement continues, but the appliance refused to
          present rule identities that would not survive a restart, and
          identity-addressed changes are refused until durable identity is
          established. Appliance reason: <Mono>{identityDegraded.reason}</Mono>.
          Fix the settings persistence issue on the appliance and restart it.
        </ErrorState>
      )}
      {snap === undefined && q.isError && identityDegraded === null && (
        <ErrorState title="Header-rewrite rules unavailable">
          The rewrite-rule snapshot could not be loaded. Refresh to try again.
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
                    setCreating(true);
                    setNotice("");
                  }}
                >
                  New rewrite rule…
                </Button>
              </div>
            )}
            <span className={styles.counts}>
              {String(rules.length)} rewrite{" "}
              {rules.length === 1 ? "rule" : "rules"} — applied in the order
              shown
            </span>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">
                Header-rewrite rules in evaluation order
              </caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Details" />
                  <th scope="col" className={styles.numeric}>
                    #
                  </th>
                  <th scope="col">Host scope</th>
                  <th scope="col">Request headers</th>
                  <th scope="col">Response headers</th>
                  {canWrite && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 && (
                  <tr>
                    <td colSpan={canWrite ? 6 : 5}>
                      No header-rewrite rules are defined.
                    </td>
                  </tr>
                )}
                {rules.map((r, idx) => (
                  <RewriteRow
                    key={r.stableId !== "" ? r.stableId : `pos-${String(idx)}`}
                    r={r}
                    position={idx + 1}
                    open={openId === r.stableId}
                    canWrite={canWrite}
                    blocked={blocked}
                    onToggle={() => {
                      setOpenId(openId === r.stableId ? null : r.stableId);
                    }}
                    onDelete={() => {
                      setDeleting(r);
                      setNotice("");
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {creating && canWrite && snap !== undefined && (
        <RewriteEditor
          revision={revision}
          blocked={blocked}
          page={page}
          onDone={() => {
            setCreating(false);
            setEditorDirty(false);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setCreating(false);
            setEditorDirty(false);
          }}
          onDirtyChange={setEditorDirty}
          onConflictNotice={setNotice}
        />
      )}

      {deleting !== null && canWrite && (
        <RewriteDeleteDialog
          rule={deleting}
          revision={revision}
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

function hostScopeLabel(host: string): string {
  return host === "" ? "All hosts" : host;
}

function RewriteRow({
  r,
  position,
  open,
  canWrite,
  blocked,
  onToggle,
  onDelete,
}: {
  r: RewriteRuleView;
  position: number;
  open: boolean;
  canWrite: boolean;
  blocked: boolean;
  onToggle: () => void;
  onDelete: () => void;
}): JSX.Element {
  return (
    <>
      <tr className={styles.ruleRow}>
        <td>
          <Button
            size="sm"
            variant="ghost"
            aria-expanded={open}
            aria-label={`Details for rewrite rule ${String(position)}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </Button>
        </td>
        <td className={styles.numeric}>{String(position)}</td>
        <td>{r.host === "" ? <em>All hosts</em> : <Mono>{r.host}</Mono>}</td>
        <td className={styles.refDetail}>
          {summarizeOps(r.reqSet, r.reqAdd, r.reqRemove)}
        </td>
        <td className={styles.refDetail}>
          {summarizeOps(r.respSet, r.respAdd, r.respRemove)}
        </td>
        {canWrite && (
          <td>
            <span className={styles.rowActions}>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked || r.stableId === ""}
                aria-label={`Delete rewrite rule ${String(position)}`}
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
                  <dt className={styles.refDetail}>Stable ID</dt>
                  <dd>
                    <Mono>
                      {r.stableId === "" ? "(not assigned)" : r.stableId}
                    </Mono>
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Legacy numeric id</dt>
                  <dd>
                    <Mono>{String(r.legacyId)}</Mono> (process-local — not an
                    identity)
                  </dd>
                </div>
                <div>
                  <dt className={styles.refDetail}>Host scope</dt>
                  <dd>{hostScopeLabel(r.host)}</dd>
                </div>
              </dl>
              <OpsDetail
                title="Request headers"
                set={r.reqSet}
                add={r.reqAdd}
                remove={r.reqRemove}
              />
              <OpsDetail
                title="Response headers"
                set={r.respSet}
                add={r.respAdd}
                remove={r.respRemove}
              />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function OpsDetail({
  title,
  set,
  add,
  remove,
}: {
  title: string;
  set: Readonly<Record<string, string>>;
  add: Readonly<Record<string, string>>;
  remove: readonly string[];
}): JSX.Element {
  const setKeys = Object.keys(set);
  const addKeys = Object.keys(add);
  const empty =
    setKeys.length === 0 && addKeys.length === 0 && remove.length === 0;
  return (
    <div>
      <p className={styles.refDetail}>{title}</p>
      {empty ? (
        <p className={styles.refDetail}>No operations.</p>
      ) : (
        <ul>
          {setKeys.map((k) => (
            <li key={`set-${k}`}>
              Set <Mono>{k}</Mono> → <Mono>{set[k] ?? ""}</Mono>
            </li>
          ))}
          {addKeys.map((k) => (
            <li key={`add-${k}`}>
              Add <Mono>{k}</Mono> → <Mono>{add[k] ?? ""}</Mono>
            </li>
          ))}
          {remove.map((k) => (
            <li key={`rm-${k}`}>
              Remove <Mono>{k}</Mono>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Delete ──────────────────────────────────────────────────────────────────
//
// Rewrite rules have no reference graph (nothing links to a rewrite rule), so
// this is a plain T2 confirm — no Where Used preflight. The revision fence
// still guards against deleting a rule based on a stale view of the list.

function RewriteDeleteDialog<T>({
  rule,
  revision,
  page,
  onDone,
  onCancel,
  onConflictNotice,
}: {
  rule: RewriteRuleView;
  revision: string;
  page: ReturnType<typeof useObjectPage<T>>;
  onDone: () => void;
  onCancel: () => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");

  const confirm = (): void => {
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    deleteRewriteRule(rule.stableId, revision, signal)
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("delete");
          onCancel();
          return;
        }
        if (asRevisionConflict(err) !== null) {
          onConflictNotice(
            "The rewrite rules changed since you loaded them. The delete was not applied — review the refreshed rules and retry.",
          );
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance refused the delete."),
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
      onClose={() => {
        if (!pending) onCancel();
      }}
      title="Delete rewrite rule"
      closeOnEscape={!pending}
    >
      <DialogBody>
        <p>
          This deletes the header-rewrite rule for{" "}
          <strong>{hostScopeLabel(rule.host)}</strong> (
          {summarizeOps(rule.reqSet, rule.reqAdd, rule.reqRemove)} /{" "}
          {summarizeOps(rule.respSet, rule.respAdd, rule.respRemove)}). Later
          rules move up one position; their identities are unchanged.
        </p>
        <p className={styles.refDetail}>
          Stable ID <Mono>{rule.stableId}</Mono>
        </p>
        {serverError !== "" && (
          <Callout variant="critical" title="Delete failed" role="alert">
            {serverError}
          </Callout>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" disabled={pending} onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="danger" disabled={pending} onClick={confirm}>
          Delete
        </Button>
      </DialogFooter>
    </Dialog>
  );
}

// ── Editor (create only — the backend has no rewrite update primitive) ──────

interface ParsedMap {
  map: Record<string, string>;
  errors: readonly string[];
}

/** Parse "Header-Name: value" lines into a header map. Duplicate names within
 * one section keep the LAST value (a map can hold one value per name). */
export function parseHeaderMapLines(text: string): ParsedMap {
  const map: Record<string, string> = {};
  const errors: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    const idx = line.indexOf(":");
    if (idx <= 0) {
      errors.push(`"${line}" — expected the form "Header-Name: value".`);
      continue;
    }
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (name === "") {
      errors.push(`"${line}" — the header name is empty.`);
      continue;
    }
    map[name] = value;
  }
  return { map, errors };
}

/** Parse one header NAME per line (for the Remove sections). */
export function parseHeaderNameLines(text: string): readonly string[] {
  const out: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line !== "") out.push(line);
  }
  return out;
}

function RewriteEditor<T>({
  revision,
  blocked,
  page,
  onDone,
  onCancel,
  onDirtyChange,
  onConflictNotice,
}: {
  revision: string;
  blocked: boolean;
  page: ReturnType<typeof useObjectPage<T>>;
  onDone: () => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const [host, setHost] = useState("");
  const [reqSetText, setReqSetText] = useState("");
  const [reqAddText, setReqAddText] = useState("");
  const [reqRemoveText, setReqRemoveText] = useState("");
  const [respSetText, setRespSetText] = useState("");
  const [respAddText, setRespAddText] = useState("");
  const [respRemoveText, setRespRemoveText] = useState("");
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");

  const dirty =
    host !== "" ||
    reqSetText !== "" ||
    reqAddText !== "" ||
    reqRemoveText !== "" ||
    respSetText !== "" ||
    respAddText !== "" ||
    respRemoveText !== "";
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);

  const reqSet = parseHeaderMapLines(reqSetText);
  const reqAdd = parseHeaderMapLines(reqAddText);
  const respSet = parseHeaderMapLines(respSetText);
  const respAdd = parseHeaderMapLines(respAddText);
  const reqRemove = parseHeaderNameLines(reqRemoveText);
  const respRemove = parseHeaderNameLines(respRemoveText);
  const parseErrors = [
    ...reqSet.errors,
    ...reqAdd.errors,
    ...respSet.errors,
    ...respAdd.errors,
  ];
  const opCount =
    Object.keys(reqSet.map).length +
    Object.keys(reqAdd.map).length +
    reqRemove.length +
    Object.keys(respSet.map).length +
    Object.keys(respAdd.map).length +
    respRemove.length;

  const submit = (): void => {
    if (parseErrors.length > 0) {
      setServerError("Fix the header lines flagged below first.");
      return;
    }
    if (opCount === 0) {
      setServerError(
        "At least one header operation (set, add, or remove) is required.",
      );
      return;
    }
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    const write: RewriteRuleWrite = {
      host: host.trim(),
      reqSet: reqSet.map,
      reqAdd: reqAdd.map,
      reqRemove,
      respSet: respSet.map,
      respAdd: respAdd.map,
      respRemove,
    };
    createRewriteRule(write, revision, signal)
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("create");
          onCancel();
          return;
        }
        if (asRevisionConflict(err) !== null) {
          onConflictNotice(
            "The rewrite rules changed since you loaded them. The rule was not created — review the refreshed rules and reapply.",
          );
          onCancel();
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance rejected the rule."),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
        setPending(false);
      });
  };

  return (
    <Dialog open onClose={onCancel} title="New header-rewrite rule">
      <DialogBody>
        <InputField
          label="Host scope"
          value={host}
          disabled={pending}
          placeholder="example.com, *.example.com — empty applies to all hosts"
          onChange={(e) => {
            setHost(e.target.value);
          }}
        />
        <p className={styles.refDetail}>
          Exact host (<Mono>example.com</Mono>), wildcard subdomains (
          <Mono>*.example.com</Mono>), or empty for every host. New rules are
          appended after the existing rules — multiple matching rules are
          applied in the displayed order.
        </p>

        <p className={styles.refDetail}>Request headers</p>
        <TextareaField
          label="Set (Header-Name: value, one per line — replaces any existing value)"
          value={reqSetText}
          rows={3}
          disabled={pending}
          onChange={(e) => {
            setReqSetText(e.target.value);
          }}
        />
        <TextareaField
          label="Add (Header-Name: value, one per line — appends a value)"
          value={reqAddText}
          rows={3}
          disabled={pending}
          onChange={(e) => {
            setReqAddText(e.target.value);
          }}
        />
        <TextareaField
          label="Remove (header name, one per line)"
          value={reqRemoveText}
          rows={3}
          disabled={pending}
          onChange={(e) => {
            setReqRemoveText(e.target.value);
          }}
        />

        <p className={styles.refDetail}>Response headers</p>
        <TextareaField
          label="Set (Header-Name: value, one per line — replaces any existing value)"
          value={respSetText}
          rows={3}
          disabled={pending}
          onChange={(e) => {
            setRespSetText(e.target.value);
          }}
        />
        <TextareaField
          label="Add (Header-Name: value, one per line — appends a value)"
          value={respAddText}
          rows={3}
          disabled={pending}
          onChange={(e) => {
            setRespAddText(e.target.value);
          }}
        />
        <TextareaField
          label="Remove (header name, one per line)"
          value={respRemoveText}
          rows={3}
          disabled={pending}
          onChange={(e) => {
            setRespRemoveText(e.target.value);
          }}
        />

        <p className={styles.refDetail}>
          {String(opCount)} header {opCount === 1 ? "operation" : "operations"}{" "}
          defined. The appliance assigns the rule&apos;s durable identity on
          create.
        </p>

        {parseErrors.length > 0 && (
          <Callout variant="warning" title="Lines that could not be parsed">
            <ul>
              {parseErrors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </Callout>
        )}
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
          Create rule
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
