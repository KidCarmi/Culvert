// 2F-E — PAC pools (cluster-synced with the profiles): etag-fenced edits,
// collectionEtag-fenced creation, query-token deletes with the referential
// 409 rendered as the fact it is (a pool still referenced by a profile).
import { useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  Mono,
  Skeleton,
} from "../../../design-system/primitives";
import { InputField, TextareaField } from "../../../design-system/forms";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../../design-system/dialog";
import { SnapshotBar } from "../../../shared/snapshot";
import { useObjectPage } from "../../objects/useObjectPage";
import {
  serverErrorText,
  unknownOutcome,
} from "../../../shared/mutationOutcome";
import {
  asPacFence,
  asPacIssues,
  createPacPool,
  deletePacPool,
  getPacPools,
  getPacProfiles,
  updatePacPool,
} from "../../../api/pac";
import type {
  PacFenceRefusal,
  PacIssuesRefusal,
  PacPoolView,
} from "../../../api/pac";
import { FenceCallout, IssuesCallout } from "./pacShared";
import { shortDigest } from "./pacLifecycle";
import styles from "../../policy/policy.module.css";

type Editor =
  | { kind: "closed" }
  | {
      kind: "create";
      id: string;
      name: string;
      endpoints: string;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "edit";
      pool: PacPoolView;
      name: string;
      endpoints: string;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "delete";
      pool: PacPoolView;
      result: ConfirmResult;
      errorText: string;
    };

function parseEndpoints(
  text: string,
): { host: string; port: number }[] | string {
  const out: { host: string; port: number }[] = [];
  for (const line of text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "")) {
    const idx = line.lastIndexOf(":");
    const port = Number(line.slice(idx + 1));
    if (idx <= 0 || !Number.isInteger(port) || port <= 0 || port > 65535)
      return `"${line}" is not host:port`;
    out.push({ host: line.slice(0, idx), port });
  }
  return out;
}

export function PoolsTab({ isAdmin }: { isAdmin: boolean }): JSX.Element {
  const page = useObjectPage(["network", "pac", "pools"], getPacPools);
  const pools = page.q.data;
  const [editor, setEditor] = useState<Editor>({ kind: "closed" });
  const [fence, setFence] = useState<{
    fence: PacFenceRefusal;
    token: string;
  } | null>(null);
  const [issues, setIssues] = useState<PacIssuesRefusal | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const fail = (err: unknown, fallback: string): void => {
    const f = asPacFence(err);
    const i = asPacIssues(err);
    if (f !== null) {
      setEditor({ kind: "closed" });
      setFence({
        fence: f,
        token: f.current["etag"] !== undefined ? "etag" : "collectionEtag",
      });
      page.refreshToResolve();
    } else if (i !== null) {
      setIssues(i);
      setEditor((e) => (e.kind === "closed" ? e : { ...e, result: "idle" }));
    } else if (unknownOutcome(err)) {
      setEditor({ kind: "closed" });
      page.latchUnknown("edit");
    } else {
      setEditor((e) =>
        e.kind === "closed"
          ? e
          : {
              ...e,
              result: "failed",
              errorText: serverErrorText(err, fallback),
            },
      );
    }
  };

  const runCreate = async (
    e: Extract<Editor, { kind: "create" }>,
  ): Promise<void> => {
    const eps = parseEndpoints(e.endpoints);
    if (typeof eps === "string") {
      setEditor({ ...e, result: "failed", errorText: eps });
      return;
    }
    setIssues(null);
    setFence(null);
    const signal = page.owner.begin();
    try {
      const l = await getPacProfiles(signal);
      const created = await createPacPool(
        { id: e.id.trim(), name: e.name.trim(), endpoints: eps },
        l.collectionEtag,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(`Pool ${created.id} created.`);
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Create refused.");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runEdit = async (
    e: Extract<Editor, { kind: "edit" }>,
  ): Promise<void> => {
    const eps = parseEndpoints(e.endpoints);
    if (typeof eps === "string") {
      setEditor({ ...e, result: "failed", errorText: eps });
      return;
    }
    setIssues(null);
    setFence(null);
    const signal = page.owner.begin();
    try {
      await updatePacPool(
        e.pool.id,
        { id: e.pool.id, name: e.name.trim(), endpoints: eps },
        e.pool.etag,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(
        `Pool ${e.pool.id} updated. Profiles referencing it now report a changed pool until they are published again.`,
      );
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Update refused.");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runDelete = async (
    e: Extract<Editor, { kind: "delete" }>,
  ): Promise<void> => {
    setFence(null);
    const signal = page.owner.begin();
    try {
      await deletePacPool(e.pool.id, e.pool.etag, signal);
      setEditor({ kind: "closed" });
      setNotice(`Pool ${e.pool.id} deleted.`);
      page.refreshToResolve();
    } catch (err) {
      fail(
        err,
        "Delete refused (a profile or rule may still reference this pool).",
      );
    } finally {
      page.owner.settle(signal);
    }
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={pools !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
          }}
        />
        {isAdmin && pools !== undefined && page.unknown === null && (
          <Button
            size="sm"
            variant="primary"
            onClick={() => {
              setEditor({
                kind: "create",
                id: "",
                name: "",
                endpoints: "",
                result: "idle",
                errorText: "",
              });
            }}
          >
            New pool
          </Button>
        )}
      </div>
      <p className={styles.authNote}>
        Pools are part of the cluster-synced PAC configuration; a pool change is
        recorded against every profile that references it (poolChangedSince)
        until that profile is published again.
      </p>
      {page.unknown !== null && (
        <Callout variant="unknown" title="Last change unconfirmed" role="alert">
          A request was sent but no result was observed. Refresh to resolve
          before further changes.
        </Callout>
      )}
      {notice !== null && (
        <Callout variant="success" role="status">
          {notice}
        </Callout>
      )}
      {fence !== null && (
        <FenceCallout fence={fence.fence} tokenLabel={fence.token} />
      )}
      {issues !== null && <IssuesCallout issues={issues} />}
      {pools === undefined && page.q.isPending && (
        <Skeleton>Loading pools…</Skeleton>
      )}
      {pools === undefined && page.q.isError && (
        <ErrorState title="Pools unavailable">
          {serverErrorText(page.q.error, "The pools could not be read.")}
        </ErrorState>
      )}
      {pools !== undefined && (
        <Card title={`Pools (${String(pools.length)})`}>
          {pools.length === 0 ? (
            <EmptyState title="No pools">
              A pool names up to three proxy endpoints a profile or rule steers
              traffic to.
            </EmptyState>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className={styles.srOnly}>PAC pools</caption>
                <thead>
                  <tr>
                    <th scope="col">Id</th>
                    <th scope="col">Name</th>
                    <th scope="col">Endpoints</th>
                    <th scope="col">Etag</th>
                    {isAdmin && <th scope="col">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {pools.map((pool) => (
                    <tr key={pool.id}>
                      <td>
                        <Mono>{pool.id}</Mono>
                      </td>
                      <td>{pool.name}</td>
                      <td>
                        {pool.endpoints
                          .map((e) => `${e.host}:${String(e.port)}`)
                          .join(", ")}
                      </td>
                      <td>
                        <Mono>{shortDigest(pool.etag)}</Mono>
                      </td>
                      {isAdmin && (
                        <td className={styles.rowActions}>
                          <Button
                            size="sm"
                            disabled={page.unknown !== null}
                            onClick={() => {
                              setEditor({
                                kind: "edit",
                                pool,
                                name: pool.name,
                                endpoints: pool.endpoints
                                  .map((e) => `${e.host}:${String(e.port)}`)
                                  .join("\n"),
                                result: "idle",
                                errorText: "",
                              });
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="danger-quiet"
                            disabled={page.unknown !== null}
                            onClick={() => {
                              setEditor({
                                kind: "delete",
                                pool,
                                result: "idle",
                                errorText: "",
                              });
                            }}
                          >
                            Delete pool
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
      {(editor.kind === "create" || editor.kind === "edit") && (
        <ConfirmationDialog
          open
          tier={2}
          title={
            editor.kind === "create"
              ? "New pool"
              : `Edit pool ${editor.pool.id}`
          }
          body={
            <div className={styles.editorGroup}>
              {editor.kind === "create" && (
                <InputField
                  label="Id"
                  value={editor.id}
                  onChange={(e) => {
                    setEditor({ ...editor, id: e.target.value });
                  }}
                />
              )}
              <InputField
                label="Name"
                value={editor.name}
                onChange={(e) => {
                  setEditor({ ...editor, name: e.target.value });
                }}
              />
              <TextareaField
                label="Endpoints (host:port, one per line, max 3)"
                rows={3}
                value={editor.endpoints}
                onChange={(e) => {
                  setEditor({ ...editor, endpoints: e.target.value });
                }}
              />
            </div>
          }
          impact={
            editor.kind === "create"
              ? "The pool becomes referenceable by profiles and rules."
              : "Every profile referencing this pool serves the new endpoints on its next publish; until then it reports poolChangedSince."
          }
          rollback="Edit the pool again."
          confirmLabel={editor.kind === "create" ? "Create pool" : "Save pool"}
          result={editor.result}
          {...(editor.errorText !== "" ? { errorText: editor.errorText } : {})}
          onConfirm={() => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            if (editor.kind === "create") void runCreate(editor);
            else void runEdit(editor);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
      {editor.kind === "delete" && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Delete pool ${editor.pool.id}`}
          body={
            <p>
              The appliance refuses while any profile or rule still references
              the pool.
            </p>
          }
          impact="Profiles can no longer reference this pool."
          rollback="Recreate the pool with the same endpoints."
          confirmLabel="Delete pool"
          result={editor.result}
          {...(editor.errorText !== "" ? { errorText: editor.errorText } : {})}
          onConfirm={() => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            void runDelete(editor);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
    </div>
  );
}
