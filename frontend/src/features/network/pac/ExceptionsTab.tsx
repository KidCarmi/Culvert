// 2F-E — DIRECT-exception governance: every DIRECT-capable profile must be
// owned and justified. Records are NODE-LOCAL (fenced by revision; off
// config-version rollback and cluster sync — "off rollback" ≠ "unfenced").
// Evidence class is CONFIG: what the configuration makes reachable, never
// observed usage.
import { useState, type JSX } from "react";
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
  deletePacException,
  getPacExceptions,
  getPacInventory,
  putPacException,
} from "../../../api/pac";
import type {
  PacExceptionInput,
  PacExceptionView,
  PacFenceRefusal,
  PacIssuesRefusal,
} from "../../../api/pac";
import { FenceCallout, IssuesCallout } from "./pacShared";
import styles from "../../policy/policy.module.css";

interface Listing {
  exceptions: readonly PacExceptionView[];
  inventory: {
    totalProfiles: number;
    directCapableProfiles: number;
    servingDirectProfiles: number;
    totalDirectPaths: number;
    broadDirectPaths: number;
    evidenceClass: string;
  };
}

async function loadListing(signal: AbortSignal): Promise<Listing> {
  const [exceptions, inv] = await Promise.all([
    getPacExceptions(signal),
    getPacInventory(signal),
  ]);
  return { exceptions, inventory: inv };
}

type Editor =
  | { kind: "closed" }
  | {
      kind: "edit";
      view: PacExceptionView;
      input: PacExceptionInput;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "clear";
      view: PacExceptionView;
      result: ConfirmResult;
      errorText: string;
    };

function statusBadge(s: PacExceptionView["status"]): JSX.Element {
  const map: Record<
    string,
    { status: "ok" | "warn" | "critical" | "neutral"; label: string }
  > = {
    governed: { status: "ok", label: "governed" },
    ungoverned: { status: "critical", label: "ungoverned" },
    expired: { status: "critical", label: "expired" },
    review_due: { status: "warn", label: "review due" },
    "": { status: "neutral", label: "n/a" },
  };
  const m = map[s] ?? { status: "neutral", label: s };
  return <StatusBadge status={m.status}>{m.label}</StatusBadge>;
}

function toInput(v: PacExceptionView): PacExceptionInput {
  const r = v.record;
  return {
    owner: r?.owner ?? "",
    reason: r?.reason ?? "",
    businessApp: r?.businessApp ?? "",
    ticket: r?.ticket ?? "",
    expiresAt: r?.expiresAt ?? "",
    reviewCadenceDays: r?.reviewCadenceDays ?? 0,
    lastReviewedAt: r?.lastReviewedAt ?? "",
  };
}

export function ExceptionsTab({ isAdmin }: { isAdmin: boolean }): JSX.Element {
  const page = useObjectPage(["network", "pac", "exceptions"], loadListing);
  const data = page.q.data;
  const [editor, setEditor] = useState<Editor>({ kind: "closed" });
  const [fence, setFence] = useState<PacFenceRefusal | null>(null);
  const [issues, setIssues] = useState<PacIssuesRefusal | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const fail = (err: unknown, fallback: string): void => {
    const f = asPacFence(err);
    const i = asPacIssues(err);
    if (f !== null) {
      setEditor({ kind: "closed" });
      setFence(f);
      page.refreshToResolve();
    } else if (i !== null) {
      setIssues(i);
      setEditor((e) => (e.kind === "closed" ? e : { ...e, result: "idle" }));
    } else if (unknownOutcome(err)) {
      setEditor({ kind: "closed" });
      page.latchUnknown("edit");
    } else
      setEditor((e) =>
        e.kind === "closed"
          ? e
          : {
              ...e,
              result: "failed",
              errorText: serverErrorText(err, fallback),
            },
      );
  };

  const runSave = async (
    e: Extract<Editor, { kind: "edit" }>,
  ): Promise<void> => {
    setFence(null);
    setIssues(null);
    const signal = page.owner.begin();
    try {
      const rec = await putPacException(
        e.view.profileId,
        e.input,
        e.view.record?.revision,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(
        `Governance for ${e.view.profileId} saved (revision ${String(rec.revision)}, node-local).`,
      );
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Save refused.");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runClear = async (
    e: Extract<Editor, { kind: "clear" }>,
  ): Promise<void> => {
    if (e.view.record === undefined) return;
    setFence(null);
    const signal = page.owner.begin();
    try {
      await deletePacException(
        e.view.profileId,
        e.view.record.revision,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(
        `Governance for ${e.view.profileId} cleared; the profile is ungoverned until a record is set again.`,
      );
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Clear refused.");
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
          hasData={data !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
          }}
        />
      </div>
      <p className={styles.authNote}>
        Node-local governance records (fenced by revision; never cluster-synced,
        never on config-version rollback). Evidence class: config — what the
        configuration makes reachable, not observed usage.
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
      {fence !== null && <FenceCallout fence={fence} tokenLabel="revision" />}
      {issues !== null && <IssuesCallout issues={issues} />}
      {data === undefined && page.q.isPending && (
        <Skeleton>Loading DIRECT posture…</Skeleton>
      )}
      {data === undefined && page.q.isError && (
        <ErrorState title="DIRECT posture unavailable">
          {serverErrorText(page.q.error, "The posture could not be read.")}
        </ErrorState>
      )}
      {data !== undefined && (
        <>
          <Card title="DIRECT posture (evidence: config)">
            <KeyValue
              items={[
                [
                  "DIRECT-capable profiles",
                  `${String(data.inventory.directCapableProfiles)} of ${String(data.inventory.totalProfiles)}`,
                ],
                [
                  "Serving DIRECT paths",
                  String(data.inventory.servingDirectProfiles),
                ],
                ["Total DIRECT paths", String(data.inventory.totalDirectPaths)],
                ["Broad DIRECT paths", String(data.inventory.broadDirectPaths)],
              ]}
            />
          </Card>
          <Card
            title={`Governance (${String(data.exceptions.length)} DIRECT-capable profile(s))`}
          >
            {data.exceptions.length === 0 ? (
              <EmptyState title="No DIRECT-capable profile">
                Nothing bypasses the security path by configuration.
              </EmptyState>
            ) : (
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <caption className={styles.srOnly}>
                    DIRECT exception governance
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Profile</th>
                      <th scope="col">Serving</th>
                      <th scope="col">Status</th>
                      <th scope="col">Owner</th>
                      <th scope="col">Reason</th>
                      <th scope="col">Expires</th>
                      <th scope="col">Review</th>
                      {isAdmin && <th scope="col">Actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {data.exceptions.map((v) => (
                      <tr key={v.profileId}>
                        <td>
                          {v.name} <Mono>{v.profileId}</Mono>
                        </td>
                        <td>{v.serving ? "yes" : "no"}</td>
                        <td>{statusBadge(v.status)}</td>
                        <td>{v.record?.owner ?? "—"}</td>
                        <td>{v.record?.reason ?? "—"}</td>
                        <td>
                          {v.record?.expiresAt !== undefined &&
                          v.record.expiresAt !== ""
                            ? v.record.expiresAt
                            : "—"}
                        </td>
                        <td>
                          {v.record !== undefined &&
                          v.record.reviewCadenceDays > 0
                            ? `${String(v.record.reviewCadenceDays)}d (last ${v.record.lastReviewedAt !== "" ? v.record.lastReviewedAt : "never"})`
                            : "—"}
                        </td>
                        {isAdmin && (
                          <td className={styles.rowActions}>
                            <Button
                              size="sm"
                              disabled={page.unknown !== null}
                              onClick={() => {
                                setEditor({
                                  kind: "edit",
                                  view: v,
                                  input: toInput(v),
                                  result: "idle",
                                  errorText: "",
                                });
                              }}
                            >
                              {v.record === undefined
                                ? "Set governance"
                                : "Edit governance"}
                            </Button>
                            {v.record !== undefined && (
                              <Button
                                size="sm"
                                variant="danger-quiet"
                                disabled={page.unknown !== null}
                                onClick={() => {
                                  setEditor({
                                    kind: "clear",
                                    view: v,
                                    result: "idle",
                                    errorText: "",
                                  });
                                }}
                              >
                                Clear governance
                              </Button>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
      {editor.kind === "edit" && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Govern DIRECT exception — ${editor.view.profileId}`}
          body={
            <div className={styles.editorGroup}>
              <InputField
                label="Owner"
                required
                value={editor.input.owner}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: { ...editor.input, owner: e.target.value },
                  });
                }}
              />
              <TextareaField
                label="Reason"
                required
                rows={2}
                value={editor.input.reason}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: { ...editor.input, reason: e.target.value },
                  });
                }}
              />
              <InputField
                label="Business application"
                value={editor.input.businessApp}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: { ...editor.input, businessApp: e.target.value },
                  });
                }}
              />
              <InputField
                label="Ticket"
                value={editor.input.ticket}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: { ...editor.input, ticket: e.target.value },
                  });
                }}
              />
              <InputField
                label="Expires at (RFC 3339, e.g. 2027-01-31T00:00:00Z)"
                value={editor.input.expiresAt}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: { ...editor.input, expiresAt: e.target.value },
                  });
                }}
              />
              <InputField
                label="Review cadence (days, 0 = none)"
                type="number"
                min={0}
                max={3650}
                value={String(editor.input.reviewCadenceDays)}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: {
                      ...editor.input,
                      reviewCadenceDays: Number(e.target.value) || 0,
                    },
                  });
                }}
              />
              <InputField
                label="Last reviewed at (RFC 3339)"
                value={editor.input.lastReviewedAt}
                onChange={(e) => {
                  setEditor({
                    ...editor,
                    input: { ...editor.input, lastReviewedAt: e.target.value },
                  });
                }}
              />
            </div>
          }
          impact="Records who owns this security-path bypass and why; it does not change what the PAC serves."
          rollback="Edit or clear the record."
          confirmLabel="Save governance"
          result={editor.result}
          {...(editor.errorText !== "" ? { errorText: editor.errorText } : {})}
          onConfirm={() => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            void runSave(editor);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
      {editor.kind === "clear" && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Clear governance — ${editor.view.profileId}`}
          body={
            <p>
              Removes the ownership record; the DIRECT-capable profile becomes
              ungoverned. The PAC itself is unchanged.
            </p>
          }
          impact="The bypass loses its recorded owner and justification."
          rollback="Set governance again."
          confirmLabel="Clear governance"
          result={editor.result}
          {...(editor.errorText !== "" ? { errorText: editor.errorText } : {})}
          onConfirm={() => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            void runClear(editor);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
    </div>
  );
}
