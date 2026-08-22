// FE-4 Diagnostics (§13/§14 + hardening rounds): the /api/diagnostics
// operator contract is a SNAPSHOT — verdict, generated_at, and per-check
// {code, status, message, operator_action}, with operator_action rendered
// first-class on every warn/fail row. Active /api/diagnose/{verb} runs
// perform probe work and therefore run ONLY on explicit operator action —
// never automatically, never retried. All NINE backend verbs are exposed
// (storage/upstream/dns/tls/cluster/etcd/config/support/all — the fixed
// server registry, all operator+). Results decode through PER-VERB runtime
// contracts (src/api/diagnose.ts) fail-closed and render through a
// deliberate presentation model — summary rows, check/proxy/utilization
// tables, and nested sub-results for `all` — never a raw JSON dump, never
// HTML. The in-flight run request is OWNED by an AbortController wired to
// unmount and the FE-3 authentication boundary (§10).
import { useEffect, useRef, useState } from "react";
import type { JSX } from "react";
import { useMutation } from "@tanstack/react-query";
import { getDiagnostics } from "../../api/ops";
import { runDiagnose, DIAGNOSE_VERBS } from "../../api/diagnose";
import type { DiagnoseVerb, DiagnoseView } from "../../api/diagnose";
import { ApiError } from "../../api/client";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { registerAuthCleanup } from "../../auth/teardown";
import { PageHeader } from "../../layouts/AppShell";
import { DiagnosticsResult } from "../../design-system/appliance";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { DataTable } from "../../design-system/table";
import { InputField } from "../../design-system/forms";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { createDiagnoseRunOwner } from "./runOwner";
import styles from "./diagnostics.module.css";

const statusLabel: Record<"ok" | "warn" | "fail", string> = {
  ok: "OK",
  warn: "Warning",
  fail: "Failing",
};

const statusMap = { ok: "ok", warn: "warn", fail: "critical" } as const;

// Verbs that take a target parameter (bounded, SSRF-guarded server-side).
const VERB_TARGET: Partial<
  Record<DiagnoseVerb, { label: string; key: string }>
> = {
  dns: { label: "Hostname to resolve", key: "host" },
  tls: { label: "host:port to check", key: "target" },
};

function DiagnoseResultView({ view }: { view: DiagnoseView }): JSX.Element {
  return (
    <div className={styles.runResult}>
      <KeyValue
        items={view.summary.map(
          (kv) =>
            [
              kv.label,
              kv.status !== undefined ? (
                <StatusBadge key={kv.label} status={kv.status}>
                  {kv.value}
                </StatusBadge>
              ) : (
                kv.value
              ),
            ] as const,
        )}
      />
      {view.tables.map((tbl) => (
        <div key={tbl.title} className={styles.runTable}>
          <DataTable
            caption={tbl.title}
            columns={tbl.headers.map((h, i) => ({
              key: h,
              header: h,
              render: (r: readonly string[]) => r[i] ?? "",
            }))}
            rows={tbl.rows}
            rowKey={(r) => r.join("|")}
          />
        </div>
      ))}
      {view.sub.map((s) => (
        <section key={s.verb} className={styles.subResult}>
          <h3 className={styles.subTitle}>{s.verb}</h3>
          <DiagnoseResultView view={s} />
        </section>
      ))}
    </div>
  );
}

function ActiveDiagnostics(): JSX.Element {
  const [verb, setVerb] = useState<DiagnoseVerb>("storage");
  const [target, setTarget] = useState("");
  // One AbortController per active run, owned here (§10): a new run aborts
  // its predecessor; unmount and the auth boundary abort the active run.
  const ownerRef = useRef(createDiagnoseRunOwner());
  useEffect(() => {
    const owner = ownerRef.current;
    const unregister = registerAuthCleanup(() => {
      owner.abort();
    });
    return () => {
      unregister();
      owner.abort();
    };
  }, []);
  const run = useMutation<DiagnoseView, unknown, void>({
    mutationFn: () => {
      const owner = ownerRef.current;
      const signal = owner.begin();
      const spec = VERB_TARGET[verb];
      return runDiagnose(
        verb,
        spec !== undefined ? { [spec.key]: target } : undefined,
        signal,
      ).finally(() => {
        owner.settle(signal);
      });
    },
  });
  const spec = VERB_TARGET[verb];
  const err = run.error;
  return (
    <Card title="Run a diagnostic">
      <p className={styles.runHint}>
        Active diagnostics may perform local probes or bounded network checks
        and are audited. They run only when you start them.
      </p>
      <div className={styles.runBar}>
        <div className={styles.verbGroup} role="group" aria-label="Diagnostic">
          {DIAGNOSE_VERBS.map((v) => (
            <button
              key={v}
              type="button"
              className={styles.verbBtn}
              aria-pressed={verb === v}
              onClick={() => {
                setVerb(v);
                run.reset();
              }}
            >
              {v}
            </button>
          ))}
        </div>
        {spec !== undefined && (
          <InputField
            label={spec.label}
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
            }}
          />
        )}
        <Button
          variant="primary"
          disabled={
            run.isPending || (spec !== undefined && target.trim() === "")
          }
          onClick={() => {
            run.mutate();
          }}
        >
          {run.isPending ? "Running…" : `Run ${verb} diagnostic`}
        </Button>
      </div>
      {err !== null && (
        <Callout variant="critical" role="alert">
          {err instanceof ApiError && err.kind === "decode"
            ? "The diagnostic returned an unsupported or malformed result schema — not rendered."
            : err instanceof ApiError &&
                err.bodyText !== undefined &&
                err.bodyText !== ""
              ? err.bodyText
              : "The diagnostic could not be completed."}
        </Callout>
      )}
      {run.data !== undefined && <DiagnoseResultView view={run.data} />}
    </Card>
  );
}

export function DiagnosticsPage(): JSX.Element {
  const { state } = useAuth();
  const q = useSnapshot(["ops", "diagnostics"], getDiagnostics);
  const snap = q.data;
  const canRun = state.role !== null && hasRole(state.role, "operator");
  return (
    <>
      <PageHeader
        title="Diagnostics"
        subtitle="Operator contract snapshot + explicit diagnostic runs"
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={snap !== undefined}
            onRefresh={() => {
              void q.refetch();
            }}
          />
        }
      />
      {snap === undefined && q.isPending && (
        <Skeleton>Loading diagnostics…</Skeleton>
      )}
      {snap === undefined && q.isError && (
        <ErrorState title="Diagnostics unavailable">
          The operator contract could not be loaded. Use Refresh to retry.
        </ErrorState>
      )}
      {snap !== undefined && (
        <div className={styles.stack}>
          <Card>
            <DiagnosticsResult
              verdict={statusMap[snap.verdict]}
              verdictLabel={statusLabel[snap.verdict]}
              generatedAt={snap.generatedAt}
              checks={snap.checks.map((c) => {
                const base = {
                  code: c.code,
                  status: statusMap[c.status],
                  statusLabel: statusLabel[c.status],
                  message: c.message,
                };
                return c.operatorAction !== ""
                  ? { ...base, operatorAction: c.operatorAction }
                  : base;
              })}
            />
          </Card>
          {canRun && <ActiveDiagnostics />}
        </div>
      )}
    </>
  );
}
