// Golden appliance components (FE-2 §16) — presentation-only in FE-2, fixture
// data only. They establish the shared vocabulary future feature rounds
// consume for health, diagnosis, change impact, operations, rollback, audit.
// Vocabulary matches the backend contracts they will bind to in later rounds
// (OperatorContract codes/status/operator_action; config-diff field rows;
// dispatch phase models) without calling any endpoint.
import type { JSX, ReactNode } from "react";
import { IconRollback } from "./icons";
import { Mono, StatusBadge, Timestamp } from "./primitives";
import type { Status } from "./primitives";
import styles from "./appliance.module.css";

// ── HealthCheck ─────────────────────────────────────────────────────────────
export interface HealthItem {
  name: string;
  status: Status;
  statusLabel: string;
  detail?: string;
  operatorAction?: string;
}

export function HealthCheck({
  items,
}: {
  items: readonly HealthItem[];
}): JSX.Element {
  return (
    <ul className={styles.healthList}>
      {items.map((it) => (
        <li key={it.name} className={styles.healthRow}>
          <span className={styles.healthName}>{it.name}</span>
          <StatusBadge status={it.status}>{it.statusLabel}</StatusBadge>
          <span className={styles.healthDetail}>
            {it.detail}
            {it.operatorAction !== undefined && (
              <span className={styles.operatorAction}>{it.operatorAction}</span>
            )}
          </span>
        </li>
      ))}
    </ul>
  );
}

// ── DiagnosticsResult (OperatorContract vocabulary) ─────────────────────────
export interface DiagnosticsCheck {
  code: string;
  status: Status;
  statusLabel: string;
  message: string;
  operatorAction?: string;
}

export function DiagnosticsResult({
  verdict,
  verdictLabel,
  generatedAt,
  checks,
}: {
  verdict: Status;
  verdictLabel: string;
  generatedAt: string;
  checks: readonly DiagnosticsCheck[];
}): JSX.Element {
  return (
    <div>
      <div className={styles.diagHeader}>
        <StatusBadge status={verdict}>{verdictLabel}</StatusBadge>
        <Timestamp iso={generatedAt} />
      </div>
      <HealthCheck
        items={checks.map((c) => {
          const item: HealthItem = {
            name: c.code,
            status: c.status,
            statusLabel: c.statusLabel,
            detail: c.message,
          };
          if (c.operatorAction !== undefined)
            item.operatorAction = c.operatorAction;
          return item;
        })}
      />
    </div>
  );
}

// ── ConfigDiff ──────────────────────────────────────────────────────────────
export interface DiffRow {
  field: string;
  kind: "added" | "removed" | "changed";
  before?: string;
  after?: string;
}

const diffMarks = { added: "+", removed: "−", changed: "~" } as const;

export function ConfigDiff({
  rows,
}: {
  rows: readonly DiffRow[];
}): JSX.Element {
  return (
    <div
      className={styles.diff}
      role="table"
      aria-label="Configuration changes"
    >
      {rows.map((r) => (
        <div
          key={`${r.kind}-${r.field}`}
          className={styles.diffRow}
          data-kind={r.kind}
          role="row"
        >
          <span className={styles.diffMark} aria-hidden="true">
            {diffMarks[r.kind]}
          </span>
          <span className={styles.diffField} role="cell">
            {r.field}
          </span>
          <span role="cell">
            <span className="sr-only">{r.kind}: </span>
            {r.before !== undefined && (
              <span className={styles.diffBefore}>{r.before}</span>
            )}
            {r.before !== undefined && r.after !== undefined && " → "}
            {r.after}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── OperationProgress ───────────────────────────────────────────────────────
export type PhaseState = "done" | "active" | "pending" | "failed" | "unknown";

export interface OperationPhase {
  label: string;
  state: PhaseState;
  detail?: string;
}

export function OperationProgress({
  phases,
}: {
  phases: readonly OperationPhase[];
}): JSX.Element {
  const active = phases.find((p) => p.state === "active");
  return (
    <ol className={styles.opList} aria-label="Operation progress">
      {/* aria-live on the container would announce every rerender; the
          consumer decides announcement policy. */}
      {phases.map((p) => (
        <li key={p.label} className={styles.opPhase} data-state={p.state}>
          <span className={styles.opDot} aria-hidden="true" />
          {p.label}
          <span className="sr-only">, {p.state}</span>
          {p.detail !== undefined && (
            <span className={styles.opDetail}>{p.detail}</span>
          )}
          {p === active && <span className="sr-only">(current step)</span>}
        </li>
      ))}
    </ol>
  );
}

// ── RollbackBanner ──────────────────────────────────────────────────────────
export function RollbackBanner({
  children,
  action,
}: {
  children: ReactNode;
  action?: ReactNode;
}): JSX.Element {
  return (
    <div className={styles.rollback} role="status">
      <span className={styles.rollbackIcon}>
        <IconRollback />
      </span>
      <span className={styles.rollbackText}>{children}</span>
      {action}
    </div>
  );
}

// ── AuditTimeline ───────────────────────────────────────────────────────────
export interface AuditEntry {
  ts: string;
  actor: string;
  action: string;
  object?: string;
}

export function AuditTimeline({
  entries,
}: {
  entries: readonly AuditEntry[];
}): JSX.Element {
  return (
    <ol className={styles.timeline} aria-label="Audit history">
      {entries.map((e) => (
        <li key={`${e.ts}-${e.action}`} className={styles.timelineRow}>
          <Timestamp iso={e.ts} />
          <span className={styles.timelineActor}>{e.actor}</span>
          <span>
            {e.action}
            {e.object !== undefined && (
              <>
                {" "}
                <span className={styles.timelineObject}>
                  <Mono>{e.object}</Mono>
                </span>
              </>
            )}
          </span>
        </li>
      ))}
    </ol>
  );
}
