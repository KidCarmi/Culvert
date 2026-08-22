// Slice 2A Access Rules (FE-V16 READ surface): the Stage-2 rulebase as an
// appliance rulebase — server priority order preserved (evaluation order is
// load-bearing; no arbitrary column sorting), snapshot/refresh per ADR-FE-002,
// client-side filtering for the bounded 500-rule target, row-detail expansion
// for secondary metadata, and the ?rule=<stable-id> deep link resolved by
// DATA EQUALITY (never a selector). Read-only: mutation controls do not exist
// until Slice 2B — the draft/running truth is presented, never operated on.
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
import { PageHeader } from "../../layouts/AppShell";
import {
  Callout,
  ErrorState,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { InputField } from "../../design-system/forms";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { getPolicy, isPlausibleRuleID } from "../../api/policy";
import type { PolicyRuleView, PolicySnapshot } from "../../api/policy";
import { WhereUsed } from "./WhereUsed";
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
  const q = useSnapshot(["policy", "snapshot"], (signal) => getPolicy(signal));
  const snap: PolicySnapshot | undefined = q.data;
  const [filter, setFilter] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
  const ruleParam = searchParams.get("rule") ?? "";

  const accessRules = snap?.accessRules ?? [];
  const filtered = useMemo(() => {
    const needle = filter.trim();
    if (needle === "") return accessRules;
    return accessRules.filter((r) => ruleMatchesFilter(r, needle));
  }, [accessRules, filter]);

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
            onRefresh={() => {
              void q.refetch();
            }}
          />
        }
      />
      <span role="status" aria-live="polite" className={styles.srOnly}>
        {announce}
      </span>

      {snap !== undefined && draft && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Viewing Policy Draft candidate">
            These rules are staged and are not the running enforcement policy
            until they are committed. Draft review and commit arrive in a later
            slice; the legacy console remains the write surface.
          </Callout>
        </div>
      )}
      {snap !== undefined && !draft && (
        <div className={styles.calloutSpace}>
          <Callout variant="info" title="Running rulebase">
            This is the effective rulebase currently enforcing traffic.
          </Callout>
        </div>
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
              help="Matches name, source, destination, action, and rule ID. Display only — priority order is preserved."
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value);
              }}
            />
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
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={10}>
                      {accessRules.length === 0
                        ? "No access rules are defined. Unmatched traffic receives the default action."
                        : "No rules match the filter."}
                    </td>
                  </tr>
                )}
                {filtered.map((r) => {
                  const rowKey = r.id !== "" ? r.id : `p${String(r.priority)}`;
                  const isTarget = target !== undefined && r.id === target.id;
                  const open = openId === rowKey;
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
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
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
}: {
  r: PolicyRuleView;
  open: boolean;
  highlighted: boolean;
  rowRef: Ref<HTMLTableRowElement> | undefined;
  onToggle: () => void;
}): JSX.Element {
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
      </tr>
      {open && (
        <tr className={styles.detailRow}>
          <td colSpan={10}>
            <RuleDetail r={r} />
          </td>
        </tr>
      )}
    </>
  );
}
