// Slice 2A Policy Tester (FE-V06): the explainability surface over the
// viewer-accessible DRY RUN POST /api/policy/test. Nothing here mutates
// policy: the server evaluates the effective rulebase without touching hit
// counts, and the page's most important truth is WHICH rulebase was tested
// (the server's `rulebase` field — running vs Policy Draft candidate).
// Requests run ONLY on the explicit "Run test" action, owned by the shared
// explicit-run AbortController (new run aborts old; unmount and the FE-3
// authentication boundary abort; no result from a prior identity renders).
// No tester input or result is ever persisted.
import { useEffect, useRef, useState, type JSX } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageHeader } from "../../layouts/AppShell";
import {
  Callout,
  Card,
  ErrorState,
  Mono,
  StatusBadge,
} from "../../design-system/primitives";
import { InputField, SelectField } from "../../design-system/forms";
import { Button } from "../../design-system/primitives";
import { runPolicyTest } from "../../api/policy";
import type { TesterResult } from "../../api/policy";
import { ApiError } from "../../api/client";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import styles from "./policy.module.css";

function rulebaseBadge(rulebase: "running" | "draft"): JSX.Element {
  return rulebase === "draft" ? (
    <StatusBadge status="warn">Policy Draft candidate</StatusBadge>
  ) : (
    <StatusBadge status="ok">Running rulebase</StatusBadge>
  );
}

function ResultView({ result }: { result: TesterResult }): JSX.Element {
  return (
    <>
      <div className={styles.verdictRow}>
        {rulebaseBadge(result.rulebase)}
        {result.matched ? (
          <>
            <StatusBadge status="info">Matched</StatusBadge>
            <span>
              Rule <strong>{result.rule.name}</strong> (priority{" "}
              {String(result.rule.priority)}) →{" "}
            </span>
            <StatusBadge
              status={result.action === "Allow" ? "ok" : "critical"}
            >
              {result.action}
            </StatusBadge>
            {result.rule.id !== "" && <Mono>{result.rule.id}</Mono>}
          </>
        ) : (
          <>
            <StatusBadge status="neutral">No rule matched</StatusBadge>
            <span>Default action → </span>
            <StatusBadge
              status={result.defaultAction === "allow" ? "ok" : "critical"}
            >
              {result.defaultAction}
            </StatusBadge>
          </>
        )}
      </div>
      {result.rulebase === "draft" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="This tested the Policy Draft candidate">
            The result reflects staged rules, not the running enforcement
            policy. Commit the draft (later slice / legacy console) before
            expecting live traffic to behave this way.
          </Callout>
        </div>
      )}
      <div className={styles.resultGrid}>
        <Card title="Host category">
          <dl className={styles.kvGrid}>
            <div>
              <dt className={styles.refDetail}>Category</dt>
              <dd>
                {result.hostCategory.category === ""
                  ? "(uncategorized)"
                  : result.hostCategory.category}
              </dd>
            </div>
            <div>
              <dt className={styles.refDetail}>Tier</dt>
              <dd>
                {result.hostCategory.tier === "" ? "—" : result.hostCategory.tier}
              </dd>
            </div>
            <div>
              <dt className={styles.refDetail}>Matched by</dt>
              <dd>
                {result.hostCategory.matchedBy === ""
                  ? "—"
                  : result.hostCategory.matchedBy}
              </dd>
            </div>
          </dl>
        </Card>
        <Card title="Authentication stage (Stage-1)">
          <dl className={styles.kvGrid}>
            <div>
              <dt className={styles.refDetail}>Outcome</dt>
              <dd>{result.auth.outcome}</dd>
            </div>
            <div>
              <dt className={styles.refDetail}>Default auth outcome</dt>
              <dd>
                {result.auth.defaultAuthOutcome}
                {result.auth.fromDefault && " (applied — no scoped rule)"}
              </dd>
            </div>
            <div>
              <dt className={styles.refDetail}>Credentials presented</dt>
              <dd>{result.auth.credentialsPresented ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt className={styles.refDetail}>Stage-2 auth source</dt>
              <dd>
                <Mono>{result.auth.stage2AuthSource}</Mono>
              </dd>
            </div>
            <div>
              <dt className={styles.refDetail}>Stage-2 reached at runtime</dt>
              <dd>{result.auth.stage2Reached ? "yes" : "no"}</dd>
            </div>
            {result.auth.killSwitch && (
              <div>
                <dt className={styles.refDetail}>Kill switch</dt>
                <dd>engaged — exemptions forced to Default</dd>
              </div>
            )}
            {result.auth.rule !== undefined && (
              <div>
                <dt className={styles.refDetail}>Matched auth rule</dt>
                <dd>
                  {result.auth.rule.name}
                  {result.auth.rule.owner !== "" &&
                    ` (owner ${result.auth.rule.owner})`}
                </dd>
              </div>
            )}
          </dl>
          {result.auth.stage2Note !== "" && (
            <p className={styles.authNote}>{result.auth.stage2Note}</p>
          )}
          {result.auth.note !== "" && (
            <p className={styles.authNote}>{result.auth.note}</p>
          )}
        </Card>
      </div>
      <Card title="Rule evaluation trace">
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <caption className="sr-only">
              Per-rule evaluation trace in priority order
            </caption>
            <thead>
              <tr>
                <th scope="col" className={styles.numeric}>
                  Priority
                </th>
                <th scope="col">Rule</th>
                <th scope="col">Why skipped</th>
              </tr>
            </thead>
            <tbody>
              {result.trace.length === 0 && (
                <tr>
                  <td colSpan={3}>No rules were evaluated.</td>
                </tr>
              )}
              {result.trace.map((t, i) => (
                <tr key={`${String(t.priority)}:${String(i)}`}>
                  <td className={styles.numeric}>{t.priority}</td>
                  <td className={styles.nameCell}>{t.name}</td>
                  <td className={styles.traceSkip}>
                    {t.skipReason === "" ? "evaluated" : t.skipReason}
                  </td>
                </tr>
              ))}
              {result.matched && (
                <tr>
                  <td className={styles.numeric}>{result.rule.priority}</td>
                  <td className={styles.nameCell}>{result.rule.name}</td>
                  <td>
                    <StatusBadge status="info">matched — evaluation stops</StatusBadge>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

export function TesterPage(): JSX.Element {
  const [host, setHost] = useState("");
  const [sourceIP, setSourceIP] = useState("");
  const [identity, setIdentity] = useState("");
  const [authSource, setAuthSource] = useState("");
  const [groups, setGroups] = useState("");
  const [protocol, setProtocol] = useState<"http" | "connect">("http");
  const [method, setMethod] = useState("");

  const ownerRef = useRef(createRequestRunOwner());
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

  const run = useMutation<TesterResult, unknown, void>({
    mutationFn: () => {
      const owner = ownerRef.current;
      const signal = owner.begin();
      const groupList = groups
        .split(",")
        .map((g) => g.trim())
        .filter((g) => g !== "");
      return runPolicyTest(
        {
          host: host.trim(),
          sourceIP: sourceIP.trim(),
          identity: identity.trim(),
          authSource: authSource.trim(),
          groups: groupList,
          protocol,
          method: method.trim(),
        },
        signal,
      ).finally(() => {
        owner.settle(signal);
      });
    },
  });

  const err = run.error;
  const hostMissing = host.trim() === "";

  return (
    <>
      <PageHeader
        title="Policy Tester"
        subtitle="Dry-run a hypothetical request against the effective rulebase. Nothing is changed: no hit counts, no rules, no configuration."
      />
      <form
        className={styles.testerForm}
        onSubmit={(e) => {
          e.preventDefault();
          if (!hostMissing && !run.isPending) run.mutate();
        }}
      >
        <InputField
          label="Host"
          required
          help="Destination host to evaluate (required)"
          value={host}
          onChange={(e) => {
            setHost(e.target.value);
          }}
        />
        <InputField
          label="Source IP"
          value={sourceIP}
          onChange={(e) => {
            setSourceIP(e.target.value);
          }}
        />
        <InputField
          label="Identity"
          value={identity}
          onChange={(e) => {
            setIdentity(e.target.value);
          }}
        />
        <InputField
          label="Auth source"
          value={authSource}
          onChange={(e) => {
            setAuthSource(e.target.value);
          }}
        />
        <InputField
          label="Groups"
          help="Comma-separated"
          value={groups}
          onChange={(e) => {
            setGroups(e.target.value);
          }}
        />
        <SelectField
          label="Protocol"
          value={protocol}
          onChange={(e) => {
            setProtocol(e.target.value === "connect" ? "connect" : "http");
          }}
        >
          <option value="http">http</option>
          <option value="connect">connect</option>
        </SelectField>
        <InputField
          label="Method"
          help="Stage-1 simulation only"
          value={method}
          onChange={(e) => {
            setMethod(e.target.value);
          }}
        />
        <div className={styles.testerActions}>
          <Button
            type="submit"
            variant="primary"
            disabled={hostMissing || run.isPending}
          >
            {run.isPending ? "Running…" : "Run test"}
          </Button>
        </div>
      </form>

      {err !== null && !(err instanceof ApiError && err.kind === "aborted") && (
        <ErrorState title="Test failed">
          {err instanceof ApiError
            ? (err.bodyText !== undefined && err.bodyText !== ""
                ? err.bodyText
                : err.message)
            : "The test request failed."}
        </ErrorState>
      )}
      {run.data !== undefined && !run.isPending && (
        <ResultView result={run.data} />
      )}
    </>
  );
}
