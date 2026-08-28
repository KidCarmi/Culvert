// 2C.4/2C.5 — Policy Learning (ADR-0025 M5A/M5B): the governed, ADVISORY,
// NODE-LOCAL learning surface. Snapshot model only — no polling, no
// auto-generate, no auto-accept, no invented confidence, no automation
// theater (§41). Both scope statements are SERVER truth rendered verbatim.
//
// RBAC: viewer reads everything; operator runs session lifecycle + generate
// + reject; admin governs enablement + the recommendable-category guardrail
// and owns Accept. Thresholds are READ-ONLY transparency (thresholds_editable
// is false in M5A — no sliders exist here by design).
import { useMemo, useState, type JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { Checkbox } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import {
  generateRecommendations,
  postLearningSession,
  putLearningConfig,
} from "../../api/policyLearning";
import type {
  GenerateResult,
  LearningSessionAction,
  PLSession,
  PLTransport,
} from "../../api/policyLearning";
import { getURLCategoryNames } from "../../api/policyWrite";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import { LearningRecommendations } from "./LearningRecommendations";
import { useLearningWrites } from "./useLearningWrites";
import styles from "./learning.module.css";

function transportFacts(t: PLTransport): string {
  return `accepted ${String(t.accepted)} · dropped ${String(t.dropped)} · rejected ${String(t.rejected)} · consumer panics ${String(t.consumerPanics)} · groups truncated ${String(t.groupsTruncated)}`;
}

function SessionFacts({ s }: { s: PLSession }): JSX.Element {
  return (
    <div className={styles.sessionFacts}>
      <p>
        <StatusBadge
          status={
            s.state === "learning"
              ? "info"
              : s.state === "completed"
                ? "ok"
                : "neutral"
          }
        >
          {s.state}
        </StatusBadge>{" "}
        <Mono>{s.id.slice(0, 12)}</Mono> · started {s.startedAt}
        {s.stoppedAt !== "" && <> · stopped {s.stoppedAt}</>} · by {s.createdBy}
      </p>
      <p className={styles.factLine}>
        Observation window: {transportFacts(s.transport)}
        {s.transport.degraded && (
          <>
            {" "}
            <StatusBadge status="warn">loss occurred</StatusBadge>
          </>
        )}
      </p>
      <p className={styles.factLine}>
        Aggregation: {String(s.cells)} cells
        {s.cellsDropped > 0 && ` · ${String(s.cellsDropped)} cells dropped`}
        {s.churnEvents > 0 &&
          ` · ${String(s.churnEvents)} category churn events`}
        {s.churnOverflow > 0 && ` · churn overflow ${String(s.churnOverflow)}`}
      </p>
      {s.subjectKeyChanged && (
        <Callout variant="warning" title="Subject key changed">
          The pseudonymization key changed during this session&apos;s lifetime —
          distinct-subject evidence cannot be trusted and recommendation
          generation from it is refused.
        </Callout>
      )}
      {s.gaps.length > 0 && (
        <p className={styles.factLine}>
          Gaps: {s.gaps.map((g) => `${g.at} (${g.reason})`).join("; ")}
        </p>
      )}
    </div>
  );
}

export function PolicyLearningPage(): JSX.Element {
  const lw = useLearningWrites();
  const { state } = useAuth();
  const isAdmin = hasRole(state.role ?? "viewer", "admin");
  const canOperate = hasRole(state.role ?? "viewer", "operator");
  const blocked = lw.unknown !== null;

  const status = lw.statusQ.data;
  const config = lw.configQ.data;
  const sessions = lw.sessionsQ.data;
  const recs = lw.recsQ.data;

  // ── config editing (admin): enable/disable + guardrail categories ────────
  const [enableTarget, setEnableTarget] = useState<boolean | null>(null);
  const [enableResult, setEnableResult] = useState<ConfirmResult>("idle");
  const [enableError, setEnableError] = useState("");

  const [catsDraft, setCatsDraft] = useState<readonly string[] | null>(null);
  const [catsPending, setCatsPending] = useState(false);
  const [catsError, setCatsError] = useState("");
  const catOptQ = useQuery({
    queryKey: ["learning", "category-options"],
    enabled: catsDraft !== null,
    staleTime: Infinity,
    retry: false,
    queryFn: async ({ signal }) => getURLCategoryNames(signal),
  });

  // ── session ops ──────────────────────────────────────────────────────────
  const [sessionAction, setSessionAction] =
    useState<LearningSessionAction | null>(null);
  const [sessionResult, setSessionResult] = useState<ConfirmResult>("idle");
  const [sessionError, setSessionError] = useState("");

  // ── generate ─────────────────────────────────────────────────────────────
  const [generatePending, setGeneratePending] = useState(false);
  const [generateError, setGenerateError] = useState("");
  const [generateSummary, setGenerateSummary] = useState<GenerateResult | null>(
    null,
  );

  const closeAllWriteState = (): void => {
    setEnableTarget(null);
    setEnableResult("idle");
    setEnableError("");
    setCatsDraft(null);
    setCatsPending(false);
    setCatsError("");
    setSessionAction(null);
    setSessionResult("idle");
    setSessionError("");
    setGeneratePending(false);
    setGenerateError("");
    setGenerateSummary(null);
  };
  lw.setBoundaryCleanup(closeAllWriteState);

  const catsDirty = useMemo(() => {
    if (catsDraft === null || config === undefined) return false;
    const cur = [...config.recommendableCategories].sort();
    const next = [...catsDraft].sort();
    return cur.length !== next.length || cur.some((c, i) => next[i] !== c);
  }, [catsDraft, config]);
  const guard = useDirtyGuard(
    catsDirty,
    "the unsaved recommendable-category guardrail changes",
  );

  const runEnable = (target: boolean): void => {
    const signal = lw.owner.begin();
    setEnableResult("pending");
    putLearningConfig({ enabled: target }, signal)
      .then(() => {
        setEnableTarget(null);
        setEnableResult("idle");
        setEnableError("");
        lw.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setEnableTarget(null);
          setEnableResult("idle");
          lw.latchUnknown("config change");
          return;
        }
        setEnableResult("failed");
        setEnableError(
          serverErrorText(err, "The appliance refused the change."),
        );
      })
      .finally(() => {
        lw.owner.settle(signal);
      });
  };

  const saveCats = (): void => {
    if (catsDraft === null) return;
    const signal = lw.owner.begin();
    setCatsPending(true);
    setCatsError("");
    putLearningConfig({ recommendableCategories: catsDraft }, signal)
      .then(() => {
        setCatsDraft(null);
        lw.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setCatsDraft(null);
          lw.latchUnknown("config change");
          return;
        }
        setCatsError(
          serverErrorText(err, "The appliance refused the guardrail change."),
        );
      })
      .finally(() => {
        lw.owner.settle(signal);
        setCatsPending(false);
      });
  };

  const runSession = (action: LearningSessionAction): void => {
    const signal = lw.owner.begin();
    setSessionResult("pending");
    postLearningSession(action, signal)
      .then(() => {
        setSessionAction(null);
        setSessionResult("idle");
        setSessionError("");
        lw.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setSessionAction(null);
          setSessionResult("idle");
          lw.latchUnknown(
            action === "start"
              ? "session start"
              : action === "complete"
                ? "session complete"
                : "session cancel",
          );
          return;
        }
        setSessionResult("failed");
        setSessionError(
          serverErrorText(err, "The appliance refused the transition."),
        );
      })
      .finally(() => {
        lw.owner.settle(signal);
      });
  };

  const runGenerate = (sessionId: string): void => {
    const signal = lw.owner.begin();
    setGeneratePending(true);
    setGenerateError("");
    generateRecommendations(sessionId, signal)
      .then((res) => {
        setGenerateSummary(res);
        lw.refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          lw.latchUnknown("generate");
          return;
        }
        setGenerateError(
          serverErrorText(err, "The appliance refused generation."),
        );
      })
      .finally(() => {
        lw.owner.settle(signal);
        setGeneratePending(false);
      });
  };

  const activeSession = status?.activeSession;

  return (
    <>
      <PageHeader
        title="Policy Learning"
        subtitle="Observes traffic and recommends — advisory only, never enforcement."
        actions={
          <SnapshotBar
            updatedAt={lw.statusQ.dataUpdatedAt}
            fetching={lw.statusQ.isFetching}
            error={lw.statusQ.isError}
            hasData={status !== undefined}
            onRefresh={lw.refreshToResolve}
          />
        }
      />

      {lw.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the {lw.unknown} may or may not have happened. Refresh to load the
            current learning state before making further decisions
            {lw.unknown === "accept" &&
              " — never repeat an Accept without fresh recommendation and draft truth"}
            .
            <div className={styles.calloutAction}>
              <Button size="sm" onClick={lw.refreshToResolve}>
                Refresh learning state
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {status !== undefined && (
        <div className={styles.calloutSpace}>
          <Callout variant="info" title="Node-local and advisory">
            <StatusBadge status="info">node-local</StatusBadge>{" "}
            <StatusBadge status="info">advisory only</StatusBadge>{" "}
            {status.scopeNote} {status.advisoryNote}
          </Callout>
          {status.runtimeError !== "" && (
            <Callout variant="critical" title="Learning runtime error">
              {status.runtimeError}
            </Callout>
          )}
        </div>
      )}

      {status === undefined && lw.statusQ.isPending && (
        <Skeleton>Loading learning state…</Skeleton>
      )}
      {status === undefined && lw.statusQ.isError && (
        <ErrorState title="Learning state unavailable">
          The Policy Learning status could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {status !== undefined && config !== undefined && (
        <Card title="Governance">
          <p>
            {status.enabled ? (
              <>
                <StatusBadge status="ok">enabled</StatusBadge> Learning is
                enabled.{" "}
                {status.learningActive
                  ? "A session is actively observing."
                  : "Observation is idle — it arms only when a session starts."}
              </>
            ) : (
              <>
                <StatusBadge status="neutral">disabled</StatusBadge> Learning is
                disabled. Node-local learning state is retained on disk.
              </>
            )}
          </p>
          {isAdmin && (
            <div className={styles.calloutAction}>
              <Button
                size="sm"
                disabled={blocked}
                onClick={() => {
                  setEnableTarget(!status.enabled);
                  setEnableResult("idle");
                  setEnableError("");
                }}
              >
                {status.enabled ? "Disable learning…" : "Enable learning…"}
              </Button>
            </div>
          )}
          <p className={styles.factLine}>
            Recommendable categories (guardrail):{" "}
            {config.recommendableCategories.length === 0
              ? "none (nothing recommendable — fail closed)"
              : config.recommendableCategories.join(", ")}
            {config.categoriesAreSeed && ` (seed: ${config.seedSource})`}
          </p>
          {isAdmin && catsDraft === null && (
            <Button
              size="sm"
              variant="ghost"
              disabled={blocked}
              onClick={() => {
                setCatsDraft(config.recommendableCategories);
                setCatsError("");
              }}
            >
              Edit guardrail…
            </Button>
          )}
          {catsDraft !== null && (
            <div className={styles.guardrailEditor}>
              {catsError !== "" && (
                <Callout variant="warning" title="Guardrail not saved">
                  {catsError}
                </Callout>
              )}
              <p className={styles.factLine}>
                Only these categories may ever be recommended (an allowlist —
                empty means nothing is recommendable). Changing it while a
                session is active is refused by the appliance.
              </p>
              {(catOptQ.data ?? []).map((c) => (
                <Checkbox
                  key={c}
                  label={c}
                  checked={catsDraft.includes(c)}
                  onChange={() => {
                    setCatsDraft((cur) =>
                      cur === null
                        ? cur
                        : cur.includes(c)
                          ? cur.filter((x) => x !== c)
                          : [...cur, c],
                    );
                  }}
                />
              ))}
              {catsDraft
                .filter((c) => !(catOptQ.data ?? []).includes(c))
                .map((c) => (
                  <Checkbox
                    key={c}
                    label={`${c} (not in current category list)`}
                    checked
                    onChange={() => {
                      setCatsDraft((cur) =>
                        cur === null ? cur : cur.filter((x) => x !== c),
                      );
                    }}
                  />
                ))}
              <div className={styles.calloutAction}>
                <Button
                  size="sm"
                  disabled={catsPending || !catsDirty}
                  onClick={saveCats}
                >
                  Save guardrail
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={catsPending}
                  onClick={() => {
                    setCatsDraft(null);
                    setCatsError("");
                  }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
          {status.recommendationPolicy !== undefined && (
            <p className={styles.factLine}>
              Decision thresholds (read-only — not editable in this release):
              high ≥{" "}
              {String(status.recommendationPolicy.highMinAllowedRequests)}{" "}
              requests / {String(status.recommendationPolicy.highMinSubjects)}{" "}
              subjects / {String(status.recommendationPolicy.highMinDays)} days;
              medium ≥{" "}
              {String(status.recommendationPolicy.mediumMinAllowedRequests)} /{" "}
              {String(status.recommendationPolicy.mediumMinSubjects)} /{" "}
              {String(status.recommendationPolicy.mediumMinDays)} · guardrails
              hash <Mono>{status.guardrailsHash.slice(0, 12)}</Mono>
            </p>
          )}
          {status.observation !== undefined && (
            <p className={styles.factLine}>
              Observation transport (engine lifetime):{" "}
              {transportFacts(status.observation)}
            </p>
          )}
        </Card>
      )}

      {status !== undefined && status.enabled && (
        <Card title="Learning session">
          {activeSession !== undefined ? (
            <>
              <SessionFacts s={activeSession} />
              {canOperate && (
                <div className={styles.calloutAction}>
                  <Button
                    size="sm"
                    disabled={blocked}
                    onClick={() => {
                      setSessionAction("complete");
                      setSessionResult("idle");
                      setSessionError("");
                    }}
                  >
                    Complete session…
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={blocked}
                    onClick={() => {
                      setSessionAction("cancel");
                      setSessionResult("idle");
                      setSessionError("");
                    }}
                  >
                    Cancel session…
                  </Button>
                </div>
              )}
            </>
          ) : (
            <>
              <p>No session is active. Observation is idle.</p>
              {canOperate && (
                <div className={styles.calloutAction}>
                  <Button
                    size="sm"
                    disabled={blocked}
                    onClick={() => {
                      setSessionAction("start");
                      setSessionResult("idle");
                      setSessionError("");
                    }}
                  >
                    Start session…
                  </Button>
                </div>
              )}
            </>
          )}
        </Card>
      )}

      {sessions !== undefined && sessions.sessions.length > 0 && (
        <Card title="Retained sessions">
          {generateSummary !== null && (
            <Callout variant="success" title="Recommendations generated">
              Session <Mono>{generateSummary.sessionId.slice(0, 12)}</Mono>:{" "}
              {String(generateSummary.recommendations.length)} generated,{" "}
              {String(generateSummary.superseded)} superseded,{" "}
              {String(generateSummary.unchanged)} unchanged,{" "}
              {String(generateSummary.eligibleCells)} eligible cells (
              {String(generateSummary.skippedSyntheticScope)} synthetic-scope,{" "}
              {String(generateSummary.skippedCategory)} category and{" "}
              {String(generateSummary.skippedNoAllowedEvidence)}{" "}
              no-allowed-evidence cells skipped).
            </Callout>
          )}
          {generateError !== "" && (
            <Callout variant="warning" title="Generation refused" role="alert">
              {generateError}
            </Callout>
          )}
          <ul className={styles.sessionList}>
            {sessions.sessions.map((s) => (
              <li key={s.id}>
                <SessionFacts s={s} />
                {canOperate && s.state === "completed" && (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={blocked || generatePending}
                    onClick={() => {
                      runGenerate(s.id);
                    }}
                  >
                    Generate recommendations
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {recs !== undefined && recs.enabled && (
        <LearningRecommendations
          list={recs}
          isAdmin={isAdmin}
          canOperate={canOperate}
          blocked={blocked}
          owner={lw.owner}
          refetchAll={lw.refetchAll}
          latchUnknown={lw.latchUnknown}
        />
      )}

      {enableTarget !== null && (
        <ConfirmationDialog
          open
          tier={2}
          title={
            enableTarget ? "Enable Policy Learning" : "Disable Policy Learning"
          }
          body={
            enableTarget ? (
              <>
                Enables the advisory learning engine on THIS NODE. Observation
                stays idle until a session is explicitly started; nothing is
                enforced or changed by learning itself.
              </>
            ) : (
              <>
                Disables the learning engine on this node. If a session is
                active the appliance refuses — Complete or Cancel the active
                session first. Node-local learning state stays on disk; nothing
                is deleted.
              </>
            )
          }
          impact={
            enableTarget
              ? "The engine is constructed and sessions can be started."
              : "Sessions and recommendations become unavailable until re-enabled (state retained)."
          }
          rollback="Toggle back at any time."
          confirmLabel={enableTarget ? "Enable learning" : "Disable learning"}
          destructive={false}
          result={enableResult}
          errorText={enableError}
          onConfirm={() => {
            if (enableResult !== "pending") runEnable(enableTarget);
          }}
          onCancel={() => {
            if (enableResult !== "pending") {
              setEnableTarget(null);
              setEnableResult("idle");
              setEnableError("");
            }
          }}
        />
      )}

      {sessionAction === "start" && (
        <ConfirmationDialog
          open
          tier={1}
          title="Start a Learning session"
          body={
            <>
              Starts observing THIS NODE&apos;s policy decisions (host-level
              facts only — never URLs, headers, or credentials) until the
              session is completed or cancelled. Advisory only.
            </>
          }
          confirmLabel="Start session"
          destructive={false}
          result={sessionResult}
          errorText={sessionError}
          onConfirm={() => {
            if (sessionResult !== "pending") runSession("start");
          }}
          onCancel={() => {
            if (sessionResult !== "pending") {
              setSessionAction(null);
              setSessionResult("idle");
              setSessionError("");
            }
          }}
        />
      )}
      {sessionAction === "complete" && (
        <ConfirmationDialog
          open
          tier={1}
          title="Complete the Learning session"
          body={
            <>
              Stops observation and finalizes this session&apos;s evidence.
              Recommendations can then be generated from it on demand.
            </>
          }
          confirmLabel="Complete session"
          destructive={false}
          result={sessionResult}
          errorText={sessionError}
          onConfirm={() => {
            if (sessionResult !== "pending") runSession("complete");
          }}
          onCancel={() => {
            if (sessionResult !== "pending") {
              setSessionAction(null);
              setSessionResult("idle");
              setSessionError("");
            }
          }}
        />
      )}
      {sessionAction === "cancel" && (
        <ConfirmationDialog
          open
          tier={2}
          title="Cancel the Learning session"
          body={
            <>
              Stops observation and marks this session cancelled. A cancelled
              session is never eligible for recommendation generation; its
              recorded facts remain in the retained session list until pruned by
              the engine&apos;s retention bound.
            </>
          }
          impact="This session's observation window ends without producing recommendations."
          rollback="None — start a new session to observe again."
          confirmLabel="Cancel session"
          destructive
          result={sessionResult}
          errorText={sessionError}
          onConfirm={() => {
            if (sessionResult !== "pending") runSession("cancel");
          }}
          onCancel={() => {
            if (sessionResult !== "pending") {
              setSessionAction(null);
              setSessionResult("idle");
              setSessionError("");
            }
          }}
        />
      )}
      {guard.element}
    </>
  );
}
