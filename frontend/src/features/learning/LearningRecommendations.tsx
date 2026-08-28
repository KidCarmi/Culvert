// 2C.5/2C.6 — the recommendation surface: full-fidelity factual rendering
// (evidence, coverage, confidence with its named reasons AND limits, the
// decision-policy transparency, server-computed staleness) plus the M5B
// decision boundary:
//
//   Accept — "Accept to Policy Draft" (never Apply/Enforce/Allow/Deploy):
//   ADMIN-only, offered only for a FRESH (stale_reasons empty), state
//   "generated" recommendation while draft mode is armed; the POST body is
//   exactly {id, action:"accept", if_version:<listing policy_version>}; the
//   backend owns translation and creates a DISABLED rule in the shared
//   Policy Draft. When draft mode is NOT armed the button is absent and an
//   explanation appears — this page never arms Require Commit itself (§30).
//
//   Reject — operator+, decision-only with a bounded reason; no policy or
//   config mutation.
//
// Success renders SERVER truth (the returned recommendation + rule_id +
// already_done + note) and offers "Review created rule" into the Access
// Rules draft view. A post-accept agreement check (§33) verifies the draft
// now carries the DISABLED target rule; disagreement renders a controlled
// inconsistency warning, never silence.
import { useState, type JSX } from "react";
import { Link } from "react-router";
import {
  Button,
  Callout,
  Card,
  Mono,
  StatusBadge,
} from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { TextareaField } from "../../design-system/forms";
import {
  acceptRecommendation,
  rejectRecommendation,
} from "../../api/policyLearning";
import type {
  PLRecommendation,
  RecommendationList,
} from "../../api/policyLearning";
import { getPolicy } from "../../api/policy";
import { getDraftState } from "../../api/policyDraft";
import type { RequestRunOwner } from "../../shared/runOwner";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import styles from "./learning.module.css";

export interface LearningRecommendationsProps {
  list: RecommendationList;
  isAdmin: boolean;
  canOperate: boolean;
  blocked: boolean;
  owner: RequestRunOwner;
  refetchAll: () => void;
  latchUnknown: (op: "accept" | "reject") => void;
}

interface AcceptSuccess {
  recId: string;
  ruleId: string;
  alreadyDone: boolean;
  note: string;
  /** §33 agreement check outcome: null = checking / not run */
  agreement: "ok" | "inconsistent" | null;
  agreementDetail: string;
}

function confidenceBadge(c: string): JSX.Element {
  const status = c === "high" ? "ok" : c === "medium" ? "info" : "neutral";
  return <StatusBadge status={status}>{c}</StatusBadge>;
}

function stateBadge(r: PLRecommendation): JSX.Element {
  switch (r.state) {
    case "generated":
      return <StatusBadge status="info">generated</StatusBadge>;
    case "accepted":
      return <StatusBadge status="ok">accepted</StatusBadge>;
    case "accepting":
      return <StatusBadge status="warn">accepting</StatusBadge>;
    case "rejected":
      return <StatusBadge status="neutral">rejected</StatusBadge>;
    case "superseded":
      return <StatusBadge status="neutral">superseded</StatusBadge>;
    default:
      return <StatusBadge status="unknown">{r.state}</StatusBadge>;
  }
}

function factRow(label: string, value: string): JSX.Element {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function RecommendationEvidence({ r }: { r: PLRecommendation }): JSX.Element {
  const e = r.evidence;
  const c = r.coverage;
  return (
    <details>
      <summary>Evidence &amp; coverage (facts)</summary>
      <dl className={styles.factGrid}>
        {factRow("Allowed requests", String(e.allowedRequests))}
        {factRow(
          "Distinct subjects (allowed)",
          `${String(e.observedAllowedSubjects)}${e.subjectsIsLowerBound ? " (lower bound — overflow occurred)" : ""}`,
        )}
        {factRow(
          "Observation days (allowed)",
          `${String(e.allowedObservationDays)}${e.daysIsLowerBound ? " (lower bound)" : ""}`,
        )}
        {e.policyBlockedRequests > 0 &&
          factRow(
            "Policy-blocked requests (negative evidence)",
            String(e.policyBlockedRequests),
          )}
        {e.threatBlockedRequests > 0 &&
          factRow(
            "Threat-blocked requests (negative evidence)",
            String(e.threatBlockedRequests),
          )}
        {factRow("Session window (days)", String(c.sessionWindowDays))}
        {factRow(
          "Membership denominator",
          c.membershipDenominatorKnown
            ? "known"
            : "not known — coverage is observed-subjects only, never a percentage of a group",
        )}
        {c.transportDegraded &&
          factRow(
            "Transport loss in window",
            `dropped ${String(c.transportLoss?.dropped ?? 0)}, rejected ${String(c.transportLoss?.rejected ?? 0)}, panics ${String(c.transportLoss?.consumerPanics ?? 0)}, groups truncated ${String(c.transportLoss?.groupsTruncated ?? 0)}`,
          )}
      </dl>
      {e.topAllowedHosts.length > 0 && (
        <p className={styles.hostList}>
          Top allowed hosts:{" "}
          {e.topAllowedHosts
            .map((h) => `${h.host} (${String(h.count)})`)
            .join(", ")}
          {e.otherAllowedHosts > 0 &&
            ` + ${String(e.otherAllowedHosts)} other hosts`}
        </p>
      )}
      <p className={styles.hostList}>
        Decision policy: algorithm v{String(r.policy.algorithmVersion)}, high ≥{" "}
        {String(r.policy.highMinAllowedRequests)} requests /{" "}
        {String(r.policy.highMinSubjects)} subjects /{" "}
        {String(r.policy.highMinDays)} days · policy hash{" "}
        <Mono>{r.policyHash.slice(0, 12)}</Mono>
      </p>
    </details>
  );
}

export function LearningRecommendations(
  props: LearningRecommendationsProps,
): JSX.Element {
  const {
    list,
    isAdmin,
    canOperate,
    blocked,
    owner,
    refetchAll,
    latchUnknown,
  } = props;

  const [accepting, setAccepting] = useState<PLRecommendation | null>(null);
  const [acceptResult, setAcceptResult] = useState<ConfirmResult>("idle");
  const [acceptError, setAcceptError] = useState("");
  const [acceptSuccess, setAcceptSuccess] = useState<AcceptSuccess | null>(
    null,
  );

  const [rejecting, setRejecting] = useState<PLRecommendation | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [rejectResult, setRejectResult] = useState<ConfirmResult>("idle");
  const [rejectError, setRejectError] = useState("");

  // §33 — post-accept agreement check: the draft must be active and the
  // effective (candidate) rulebase must carry the DISABLED target rule.
  const runAgreementCheck = (recId: string, ruleId: string): void => {
    const signal = owner.begin();
    void Promise.all([getPolicy(signal), getDraftState(signal)])
      .then(([snap, draft]) => {
        const target = snap.rules.find((r) => r.id === ruleId);
        const ok =
          draft.active && snap.draft && target !== undefined && !target.enabled;
        setAcceptSuccess((cur) =>
          cur === null || cur.recId !== recId
            ? cur
            : {
                ...cur,
                agreement: ok ? "ok" : "inconsistent",
                agreementDetail: ok
                  ? ""
                  : !draft.active
                    ? "No active Policy Draft was found after the accept."
                    : target === undefined
                      ? "The created rule is not visible in the draft rulebase snapshot."
                      : "The created rule is not disabled as expected.",
              },
        );
      })
      .catch(() => {
        setAcceptSuccess((cur) =>
          cur === null || cur.recId !== recId
            ? cur
            : {
                ...cur,
                agreement: "inconsistent",
                agreementDetail:
                  "The post-accept verification could not be completed — review the Policy Draft directly.",
              },
        );
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  const runAccept = (rec: PLRecommendation): void => {
    const signal = owner.begin();
    setAcceptResult("pending");
    acceptRecommendation(rec.id, list.policyVersion, signal)
      .then((res) => {
        setAccepting(null);
        setAcceptResult("idle");
        setAcceptError("");
        setAcceptSuccess({
          recId: res.recommendation.id,
          ruleId: res.ruleId,
          alreadyDone: res.alreadyDone,
          note: res.note,
          agreement: null,
          agreementDetail: "",
        });
        refetchAll();
        runAgreementCheck(res.recommendation.id, res.ruleId);
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          // §34: NEVER blindly re-Accept — close into the page latch; the
          // resolution path refetches recommendation + draft truth first.
          setAccepting(null);
          setAcceptResult("idle");
          latchUnknown("accept");
          return;
        }
        setAcceptResult("failed");
        setAcceptError(
          serverErrorText(err, "The appliance refused the accept."),
        );
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  const runReject = (rec: PLRecommendation): void => {
    const signal = owner.begin();
    setRejectResult("pending");
    rejectRecommendation(rec.id, rejectReason.trim(), signal)
      .then(() => {
        setRejecting(null);
        setRejectReason("");
        setRejectResult("idle");
        setRejectError("");
        refetchAll();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setRejecting(null);
          setRejectResult("idle");
          latchUnknown("reject");
          return;
        }
        setRejectResult("failed");
        setRejectError(
          serverErrorText(err, "The appliance refused the reject."),
        );
      })
      .finally(() => {
        owner.settle(signal);
      });
  };

  return (
    <Card title="Recommendations">
      {acceptSuccess !== null && (
        <Callout
          variant={
            acceptSuccess.agreement === "inconsistent" ? "warning" : "success"
          }
          title={
            acceptSuccess.alreadyDone
              ? "Already accepted (idempotent)"
              : "Accepted to Policy Draft"
          }
        >
          {acceptSuccess.note} Created rule <Mono>{acceptSuccess.ruleId}</Mono>.{" "}
          <Link
            to={`/policies/access-rules?rule=${encodeURIComponent(acceptSuccess.ruleId)}`}
          >
            Review created rule
          </Link>
          {acceptSuccess.agreement === "inconsistent" && (
            <p>
              Post-accept verification found an inconsistency:{" "}
              {acceptSuccess.agreementDetail} The appliance&apos;s durable
              intent record reconciles on the next admin action — review the
              Policy Draft before further decisions.
            </p>
          )}
        </Callout>
      )}

      {!list.draftModeArmed && isAdmin && (
        <Callout variant="info" title="Policy Draft mode is not armed">
          Accepting a recommendation creates a DISABLED rule in the shared
          Policy Draft, which requires Require Commit to be armed. Arm it from
          the Access Rules page — this page never changes the draft mode itself.
        </Callout>
      )}

      {list.recommendations.length === 0 && (
        <p>
          No recommendations. Complete a Learning session and generate
          recommendations from it — nothing is generated automatically.
        </p>
      )}

      <ul className={styles.recList}>
        {list.recommendations.map((r) => {
          const fresh = r.staleReasons.length === 0;
          const acceptable =
            isAdmin && r.state === "generated" && fresh && list.draftModeArmed;
          return (
            <li key={r.id} className={styles.recCard}>
              <div className={styles.recHeader}>
                {stateBadge(r)} {confidenceBadge(r.confidence)}{" "}
                <strong>
                  Allow group {r.group} → category {r.category}
                </strong>{" "}
                <Mono>{r.id.slice(0, 12)}</Mono>
              </div>
              <p className={styles.recMeta}>
                Proposed rule (born safe): action {r.proposedRule.action}, TLS{" "}
                {r.proposedRule.sslAction},{" "}
                {r.proposedRule.enabled ? "ENABLED" : "disabled"} · generated{" "}
                {r.generatedAt} · session{" "}
                <Mono>{r.sessionId.slice(0, 12)}</Mono>
              </p>
              {r.confidenceReasons.length > 0 && (
                <p className={styles.recMeta}>
                  Supported by: {r.confidenceReasons.join("; ")}
                </p>
              )}
              {r.confidenceLimits.length > 0 && (
                <p className={styles.recMeta}>
                  Limited by: {r.confidenceLimits.join("; ")}
                </p>
              )}
              {!fresh && (
                <Callout variant="warning" title="Stale (server-evaluated)">
                  <ul>
                    {r.staleReasons.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                  A stale recommendation cannot be accepted as fresh evidence —
                  re-run a Learning session against the current policy state.
                </Callout>
              )}
              {r.state === "accepted" && r.targetRuleId !== "" && (
                <p className={styles.recMeta}>
                  Accepted {r.acceptedAt} by {r.acceptedBy} → draft rule{" "}
                  <Link
                    to={`/policies/access-rules?rule=${encodeURIComponent(r.targetRuleId)}`}
                  >
                    <Mono>{r.targetRuleId}</Mono>
                  </Link>
                </p>
              )}
              {r.state === "rejected" && (
                <p className={styles.recMeta}>
                  Rejected {r.rejectedAt} by {r.rejectedBy}
                  {r.rejectReason !== "" && <> — {r.rejectReason}</>}
                </p>
              )}
              <RecommendationEvidence r={r} />
              <div className={styles.recActions}>
                {acceptable && (
                  <Button
                    size="sm"
                    disabled={blocked}
                    onClick={() => {
                      setAccepting(r);
                      setAcceptResult("idle");
                      setAcceptError("");
                    }}
                  >
                    Accept to Policy Draft…
                  </Button>
                )}
                {canOperate && r.state === "generated" && (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={blocked}
                    onClick={() => {
                      setRejecting(r);
                      setRejectReason("");
                      setRejectResult("idle");
                      setRejectError("");
                    }}
                  >
                    Reject…
                  </Button>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      {accepting !== null && (
        <ConfirmationDialog
          open
          tier={2}
          title={`Accept to Policy Draft: ${accepting.group} → ${accepting.category}`}
          body={
            <>
              This creates a DISABLED Access Rule in the shared Policy Draft. It
              does not change enforcement. The rule must be reviewed and
              explicitly committed before it can affect live traffic.
            </>
          }
          impact="A disabled draft rule is created from this recommendation's evidence; live policy is unchanged."
          rollback="Delete the draft rule, or revert the Policy Draft."
          confirmLabel="Accept to Policy Draft"
          destructive={false}
          result={acceptResult}
          errorText={acceptError}
          onConfirm={() => {
            if (acceptResult !== "pending") runAccept(accepting);
          }}
          onCancel={() => {
            if (acceptResult !== "pending") {
              setAccepting(null);
              setAcceptResult("idle");
              setAcceptError("");
            }
          }}
        />
      )}

      {rejecting !== null && (
        <ConfirmationDialog
          open
          tier={1}
          title={`Reject recommendation: ${rejecting.group} → ${rejecting.category}`}
          body={
            <>
              <p>
                Rejecting records a decision on this recommendation only — no
                policy or configuration changes.
              </p>
              <TextareaField
                label="Reason (optional, recorded in the audit trail)"
                value={rejectReason}
                onChange={(e) => {
                  setRejectReason(e.target.value);
                }}
              />
            </>
          }
          confirmLabel="Reject"
          destructive={false}
          result={rejectResult}
          errorText={rejectError}
          onConfirm={() => {
            if (rejectResult !== "pending") runReject(rejecting);
          }}
          onCancel={() => {
            if (rejectResult !== "pending") {
              setRejecting(null);
              setRejectReason("");
              setRejectResult("idle");
              setRejectError("");
            }
          }}
        />
      )}
    </Card>
  );
}
