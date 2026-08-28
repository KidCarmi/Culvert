// 2C.4 — Policy Learning decoder proofs (§25/§38): full field decode of the
// recommendation DTO (evidence, coverage, decision-policy transparency,
// baseline, server staleness, decision metadata), the status/config/session
// envelopes, the listing's accept-prerequisite facts, and fail-closed
// behavior on malformed nested evidence. Staleness is SERVER truth — these
// decoders carry stale_reasons verbatim and compute nothing.
import { describe, expect, it } from "vitest";
import {
  decodeLearningConfig,
  decodeLearningStatus,
  decodePLRecommendation,
  decodePLSession,
  isKnownRecState,
} from "../api/policyLearning";
import { DecodeError } from "../api/decode";

export const WIRE_REC = {
  id: "rec-abc123def456",
  session_id: "sess-0001",
  state: "generated",
  group: "engineering",
  category: "Software Downloads",
  proposed_rule: {
    action: "Allow",
    ssl_action: "Inspect",
    enabled: false,
    source_group: "engineering",
    dest_category: "Software Downloads",
  },
  confidence: "medium",
  confidence_reasons: ["allowed_requests >= 10", "subjects >= 3"],
  confidence_limits: ["transport loss occurred in the session window"],
  coverage: {
    observed_subjects: 4,
    observation_days: 3,
    session_window_days: 5,
    transport_loss: { dropped: 2, groups_truncated: 1 },
    transport_degraded: true,
    membership_denominator_known: false,
  },
  evidence: {
    allowed_requests: 42,
    policy_blocked_requests: 3,
    observed_allowed_subjects: 4,
    subjects_is_lower_bound: true,
    subject_overflow: 9,
    allowed_observation_days: 3,
    allowed_first_seen: 1756290000,
    allowed_last_seen: 1756390000,
    top_allowed_hosts: [{ host: "dl.example.test", count: 30 }],
    other_allowed_hosts: 7,
    rule_hits: [{ key: "rule-1", count: 40 }],
    tier_hits: [{ key: "community", count: 42 }],
  },
  baseline: {
    policy_generation: 12,
    default_action: "deny",
    captured_at: "2026-08-20T00:00:00Z",
    category_epoch: "v2|abc",
    guardrails_hash: "gh-1",
    policy_content_hash: "pch-1",
  },
  policy: {
    algorithm_version: 1,
    high_min_allowed_requests: 30,
    high_min_subjects: 5,
    high_min_days: 5,
    medium_min_allowed_requests: 10,
    medium_min_subjects: 3,
    medium_min_days: 2,
    community_tiers: ["community"],
  },
  policy_hash: "ph-1",
  generated_at: "2026-08-27T00:00:00Z",
  stale_reasons: [],
};

describe("decodePLRecommendation", () => {
  it("decodes every field of the full DTO", () => {
    const r = decodePLRecommendation(WIRE_REC);
    expect(r.id).toBe("rec-abc123def456");
    expect(r.state).toBe("generated");
    expect(r.stateKnown).toBe(true);
    expect(r.proposedRule).toEqual({
      action: "Allow",
      sslAction: "Inspect",
      enabled: false,
      sourceGroup: "engineering",
      destCategory: "Software Downloads",
    });
    expect(r.confidence).toBe("medium");
    expect(r.confidenceReasons).toHaveLength(2);
    expect(r.confidenceLimits).toHaveLength(1);
    expect(r.evidence.allowedRequests).toBe(42);
    expect(r.evidence.policyBlockedRequests).toBe(3);
    expect(r.evidence.subjectsIsLowerBound).toBe(true);
    expect(r.evidence.subjectOverflow).toBe(9);
    expect(r.evidence.topAllowedHosts[0]).toEqual({
      host: "dl.example.test",
      count: 30,
    });
    expect(r.evidence.ruleHits[0]?.key).toBe("rule-1");
    expect(r.coverage.transportDegraded).toBe(true);
    expect(r.coverage.transportLoss?.dropped).toBe(2);
    expect(r.coverage.membershipDenominatorKnown).toBe(false);
    expect(r.baseline.policyGeneration).toBe(12);
    expect(r.baseline.guardrailsHash).toBe("gh-1");
    expect(r.policy.algorithmVersion).toBe(1);
    expect(r.policy.mediumMinSubjects).toBe(3);
    expect(r.policyHash).toBe("ph-1");
    expect(r.staleReasons).toEqual([]);
    expect(r.targetRuleId).toBe("");
  });

  it("carries server staleness verbatim and decision metadata", () => {
    const r = decodePLRecommendation({
      ...WIRE_REC,
      state: "accepted",
      stale_reasons: ["policy_content_changed"],
      target_rule_id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
      accepted_at: "2026-08-28T00:00:00Z",
      accepted_by: "admin",
    });
    expect(r.staleReasons).toEqual(["policy_content_changed"]);
    expect(r.targetRuleId).toBe("01J3ZV9E3JD0AAAAAAAAAAAAAA");
    expect(r.acceptedBy).toBe("admin");
  });

  it("an unknown state is preserved verbatim and classified unknown", () => {
    const r = decodePLRecommendation({ ...WIRE_REC, state: "quantum" });
    expect(r.state).toBe("quantum");
    expect(r.stateKnown).toBe(false);
    expect(isKnownRecState("quantum")).toBe(false);
  });

  it("malformed nested evidence fails closed", () => {
    expect(() =>
      decodePLRecommendation({
        ...WIRE_REC,
        evidence: { ...WIRE_REC.evidence, allowed_requests: "not-a-number" },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodePLRecommendation({
        ...WIRE_REC,
        evidence: {
          ...WIRE_REC.evidence,
          top_allowed_hosts: [{ host: 42, count: "x" }],
        },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodePLRecommendation({ ...WIRE_REC, coverage: "nope" }),
    ).toThrow(DecodeError);
    expect(() => decodePLRecommendation({ ...WIRE_REC, policy: null })).toThrow(
      DecodeError,
    );
  });
});

describe("session + status + config envelopes", () => {
  const WIRE_SESSION = {
    id: "sess-0001",
    state: "completed",
    created_at: "2026-08-25T00:00:00Z",
    started_at: "2026-08-25T00:00:00Z",
    stopped_at: "2026-08-27T00:00:00Z",
    created_by: "op-user",
    stopped_by: "op-user",
    baseline: { policy_generation: 12 },
    gaps: [{ at: "2026-08-26T00:00:00Z", reason: "restart" }],
    transport: {
      accepted: 100,
      dropped: 2,
      rejected: 0,
      consumer_panics: 0,
      groups_truncated: 1,
      degraded: true,
    },
    churn_events: 1,
    cells: 6,
    cells_dropped: 0,
    churn_overflow: 0,
    subject_key_changed: false,
  };

  it("decodes the session DTO with quality facts", () => {
    const s = decodePLSession(WIRE_SESSION);
    expect(s.state).toBe("completed");
    expect(s.transport.accepted).toBe(100);
    expect(s.transport.degraded).toBe(true);
    expect(s.transport.groupsTruncated).toBe(1);
    expect(s.gaps[0]?.reason).toBe("restart");
    expect(s.cells).toBe(6);
    expect(s.subjectKeyChanged).toBe(false);
  });

  it("decodes the status envelope (enabled shape)", () => {
    const st = decodeLearningStatus({
      enabled: true,
      scope: "node-local",
      scope_note: "Learning observes traffic on this node only",
      advisory_note: "Policy Learning is advisory only",
      learning_active: true,
      active_session: WIRE_SESSION,
      engine: {
        sessions: 2,
        recommendations: 3,
        read_only: false,
        schema_version: 7,
        max_retained: 16,
        max_duration_sec: 86400,
      },
      observation: {
        accepted: 100,
        dropped: 0,
        rejected: 0,
        consumer_panics: 0,
        groups_truncated: 0,
        degraded: false,
      },
      recommendation_policy: WIRE_REC.policy,
      recommendation_policy_hash: "ph-1",
      guardrails_hash: "gh-1",
    });
    expect(st.enabled).toBe(true);
    expect(st.learningActive).toBe(true);
    expect(st.activeSession?.id).toBe("sess-0001");
    expect(st.engine?.readOnly).toBe(false);
    expect(st.observation?.degraded).toBe(false);
    expect(st.recommendationPolicy?.highMinSubjects).toBe(5);
  });

  it("decodes the disabled status shape (no engine)", () => {
    const st = decodeLearningStatus({
      enabled: false,
      scope: "node-local",
      scope_note: "n",
      advisory_note: "a",
      learning_active: false,
    });
    expect(st.enabled).toBe(false);
    expect(st.engine).toBeUndefined();
    expect(st.activeSession).toBeUndefined();
  });

  it("decodes config with the READ-ONLY thresholds contract", () => {
    const c = decodeLearningConfig({
      enabled: true,
      governed: true,
      recommendable_categories: ["News", "Software Downloads"],
      categories_are_seed: false,
      seed_source: "embedded business-category set",
      thresholds_editable: false,
      advisory_note: "a",
      scope: "node-local",
    });
    expect(c.thresholdsEditable).toBe(false);
    expect(c.recommendableCategories).toEqual(["News", "Software Downloads"]);
    expect(c.governed).toBe(true);
  });
});
