// 2C.4 — Policy Learning API adapters (ADR-0025; M5A/M5B admin surface,
// ui_policy_learning.go). ADVISORY ONLY and NODE-LOCAL by design — the notes
// stating both are SERVER truth carried on the status/config envelopes and
// rendered verbatim. Snapshot model only (ADR-FE-002): no polling, no SSE,
// no auto-generate, no auto-accept.
//
// Field fidelity (§22/§25): every DTO below is derived from the Go source
// (plSessionDTO / plRecommendationDTO and the policylearn Evidence/Coverage/
// ProposedRule/RecommendationPolicy structs). Staleness is SERVER-computed
// (stale_reasons); this client renders the returned reasons and reproduces
// no staleness logic. Malformed nested evidence fails closed (DecodeError).
import { apiRequest } from "./client";
import {
  field,
  readArray,
  readBoolean,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

const optStr = readOptional(readString);
const optNum = readOptional(readNumber);
const optBool = readOptional(readBoolean);

function readStringsOrNull(v: unknown, path: string): readonly string[] {
  if (v === undefined || v === null) return [];
  return readArray(readString)(v, path);
}

// ── vocabulary (closed sets from the engine; unknown values are preserved
// verbatim and classified unknown — never guessed) ─────────────────────────
export const PL_SESSION_STATES = [
  "learning",
  "completed",
  "cancelled",
] as const;
export const PL_REC_STATES = [
  "generated",
  "superseded",
  "accepting",
  "accepted",
  "rejected",
] as const;
export const PL_CONFIDENCE = ["high", "medium", "low"] as const;

export function isKnownRecState(s: string): boolean {
  return PL_REC_STATES.some((k) => k === s);
}

// ── shared DTOs ────────────────────────────────────────────────────────────

export interface PLTransport {
  accepted: number;
  dropped: number;
  rejected: number;
  consumerPanics: number;
  groupsTruncated: number;
  degraded: boolean;
}

const decodeTransport: Decoder<PLTransport> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    accepted: field(o, "accepted", optNum, path) ?? 0,
    dropped: field(o, "dropped", optNum, path) ?? 0,
    rejected: field(o, "rejected", optNum, path) ?? 0,
    consumerPanics: field(o, "consumer_panics", optNum, path) ?? 0,
    groupsTruncated: field(o, "groups_truncated", optNum, path) ?? 0,
    degraded: field(o, "degraded", optBool, path) ?? false,
  };
};

export interface PLBaseline {
  policyGeneration: number;
  defaultAction: string;
  capturedAt: string;
  categoryEpoch: string;
  guardrailsHash: string;
  policyContentHash: string;
}

const decodeBaseline: Decoder<PLBaseline> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    policyGeneration: field(o, "policy_generation", readNumber, path),
    defaultAction: field(o, "default_action", optStr, path) ?? "",
    capturedAt: field(o, "captured_at", optStr, path) ?? "",
    categoryEpoch: field(o, "category_epoch", optStr, path) ?? "",
    guardrailsHash: field(o, "guardrails_hash", optStr, path) ?? "",
    policyContentHash: field(o, "policy_content_hash", optStr, path) ?? "",
  };
};

export interface PLGap {
  at: string;
  reason: string;
}

const decodeGap: Decoder<PLGap> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    at: field(o, "at", readString, path),
    reason: field(o, "reason", readString, path),
  };
};

export interface PLSession {
  id: string;
  state: string;
  createdAt: string;
  startedAt: string;
  stoppedAt: string;
  createdBy: string;
  stoppedBy: string;
  baseline: PLBaseline;
  gaps: readonly PLGap[];
  transport: PLTransport;
  churnEvents: number;
  cells: number;
  cellsDropped: number;
  churnOverflow: number;
  subjectKeyChanged: boolean;
}

export const decodePLSession: Decoder<PLSession> = (v, path = "$") => {
  const o = readRecord(v, path);
  const gapsRaw = o["gaps"];
  return {
    id: field(o, "id", readString, path),
    state: field(o, "state", readString, path),
    createdAt: field(o, "created_at", readString, path),
    startedAt: field(o, "started_at", readString, path),
    stoppedAt: field(o, "stopped_at", optStr, path) ?? "",
    createdBy: field(o, "created_by", optStr, path) ?? "",
    stoppedBy: field(o, "stopped_by", optStr, path) ?? "",
    baseline: field(o, "baseline", decodeBaseline, path),
    gaps:
      gapsRaw === undefined || gapsRaw === null
        ? []
        : readArray(decodeGap)(gapsRaw, `${path}.gaps`),
    transport: field(o, "transport", decodeTransport, path),
    churnEvents: field(o, "churn_events", readNumber, path),
    cells: field(o, "cells", optNum, path) ?? 0,
    cellsDropped: field(o, "cells_dropped", optNum, path) ?? 0,
    churnOverflow: field(o, "churn_overflow", optNum, path) ?? 0,
    subjectKeyChanged: field(o, "subject_key_changed", optBool, path) ?? false,
  };
};

// ── status (GET /api/policy-learning) ──────────────────────────────────────

export interface PLEngineStats {
  sessions: number;
  recommendations: number;
  readOnly: boolean;
  schemaVersion: number;
  maxRetained: number;
  maxDurationSec: number;
}

export interface LearningStatus {
  enabled: boolean;
  scope: string;
  scopeNote: string;
  advisoryNote: string;
  runtimeError: string;
  learningActive: boolean;
  activeSession: PLSession | undefined;
  engine: PLEngineStats | undefined;
  observation: PLTransport | undefined;
  recommendationPolicy: PLRecommendationPolicy | undefined;
  recommendationPolicyHash: string;
  guardrailsHash: string;
}

export const decodeLearningStatus: Decoder<LearningStatus> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const engineRaw = o["engine"];
  let engine: PLEngineStats | undefined;
  if (engineRaw !== undefined && engineRaw !== null) {
    const e = readRecord(engineRaw, `${path}.engine`);
    engine = {
      sessions: field(e, "sessions", readNumber, `${path}.engine`),
      recommendations: field(
        e,
        "recommendations",
        readNumber,
        `${path}.engine`,
      ),
      readOnly: field(e, "read_only", readBoolean, `${path}.engine`),
      schemaVersion: field(e, "schema_version", readNumber, `${path}.engine`),
      maxRetained: field(e, "max_retained", readNumber, `${path}.engine`),
      maxDurationSec: field(
        e,
        "max_duration_sec",
        readNumber,
        `${path}.engine`,
      ),
    };
  }
  return {
    enabled: field(o, "enabled", readBoolean, path),
    scope: field(o, "scope", readString, path),
    scopeNote: field(o, "scope_note", optStr, path) ?? "",
    advisoryNote: field(o, "advisory_note", optStr, path) ?? "",
    runtimeError: field(o, "runtime_error", optStr, path) ?? "",
    learningActive: field(o, "learning_active", optBool, path) ?? false,
    activeSession: field(
      o,
      "active_session",
      readOptional(decodePLSession),
      path,
    ),
    engine,
    observation: field(o, "observation", readOptional(decodeTransport), path),
    recommendationPolicy: field(
      o,
      "recommendation_policy",
      readOptional(decodeRecommendationPolicy),
      path,
    ),
    recommendationPolicyHash:
      field(o, "recommendation_policy_hash", optStr, path) ?? "",
    guardrailsHash: field(o, "guardrails_hash", optStr, path) ?? "",
  };
};

export function getLearningStatus(
  signal?: AbortSignal,
): Promise<LearningStatus> {
  return apiRequest(
    "/api/policy-learning",
    decodeLearningStatus,
    signal !== undefined ? { signal } : {},
  );
}

// ── config (GET/PUT /api/policy-learning/config) ───────────────────────────

export interface LearningConfig {
  enabled: boolean;
  governed: boolean;
  recommendableCategories: readonly string[];
  categoriesAreSeed: boolean;
  seedSource: string;
  /** M5A: the decision policy is READ-ONLY — the UI must offer no editors */
  thresholdsEditable: boolean;
  advisoryNote: string;
  scope: string;
  recommendationPolicy: PLRecommendationPolicy | undefined;
  recommendationPolicyHash: string;
  guardrailsHash: string;
}

export const decodeLearningConfig: Decoder<LearningConfig> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    governed: field(o, "governed", readBoolean, path),
    recommendableCategories: readStringsOrNull(
      o["recommendable_categories"],
      `${path}.recommendable_categories`,
    ),
    categoriesAreSeed: field(o, "categories_are_seed", readBoolean, path),
    seedSource: field(o, "seed_source", optStr, path) ?? "",
    thresholdsEditable: field(o, "thresholds_editable", readBoolean, path),
    advisoryNote: field(o, "advisory_note", optStr, path) ?? "",
    scope: field(o, "scope", optStr, path) ?? "",
    recommendationPolicy: field(
      o,
      "recommendation_policy",
      readOptional(decodeRecommendationPolicy),
      path,
    ),
    recommendationPolicyHash:
      field(o, "recommendation_policy_hash", optStr, path) ?? "",
    guardrailsHash: field(o, "guardrails_hash", optStr, path) ?? "",
  };
};

export function getLearningConfig(
  signal?: AbortSignal,
): Promise<LearningConfig> {
  return apiRequest(
    "/api/policy-learning/config",
    decodeLearningConfig,
    signal !== undefined ? { signal } : {},
  );
}

export interface LearningConfigWrite {
  enabled?: boolean;
  recommendableCategories?: readonly string[];
}

const decodeConfigPutResult: Decoder<{
  enabled: boolean;
  recommendableCategories: readonly string[];
  runtimeError: string;
}> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    recommendableCategories: readStringsOrNull(
      o["recommendable_categories"],
      `${path}.recommendable_categories`,
    ),
    runtimeError: field(o, "runtime_error", optStr, path) ?? "",
  };
};

export function putLearningConfig(
  w: LearningConfigWrite,
  signal?: AbortSignal,
): Promise<{
  enabled: boolean;
  recommendableCategories: readonly string[];
  runtimeError: string;
}> {
  const body: Record<string, unknown> = {};
  if (w.enabled !== undefined) body["enabled"] = w.enabled;
  if (w.recommendableCategories !== undefined)
    body["recommendable_categories"] = w.recommendableCategories;
  return apiRequest("/api/policy-learning/config", decodeConfigPutResult, {
    method: "PUT",
    body,
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── session lifecycle (POST /api/policy-learning/session) ──────────────────

export type LearningSessionAction = "start" | "complete" | "cancel";

export function postLearningSession(
  action: LearningSessionAction,
  signal?: AbortSignal,
): Promise<PLSession> {
  return apiRequest("/api/policy-learning/session", decodePLSession, {
    method: "POST",
    body: { action },
    ...(signal !== undefined ? { signal } : {}),
  });
}

export interface SessionList {
  enabled: boolean;
  scope: string;
  sessions: readonly PLSession[];
}

const decodeSessionList: Decoder<SessionList> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["sessions"];
  return {
    enabled: field(o, "enabled", readBoolean, path),
    scope: field(o, "scope", optStr, path) ?? "",
    sessions:
      raw === undefined || raw === null
        ? []
        : readArray(decodePLSession)(raw, `${path}.sessions`),
  };
};

export function getLearningSessions(
  signal?: AbortSignal,
): Promise<SessionList> {
  return apiRequest(
    "/api/policy-learning/sessions",
    decodeSessionList,
    signal !== undefined ? { signal } : {},
  );
}

// ── recommendations ────────────────────────────────────────────────────────

export interface PLProposedRule {
  action: string;
  sslAction: string;
  enabled: boolean;
  sourceGroup: string;
  destCategory: string;
}

const decodeProposedRule: Decoder<PLProposedRule> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    action: field(o, "action", readString, path),
    sslAction: field(o, "ssl_action", readString, path),
    enabled: field(o, "enabled", readBoolean, path),
    sourceGroup: field(o, "source_group", readString, path),
    destCategory: field(o, "dest_category", readString, path),
  };
};

export interface PLHostCount {
  host: string;
  count: number;
}

const decodeHostCount: Decoder<PLHostCount> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    host: field(o, "host", readString, path),
    count: field(o, "count", readNumber, path),
  };
};

export interface PLAttributionCount {
  key: string;
  count: number;
}

const decodeAttributionCount: Decoder<PLAttributionCount> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    key: field(o, "key", readString, path),
    count: field(o, "count", readNumber, path),
  };
};

export interface PLEvidence {
  allowedRequests: number;
  policyBlockedRequests: number;
  threatBlockedRequests: number;
  observedAllowedSubjects: number;
  subjectsIsLowerBound: boolean;
  subjectOverflow: number;
  allowedObservationDays: number;
  daysIsLowerBound: boolean;
  dayOverflow: number;
  allowedFirstSeen: number;
  allowedLastSeen: number;
  topAllowedHosts: readonly PLHostCount[];
  otherAllowedHosts: number;
  ruleHits: readonly PLAttributionCount[];
  otherRules: number;
  tierHits: readonly PLAttributionCount[];
  otherTiers: number;
}

const decodeEvidence: Decoder<PLEvidence> = (v, path = "$") => {
  const o = readRecord(v, path);
  const hostsRaw = o["top_allowed_hosts"];
  const rulesRaw = o["rule_hits"];
  const tiersRaw = o["tier_hits"];
  return {
    allowedRequests: field(o, "allowed_requests", readNumber, path),
    policyBlockedRequests:
      field(o, "policy_blocked_requests", optNum, path) ?? 0,
    threatBlockedRequests:
      field(o, "threat_blocked_requests", optNum, path) ?? 0,
    observedAllowedSubjects: field(
      o,
      "observed_allowed_subjects",
      readNumber,
      path,
    ),
    subjectsIsLowerBound:
      field(o, "subjects_is_lower_bound", optBool, path) ?? false,
    subjectOverflow: field(o, "subject_overflow", optNum, path) ?? 0,
    allowedObservationDays: field(
      o,
      "allowed_observation_days",
      readNumber,
      path,
    ),
    daysIsLowerBound: field(o, "days_is_lower_bound", optBool, path) ?? false,
    dayOverflow: field(o, "day_overflow", optNum, path) ?? 0,
    allowedFirstSeen: field(o, "allowed_first_seen", optNum, path) ?? 0,
    allowedLastSeen: field(o, "allowed_last_seen", optNum, path) ?? 0,
    topAllowedHosts:
      hostsRaw === undefined || hostsRaw === null
        ? []
        : readArray(decodeHostCount)(hostsRaw, `${path}.top_allowed_hosts`),
    otherAllowedHosts: field(o, "other_allowed_hosts", optNum, path) ?? 0,
    ruleHits:
      rulesRaw === undefined || rulesRaw === null
        ? []
        : readArray(decodeAttributionCount)(rulesRaw, `${path}.rule_hits`),
    otherRules: field(o, "other_rules", optNum, path) ?? 0,
    tierHits:
      tiersRaw === undefined || tiersRaw === null
        ? []
        : readArray(decodeAttributionCount)(tiersRaw, `${path}.tier_hits`),
    otherTiers: field(o, "other_tiers", optNum, path) ?? 0,
  };
};

export interface PLTransportWindow {
  accepted: number;
  dropped: number;
  rejected: number;
  consumerPanics: number;
  groupsTruncated: number;
}

const decodeTransportWindow: Decoder<PLTransportWindow> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    accepted: field(o, "accepted", optNum, path) ?? 0,
    dropped: field(o, "dropped", optNum, path) ?? 0,
    rejected: field(o, "rejected", optNum, path) ?? 0,
    consumerPanics: field(o, "consumer_panics", optNum, path) ?? 0,
    groupsTruncated: field(o, "groups_truncated", optNum, path) ?? 0,
  };
};

export interface PLCoverage {
  observedSubjects: number;
  subjectsIsLowerBound: boolean;
  observationDays: number;
  daysIsLowerBound: boolean;
  sessionWindowDays: number;
  transportLoss: PLTransportWindow | undefined;
  transportDegraded: boolean;
  membershipDenominatorKnown: boolean;
}

const decodeCoverage: Decoder<PLCoverage> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    observedSubjects: field(o, "observed_subjects", readNumber, path),
    subjectsIsLowerBound:
      field(o, "subjects_is_lower_bound", optBool, path) ?? false,
    observationDays: field(o, "observation_days", readNumber, path),
    daysIsLowerBound: field(o, "days_is_lower_bound", optBool, path) ?? false,
    sessionWindowDays: field(o, "session_window_days", optNum, path) ?? 0,
    transportLoss: field(
      o,
      "transport_loss",
      readOptional(decodeTransportWindow),
      path,
    ),
    transportDegraded: field(o, "transport_degraded", optBool, path) ?? false,
    membershipDenominatorKnown: field(
      o,
      "membership_denominator_known",
      readBoolean,
      path,
    ),
  };
};

export interface PLRecommendationPolicy {
  algorithmVersion: number;
  highMinAllowedRequests: number;
  highMinSubjects: number;
  highMinDays: number;
  mediumMinAllowedRequests: number;
  mediumMinSubjects: number;
  mediumMinDays: number;
  communityTiers: readonly string[];
}

const decodeRecommendationPolicy: Decoder<PLRecommendationPolicy> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    algorithmVersion: field(o, "algorithm_version", readNumber, path),
    highMinAllowedRequests: field(
      o,
      "high_min_allowed_requests",
      readNumber,
      path,
    ),
    highMinSubjects: field(o, "high_min_subjects", readNumber, path),
    highMinDays: field(o, "high_min_days", readNumber, path),
    mediumMinAllowedRequests: field(
      o,
      "medium_min_allowed_requests",
      readNumber,
      path,
    ),
    mediumMinSubjects: field(o, "medium_min_subjects", readNumber, path),
    mediumMinDays: field(o, "medium_min_days", readNumber, path),
    communityTiers: readStringsOrNull(
      o["community_tiers"],
      `${path}.community_tiers`,
    ),
  };
};

export interface PLRecommendation {
  id: string;
  sessionId: string;
  /** wire state verbatim; only known states get decision affordances */
  state: string;
  stateKnown: boolean;
  group: string;
  category: string;
  proposedRule: PLProposedRule;
  confidence: string;
  confidenceReasons: readonly string[];
  confidenceLimits: readonly string[];
  coverage: PLCoverage;
  evidence: PLEvidence;
  baseline: PLBaseline;
  policy: PLRecommendationPolicy;
  policyHash: string;
  generatedAt: string;
  /** SERVER-computed staleness; empty = fresh. Never recomputed client-side. */
  staleReasons: readonly string[];
  targetRuleId: string;
  acceptedAt: string;
  acceptedBy: string;
  rejectedAt: string;
  rejectedBy: string;
  rejectReason: string;
}

export const decodePLRecommendation: Decoder<PLRecommendation> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const state = field(o, "state", readString, path);
  return {
    id: field(o, "id", readString, path),
    sessionId: field(o, "session_id", readString, path),
    state,
    stateKnown: isKnownRecState(state),
    group: field(o, "group", readString, path),
    category: field(o, "category", readString, path),
    proposedRule: field(o, "proposed_rule", decodeProposedRule, path),
    confidence: field(o, "confidence", readString, path),
    confidenceReasons: readStringsOrNull(
      o["confidence_reasons"],
      `${path}.confidence_reasons`,
    ),
    confidenceLimits: readStringsOrNull(
      o["confidence_limits"],
      `${path}.confidence_limits`,
    ),
    coverage: field(o, "coverage", decodeCoverage, path),
    evidence: field(o, "evidence", decodeEvidence, path),
    baseline: field(o, "baseline", decodeBaseline, path),
    policy: field(o, "policy", decodeRecommendationPolicy, path),
    policyHash: field(o, "policy_hash", readString, path),
    generatedAt: field(o, "generated_at", readString, path),
    staleReasons: readStringsOrNull(
      o["stale_reasons"],
      `${path}.stale_reasons`,
    ),
    targetRuleId: field(o, "target_rule_id", optStr, path) ?? "",
    acceptedAt: field(o, "accepted_at", optStr, path) ?? "",
    acceptedBy: field(o, "accepted_by", optStr, path) ?? "",
    rejectedAt: field(o, "rejected_at", optStr, path) ?? "",
    rejectedBy: field(o, "rejected_by", optStr, path) ?? "",
    rejectReason: field(o, "reject_reason", optStr, path) ?? "",
  };
};

export interface RecommendationList {
  enabled: boolean;
  scope: string;
  recommendations: readonly PLRecommendation[];
  /** M5B accept prerequisites — server facts; the server stays the authority */
  draftModeArmed: boolean;
  policyVersion: number;
}

const decodeRecommendationList: Decoder<RecommendationList> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = o["recommendations"];
  return {
    enabled: field(o, "enabled", readBoolean, path),
    scope: field(o, "scope", optStr, path) ?? "",
    recommendations:
      raw === undefined || raw === null
        ? []
        : readArray(decodePLRecommendation)(raw, `${path}.recommendations`),
    draftModeArmed: field(o, "draft_mode_armed", optBool, path) ?? false,
    policyVersion: field(o, "policy_version", optNum, path) ?? 0,
  };
};

export function getLearningRecommendations(
  signal?: AbortSignal,
): Promise<RecommendationList> {
  return apiRequest(
    "/api/policy-learning/recommendations",
    decodeRecommendationList,
    signal !== undefined ? { signal } : {},
  );
}

// ── generate (POST, operator; existing action only — no automation) ────────

export interface GenerateResult {
  sessionId: string;
  recommendations: readonly PLRecommendation[];
  eligibleCells: number;
  truncatedCells: number;
  skippedSyntheticScope: number;
  skippedCategory: number;
  skippedNoAllowedEvidence: number;
  superseded: number;
  unchanged: number;
}

const decodeGenerateResult: Decoder<GenerateResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["recommendations"];
  return {
    sessionId: field(o, "session_id", readString, path),
    recommendations:
      raw === undefined || raw === null
        ? []
        : readArray(decodePLRecommendation)(raw, `${path}.recommendations`),
    eligibleCells: field(o, "eligible_cells", optNum, path) ?? 0,
    truncatedCells: field(o, "truncated_cells", optNum, path) ?? 0,
    skippedSyntheticScope:
      field(o, "skipped_synthetic_scope", optNum, path) ?? 0,
    skippedCategory: field(o, "skipped_category", optNum, path) ?? 0,
    skippedNoAllowedEvidence:
      field(o, "skipped_no_allowed_evidence", optNum, path) ?? 0,
    superseded: field(o, "superseded", optNum, path) ?? 0,
    unchanged: field(o, "unchanged", optNum, path) ?? 0,
  };
};

export function generateRecommendations(
  sessionId: string,
  signal?: AbortSignal,
): Promise<GenerateResult> {
  return apiRequest(
    "/api/policy-learning/recommendations/generate",
    decodeGenerateResult,
    {
      method: "POST",
      body: { session_id: sessionId },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── the M5B decision boundary (§28–§32) ────────────────────────────────────
// Accept: ADMIN, RequireCommit armed, fresh recommendation, the LISTING's
// policy_version as if_version — body is EXACTLY {id, action, if_version};
// the backend owns translation, and the created rule is DISABLED in the
// Policy Draft only. Reject: operator+, decision-only, bounded reason.

export interface AcceptResult {
  recommendation: PLRecommendation;
  ruleId: string;
  /** idempotent re-accept converged on the already-created target */
  alreadyDone: boolean;
  note: string;
}

const decodeAcceptResult: Decoder<AcceptResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    recommendation: field(o, "recommendation", decodePLRecommendation, path),
    ruleId: field(o, "rule_id", readString, path),
    alreadyDone: field(o, "already_done", readBoolean, path),
    note: field(o, "note", optStr, path) ?? "",
  };
};

export function acceptRecommendation(
  id: string,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<AcceptResult> {
  return apiRequest(
    "/api/policy-learning/recommendations",
    decodeAcceptResult,
    {
      method: "POST",
      body: { id, action: "accept", if_version: ifVersion },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

const decodeRejectResult: Decoder<PLRecommendation> = (v, path = "$") => {
  const o = readRecord(v, path);
  return field(o, "recommendation", decodePLRecommendation, path);
};

export function rejectRecommendation(
  id: string,
  reason: string,
  signal?: AbortSignal,
): Promise<PLRecommendation> {
  return apiRequest(
    "/api/policy-learning/recommendations",
    decodeRejectResult,
    {
      method: "POST",
      body: { id, action: "reject", reason },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}
