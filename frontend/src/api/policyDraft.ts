// 2B.1 — Policy Draft state contract (GET /api/policy/draft) + the draft
// lifecycle mutations (Require Commit mode, commit, revert).
//
// The GET response is DISCRIMINATED on `active`: the common truth
// (requireCommit/active/actor/startedAt) is always required; the candidate
// fields (diff/pendingCount/version/shadows) are REQUIRED when active=true
// and structurally absent when active=false — the decoder never invents
// empty active fields, and an active response missing them fails closed.
import type { Decoder } from "./decode";
import {
  field,
  readArray,
  readBoolean,
  readNumber,
  readRecord,
  readString,
} from "./decode";
import { apiRequest } from "./client";

export interface DraftDiff {
  added: readonly string[];
  modified: readonly string[];
  removed: readonly string[];
}

export interface ShadowFinding {
  rule: string;
  shadowedBy: string;
}

export interface DraftStateCommon {
  requireCommit: boolean;
  actor: string;
  startedAt: string;
}

export interface DraftInactive extends DraftStateCommon {
  active: false;
}

export interface DraftActive extends DraftStateCommon {
  active: true;
  diff: DraftDiff;
  pendingCount: number;
  /** the candidate generation — the ifVersion a reviewed commit must assert */
  version: number;
  shadows: readonly ShadowFinding[];
}

export type DraftState = DraftInactive | DraftActive;

const readStringsOrNull = (v: unknown, path: string): readonly string[] => {
  if (v === undefined || v === null) return [];
  return readArray(readString)(v, path);
};

const decodeDiff: Decoder<DraftDiff> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    added: readStringsOrNull(o["added"], `${path}.added`),
    modified: readStringsOrNull(o["modified"], `${path}.modified`),
    removed: readStringsOrNull(o["removed"], `${path}.removed`),
  };
};

const decodeShadow: Decoder<ShadowFinding> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    rule: field(o, "rule", readString, path),
    shadowedBy: field(o, "shadowedBy", readString, path),
  };
};

const readShadowsOrNull = (
  v: unknown,
  path: string,
): readonly ShadowFinding[] => {
  if (v === undefined || v === null) return [];
  return readArray(decodeShadow)(v, path);
};

export const decodeDraftState: Decoder<DraftState> = (v, path = "$") => {
  const o = readRecord(v, path);
  const common: DraftStateCommon = {
    requireCommit: field(o, "requireCommit", readBoolean, path),
    actor: field(o, "actor", readString, path),
    startedAt: field(o, "startedAt", readString, path),
  };
  const active = field(o, "active", readBoolean, path);
  if (!active) {
    return { ...common, active: false };
  }
  return {
    ...common,
    active: true,
    diff: field(o, "diff", decodeDiff, path),
    pendingCount: field(o, "pendingCount", readNumber, path),
    version: field(o, "version", readNumber, path),
    shadows: readShadowsOrNull(o["shadows"], `${path}.shadows`),
  };
};

export function getDraftState(signal?: AbortSignal): Promise<DraftState> {
  return apiRequest(
    "/api/policy/draft",
    decodeDraftState,
    signal !== undefined ? { signal } : {},
  );
}

// ── Lifecycle mutations ─────────────────────────────────────────────────────

const decodeRequireCommit: Decoder<boolean> = (v, path = "$") => {
  const o = readRecord(v, path);
  return field(o, "requireCommit", readBoolean, path);
};

/** PUT /api/policy/draft — arm/disarm Require Commit (admin). Disarming while
 * a dirty draft exists 409s server-side; the caller surfaces that verbatim. */
export function putRequireCommit(
  on: boolean,
  signal?: AbortSignal,
): Promise<boolean> {
  return apiRequest("/api/policy/draft", decodeRequireCommit, {
    method: "PUT",
    body: { require_commit: on },
    ...(signal !== undefined ? { signal } : {}),
  });
}

export interface CommitResult {
  committed: number;
  diff: DraftDiff;
}

const decodeCommitResult: Decoder<CommitResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  field(o, "ok", readBoolean, path);
  return {
    committed: field(o, "committed", readNumber, path),
    diff: field(o, "diff", decodeDiff, path),
  };
};

/** POST /api/policy/draft/commit?ifVersion=<reviewed candidate version>.
 * The comment is REQUIRED by the server; the ceremony enforces it client-side
 * too so the operator learns before submitting. */
export function commitDraft(
  comment: string,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<CommitResult> {
  return apiRequest(
    `/api/policy/draft/commit?ifVersion=${String(ifVersion)}`,
    decodeCommitResult,
    {
      method: "POST",
      body: { comment },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export interface RevertResult {
  discarded: number;
}

const decodeRevertResult: Decoder<RevertResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  field(o, "ok", readBoolean, path);
  return { discarded: field(o, "discarded", readNumber, path) };
};

/** POST /api/policy/draft/revert — discards the entire shared candidate. */
export function revertDraft(signal?: AbortSignal): Promise<RevertResult> {
  return apiRequest("/api/policy/draft/revert", decodeRevertResult, {
    method: "POST",
    ...(signal !== undefined ? { signal } : {}),
  });
}
