// 2C post-accept concurrency correction — the post-Accept verification state
// model.
//
// The server's Accept operation guarantees: acceptance never directly mutates
// running policy; the translated rule is born DISABLED; it enters the Policy
// Draft; enforcement is unchanged BY THE ACCEPT OPERATION ITSELF. But the
// frontend verification runs LATER, and between the confirmed Accept response
// and the verification GETs another admin may legitimately commit the draft,
// edit the accepted draft rule, delete it, or revert the draft. Those are
// POLICY STATE ADVANCING after a confirmed Accept — not a violation of
// Accept's contract — so the verification distinguishes "Accept violated its
// contract" (which this model never claims without server evidence) from
// "the Policy state advanced after acceptance".
//
// Identification is by STABLE target rule ULID only — never name, priority,
// or group/category text. The inputs are the minimum current truth:
// GET /api/policy (the EFFECTIVE snapshot — candidate while a draft is
// engaged, else running) and GET /api/policy/draft. Verification never
// mutates anything and never retries Accept.
import type { PolicySnapshot } from "../../api/policy";
import type { DraftState } from "../../api/policyDraft";

/** The full verification lifecycle, including the pre-result and
 * failed-observation states owned by the component. */
export type PostAcceptState =
  "checking" | PostAcceptVerified | "verification-unavailable";

/** What a SUCCESSFUL verification observation can conclude. */
export type PostAcceptVerified =
  /** Draft active, effective snapshot is the candidate, target present and
   * still disabled — the born-safe draft state is confirmed. */
  | "draft-confirmed"
  /** The effective snapshot is RUNNING and the target rule is present: the
   * Policy state advanced after acceptance (for example, a separate commit).
   * NOT an inconsistency, and never described as Accept enforcing anything. */
  | "running-now"
  /** The target exists but its observable state differs from the born-safe
   * translation (e.g. it is now enabled) — another admin may have edited it
   * after acceptance. Not an accusation of protocol corruption. */
  | "advanced-changed"
  /** The target is not currently present in the effective snapshot (and/or
   * the draft is no longer active) — a concurrent revert/delete/commit
   * lifecycle may have occurred. The server-returned Accepted decision
   * remains the historical record. */
  | "advanced-absent";

/** classifyPostAccept: pure classification of one successful verification
 * observation. Deterministic; the component maps GET failures to
 * "verification-unavailable" before ever calling this. */
export function classifyPostAccept(
  snap: PolicySnapshot,
  draft: DraftState,
  ruleId: string,
): PostAcceptVerified {
  const target = snap.rules.find((r) => r.id === ruleId);
  if (target === undefined) return "advanced-absent";
  if (!snap.draft) return "running-now";
  if (target.enabled) return "advanced-changed";
  if (!draft.active) return "advanced-changed"; // candidate view without an active draft — indeterminate mid-transition; the state moved
  return "draft-confirmed";
}
