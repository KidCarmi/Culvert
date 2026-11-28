# Verification program: state, evidence and decisions

Goal: independent, measurable evidence that a change preserves Culvert's critical security
and lifecycle contracts, so that autonomous changes and releases can be gated on evidence.
This page is the entry point; it states what is verified, what is only tested, and what is
assumed. It claims no proof of universal correctness: the tools are bounded model
checking, differential conformance and mutation evidence.

## 1. What exists

| Domain | Pieces | Mode | PR |
|---|---|---|---|
| Maintenance-agent upgrade lifecycle | Explicit-state model + checker (19 properties), model-derived conformance vectors run against the real agent through a fake exec layer, scheduled mutation campaign | shadow | #2006 (merged) |
| | Reviewed-baseline lock: every verdict, counterexample, vector line and unpredicted real-code observation pinned in `baseline.json` / `observed.json`; drift fails the shadow run; regeneration prints a mandatory review block | shadow | #2020 |
| | Real-Docker check of the fake's assumptions; every vector under both Docker image stores | shadow | #2030 (stacked on #2020) |
| Stage-2 access policy | Independent reference model (clauses R1–R15, stdlib only), differential against enforcement **and** Policy Tester paths, publication and snapshot-atomicity suites | shadow | #2029 |

Everything is behind build tags (`lifecycle_conformance`, `policy_conformance`) and
non-required workflows. No property or clause is owner-approved.

## 2. Evidence (measured 2026-11-23)

Lifecycle:
- 5,864 states / 8,096 transitions explored completely; 172 apply + 147 crash vectors and
  435,456 reconcile inputs replayed against the real agent; under both image stores, 0
  mismatches.
- Before the baseline lock, four regression shapes (code+model co-changes and a code-only
  change to an unmodelled API field) exited 0; all exit 1 now. Two independent reviews
  found 11 further defects in the lock itself (one blocker: an unrendered
  `upgrade_succeeded`); each was reproduced, fixed and re-verified.
- Real Docker 29.10 / Compose v5.7.1: `ok_stale` never observed (0/10);
  `up_fail_stale` and `up_fail_recreated` are real; container image identity differs by
  image store (config digest vs registry index digest). The agent's decisions are
  store-independent; only the reported running digest differs.
- Mutation (#2006 baseline, 350 mutants): existing tests 75.8 %, conformance 70.8 %,
  together 80.8 %; 17 mutants killed by conformance only.

Policy:
- ~100k comparisons, 0 mismatches. 17 targeted security mutants: 16/16 non-equivalent
  killed — and the existing tests kill the same 16, so no unique kills on this sample.
  The suite's value is an implementation-independent oracle, path parity and the open
  questions it surfaced. The first run missed a mutant because the harness built
  inputs the product refuses; the suite now fails as VACUOUS in that case.

## 3. Rules that keep the evidence honest

- INCOMPLETE (budget hit, vacuous property, skipped suite, unreadable evidence) is exit 2
  and never a pass.
- A regenerated baseline records behaviour; it is **not** proof of correctness. The
  reviewer accepts each drift line; PASS→FAIL verdicts are regression candidates and
  FAIL→PASS verdicts must be shown to be real improvements.
- Where a reference model's clauses do not settle a case, the product's answer is reported
  as an open contract question and never asserted.
- A worker or agent summary is not verification: critical claims are re-checked at source.

## 4. Promotion to a required merge gate

Per property or clause, never per suite, and only with explicit owner approval recorded in
`contracts/registry.yaml`:
1. The owner approves (or corrects) the property's semantics.
2. Its environmental assumptions are checked on a real environment (done for the lifecycle
   fake's Docker outcomes; not yet for crash recovery).
3. Several weeks of shadow runs without a false alarm, and at least one intended change
   that went through the drift review cleanly.
4. The check names its scope.

First candidates once approved: S2 (rollback preservation), S4 (journal retirement),
S7 (write-ahead barrier); policy R1/R3/R4/R11 (precedence, disabled rules, stage
separation, FQDN boundary).

## 5. Owner decisions (recorded 2026-11-23)

This page and the four proposals below are the engineering decision record. Verification-only
and production-behaviour changes land in separate PRs; no unapproved property becomes a
required check.

**PRs.** #2020, #2029 and #2030 are approved in direction; #2030 is retargeted to `main` after #2020
merges and keeps both image-store models and the real-Docker evidence. #2029 stays shadow.

**Decision 1 — AGT-900: approve the conservative, opt-in `converge` design.**
- Default stays OFF; not enabled by default or deployed until real-Docker E2E validates the
  safety properties.
- No adoption of an unverified target image; never report upgrade success from a
  running-image guess; never automatically restart an unhealthy or unverified target.
- `recovery_required` when evidence is insufficient; Docker unavailable is non-destructive.
- The original interrupted operation keeps its outcome; recovery is a separate operation.
- Journal retirement only after verified convergence and durable audit evidence.
- Optional `RollbackArmed` journal field, instance locking, bounded retries.
- Implemented in focused PRs, including an explicitly documented AGT-004 amendment that
  scopes "changes nothing in Docker" to the default (off) mode.

**Decision 2 — `final_running_digest`: approve the evidence-based correction, option C.**
Reuse existing captures plus one bounded, read-only final capture when evidence is stale or
missing. `final_running_digest` stays a registry digest (never a config/image id). Add
`final_running_state` and `final_running_image_id`. A guessed image is never reported as
verified. Wire compatibility preserved; negative controls required.

**Decision 3 — Policy B/C/D: approve the conservative recommendations, each independently.**
- B: reject new invalid category references and reserved `Any` case variants; preserve
  stored rules; expose unresolved references in diagnostics.
- C: stable stored-order precedence for equal priorities, with migration/compatibility
  evidence; no silent renumbering.
- D: invalid persisted default actions stay fail-closed deny, with visible warnings and strict
  validation on future writes; never reinterpreted as allow.

**Decision 4 — SOCKS5 belongs inside the managed security boundary.** Stages:
1. Correct operator/deployment docs; startup and diagnostic warnings when legacy SOCKS5 is
   enabled (no behaviour change).
2. Non-enforcing shadow evaluation through the existing policy engine, without touching
   accounting or decisions.
3. Threat-feed parity and shared identity resolution.
4. Opt-in enforce mode after differential and real-network verification.

Existing installations keep current behaviour until explicitly migrated. In enforce mode a
policy requiring TLS inspection must not silently become an uninspected allow: refuse, unless
an explicit, documented operator exception authorises it. Investigate bind-address exposure
and provide a safe configuration option.

**Execution priority:** (1) finish the verification PRs; (2) SOCKS5 visibility (no behaviour
change); (3) image-reporting correctness; (4) lifecycle recovery behind an off-by-default
switch; (5) policy semantics gaps; (6) SOCKS5 policy parity. Independent domains in parallel.
No automatic production deployment or broad enforcement change.

### Owner correction — pre-customer product stage (2026-11-23)

Culvert has **no active customers or installed base**. Constraints above that protect existing
installations ("existing installations keep current behaviour", one-release upgrade warnings,
legacy compatibility modes) are withdrawn wherever they only served a hypothetical installed
base. Prioritise the correct long-term design, secure defaults, simplicity and velocity. What
does NOT change: data integrity, correct current backup/restore round trips (and effective
policy semantics during any explicit migration), and verification evidence.

- **#2037 (policy C) approved:** deterministic ordering and strict priority validation. The
  one-release tie-order warning was removed as an unneeded shim; a test pins the current
  export → replace-import round trip.
- **AGT-900 (#2038/#2039):** the contract stays `open` until a real-Docker e2e demonstrates
  the safety properties (in progress). After it validates, evaluate making conservative
  startup convergence the **default** before the first customer release.
- **SOCKS5 Stage 3 approved**, with this target end state: disabled unless configured; when
  enabled it enforces applicable policy; threat-feed protection active; identity through the
  shared authentication architecture (no permanent legacy SOCKS5 credential path); actions
  SOCKS5 cannot honour — including required TLS inspection — refuse rather than downgrade to
  uninspected access (the "documented operator exception" above is not planned). The mode
  setting (`legacy`/`shadow`/`enforce`) is an integration and verification aid, not a
  permanent compatibility surface: after differential and e2e verification pass, move to
  secure enforcement defaults and retire `legacy`.
- AGT-900 e2e and SOCKS5 Stage 3 run in parallel. Avoid compatibility shims, permanent dual
  implementations and approval loops.

### Proposal documents

| Topic | Document | Open items after the decisions |
|---|---|---|
| AGT-900 startup crash recovery: failure matrix (A1–X6) and staged implementation | [AGT-900-STARTUP-RECOVERY-PROPOSAL.md](AGT-900-STARTUP-RECOVERY-PROPOSAL.md) | Decided (Decision 1). `converge_adopt` (adopting an ungated live target after a fresh gate) is NOT approved |
| `final_running_digest` = verified running image or "unverified" | [FINAL-RUNNING-DIGEST-PROPOSAL.md](FINAL-RUNNING-DIGEST-PROPOSAL.md) | Decided: option C (Decision 2); AGT-006 proposed, owner approval pending |
| Invalid categories, equal priorities, `default_action` spellings | [POLICY-SEMANTICS-B-C-D-PROPOSAL.md](POLICY-SEMANTICS-B-C-D-PROPOSAL.md) | Decided (Decision 3); the renumber endpoint is not yet decided |
| SOCKS5 Stage-2 alignment (SWG-901) | [SWG-901-SOCKS5-ALIGNMENT-PROPOSAL.md](SWG-901-SOCKS5-ALIGNMENT-PROPOSAL.md) | Decided: D1 = inside the boundary, staged (Decision 4); D5 superseded: Inspect rules refuse in enforce mode unless an explicit operator exception |

Headline findings from those investigations (each verified at source):
- AGT-900: 36 of 147 crash vectors would today be "adopted" as a successful upgrade
  while the previous image runs; rollback stages write no journal evidence; the decision's
  tag input has no production source; the health probe has no definitive-unhealthy result.
- `final_running_digest`: the field is inferred from flags, never captured; 14 of the 48
  misreports are wrong although the agent already held the truth.
- SOCKS5 (opt-in, off by default): besides Stage-2 policy it also skips the threat-feed
  check, and its credential check ignores the IdP registry, so no identity exists for
  identity rules; operator docs do not disclose the gap and the deployment guide enables
  it.
- Policy: category references are already validated on API/bulk writes (the gap is
  file loaders and later feed drift); YAML `default_action` is already strict (the silent
  case is persisted admin settings); tie order is in practice stored order and only
  perturbed at ≥ 13 rules.

## 6. Roadmap

1. Land #2020, #2030, #2029 (shadow).
2. Implement the §5 decisions in the recorded priority order, as focused PRs with contract
   records, each regenerating baselines through the drift review.
3. Next verification domains, in order of security value: SOCKS5 parity (a differential
   SOCKS5-vs-CONNECT oracle once SWG-901 is decided), authentication and sessions,
   admission (IP filter and rate limits).
4. Shared primitives, extracted only when a third domain needs them: the reviewed-baseline
   lock (line rendering, multiset drift, review block) and counterexample minimisation.
   The model checkers and reference models stay with their owners.
