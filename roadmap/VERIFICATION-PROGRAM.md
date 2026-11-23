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

## 5. Proposals awaiting owner decision

| Topic | Document | Owner decisions |
|---|---|---|
| AGT-900 startup crash recovery: failure matrix (A1–X6) and staged implementation | [AGT-900-STARTUP-RECOVERY-PROPOSAL.md](AGT-900-STARTUP-RECOVERY-PROPOSAL.md) | D1–D8; AGT-004 needs an `amended` record |
| `final_running_digest` = verified running image or "unverified" | [FINAL-RUNNING-DIGEST-PROPOSAL.md](FINAL-RUNNING-DIGEST-PROPOSAL.md) | option B vs C; new AGT-006 |
| Invalid categories, equal priorities, `default_action` spellings | [POLICY-SEMANTICS-B-C-D-PROPOSAL.md](POLICY-SEMANTICS-B-C-D-PROPOSAL.md) | new 400s, stable tie order as contract, renumber endpoint, raw admin-settings value |
| SOCKS5 Stage-2 alignment (SWG-901) | [SWG-901-SOCKS5-ALIGNMENT-PROPOSAL.md](SWG-901-SOCKS5-ALIGNMENT-PROPOSAL.md) | D1–D10; a no-behaviour-change disclosure step can ship first |

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
2. Owner decisions on §5; production fixes then land as focused PRs with contract records,
   each regenerating baselines through the drift review.
3. Next verification domains, in order of security value: SOCKS5 parity (a differential
   SOCKS5-vs-CONNECT oracle once SWG-901 is decided), authentication and sessions,
   admission (IP filter and rate limits).
4. Shared primitives, extracted only when a third domain needs them: the reviewed-baseline
   lock (line rendering, multiset drift, review block) and counterexample minimisation.
   The model checkers and reference models stay with their owners.
