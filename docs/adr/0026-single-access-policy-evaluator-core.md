# ADR-0026: One canonical access-policy evaluator — a pure core shared by enforcement, testing, replay, and shadow

- **Status:** Accepted (2026-08-13 — Foundation Round) — extraction landing in F3, tester adoption in F4
- **Date:** 2026-08-13
- **Deciders:** project maintainer (accepted); Claude architecture review (proposed, Policy Learning Foundation Round)
- **Related:** ADR-0025 (policy learning advisory boundary), `docs/design/POLICY-DRAFT-DESIGN.md`, `docs/enterprise/POLICY-ROLLOUT-GUIDE.md` (GAP-POL-03), `internal/mcp/policy/simulate` (in-repo precedent: "the EXACT SAME compiled evaluator the runtime uses — there is no second simulation evaluator")
- **Numbering:** 0026 verified free at acceptance — re-verify against open PRs at landing.

## Context

Stage-2 access evaluation exists **twice** on current main: [FACT: verified]

- **`PolicyStore.Evaluate`** (`policy.go:1090-1160`) — the enforcement path. Uses
  the published snapshot with each rule's precomputed matcher fields
  (`normFQDN`, `srcIPNet`, `matchedConds`), normalizes the host and parses the
  client IP once per scan, reads the clock **at most once per scan**, lazily on
  the first scheduled rule reached (`policy.go:1111`, `1127-1133`), and mutates
  per-rule hit accounting on match (`policy.go:1141-1142`).
- **`walkPolicyTestRules`** (`ui_policy.go:1981-2004`) — the Policy Tester's dry
  run. Re-implements the same priority/first-match loop using the *allocating
  fallback* matchers (`matchSource` / `matchSchedule` / `matchDest`) and reads
  the clock **per rule** via `matchSchedule` (`ui_policy.go:1992`).

Two problems follow from the duplication:

1. **Latent semantic divergence.** Agreement between the two walks is pinned
   only by equivalence tests (`TestPolicySecurity_OptimizedMatchesCanonical`
   and the tester suites). Those pin agreement at commit time, not across future
   matcher edits. Concretely today, the per-rule clock read in the tester means
   a scan that straddles a schedule boundary can disagree with `Evaluate` for
   the same instant-in-time question — a real, if narrow, behavioral gap.
2. **No safe foundation for replay/shadow.** The Learning Mode program
   (ADR-0025) adds evaluation consumers — historical replay (a follow-on slice)
   and, later, shadow evaluation. The house rule, already enforced in the MCP
   subsystem (`internal/mcp/policy/simulate/simulate.go`), is that simulation
   must run the exact runtime evaluator, never a second one. A third and fourth
   hand-rolled walk would multiply the divergence risk into a policy-integrity
   problem.

Separately, `apiPolicyTest` evaluates `policyStore.List()` — the **running**
rulebase — even when a draft candidate is engaged (`ui_policy.go:2038`,
GAP-POL-03), so there is no way to validate a draft before commit.

## Decision

1. **Extract a single pure core** in `policy.go`:

   ```go
   // evalAccessRules scans access rules in priority order and returns the
   // first match (nil = none). Pure of mutation and accounting: no counter
   // writes, no logging, no store locks. The clock is supplied and read at
   // most once, lazily, on the first scheduled rule. trace is optional
   // (nil on the hot path — must not allocate); when non-nil it is called
   // once per rule with its skip reason.
   func evalAccessRules(rules []*PolicyRule, in accessEvalInput,
       now func() time.Time,
       trace func(rule *PolicyRule, skip string)) *PolicyRule
   ```

   `accessEvalInput` carries `clientIP` (+ the once-parsed `net.IP`),
   `identity`, `authSource`, `host` (+ the once-normalized form), and `groups`.

2. **`PolicyStore.Evaluate` becomes** `evaluationSnapshot()` →
   `evalAccessRules(..., time.Now, nil)` → hit accounting + `PolicyMatch`
   construction at the call site. Behavior is byte-identical, including the
   one-instant-per-scan clock rule and the precompute fast paths (the core keeps
   calling the canonical matchers with their existing precompute-or-fallback
   behavior; the precompute≡canonical equivalence suite continues to guard that
   axis).

3. **`walkPolicyTestRules` is retired as an independent walk.** The tester calls
   the core with an injected clock and a `trace` callback that records the
   per-rule skip reason. This **corrects** the tester's per-rule clock read to
   the runtime's one-instant semantics — an intentional, isolated behavior
   correction (landed in F4, separately from the byte-identical extraction in
   F3, so a bisect is unambiguous), not drift.

4. **Replay and shadow (ADR-0025 follow-ons) consume the core only**, through an
   injected function value; `internal/policylearn` never imports policy
   internals.

5. **Scope of "pure."** Pure means *pure of mutation and accounting*. The
   destination matchers still consult the live category / geo / category-group
   singletons — that environment **is** the evaluation semantics. Callers that
   need a pinned environment (learning evidence) pin generations per ADR-0025 §6
   rather than forking the environment or the evaluator.

6. **Close GAP-POL-03.** The Policy Tester evaluates `effectivePolicyList()`
   (the draft candidate when Draft Mode is engaged, else the running rulebase)
   for both the Stage-1 simulation and the Stage-2 walk, and the response gains
   an additive `"rulebase": "draft" | "running"` field surfaced in the UI.

## Consequences

- **Positive:** exactly one definition of access-decision semantics; the
  tester's schedule-boundary divergence class is eliminated structurally;
  replay/shadow become possible with no second evaluator; the equivalence tests
  shrink from "two independent walks agree" to "fallback ≡ precompute within one
  walk."
- **Cost:** a hot-path refactor. Requires benchgate parity
  (`policy_bench_test`, `bench_regression_test`) and the full policy/e2e/race/
  determinism suite before merge; the `trace` callback must be provably free on
  the nil path (no closure allocation on the runtime path).
- **Risk:** subtle behavior deltas during extraction — mitigated by landing the
  byte-identical extraction (F3) separately from the tester behavior change +
  draft awareness (F4), each independently revertible.

## Alternatives considered

- **Keep dual evaluators, strengthen equivalence tests** — rejected: tests pin
  agreement only at commit time; every future matcher edit re-opens the gap, and
  learning replay would turn silent divergence into a policy-integrity issue.
- **Give the tester/replay a snapshot-parameterized `Engine` struct (the MCP
  shape)** — rejected for now: the flat function core achieves the same
  single-semantics guarantee without restructuring `PolicyStore`; an `Engine`
  wrapper can be layered later without a new decision.
- **Fold hit accounting into the core behind a flag** — rejected: accounting is
  the enforcement call site's concern; a flagged core reintroduces "which mode
  am I in" state, the exact ambiguity this ADR removes.
