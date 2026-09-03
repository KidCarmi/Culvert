# ADR-0025: Policy Learning Mode is advisory and never an enforcement authority

- **Status:** Accepted (2026-08-13 — Foundation Round) — implemented (slices M1–M5B shipped; see CLAUDE.md's Architecture Notes entry for `internal/policylearn` and `docs/operator/policy-learning-mode.md` for the live operator runbook)
- **Date:** 2026-08-13
- **Deciders:** project maintainer (accepted); Claude architecture review (proposed, Policy Learning Foundation Round)
- **Related:** ADR-0008 (spoofable decryption-exclusion evidence), ADR-0011 (decryption observability), ADR-0026 (single access-policy evaluator core), `docs/design/POLICY-DRAFT-DESIGN.md`, `roadmap/PAC-EXCEPTION-INTELLIGENCE.md` (evidence-class + de-scalarisation doctrine)
- **Numbering:** repository-wide per ADR-0024; `docs/adr/` and `docs/support/rfc/` occupy through 0024, the only open ADR PR is #854 (ADR-0023). 0025 verified free at acceptance — re-verify against open PRs at implementation landing.

## Context

Culvert is gaining a **Security Policy Learning Mode**: an opt-in, non-enforcing
mode that observes production traffic, builds an explainable behavioral
baseline, and generates reviewable `Group → URL-Category → ALLOW`
recommendations, to cut the friction of deploying an SWG into an existing
organization. `docs/enterprise/POLICY-ROLLOUT-GUIDE.md` GAP-POL-01 (no
monitor-only enforcement mode) is the motivating gap.

Two existing subsystems establish the house doctrine the feature must inherit:

- **`internal/autoexclude`** (ADR-0008/0010/0011) — the adaptive
  decryption-exclusion cache, the repository's only traffic-learning subsystem
  today. Its security record is the reference for learned behavior: scoped keys
  bound to a policy object (never a raw traffic attribute), security-generation
  fencing, confirm-counts over **distinct server-derived** evidence tokens,
  fail-closed classifiers, volatile learned state with node-local durable
  tunables, bounded caches with deterministic fail-closed eviction, and audited
  promotion. `docs/operator/decryption-auto-exclusions.md` already names the
  target posture for a review-gated learner: *"learn-review — record + alert,
  bypass only after operator approval."*
- **PAC Exception Intelligence** (`roadmap/PAC-EXCEPTION-INTELLIGENCE.md`) — the
  evidence-honesty doctrine: an A/B/C/D evidence-class taxonomy, a frozen
  wording contract ("observed"/"would match", never "used"/"safe"), the
  **de-scalarisation rule** (a single composite posture score is banned), and
  "**absence of evidence is never evidence**"; the architecture rule is
  "proposes, never auto-mutates."

Enforcement policy has exactly one canonical mutation path today. Mutating
policy handlers route through `policyWriteStore(actor)` (`policy_draft.go:364`)
into either the live `policyStore` or, when `RequireCommit` is armed, the draft
candidate; commit (`apiPolicyDraftCommit` → `policyStore.ReplaceAll(cand)`,
`policy_draft.go:635-637`) is the sole activation step, and it is the point at
which config-versioning, audit, and CP→DP sync engage. [FACT: verified on
current main]

The threat brief for this feature (poisoning, over-generalization, rare
legitimate traffic, existing malicious activity, spoofable evidence, unbounded
growth, generation drift) makes Learning Mode itself a security-sensitive
subsystem. The single most dangerous failure would be for observation to
silently become enforcement through shared mutable state. This ADR fixes the
trust boundary that prevents it, before any learning code is written.

## Decision

1. **Advisory-only, single activation path.** Learning Mode may observe and
   recommend. Only the existing canonical path (`policyWriteStore` → draft
   candidate → commit) may create or activate enforcement configuration. The
   learning engine (`internal/policylearn`) has **no import path** to
   `PolicyStore` mutators, `sslbypass`, `autoexclude`, PAC, CDR,
   default-action, or decryption-profile state. An architecture wall test pins
   its import surface to stdlib + `internal/fileutil` + `internal/obs` + its
   own DTOs; all policy/category/evaluator access is through injected narrow
   interfaces.

2. **Explicit lifecycle; one audited, RBAC-gated transition per step.**
   `Observation ≠ Recommendation ≠ Draft ≠ Shadow ≠ Enforcement.` Accepting a
   recommendation ("Add to Draft") requires `RoleAdmin`, requires
   `RequireCommit` to be armed (409 otherwise), and writes the rule into the
   **draft candidate only** — so the existing commit remains the sole
   activation. Starting/stopping a learning session is an operator action;
   viewing aggregates is a viewer action.

3. **Accepted rules are born safe.** A rule created from a recommendation is
   `Action=Allow`, `SSLAction=Inspect`, `Enabled=false`, appended last in
   priority. Learning never emits Block/Drop rules, TLS bypasses,
   decryption-profile references, PAC/CDR/default-action changes, or reorders,
   and never modifies an existing rule.

4. **Recommendable-category allowlist, fail-closed.** ALLOW is recommendable
   only for categories on an explicit, admin-managed allowlist, seeded from the
   embedded business-category set (`internal/urlcat/default_categories.json`).
   Categories not on the list — including every admin-created,
   community-DB-derived (UT1), and future signed-feed category — are never
   recommendable. A denylist of "dangerous" names is rejected: it fails open on
   unknown names, and the taxonomy carries no risk-class field to key one on.

5. **Server-derived evidence only.** The observation subject is
   `(authSource, Identity.Sub)`; groups come from the resolved
   `Identity.Groups`. Evidence is never taken from `X-User-Identity` or any
   client-supplied header (ADR-0025 depends on the F1 ingress-scrub fix,
   RISK-024). Unauthenticated / exempt traffic aggregates separately and never
   contributes group evidence. Blocked traffic (any block-class status) never
   contributes ALLOW evidence; frequency alone never raises confidence past LOW
   without distinct-subject and distinct-day evidence. Legacy LDAP/local paths
   that produce an identity but no groups are surfaced as such, never inferred.

6. **Generation-pinned evidence.** Every session pins a `Baseline`: the policy
   rule-set content hash (ADR-0026), the category epoch (signed-feed
   `GenerationID` / `SnapshotSHA256` / `ConfigRevision`, plus the admin
   taxonomy's semantic content identity; UT1 has no digest today and is
   flagged lower-confidence), a guardrail-config hash (the allowlist), and an
   identity-config audit watermark. Every recommendation embeds a copy by
   value, so evidence survives feed refreshes, restarts, and upgrades. Any
   mismatch at read time renders the recommendation **Stale** (latched);
   a stale recommendation cannot be accepted, only regenerated.

   *Amendment (2026-08-21, preview-qualification finding QB-2)*: the admin
   taxonomy component was originally the process-local `urlcat` revision
   COUNTER, which restarts reset — an unchanged taxonomy produced a different
   epoch after every restart, staling every recommendation of any session
   that spanned one. The epoch is now scheme **v2** (`"v2|"`-tagged): the
   admin component is `urlcat.Store.ContentFingerprint()`, a cached
   deterministic hash over exactly the resolution-relevant taxonomy content
   (entry SEQUENCE order — the first-match-wins resolvers make order
   semantic under overlapping patterns (QB-2.1); original-case names,
   BuiltIn tier flags, lowercased/deduped/sorted host patterns;
   length-prefixed domain-tagged framing). A no-overlap reorder also changes
   the identity — accepted CONSERVATIVE false-stale for Preview: safer than
   missing a real categorization change. Same ordered effective taxonomy ⇒
   same identity across restart/reload;
   different ⇒ different. Old counter-scheme pins are NOT backfilled or
   reinterpreted: the scheme tag guarantees they can never compare equal to a
   v2 value, so sessions/recommendations created before the upgrade go stale
   exactly once (`category_epoch_changed`) and are regenerated — historical
   evidence is never rewritten.

7. **Bounded, node-local, off every config surface.** Learned/session/
   recommendation state lives in node-local files under
   `<dataDir>/policy_learning/` — off export/import, off config-version
   rollback, off CP→DP sync (the autoexclude-tunables precedent,
   `config_surfaces.go:437-452`). Tunables live in `AdminSettings` behind a
   `PolicyLearningSaved` sentinel. Every structure carries a hard cap; overflow
   and eviction are **counted and degrade claims, never inflate them** (a lower
   observation count can never increase coverage).

8. **Dropped telemetry degrades readiness; enforcement is never impeded.** The
   observation pipeline is a **load shedder** — a full queue drops and counts,
   the request path never blocks on it, and disabled mode costs one atomic
   nil-check (benchgate-pinned). Any loss (queue drop, flush gap, restart) is
   recorded, surfaces as a readiness blocker, and annotates evidence.
   Full-confidence output over a lossy window is impossible by construction.

9. **Evidence honesty (PEI contract).** No composite/black-box confidence
   scores. Confidence and Coverage are **separate**, deterministically derived
   from named predicates; `Confidence: HIGH / Coverage: LOW` is a first-class,
   explicitly non-production-ready state. Coverage denominators are shown only
   where a real roster exists (`IdPProfile.KnownGroups`); where none exists the
   UI shows observed counts ("24 distinct Finance identities observed — roster
   not configured"), never a fabricated percentage.

## Consequences

- **Positive:** onboarding value without introducing a second enforcement
  authority; every learned claim is reviewable, reproducible, and
  generation-pinned; the poisoning blast radius is bounded to human-reviewed
  Allow suggestions inside an admin-blessed category set; the threat feed /
  blocklist run before rule evaluation, so no accepted ALLOW can resurrect a
  known-bad host; and accepted rules inherit the existing draft/commit
  governance (audit, config-versioning, commit-time shadow warnings) unchanged.
- **Cost:** admins must arm `RequireCommit` to accept recommendations; no
  automation of enforcement is possible even where an operator might want it
  (deliberate); roster-less deployments get counts, not percentages.
- **Risk (accepted):** an authenticated insider can accelerate evidence for an
  already-allowlisted category — bounded by human review, evidence-concentration
  flags, and the allowlist; the output is advisory.
- **If skipped:** ad-hoc learning features would accrete against the request
  path with shared mutable state — precisely the silent observation-becomes-
  enforcement risk this ADR exists to foreclose.

## Alternatives considered

- **Recommendations as Policy Draft objects directly** — rejected: contaminates
  the single shared candidate an admin is actively editing, weakens the
  observed-fact → administrative-intent boundary, and complicates
  stranded-draft recovery. Recommendations remain a separate object until an
  explicit admin action.
- **Auto-enable / auto-commit on accept** — rejected: violates the lifecycle
  invariant; the draft commit is the one activation gate the admin plane
  already audits and fences.
- **Category risk-class denylist** — rejected: fails open on admin/feed/
  community categories and is trivially renamed around; the allowlist fails
  closed.
- **Retain raw per-request events as evidence** — rejected: unbounded and
  privacy-hostile. Bounded aggregates (MVP) plus an optional bounded replay
  corpus with dropped-coverage accounting (follow-on) achieve review-grade
  evidence within fixed resource limits.
- **A composite "policy readiness / safety score"** — rejected by the PEI
  de-scalarisation rule: a single number silently sums across evidence classes.
  Readiness is a list of named, individually-true-or-false blockers.
