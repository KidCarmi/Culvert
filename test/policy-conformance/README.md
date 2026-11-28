# Policy conformance (shadow)

A deterministic differential check of the Stage-2 **access-policy decision**
against an independent reference model. **Shadow only: not a merge gate, and it
defines no contract.** None of the clauses below is owner-approved; the matching
registry contracts (POL-001..004) are all `owner_approved: false`.

## Pieces

| Piece | What it is |
|---|---|
| `internal/policyref/policyref.go` | Reference model, written from numbered clauses R1–R15 (each cites its source). Standard library only; `TestIndependence` fails if it imports anything else. Returns `Specified=false` where the clauses do not settle a case. |
| `policy_reference_conformance_test.go` | Drives the real engine through **two** paths and compares each with the model. |
| `test/policy-conformance/run.sh` | Runs both; exit 0 / 1 (mismatch) / 2 (a suite missing or skipped). |
| `.github/workflows/policy-conformance-shadow.yml` | Pull requests touching the policy owners. Not a required check. |

All of it carries the build tag `policy_conformance`, so a plain
`go build ./...` or `go test ./...` never compiles it and no existing gate changes.

## Which product paths are compared

ADR-0026 says enforcement and the Policy Tester share one evaluator core. They
reach it differently, so both are compared:

- **enforcement**: `PolicyStore.Evaluate`, over published rules with precomputed
  matchers (`normFQDN`, `srcPrefix`, scan-index prefilter);
- **Policy Tester**: `evalAccessRules` over `List()` clones, whose precomputes are
  cleared, so the fallback matchers run, with a trace callback.

## Suites

| Suite | Vectors | Covers |
|---|---|---|
| `SingleConditionGrid` | every condition value × every request dimension | FQDN glob and label boundary, IP-literal spellings, CIDR, IPv4-mapped, zoned clients, identity/group case and trimming, auth-source aliasing, category and group membership, unknown group. Each dimension must yield both matches and non-matches (anti-vacuity) |
| `RandomRuleSets` | 4,000 seeded rule sets × 12 requests | precedence, first match, disabled and auth rules, ANDed conditions, ties |
| `PublicationSequence` | after each writer op | `ReplaceAll`, `UpdateByID` (disable), `DeleteByID` (publishes without re-sort: slow snapshot path), empty rule base |
| `SnapshotAtomicity` | 12,000 concurrent decisions under `-race` | a reader sees exactly one of two alternating revisions, never a mix |
| `StartupDefault` | explicit × rule count | R15, the fail-open → fail-closed transition |

A mismatch is printed with a **minimised** rule set (rules removed one at a time
while the disagreement persists). A suite that compares nothing, or decides
everything by rule or everything by default, is VACUOUS and fails.

## Measured sensitivity (targeted mutation, 2026-11-23, base `155df09`)

17 hand-picked, security-relevant single-edit mutants of the real engine
(FQDN label boundary and apex, auth-source cross-scheme aliasing, group
trimming, disabled and auth rules deciding, priority order, first match → last
match, identity case, IP-literal and source unmapping, unknown group failing
open, group membership, the `Any` sentinel, the trailing dot, zoned clients). Each
was scored against this suite and against the existing policy tests
(`go test -run 'Polic|Categor|FQDN|Dest|Source|AuthSource|Group|Normalize|Literal'`
plus `internal/hostutil` and `internal/catgroup`).

| | Result |
|---|---|
| Killed by this suite | 16 of 16 non-equivalent |
| Killed by the existing tests | 16 of 16 |
| Killed by this suite only | **0** |
| Equivalent | 1: dropping the zoned-client check changes nothing, because `netip.Prefix.Contains` is already false for a zoned address |
| Runtime | ≈3 s of tests; the job is dominated by compiling the root package with `-race` |

The first run **missed** "auth rules decide access". The harness built auth rules
the publication gate refuses, so none ever reached the evaluator. The harness now
builds valid auth rules and fails as VACUOUS if none is published, so a gap of
that kind can no longer hide behind a pass.

What this means: on this sample the suite adds no detection the existing tests
lack. Its value is an oracle **independent of the implementation**, written as
reviewable clauses; parity between the enforcement and Policy Tester paths;
snapshot atomicity under `-race`; and the open questions below, which no existing
test states. A hand-picked sample is evidence, not a mutation score.

## Not covered (stated, not implied)

Schedules (time), destination country (geo cache), IDNA/punycode beyond ASCII
case and trailing dot, the community category DB and the signed-feed view, action
side fields (SSL, file, redirect), the proxy's handling of a decision
(`applyPolicyDecision`), runtime default-action changes (POL-900), and SOCKS5,
which does not call the policy engine at all (SWG-901).

## Open contract questions (reported, not resolved)

The product's answer is recorded. This tool does not decide which answer is right.

1. **R12: the "any" sentinel's casing, and categories that do not resolve.**
   `DestCategory: "Any"` means "any". `"any"` or `"ANY"`, like any category no host
   belongs to, never matches, so a **Drop** rule written that way blocks nothing.
   *Corrected after verification:* API and bulk writes do refuse a category that
   does not resolve. They go through `validateRuleObjectRefs` →
   `referencedCategoryResolvable` (`policy_ref_validation.go:79,129`), which
   rejects `"any"` because no category of that name exists. The gaps are the
   writers that skip that check (config-file `PolicyStore.Load`, draft reload and
   commit) and categories that disappear after a rule is written (feed or
   community-DB changes). An admin can also create a real category named `Any`,
   which `"any"` rules would then match.
2. **R2: equal priorities.** Ordering is by `sort.Slice`, which is not stable.
   `Add` and `Reorder` keep priorities unique, but `Update`, `Load` and
   `ReplaceAll` do not dedupe them. With two matching rules at one priority the
   winner is unspecified (694 seeded vectors hit this).
3. **R6: a malformed or zoned SourceIP.** API ingress refuses a malformed one,
   while a config-file load only warns and leaves the rule inert (it matches
   nothing). A **zoned** literal (`fe80::1%eth0`) passes ingress and is matched by
   exact string. Is that intended?
4. **R15: default_action spellings.** In the product, only lower-case `allow`
   means allow. *Corrected after verification:* the YAML config is strict.
   Anything other than exactly `allow`, `deny` or empty fails startup
   (`config.go:614`). The silent case is a non-canonical value persisted in
   admin settings, cluster sync or a config-version rollback. That value is
   enforced as **deny** without a log line, and the next settings save rewrites
   it as `deny`.

## Promotion

Not before: owner approval of each clause (or its correction), resolution of the
open questions above, and several weeks of shadow runs without a false alarm.
Then promote clause by clause, not the whole suite.
