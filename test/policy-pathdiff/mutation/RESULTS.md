# Mutation campaign — results at `155df09`

15 single-edit mutants of the production paths (`mutants.py`). Each ran in a scratch copy against:

- **new**: `test/policy-pathdiff/run.sh`
- **existing**: `go test . ./internal/hostutil/` (the full root and `hostutil` suites, about 8 minutes)

An unmodified control tree passed both sides under the same load. Every existing-suite kill below
names tests about the mutated behaviour, so none is a load flake.

| ID | Mutant | New | Existing (first failing tests) |
|---|---|---|---|
| M01 | enforcement keeps the port on the host | killed | killed — `TestPolicyFlow_BlockedIPv4LiteralNotBypassedByMappedSpelling`, `TestRuleID_AllowPath_StampsMatchedRuleID` |
| M02 | tester matches the raw authority | killed | killed — `TestChaos69_DefectPolicyTesterStage1MatchesTheRuntimeHost` |
| M03 | tester skips host normalisation | survived | survived |
| M04 | enforcement skips host normalisation | killed | killed — `TestPolicySecurity_BlockRuleNotBypassable` |
| M05 | bare-name match loses its label boundary | killed | killed — `TestMatchFQDN`, `FuzzMatchFQDNNorm` |
| M06 | IPv4-mapped destination no longer unmapped | killed | killed — `TestPolicyDestLiteral_SpellingsReachTheSameRule` |
| M07 | bulk replace does not sort by priority | survived | killed — `TestLastHitWritersAreMonotonic` |
| M08 | enforcement-only prefilter rejects the second rule | killed | killed — `TestPolicyStore_Evaluate_FirstMatch` |
| M09 | disabled rules decide | killed | killed — `TestPolicyTester_SkipsDisabledRule` |
| M10 | CONNECT skips the policy decision | killed | killed — `TestMITM_BlockedHTTPSNotReached` |
| M11 | identity compared case-sensitively | killed | killed — `TestAuthzBypass_SourceIdentityNotForgeable` |
| M12 | invalid-host refusal removed on enforcement | **killed** | **survived** |
| M13a | source CIDR match no longer unmaps the client (first site) | **killed** | **survived** |
| M13b | same edit, second site | survived | survived |
| M14 | group names no longer trimmed | killed | killed — `TestPolicyStore_Evaluate_GroupsTrimSpace` |

| | Count |
|---|---|
| Killed by the new suite | 12 / 15 |
| Killed by existing tests | 11 / 15 |
| Killed only by the new suite | 2 (M12, M13a) |
| Killed only by existing tests | 1 (M07) |
| Killed by neither | 2 (M03, M13b) |

## Reading the numbers

- **The existing suite is strong on these paths.** On this sample the new suite adds two kills and
  loses one. That is a modest gain, not a step change.
- **Every new-suite kill came from baseline drift**, not from a cross-path assertion. Drift says
  behaviour changed; a person still has to say whether the change is wrong. M08 and M10 are
  path-specific mutants and also changed difference signatures, which is the differential at work.
- **M07** is invisible to decisions: `evaluationSnapshot` re-normalises a rule slice it has not
  verified, so evaluation order is unaffected. The existing test catches an accounting side effect.
  This suite compares decisions and cannot see it.
- **M03 and M13b** are probably equivalent: the tester's rule copies take the fallback matchers,
  which normalise both sides themselves. Not proven.
- 15 hand-written mutants is a small sample. It supports "adds some detection", nothing stronger.

## Cost

About 105 s per mutant for the new suite (mostly compilation), about 500 s for the existing one.
A scheduled campaign is not justified yet: run it by hand when the verifier or these paths change.

## Rerun after the three fixes (2026-11-23/24), both sides

The verifier's wire model was corrected and its baselines re-recorded
(`../DRIFT-REVIEW-2026-11-23.md`), so the whole campaign was rerun on the code with #2055, #2053
and #2050 merged: the verifier (`run.sh`) and the existing root and `hostutil` suites, for the 15
original mutants plus three new ones that each undo one merged fix. An unmodified control tree
passed both sides. The table at the top of this file is the earlier result at `155df09` and is kept
as recorded.

| ID | Mutant | Verifier | Existing (first failing tests) |
|---|---|---|---|
| M01 | enforcement keeps the port on the host | killed | killed — `TestChaos69_ControlOrdinaryDestinationStillProxies` |
| M02 | tester matches the raw authority | killed | killed — `TestChaos69_ControlPortShapedAuthorityIsStillAnswered` |
| M03 | tester skips host normalisation | survived | survived |
| M04 | enforcement skips host normalisation | killed | killed — `TestNormHoist_RealScanSeedsTheCanonicalHost` |
| M05 | bare-name match loses its label boundary | killed | killed — `FuzzMatchFQDNNorm` |
| M06 | IPv4-mapped destination no longer unmapped | killed | killed — `TestPolicyDestLiteral_SpellingsReachTheSameRule` |
| M07 | bulk replace does not sort by priority | survived | killed — `TestLastHitWritersAreMonotonic` |
| M08 | enforcement-only prefilter rejects the second rule | killed | killed — `TestCategoryGroupMembership_ArmedAccessEvaluateBlocks` |
| M09 | disabled rules decide | killed | killed — `TestPolicyTester_SkipsDisabledRule` |
| M10 | CONNECT skips the policy decision | killed | killed — `TestChaos125_EstablishedInspectedTunnelOutlivesTheSetupWindow` |
| M11 | identity compared case-sensitively | killed | killed — `TestAuthzBypass_SourceIdentityNotForgeable` |
| M12 | invalid-host refusal removed on enforcement | killed | **killed** — `TestPolicyTester_AgreesWithTheWireOnOddTargets`, `TestPolicyTester_AuthorityParityWithRealSockets` |
| M13a | source CIDR match no longer unmaps the client (first site) | **killed** | **survived** |
| M13b | same edit, second site | survived | survived |
| M14 | group names no longer trimmed | killed | killed — `TestPolicyStore_Evaluate_GroupsTrimSpace` |
| M15 | zoned IPv6 destinations are no longer refused (#2055) | killed | killed — `TestZonedIPv6Dest_RefusedBeforePolicyOnHTTPAndCONNECT` |
| M16 | tester matches the typed text again (#2053) | killed | killed — `TestChaos69_DefectPolicyTesterStage1MatchesTheRuntimeHost` |
| M17 | an unknown action resolves to Allow (#2050) | killed | killed — `TestPOL004E2E_ReplaceAllUnknownActionNeverReachesBackend` |

| | Original 15 | All 18 |
|---|---|---|
| Killed by the verifier | 12 | 15 |
| Killed by existing tests | 12 | 15 |
| Killed only by the verifier | 1 (M13a) | 1 |
| Killed only by existing tests | 1 (M07) | 1 |
| Killed by neither | 2 (M03, M13b) | 2 |

What changed against the first run:

- **M12 is now killed by the existing suite too.** The tests that kill it are the real-socket
  parity tests #2053 added; before the fixes only the verifier caught it. The verifier's "only I
  catch this" count fell from 2 to 1 because a lead it produced became a regression test.
- **No verdict got worse** on either side.
- **Each of the three fixes is guarded twice:** undoing any one of them is caught by its own
  regression tests and, independently, by the verifier.
- M07's anchor text had moved (the function after `ReplaceAll` changed in #2050); the edit itself is
  unchanged.

Still true: every verifier kill is baseline drift. It says behaviour changed, and a person decides
whether the change is wrong. M03 and M13b remain uncaught by anything; both are tester- or
match-site edits whose effect the current generator does not exercise.

The run was interrupted twice (a background time limit and a container restart) and resumed; the
script skips mutants whose result file exists, so no mutant was run against a different tree.
