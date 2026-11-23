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
