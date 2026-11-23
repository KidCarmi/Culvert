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

## Rerun after the three fixes (2026-11-23), verifier side only

The verifier's wire model was corrected and its baselines re-recorded (`../DRIFT-REVIEW-2026-11-23.md`),
so the verifier side of the campaign was rerun on the final code: `MUTANTS_NEW_ONLY=1 mutants.py`.
The existing-suite side was **not** rerun; the "Existing" column above is still the result at `155df09`.

- **M01–M14: same verdict for every mutant.** 12 of 15 killed; M03, M07 and M13b survive, as before.
  M07's anchor text had moved (the function after `ReplaceAll` changed in #2050); the edit itself is
  unchanged.
- **Three new mutants, each undoing one merged fix, all killed:**

| ID | Mutant | Verifier |
|---|---|---|
| M15 | zoned IPv6 destinations are no longer refused (#2055) | killed — outcome and alias-behaviour drift |
| M16 | tester matches the typed text again, not the parsed request target (#2053) | killed — signature and alias-behaviour drift |
| M17 | an unknown action resolves to Allow (#2050) | killed — `Frobnicate` row reads `http=forward(200)`, `DIFFERS-FROM-CONTRACT` |

- Unmodified control tree: pass.

As before, every kill is baseline drift: it says behaviour changed, and a person decides whether the
change is wrong.
