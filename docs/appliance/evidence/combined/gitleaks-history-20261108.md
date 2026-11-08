# Gitleaks full-history findings: classification (2026-11-08)

This follows the procedure of `gitleaks-history-20261030.md`, under the same owner direction (PR #1528, 30 Oct):
- every finding is classified independently;
- exceptions are exact `commit:path:rule:line` fingerprints only;
- no rule, path or commit-wide suppression;
- `.gitleaks.toml` is unchanged;
- no secret value is reproduced;
- ASTRA reviews.

**Verdict: neither finding is a credential.** Two fingerprints are appended to `.gitleaksignore` (group G).

## How they surfaced

The Fast PR Gate dispatched on the FB1-R1 candidate `fdcb02a5` (run 42489203107) failed its gitleaks job with 2 findings. A dispatch scans `git log --full-history --all` over every fetched ref, not only the candidate line. Both findings come from commits made after the last green dispatch on this line (`0981ff3d`, 31 Oct), on `test/appliance-lab` and on `main`. Neither commit is in the candidate line's history.

## Method

1. **Reproduce locally.**
   - gitleaks v8.30.0, with this line's `.gitleaks.toml` and `.gitleaksignore`.
   - `--log-opts="--full-history --all"`, `--redact`, run on a clone of `review/1528-m1-engine-pins`.
   - Result: 7,212 commits scanned and exactly the same **2** findings as CI. No other finding.
2. **Inspect each finding in its exact commit**, with values masked.

## Findings

| Fingerprint | Commit / branch | What the matched value is | Class |
|---|---|---|---|
| `e18277a48938537f68985dd55fc05ade3081f939:.github/workflows/appliance-lab.yml:generic-api-key:775` | `test/appliance-lab`, 1 Nov (lab build route of `0981ff3d`) | `EXPECT_ACCESS_SHA256: <64 hex>`. This is the SHA-256 of the stamped `culvert-access` operator binary, an identity the build compares against: a public build digest. The rule matched the word "ACCESS" in the variable name. | public build fingerprint |
| `b63b43c0890c9257d17ed13811eb7ca527831225:internal/logstore/batchencode_test.go:generic-api-key:38` | `main` (and two `claude/*` branches), 2 Nov (log-store flush benchmark; a PR scan covers only its own range, so main's gate never reaches it) | `e.AuthPolicyRuleID = "<26 alphanumerics>"` in a test fixture. It is a policy-rule identifier with the same shape as the fixture's unflagged `RuleID` field two lines above. The rule matched the word "Auth" in the field name. | synthetic test identifier |

**Prevention.** The lab variable has been renamed `EXPECT_OPERATOR_BINARY_SHA256` (lab commit `739e96f7`). New build digests therefore no longer match the rule. The local scan above includes that commit and reports nothing for it.
