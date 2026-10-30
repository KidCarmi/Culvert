# Gitleaks full-history findings: classification (2026-10-30)

**Owner direction (PR #1528, 30 Oct):** classify every finding independently; no blanket allowlist, no disabled check, no secret values exposed; any exception narrow, justified and reviewed by ASTRA; escalate real credential exposure.

**Verdict: none of the 275 findings is a credential.** No revocation and no history rewrite is needed.
- The exceptions are 274 exact `commit:path:rule:line` fingerprints, appended to `.gitleaksignore`. That is the same mechanism and the same policy-checked format as the 25 reviewed earlier (`check_gitleaks_policy.py`).
- No rule, path or commit-wide suppression was added, and `.gitleaks.toml` is unchanged.
- **ASTRA review requested**, especially for the one item marked "confirm" below.

## Why the dispatch gate saw them

On `workflow_dispatch`, the Fast gate's `gitleaks-action` scans `git log --full-history --all` over **every fetched ref**: all branches and all tags. A pull_request event scans only the PR's commit range. So a dispatch run on the candidate line also reports findings on unrelated branches.

**Reachability:**
- Of the 12 commits involved, only **1** is in the candidate line's history: `b8ac5ac200`, a benchmark test also present in `main`.
- 4 more are in `main`.
- 7 sit only on other branches: `test/esxi-qualification` (4), `review/1528-fdisk-evidence` (1), `ccr-65b0821a-21cf6v` (1) and one `claude/*` branch (1).

## Method

1. **Reproduce the CI scan locally.**
   - gitleaks v8.30.0, the repository `.gitleaks.toml` and `.gitleaksignore`, `--log-opts="--full-history --all"`, `--redact`.
   - Scope: all origin branches plus 709 tags (8,904 commits).
   - Result: **275 findings** (250 `sourcegraph-access-token`, 25 `generic-api-key`) in 12 commits, i.e. 274 unique fingerprints. This matches the count of the failing CI step.
2. **Inspect every finding in its exact commit**, with values masked; no value is reproduced here or in the PR.
3. **Check every bulk group mechanically:** each of its lines must fully match the stated public-data pattern. **0 mismatches across 255 findings.**
4. **Re-scan with the fingerprints:** **0 findings** across the same refs and tags.

## Classification

| Group | Fingerprints | Commit(s) and file(s) | What matched | Why it is not a credential |
|---|---|---|---|---|
| A | 246 | `f0fe7b90` `evidence/security-r6-r7-1528/r6-compose/govulncheck-56{0,1}.json` | 40-hex strings inside `"url": "https://github.com/…/commit/<sha>"` or `go.googlesource.com/…/+/<sha>` | Public upstream fix-commit SHAs in archived govulncheck output (R6 dossier). The sourcegraph rule matches any bare 40-hex string. Mechanical check: every line is a `"url"` to a public Go/GitHub host containing a 40-hex SHA. |
| B | 6 | `f0fe7b90` `…/buildinfo-56{0,1}.txt` | `h1:` strings | Public Go module checksums from `go version -m`. Every line is `dep <module> <version> h1:<44-char base64>`. |
| C | 9 | `2f451f1b`, `01850da7` (ESXi evidence JSON) | 64-hex values | SHA-256 digests in evidence hash manifests. Every line is `"<file name>": "<64 hex>"`. |
| D | 5 | `9b7b4a83` (ESXi evidence JSON); `71e3851a` `freeze-b9105086/CI-BINDING.md` | 40-hex values; one prose phrase | A public git commit SHA (`authenticated_controller`); public commit/tree SHAs; a TLS log phrase (`Key exchange: X25519…`). |
| E | 7 | `4d99098c`, `5f781e98` (installer tests), `f2e4406e` (chaos test), `b54b8a91` (password-change test), `b8ac5ac2` (hash-cache benchmark), `07337b79` (`test/e2e/appliance/esxi/test_pixel_console.py`) | Literal test values | Synthetic fixtures inside tests: export-quoting inputs, a sequential-digit session-secret constant, `chaos…` revocation tokens, request bodies, a fixed hex key tail, and OCR text. **Confirm (ASTRA):** the `test_pixel_console.py` `PASSWORD` constant is labelled "Synthetic fixture, never a guest password". Its literal occurs in exactly one commit and one file across all refs (`git log --all -S`), and in no provisioning or evidence file. ASTRA, as owner of that lab branch, should confirm it was never a lab VM credential. |
| F | 1 | `aa278d95` `roadmap/CHAOS-ENGINEERING-REVIEW.md` | Prose | Identifier and gate names in review text. |

## Structural observation (not changed here; owner decision)

- Because a dispatch run scans every ref, this gate depends on content outside the candidate line. Any new branch commit that trips a rule turns a dispatch run red for every line.
- **Option 1:** scope the dispatch scan to the dispatched ref (`--log-opts` on that ref's history).
- **Option 2:** keep the all-refs scan as an audit, separate from the per-line gate.

That is a CI-policy change, so it is recorded as a recommendation only.
