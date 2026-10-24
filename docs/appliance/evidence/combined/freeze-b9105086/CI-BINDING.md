# CI evidence binding: frozen tree b6b80fc5

| Item | Value |
|---|---|
| PR | #1705 (draft, CI-only) |
| Head | `b910508629e9d80352067bc8ec608753ddf0924e`, tree `b6b80fc5628b14c3489b20d970f5c81f038c087f` |
| Base at CI time | `main` = `a27cffb291f97db73b44b217d9aff9bc68ee2a35` (= the owner cutoff, an ancestor of the head) |
| Synthetic merge CI checked out | `76856bd8153664c5981dbd30063e38213aff450d` = "Merge b9105086 into a27cffb2", parents `a27cffb2` + `b9105086`, **tree `b6b80fc5` — identical to the frozen tree** (verified with `git log -1 --format=%T` on `refs/pull/1705/merge`) |

## Per-job checkout (`ci-job-checkouts.tsv`; raw logs in `ci-job-logs.tar.gz`, sha256 in the TSV)

- 103 check runs on the head:
  - 61 executed Actions jobs;
  - 41 skipped jobs (release/tag-only or PR pass-through shells; they never ran, so they have no checkout);
  - 1 CodeQL app check, which is not an Actions job.
- **60 of the 61 jobs** fetched exactly `+76856bd8…:refs/remotes/pull/1705/merge` and logged `HEAD is now at 76856bd…`. Each job checked out once.
- 1 job had no checkout: `120991117086` "✅ Code Review — Complete", the summary job (echo steps only).
- No other repository SHA was fetched in any log. The only other 40-hex values are the `actions/checkout` action pins (`3d3c42e5…`, plus `8e8c483d…`, which was downloaded but never run, in two Deep jobs).
- Verdicts: Fast PR Gate APPROVED, Deep PR Gate APPROVED, QA Gate and Security Gate APPROVED, CodeQL, Snyk 0 issues. Every executed job: success.

Runs: Fast 40133521354, Deep 40133521510, QA 40133521410, Security 40133521470, CodeQL 40133521409, Code Review 40133521332, CI 40133521596, API Contract 40133521398, API Governance 40133521358, Proxy UI E2E 40133521362, Install Lifecycle E2E 40133521302, Maint Agent Update E2E 40133521446, Maint Agent Backup+Upgrade E2E 40133521481, Appliance Catalog Update E2E 40133521449, Catalog E2E 40133521348, Edge-Case Lab 40133521479.

## Correction of an earlier claim

The CI on the previous head `846d606a` checked out synthetic merge `e5b1d09d` ("Merge 846d606a into f33e9ff6"), whose tree is **not** the frozen `846d` tree. My #1528 comment 6388122768 said CI "tested the frozen tree itself"; that was wrong. Those checks remain a scoped PASS of `e5b1d09d` only. This round is different because the base (`a27cffb2`) is an ancestor of the head, which makes the synthetic merge's tree equal the head's tree. If `main` moves before any re-run, that equality must be re-checked per job.

## Secret scan of the archived logs

`gitleaks detect --no-git --redact` over the extracted logs and both receipts reports 31 findings. All are false positives:
- 22 + 2 `generic-api-key`: the ULID `IdempotencyKey` / `idempotency_key` values of the catalog-update E2E harness;
- 7 `sourcegraph-access-token`: 40-hex git commit SHAs in `git fetch` lines;
- 1: a test-fixture credential `sha256:` digest in a CDR lineage test;
- 1: the `Key exchange: X25519MLKEM768` line of a TLS test.

None are in the receipts. Actions masks real secrets as `***` in these logs.
