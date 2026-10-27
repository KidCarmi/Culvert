# M1 CI on the exact pin tree: dispatch runs (27 Oct)

**Why dispatch rather than a PR.** The required gates trigger on PRs to `main` only. A PR builds a synthetic merge with **current** `main`, which has moved 262 commits / 140 files past cutoff `a27cffb2`, so it would test a tree that is not `5c4c2be8`. ASTRA rules out a moving-main merge. A `workflow_dispatch` checks out the branch head itself and enables **every** job in both gates.

**Head tested:** `c1b08dbe`, tree `10438f78`. Its non-docs tree is **identical** to the runtime pin commit `5c4c2be8`; `git diff 5c4c2be8 c1b08dbe -- . ':!docs'` is empty. All 42 jobs report `head_sha=c1b08dbe` (`jobs.tsv`).

| Run | Result |
|---|---|
| Fast [40472535523](https://github.com/KidCarmi/Culvert/actions/runs/40472535523) | 21 success, 2 skipped, **2 failure**: `Gate · gitleaks`, plus the aggregate that follows from it |
| Deep [40472538130](https://github.com/KidCarmi/Culvert/actions/runs/40472538130) | 15 success, **2 failure**: `Deep · appliance scenario A with real ClamAV`, plus the aggregate that follows from it |

## Fast: gitleaks, a dispatch-scope artifact

- In dispatch mode the job runs `gitleaks detect` with **no commit range**. It scanned **6,939 commits**, including other branches that the checkout fetched, and reported 274 findings (`fast-gate-gitleaks-summary.txt`).
- **None was introduced by this branch.** A local gitleaks git scan of exactly `b9105086..c1b08dbe` finds **0**, and the per-finding table below agrees (0 rows with `introduced_by_m1=True`).
- In PR mode the same job scans only the PR's own commits.
- This is **not** offered as a PASS. It is a scope disposition for ASTRA to accept or reject.

**Correction (27 Oct).** The first version of this README and of the summary file said that the one ancestor finding (`b8ac5ac2`) was "a commit hash inside an advisory URL". **That was wrong.** The per-finding check shows it is `internal/hashcache/hashcache_evict_bench_test.go:67`, a 47-hex benchmark key-tail constant in a `_test.go` file (rule `generic-api-key`). It is on `main` before the cutoff and **still present in the tested tree**. It is not allow-listed in `.gitleaks.toml`/`.gitleaksignore`. A PR-mode scan does not see it because it is not a PR commit.

### Per-finding evidence (ASTRA 08:55)

| File | What it is |
|---|---|
| `gitleaks-results.sarif.gz` | The job's own SARIF, gzipped (`gzip -n`): artifact `12719806724` (zip digest `sha256:f1941d79…`). The **uncompressed** file's sha256 is `af60b76dfebb2cc6fe8b90b2c2a371a2bbbf041795e08685c3a982cceda0d2e6`, the same as the downloaded artifact. The job ran with `--redact`, so **every one of the 274 snippets reads `REDACTED`**. It carries commit, path, line, columns and rule only. |
| `gitleaks-findings.tsv` | One row per SARIF result, **in SARIF order**. Commits are shortened to 12 hex; the full ID is in the SARIF at the same position. |
| `gitleaks-verify.py` | Re-checks the TSV against the SARIF and git. Prints counts and row numbers only, never matched text. |

**TSV columns:**
- **Identity:** commit, path, line, rule; copied from the SARIF.
- **Ancestry:** `introduced_by_m1` (ancestor of `c1b08dbe` but not of `b9105086`), `ancestor_of_m1_head`, `on_main`, and up to 4 remote branches containing the commit. These come from `git merge-base --is-ancestor` and `git branch -r --contains`.
- **`class` and `note`.**
- **`line_in_tested_tree_c1b08dbe`:** `file-absent`, or `yes`/`no` for whether that exact line text exists in that file in the tested tree.

**Counts:**

| Measure | Result |
|---|---|
| Rule | 250 `sourcegraph-access-token`, 24 `generic-api-key` |
| `introduced_by_m1` | 0 |
| `ancestor_of_m1_head` | 1 (row 139, `b8ac5ac2`) |
| `on_main` | 3 |
| Present in the tested tree | 1 (row 139); 1 file present with the line absent (row 7); 272 `file-absent` |

**How rows were classified.** Each flagged line was read with `git show <commit>:<path>` at the finding's **own** commit, never from the working tree. **No matched value is published**: the notes describe shapes only.

| Class | Rows | Rule the verifier re-checks |
|---|---|---|
| `git-commit-hash-in-advisory-URL` | 246 | A 40-hex token in the flagged span lies inside an `http(s)://` URL on that line (`go.googlesource.com/…/+/<sha>`, `…/commit/<sha>`, in govulncheck/Trivy JSON) |
| `go-module-h1-checksum` | 6 | The span overlaps an `h1:<base64>` go.sum-style token (Compose buildinfo dumps) |
| `git-sha-or-tree-id-in-markdown` | 4 | A 40-hex token in the span, in a `.md` file (freeze/CI-binding records) |
| `manual` | 18 | Read by me line by line; the `note` is my judgment and **is not re-derived by the verifier**. It covers test fixtures in `_test.go`/test scripts (6), sha256 digests of evidence files keyed by filename (9, two of them of `.dpapi` ciphertext), a git SHA in a JSON evidence record (1), and prose (2: the TLS group name `X25519MLKEM768`, and the words "key derivation"). |

**Why the SARIF is gzipped and the commits shortened.** Both contain hundreds of 40-hex git commit IDs, and gitleaks' `sourcegraph-access-token` rule flags any 40-hex string. Committing them as plain text would add about 540 new findings to **this branch's own commits** and break the "0 introduced by M1" result above. A local self-scan confirmed this: every hit was a real git commit object in the clone, with no other content. The 12-hex prefix and the compressed SARIF avoid that, and no information is lost.

**Verifier result** (run locally in a full clone of this branch with all remotes fetched): `rows 274 … PASS`.
- **SARIF column quirk:** gitleaks' SARIF columns land one character late against the line git stores, on every row. The verifier therefore widens the span by one character on each side. That is stated in the script.
- **Negative control:** relabelling single rows (139 → advisory-URL, 16 → h1, 8 → advisory-URL, 1 → markdown), or corrupting one row's commit, makes it **FAIL on exactly that row**, so a PASS is not vacuous.

**Reproduce:** `python3 -I gitleaks-verify.py gitleaks-results.sarif.gz gitleaks-findings.tsv` from a clone that has every commit named in the SARIF. Most of those commits live only on other remote branches.

## Deep: NEW material finding in the ClamAV sidecar, so STOP

- **The gate itself:** the appliance scenario passed (0 failures). The failing step is `CVE gate on the shipped sidecar (no fixable HIGH/CRITICAL)`. Trivy reports **CVE-2026-92392**, HIGH and fixed upstream: `libcurl 8.22.0-r0` (fixed in `8.23.0-r0`), "HTTP/2 upload Use-After-Free", in `culvert/clamav:1.5.4-culvert.3` on Alpine 3.24.2 (`deep-sidecar-cve-gate.txt`).
- **It is in the shipped artifact.** The sidecar baked into **OVA 61c46d6d** (`4c365e40`) carries the same `libcurl 8.22.0-r0`, per its SBOM. The 25 Oct exact scan was clean only because its DB (2026-10-25 12:57Z) did not yet list this CVE. The replacement OVA would inherit the same sidecar unchanged.
- **M1 is not the cause.** M1 does not touch the sidecar.
- **Not done, per owner rule 6398512423** ("material finding → STOP and report before any code or product change"):
  - no sidecar change;
  - no `libcurl` pin;
  - no F-P2 re-identity.

  The fix path would be the same approach as the earlier pcre2/zlib/nghttp2/musl pins (a `libcurl 8.23.0-r0` pin in `appliance/clamav/Dockerfile`). That **changes the sidecar's identity and F-P2 credit**, so it needs an owner decision.
- **Reachability:** a static reading, with no disposition, is in `sidecar-libcurl-reachability.md` (ASTRA 08:55).
