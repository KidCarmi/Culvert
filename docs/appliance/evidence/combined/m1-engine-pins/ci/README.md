# M1 CI on the exact pin tree: dispatch runs (27 Oct)

**Why dispatch rather than a PR.** The required gates trigger on PRs to `main` only. A PR builds a synthetic merge with **current** `main`, which has moved 262 commits / 140 files past cutoff `a27cffb2`, so it would test a tree that is not `5c4c2be8`. ASTRA rules out a moving-main merge. A `workflow_dispatch` checks out the branch head itself and enables **every** job in both gates.

**Head tested:** `c1b08dbe`, tree `10438f78`. Its non-docs tree is **identical** to the runtime pin commit `5c4c2be8`; `git diff 5c4c2be8 c1b08dbe -- . ':!docs'` is empty. All 42 jobs report `head_sha=c1b08dbe` (`jobs.tsv`).

| Run | Result |
|---|---|
| Fast [40472535523](https://github.com/KidCarmi/Culvert/actions/runs/40472535523) | 21 success, 2 skipped, **2 failure**: `Gate · gitleaks`, plus the aggregate that follows from it |
| Deep [40472538130](https://github.com/KidCarmi/Culvert/actions/runs/40472538130) | 15 success, **2 failure**: `Deep · appliance scenario A with real ClamAV`, plus the aggregate that follows from it |

## Fast: gitleaks, a dispatch-scope artifact

- In dispatch mode the job runs `gitleaks detect` with **no commit range**. It scanned **6,939 commits**, including other branches that the checkout fetched, and reported 274 findings (`fast-gate-gitleaks-summary.txt`).
- **None was introduced by this branch.** A local gitleaks git scan of exactly `b9105086..c1b08dbe` finds **0**. The only ancestor is `b8ac5ac2`, which is on `main` before the cutoff; its 1 finding is a commit hash inside an advisory URL.
- In PR mode the same job scans only the PR's own commits.
- This is **not** offered as a PASS. It is a scope disposition for ASTRA to accept or reject.

## Deep: NEW material finding in the ClamAV sidecar, so STOP

- **The gate itself:** the appliance scenario passed (0 failures). The failing step is `CVE gate on the shipped sidecar (no fixable HIGH/CRITICAL)`. Trivy reports **CVE-2026-92392**, HIGH and fixed upstream: `libcurl 8.22.0-r0` (fixed in `8.23.0-r0`), "HTTP/2 upload Use-After-Free", in `culvert/clamav:1.5.4-culvert.3` on Alpine 3.24.2 (`deep-sidecar-cve-gate.txt`).
- **It is in the shipped artifact.** The sidecar baked into **OVA 61c46d6d** (`4c365e40`) carries the same `libcurl 8.22.0-r0`, per its SBOM. The 25 Oct exact scan was clean only because its DB (2026-10-25 12:57Z) did not yet list this CVE. The replacement OVA would inherit the same sidecar unchanged.
- **M1 is not the cause.** M1 does not touch the sidecar.
- **Not done, per owner rule 6398512423** ("material finding → STOP and report before any code or product change"):
  - no sidecar change;
  - no `libcurl` pin;
  - no F-P2 re-identity.

  The fix path would be the same approach as the earlier pcre2/zlib/nghttp2/musl pins (a `libcurl 8.23.0-r0` pin in `appliance/clamav/Dockerfile`). That **changes the sidecar's identity and F-P2 credit**, so it needs an owner decision.
- **Reachability is not assessed.** I have not established which binaries in the sidecar load libcurl, or whether any HTTP/2 **upload** path runs on the appliance.
