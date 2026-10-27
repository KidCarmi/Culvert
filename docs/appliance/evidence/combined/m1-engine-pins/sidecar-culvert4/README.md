# Sidecar `culvert.4`: libcurl 8.23.0-r0 fix (27 Oct)

**The fix:** `93c83f90` on `review/1528-m1-engine-pins`.

The ClamAV sidecar gets `libcurl=8.23.0-r0` for CVE-2026-92392, in its own `apk add` without `--upgrade`. The new tag is `culvert/clamav:1.5.4-culvert.4`. The reason for the separate add is in `docs/appliance/r6-r7-security-dispositions.md`. The user directed this fix in session; earlier, owner rule 6398512423 had stopped it.

## Results

| Check | Run | Result |
|---|---|---|
| Deep gate, dispatch on `93c83f90` | [40487749917](https://github.com/KidCarmi/Culvert/actions/runs/40487749917) | **success**. Scenario A ran the real `culvert.4` sidecar from the deploy bundle. Trivy found **0** vulnerabilities in `culvert/clamav:1.5.4-culvert.4` (Alpine 3.24.2). |
| F-P2 isolated re-run | [40487883047](https://github.com/KidCarmi/Culvert/actions/runs/40487883047), lab `84403e6e` | **success**. Candidate: **0** wrong-cleans. Control: 63 (details below). |
| Fast gate, dispatch on `93c83f90` | [40487754812](https://github.com/KidCarmi/Culvert/actions/runs/40487754812) | failure: `gitleaks` (the history-scope finding from before) and a **new** `golangci-lint` failure (explained below) |

Raw files: `deep-scenario-a-excerpt.txt`, `fast-golangci-lint-excerpt.txt`, and `fp2/{candidate-culvert.4,control-1.4.6}/` (the run's artifacts, byte-for-byte).

## F-P2 on the new bytes

Both arms ran on Docker 29.9.2 with the containerd image store (the M1 engine). Each sent 520 EICAR streams while the temp directory had at most 64 KiB free, and each passed the functional check (EICAR found 100/100, clean OK 100/100).

| Arm | Image ID | Wrong-cleans (EICAR answered "OK") | Expected |
|---|---|---|---|
| Candidate `culvert.4` (ClamAV 1.5.4) | `sha256:91eae57526b246da28cb370bd824c45af51e245be0093afcc316bc3fbe941f9d` | **0** | 0 |
| Control: upstream ClamAV 1.4.6 by digest | `sha256:57deb108…86f23` | 63 | > 0, so the harness reaches the bug |

**How the candidate was built:**
- From `appliance/clamav/Dockerfile` at `93c83f90` (sha256 `4b08fcf3…`), with `SOURCE_DATE_EPOCH=1793096442` (that commit's time).
- Built twice; both builds gave the same manifest, which equals the loaded image ID.

**Candidate packages:**
- Upgraded: `libcurl-8.23.0-r0`, `musl`/`musl-utils-1.2.6-r3`, `brotli-libs-1.2.1-r0`.
- Unchanged: `pcre2-10.49-r0`, `zlib-1.3.2-r1`, `nghttp2-libs-1.70.0-r0`.
- **Not moved:** `c-ares-1.34.8-r0` and `ca-certificates-bundle-20260909-r0` are the base versions. This confirms that the separate add without `--upgrade` floats nothing.

**For the replacement OVA:**
- `build-ova.sh` defaults `SOURCE_DATE_EPOCH` to the checkout's commit time.
- To bake **exactly** the F-P2-tested identity `91eae575…`, the build must be given `SOURCE_DATE_EPOCH=1793096442`.
- Otherwise the baked ID differs, and F-P2 must run again on those bytes.

**Deep gate ID:** the Deep gate's own sidecar ID, `07da81d4…`, comes from a plain `docker build` in CI (no fixed epoch or rewrite-timestamp). It is not the OVA/F-P2 identity and is not expected to be.

## The new Fast-gate lint failure is the moving `main`, not this change

- `golangci-lint` runs **diff-scoped** against **current** `origin/main` (`--new-from-rev origin/main`).
- It flagged four lines in `auth_oidc_flow.go`, `auth_saml.go` and `scan_svc.go`.
- **This branch does not change those files:** they are byte-identical between `c1b08dbe`, whose dispatch at 08:17 passed lint, and `93c83f90`.
- **`main` changed them after that run**, for example `c6e48d2d` (09:13 UTC). The branch's older, frozen versions now differ from `main` and are reported as "new".
- This is the same moving-`main` effect that led to dispatch mode in the first place. Changing those files would alter frozen runtime code outside this fix, so they are left as they are.

## Not covered

- No OVA contains `culvert.4` yet.
- The Fast gate stays red on `gitleaks` (history scope) and `golangci-lint` (moving base). Both are for ASTRA to adjudicate.
