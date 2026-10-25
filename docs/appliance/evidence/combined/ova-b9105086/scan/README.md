# Exact-artifact security scan — internal OVA 61c46d6d (frozen source b9105086)

This scan runs under owner direction 6398512423. It is non-destructive: no rebuild, no source or product change, and no ESXi action.

**Verdict: STOP and REPORT.** The scan found material items, and the owner direction says to stop before any code or product change. This document reports the findings. It does **not** make a disposition; ASTRA and the owner decide.

## Identity (fail-closed, read from the finished OVA — no staging overlay)

| Object | Value | Check |
|---|---|---|
| OVA | `61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a` (artifact 12595618495, run 40185226897) | re-hashed before extraction |
| `build-info.json` in the OVA | `git_commit` b9105086, `git_dirty` false, `index_digest` ca27cf9a, `baked_tar_sha256` a3fabc38 | asserted |
| Baked app archive in the rootfs | `/var/lib/culvert-appliance/images/culvert.tar.gz` = a3fabc38; single manifest = `sha256:ca27cf9a…`; blobs re-hashed | asserted |
| App version stamp | `v1.0.327-candidate.gb910508629e9` in the app binary | asserted |
| ClamAV sidecar archive | ce011ffc → amd64 manifest 4c365e40 → config 0eebe5c4; guest `manifest.env` names `CLAMAV_SIDECAR_ID=4c365e40` | asserted (`summary/sidecar-binding.json`) |

Scan runs:

- Exact-scan run **40200275913**: artifact 12601438865, zip `ea932d4f…`.
- Sidecar artifact 12601048797, zip `fcb7a1a1…`.

Both zips are committed byte-for-byte as downloaded, and their sha256 equals the GitHub artifact digest. Tools: Trivy 0.69.3; the DB (v2) was updated 2026-10-25 12:57Z (see `summary/trivy-version.txt`). Govulncheck ran in binary mode on every Go binary plus source mode on the vendor engine (`engsrc/`, build settings taken from buildinfo).

## MATERIAL — new, not in any existing disposition

### M1. GO-2026-6809 / CVE-2026-111943 — crypto/x509 "distrust compromised intermediate certificates"

This advisory is in the Go **stdlib** of the vendor container engine. Those binaries were built by Docker Inc. and containerd upstream, not by Culvert:

| Binary | Go | Fixed in | Source-mode reachability |
|---|---|---|---|
| dockerd | go1.26.9 | go1.26.10 | **called** (TLS clientHandshake → Certificate.Verify) |
| docker (CLI) | go1.26.9 | go1.26.10 | **called** |
| containerd | go1.27.2 | go1.27.3 | **called** |
| ctr | go1.27.2 | go1.27.3 | **called** |
| docker-proxy, containerd-shim-runc-v2, runc | 1.26.9 / 1.27.2 | — | required (not called) |

Origin: the engine packages pinned in the OVA are Docker 29.9.0 (built with go1.26.9) and containerd.io 2.4.1 (built with go1.27.2). Docker's apt repository now lists docker-ce 5:29.9.2 and containerd.io 2.4.2. **Not verified:** which Go those were built with, or whether they carry the fix. Culvert's own binaries (app, agent 81e4214d, console, access) are go1.27.3 and are not affected (`summary/go-binaries.tsv`). Raw rows are in `summary/go-2026-6809.tsv`.

### M2. Kernel 7.0.0-38-generic: +95 advisories since the 27006cf4 scan (same kernel package)

`summary/kernel-delta-vs-27006cf4.tsv`:

- Advisory rows went from 201 to 296.
- 95 are new; none were dropped; no class or severity changed.
- New: **3 CRITICAL present**, 1 CRITICAL denied, **59 HIGH present**, 32 HIGH denied.

New CRITICAL present:

- CVE-2026-98621 (net: gue).
- CVE-2026-98571 (net: stmmac).
- CVE-2026-98725 (nvmet-auth).

**Unconfirmed applicability notes (OPUS reading only):** gue needs a configured FOU/GUE port; stmmac hardware is not present on vSphere; the appliance is not an NVMe target. These are *not* dispositions. The 59 new HIGH-present rows are **untriaged**.

Current totals:

- CRITICAL: 6 denied, 6 present.
- HIGH: 5 absent, 100 denied, 179 present.

The noble GA kernel candidate is 6.8.0-147. HWE kernel availability was not re-checked.

## Clean / unchanged

- **App image (baked bytes):** the only finding is GO-2026-5932, x/crypto openpgp. That package is not linked into `app-culvert` or `app-deploy-culvert-maint`, and the finding is in existing dispositions.
- **ClamAV sidecar:** severity summary is empty and the gate exits 0. nghttpx is absent. The gzwrite importer list is recorded in `summary/sidecar-reachability.txt`.
- **Known residuals, re-observed and unchanged in class:**
  - x/net GO-2026-6603/6610/6611/6612/6617, present in docker-compose 5.6.1 (called) and containerd/ctr. Trivy lists these in compose as CVE-2026-78669 HIGH and 78659/78660/78663/97032 MEDIUM.
  - The kernel residual set as already dispositioned.
- **New advisories that are not called** (not yet in the docs):
  - GO-2026-6238: cilium/ebpf, imported or required in containerd and runc.
  - GO-2026-6686: moby/sys/user, imported in runc.
  - GO-2026-5942: x/net, required in runc.

This is **not** a "0 CVEs" claim. The full raw results are in the two committed zips.

## Custody (report-only, user decision in session)

KidCarmi/Culvert is a **public** repository, so Actions artifact 12595618495 (the OVA, retained until 2026-11-08) can be downloaded by any signed-in GitHub user. Per the user's in-session choice, nothing was copied and nothing was deleted. Restricting access is an owner decision.

## Secret scan of this evidence

Gitleaks reported 889 hits, and all of them are false positives:

- 886 are 40-hex git commit hashes inside advisory-reference URLs (`go.googlesource.com/…/+/<sha>`, `github.com/…/commit/<sha>`).
- 3 are go.sum `h1:` module hashes in compose buildinfo.

Every hit was checked against those two patterns, and none was left unexplained.

## Not done (out of scope / needs authorization)

No OVA rebuild, no Docker or containerd pin bump, no kernel change, no source or main merge, no ESXi action, no pilot, release or distribution.
