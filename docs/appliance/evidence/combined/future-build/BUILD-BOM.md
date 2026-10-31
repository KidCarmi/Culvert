# Frozen build BOM: the ONE replacement INTERNAL-ONLY OVA after FB-1 (31 Oct 2026)

This document lists the inputs of the next replacement build. **No build is authorized by it.** ASTRA owns acceptance, the owner owns the build decision, and MERGE / PILOT / RELEASE remain NO-GO.

**What this BOM supersedes.** It replaces `../freeze-0648adeb/BOM.md` for the build commit, the candidate image and the guest package set. Everything that BOM pins and this one does not change still holds:
- the sidecar, under §5 below;
- the M2 conditions;
- the post-build checkpoint plan.

**Three values cannot live in this file**, because they are produced by the commit that adds it:
- the commit SHA itself;
- the Deep gate image built from that commit;
- the commit-stamped console.

The PR #1528 handoff that names the final SHA records them. Each of them must equal what §2 says it is derived from.

## 1. Source

| | Value |
|---|---|
| **Build commit** | The `review/1528-m1-engine-pins` commit that adds this file, named with its tree in the handoff. Built from a clean, tag-free checkout of exactly that commit. |
| **Line content** | M1 engine pins + Q7 console fix + candidate-line CI closure + FB-1 (§6 of `FB-1-APT-SNAPSHOT.md`) + FB-1 corrections and pin raise (§7) |
| **PR #1528 frozen branch** | `feat/onprem-appliance-readiness` @ `4524311b`, unchanged |
| **`SOURCE_DATE_EPOCH`** | **`1793096442`, passed explicitly.** It reproduces the F-P2-accepted sidecar bytes (§5). `appliance/clamav/` has the same tree (`8d4df1d9`) as at `0648adeb`, where that epoch was set. |
| **Provisioning drift flag** | None. Provisioning and the candidate image come from the same commit. |

## 2. Application and console

| | Value |
|---|---|
| **Candidate image** | The Deep PR Gate `deep-gate-image` (`culvert-image.tar`) of the build commit, `workflow_dispatch` on this line. `/app/VERSION` = `v1.0.<n>-candidate.g<sha12 of the build commit>`. `build-ova.sh --candidate-source` must equal the checkout; it refuses otherwise. The tar SHA-256, image ID, artifact ID and expiry are in the handoff. |
| **Preservation** | The Deep artifact expires after one day. Before the build it must be re-uploaded by a lab `[preserve-image]` run (no build, no boot), as was done for `0648adeb`. |
| **Bundled `culvert-maint`** | Built by the image's own `maintbuilder` stage from the same commit; `build-ova.sh` requires its version to equal `/app/VERSION` |
| **Console** | Built at build time by `console-bundle.sh` (go.mod compiler, `-trimpath -buildvcs=true`, `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1`). The stamped hashes embed the commit and are in the handoff. **The stamp-free hashes** (`-buildvcs=false`, otherwise identical, tag-free checkout) **must equal those of `c88c0e76`**, the source of the Q7 overlay `8b141120…` that ASTRA tested: `culvert-console` `6a6da8622d36acea38c4536a501797d470fdfa0011ce76b95e25f0581a641e73`, `culvert-access` `500adb145218ab7f78c7b5d96dc5d2571be0aae818ce54bc6dfb81db70af4c9c`. This is source equivalence, not binary identity with `8b141120…` (readiness report §0-Q7). |
| **Pinned release image (non-candidate path only)** | `ghcr.io/kidcarmi/culvert:v1.0.259`, index `sha256:238ba99b…347e`, amd64 `sha256:f714e55b…448f`. It is not used by a candidate build. |

## 3. Base image

| | Value |
|---|---|
| Serial / URL | `20260926`, `https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img` |
| SHA-256 | `6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2` |
| Signature | `SHA256SUMS.gpg` against key `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81` (`ubuntu-cloudimage-keyring.gpg`) |
| **Limit** | Packages already in the base image at the snapshot's version are not downloaded by the build. Their bytes are bound by this SHA-256 only, not package by package (`package-provenance.tsv` binding `inherited-base-image`). |

## 4. Guest packages

| | Value |
|---|---|
| **Ubuntu snapshot** | `20261029T180000Z` (`fb1-snapshot-20261029/README.md`) |
| InRelease SHA-256 | noble `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` · noble-updates `1af76bea40c6b8ddbc51a51046c5a3e7912c9611536e97afc673a4b1c39d1886` · noble-security `d90e89008640e66a6eacc13ffaad0fbbd205877cc51acdd8d4f99f9d21fcfee0` · noble-backports `b6a0b10bb67d8da7ecb72a3f62dda5f408091d5a1abe8cbda2380f4af6b705cd` |
| Authentication | gpgv Good signature, RSA key `F6ECB3762474EDA9D21B7022871920D1991BC93C`; two fetches byte-identical; 16 `Packages.xz` matched |
| Build start | Recorded once by `build-ova.sh` before any fetch (`build-info.json` `apt_build_start`); the ID must be strictly earlier |
| **Kernel** | `linux-image-virtual-hwe-24.04` → **7.0.0-42.42~24.04.1** (noble-updates). The four `-7.0.0-42-generic` packages (`linux-image`, `linux-modules`, `linux-main-modules-zfs`, `linux-main-modules-v4l2loopback`) are the approved kernel-42 identities. Their SHA-256 values are in `../esxi-325c142a/kernel-42/kernel-debs.tsv`; lab C6 re-acquired them under this pin and found them equal. |
| **Predicted package set** | 680 rows of 325c142a: 671 unchanged, 4 Docker at the pins, kernel meta 38 → 42, +4 `-42-generic`, −4 `-38-generic`, **0 downgrades, 0 outside the snapshot** (`fb1-snapshot-20261029/compare-325c142a.tsv`). This is a prediction; T5 on the built disk is the authority. |
| **Docker** (`download.docker.com`, `noble stable`, key `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`) | see the table below |

| Package | Version | `.deb` SHA-256 (manifest `*_DEB_SHA256`) |
|---|---|---|
| docker-ce | 5:29.9.2-1~ubuntu.24.04~noble | `95ddf7a2d8b8c0eb82d8597d4d604e294dcf741081f2e228524d5ab9bfd7c8ae` |
| docker-ce-cli | 5:29.9.2-1~ubuntu.24.04~noble | `74747b5c99000279b9b2c7eb82543b4121d8436a58aa3be7e78ac6681d74794f` |
| containerd.io | 2.4.2-3~ubuntu.24.04~noble | `f811ab57d1f4bb0cce19df7d526da8c711d8ebea0447cc83da1999188e664122` |
| docker-compose-plugin | 5.6.1-1~ubuntu.24.04~noble | `9725be1df7fd5ccc6b21ac24112885896c8d134345e3f4aa20b3c2064ef4620e` |

## 5. ClamAV

| | Value |
|---|---|
| Base | `docker.io/clamav/clamav:1.5`, index `sha256:638d9020…1ef6`, amd64 `sha256:705e0723…7a73` |
| Sidecar | `culvert/clamav:1.5.4-culvert.4`, built locally from `appliance/clamav/Dockerfile` (unchanged since `0648adeb`) |
| **Expected sidecar image ID** | `sha256:91eae57526b246da28cb370bd824c45af51e245be0093afcc316bc3fbe941f9d` (F-P2-accepted) |
| **Expected baked archive** | `6482ae8c2774b30913b69d3d26778da8005817bdfb4df051f324e74c93c3c8ad` |

A different ID or archive hash is **STOP/REPORT**, not a rerun. The sidecar's Alpine packages are pinned by version in the Dockerfile; they are not snapshot-pinned. That is outside FB-1, which covers the Ubuntu guest, and is unchanged from the accepted record.

## 6. Toolchain and recipe

| | Value |
|---|---|
| Go | `go1.27.3`, the root `go.mod` `toolchain` line. Image builders `golang:1.27.3-alpine@sha256:b8c9b82a…5e9c`. |
| Build host | Linux; `qemu-img`, libguestfs, Docker with the containerd image store, `curl tar gzip xz sha256sum python3 gpg gpgv`; network access to snapshot.ubuntu.com and download.docker.com |
| Cold-load check | `docker.io/library/docker@sha256:bfec1f51…7659` |
| cosign | `ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c6560…cd00` |
| VM | 2 vCPU, 4096 MB, 40 GB, `vmx-13` |
| Recipe | `SOURCE_DATE_EPOCH=1793096442 appliance/build/build-ova.sh --candidate-image-tar culvert-image.tar --candidate-source <build commit> --candidate-run-id <Deep run>` through `appliance-lab.yml` with a one-entry matrix |

## 7. Required build outputs (identity step, before any boot)

| Output | Requirement |
|---|---|
| `build-info.json` | `application.index_digest` = the candidate image ID; `apt_snapshot` = `20261029T180000Z`; `apt_build_start` later than it; git commit = the build commit, not dirty |
| `package-provenance.tsv` | 0 non-snapshot rows; every Docker row `acquired-verified` with the §4 SHA-256 |
| `acquired-debs.tsv` | present; every row verified by the reconciler |
| `build-upgrades.txt` | names the snapshot ID and the four InRelease hashes |
| Kernel | exactly one, `7.0.0-42-generic` |
| Sidecar | §5 values |

## 8. Retained references

| Path | Content |
|---|---|
| `FB-1-APT-SNAPSHOT.md` §6–§7 | Fix, corrections, tests, mutations |
| `fb1-snapshot-20261029/` | Pin selection, authenticated metadata, comparison, Docker index |
| `fb1-t4/` | T4 on the first implementation `d452d50d` (old pin) |
| `../esxi-325c142a/kernel-42/` | Approved kernel transition, its indexes and `.deb` identities |
| `../freeze-0648adeb/BOM.md` | Previous build's BOM: sidecar, M2 checkpoints |
| `../m1-engine-pins/` | Docker engine identities and scans |
