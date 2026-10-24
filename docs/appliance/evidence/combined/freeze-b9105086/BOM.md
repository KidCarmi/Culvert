# Frozen source + BOM — internal appliance (owner decision 6389524853, Option B)

**Frozen source:** commit `b910508629e9d80352067bc8ec608753ddf0924e`, tree `b6b80fc5628b14c3489b20d970f5c81f038c087f`, branch `review/1528-combined` (draft PR #1705).
Parents: `846d606a51a0f8d3541145096a232277c45a7bfd` (previous frozen head) and `a27cffb291f97db73b44b217d9aff9bc68ee2a35` (the owner-pinned main cutoff).
This evidence lives on a separate commit (session branch `ccr-65b0821a-21cf6v`), on purpose: it never changes the frozen tree. Per the owner, the base reopens only on a demonstrated new critical security/correctness defect, with an explicit recorded decision.

## 1. What the build is made of

| Component | Pin / identity | Source of truth | Changed by 846d→a27 merge? |
|---|---|---|---|
| App (proxy) binary + image | built from tree `b6b80fc5` by `appliance/build/build-ova.sh` candidate mode; Go `go1.27.3` (`go.mod` toolchain), language `go 1.26.6` | `Dockerfile` (blob `bdbeb96d`), `go.mod` `5381116b`, `go.sum` `76db5afe` | **yes**: root Go (17 files), `internal/catgroup` — see §2 |
| Image identity | the app image is NOT reproducible across builds. The OVA build receipt must record the image ID/digest it bakes, and that image must trace to this tree (`org.opencontainers.image.revision` == `b9105086…`) | build receipt | n/a |
| Maintenance agent `culvert-maint` | `cmd/culvert-maint` tree `8b1f4c35`, static, built in the Dockerfile `maintbuilder` stage, shipped in `/app/deploy/bin` | | no (identical subtree) |
| Appliance console | `cmd/culvert-console` tree `12ad87e0` | | no |
| Boot splash + provisioning | `appliance/provision` tree `7fa941d2`, `appliance/build` tree `2d5988f7` (`boot-splash_test.sh`, `prepare-guest.sh`) | | no |
| OS maintenance | `appliance/os-maintenance` tree `a91dcf9c` | | no |
| First-boot installer | `scripts/install.sh` blob `9eeb145e` (was `24f3e717`) | | **yes**: main's `secret_already_set` blank/quoted/CR passphrase fix only |
| Compose | `docker-compose.yml` `e32b2ea9`, `docker-compose.ha.yml` `4b43e855`; packaging `412b83d8` | | no |
| Guest OS | Ubuntu 24.04 cloud image serial `20260926`, sha256 `6a81c375…bb4d2`, signer `D2EB4462…7C81`; apt snapshot `20261002T120000Z` | `appliance/build/manifest.env` | no |
| Kernel | `linux-image-virtual-hwe-24.04` → `7.0.0-38-generic` (`7.0.0-38.38~24.04.4`) | manifest + `r6-r7-security-dispositions.md` | no |
| Docker Engine / CLI | `5:29.9.0-1~ubuntu.24.04~noble`; containerd.io `2.4.1-2~ubuntu.24.04~noble`; Docker apt key `9DC85822…CD88` | manifest | no |
| Compose plugin | `5.6.1-1~ubuntu.24.04~noble` | manifest | no |
| ClamAV sidecar | ref `culvert/clamav:1.5.4-culvert.3`; Dockerfile sha256 `dccebff1c328b80d6134e5160c00f763e40c1cc72a26009a389a8d859174afc7`; base `docker.io/clamav/clamav` amd64 `sha256:705e0723…7a73`; **image ID `sha256:4c365e4047f948e909bfda5a7d5bf06408f2fab68e59fc513c71681ccec65ebc`**, archive `clamav.tar.gz` sha256 `ce011ffc6c1a2cfa5496156a44efac27c977e0fcaf38786362be9c02fce4d059` at `SOURCE_DATE_EPOCH=1792855424` | `appliance/clamav` tree `c133408d` | no |
| Cold-load / cosign tooling | `docker@sha256:bfec1f51…`, `cosign:v3.0.6@sha256:de9c6560…` | manifest | no |
| VM shape | 2 vCPU / 4096 MB / 40 GB, `vmx-13` | manifest | no |

**Binding rule for the OVA:** the OVA must bake sidecar image ID `4c365e40…` (`SOURCE_DATE_EPOCH=1792855424`). If the ID differs, the F-P2 credit does not transfer and F-P2 must rerun.

## 2. Change-to-test map (846d606a → b9105086)

| Material change (main) | Shipped? | Local evidence (receipt `b9105086`) | CI on tree `b6b80fc5` | OVA / QEMU check |
|---|---|---|---|---|
| SEC-C2WILDCARD-1: C2 metadata/RBAC/audit resolves wildcard support routes (`ui_metadata_enforcement.go`, `ui_routes_meta.go`, `ui_support.go`, `api/route-classification.yaml`) | yes | cmd 3: `TestC2*`, `TestC1*`, `TestD0*`, `TestC4*`, `TestRoleMetadata*` at `-race -count=2 -shuffle` | Fast race shards, Admin-UI RBAC (playwright), API contract/governance | access-aware harness: viewer/operator/admin on `/api/support/*` |
| OIDC destination transport guard (`auth_oidc.go`, `auth_oidc_flow.go`) | yes | cmd 3: `TestOIDCTransport_SSRFBoundary` | Fast race, CodeQL | none: OIDC is not configured on the appliance by default |
| install.sh blank/quoted/CR passphrase = unset | yes (first boot) | cmd 3: `TestInstallScript*`, `TestDockerCompose*` (blank, quoted, CRLF, inline-comment, multiline, an already-set value) | Install Lifecycle E2E, Deep appliance lifecycle | QEMU first boot: `CULVERT_CA_PASSPHRASE` generated and non-empty in `.env`; CA bundle encrypted at rest |
| SEC-ENROLLAUDIT-1 cluster token revoke audit (`ui_cluster.go`) | yes | cmd 3: `TestEnrollAudit*` | Fast race | none (standalone appliance) |
| Support durable writes (`support_*.go`) | yes | cmd 3: `TestSupport*`, `TestDurableSupport*`, `TestMkdirDurableSupport*` | Fast race | QEMU: support bundle create + list after reboot |
| catgroup read view (`internal/catgroup`, `policy.go`) | yes | cmd 4: catgroup `-race -count=2 -shuffle`; cmd 5: benchgate | Fast race, perf-regression | QEMU qualify allow/block with a category-group rule |
| DP backoff (`controlplane_client.go`) | yes | cmd 3: `TestDPBackoff*`, `TestDPFailover*` | Fast race | none (standalone) |
| `release_dispatch_exec.go`, `saas_feed_download.go` | yes | cmd 7: full suite | Fast race | RM upgrade path already in the lab harness |
| CI/workflow + Trivy exception metadata, action SHA-pin gate | CI only | cmd 6: security-exceptions (0 active), evidence tests 12/12, candidate-promotion 59/59; `TestWorkflow*`, `TestStaticArtifactEvidence` | Deep trivy (both scans kept), Security/QA gates | n/a |
| Unchanged: R1 restore, F-B1/F-B2, ClamAV lifecycle, boot gates, agent, console, OS maintenance | — | cmd 3: `TestFB1*`, `TestFB2*`, `Restore|Recover|Clam|AVUnavailable|Appliance|Boot|Backup` | Deep appliance lifecycle / ClamAV / agent / console / F-DISK-1 | prior QEMU + ESXi evidence on identical subtrees still applies; the OVA rebuild reruns the standard QEMU qualification |

## 3. Limits

- The app image is rebuilt, so its bytes differ from any earlier candidate. Identity is bound by the build receipt (revision label + image ID), not by reproducibility.
- QEMU validation is preliminary and non-destructive. Real ESXi import or mutation is not approved.
- Docker-dependent installer tests skip in the receipt sandbox (no daemon); CI covers them (Install Lifecycle E2E, Deep appliance lifecycle).
- Real-directory LDAP/AD and external IdP pilots remain blocked by missing infrastructure, as recorded before.
