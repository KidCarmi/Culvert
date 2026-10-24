# Workstream C: Compose 5.6.1, appliance `--no-build`, verified sidecar reload, musl -r3

Prepared by OPUS on 2026-10-23 under owner directive 6369573402, Workstream C. This is a separate, reviewable patch on top of `review/1528-integ-on-main`.

Scope of what was done:
- **Local runs only:** a sandbox dockerd plus unit tests.
- **Not done:** no OVA build, no lab dispatch, no VM action, no PR.

Status: MERGE / PILOT / RELEASE remain **NO-GO**. Nothing here ships until the R4 replacement candidate is built and qualified.

## 1. The defect: Compose silently builds a missing sidecar

The appliance's sidecar is a local-only tag (`culvert/clamav:…`) whose compose service still carries a `build:` context, because quick-start hosts build it.

Measurement setup:
- The tag was removed and the stack was then brought up.
- Every API call went through a tap.
- The build context was replaced with one whose base image does not exist, so an attempt fails fast instead of fetching.
- Raw outputs: `workstream-c/compose-5.6.{0,1}-missing-tag.txt`, produced by script `workstream-c/measure-c.sh`.

| State before `up` | plain `up -d` (5.6.0 and 5.6.1) | `up -d --no-build` (5.6.0 and 5.6.1) |
|---|---|---|
| A: tag present | rc 0, no build | rc 0, no build |
| B: clamav running, tag missing | rc 1, **5 BuildKit session calls (build attempted)** | rc 1, 0 build/session/pull calls; running clamav untouched; volume kept |
| C: stack stopped (os-update shape), tag missing | rc 1, **build attempted** | rc 1, 0 calls; volume kept |
| D: containers removed, images pruned | rc 1, **build attempted** | rc 1, 0 calls |

Without `--no-build`, every missing-tag state makes Compose rebuild the sidecar from source: new, unscanned bytes from Docker Hub and the Alpine CDN. With `--no-build` it fails explicitly and builds nothing. Both Compose versions behave identically.

## 2. The change

| Path that could build | Before | After |
|---|---|---|
| `culvert-os-update` stack start (engine upgrade, resume) | `compose up -d` | `culvert-clamav-image ensure`, then `up -d --no-build`. On refusal the stack is **not** started and the resume marker is kept. |
| `install.sh` first `up` and agent-override `up` | plain `up` | Appliance: `ensure`, then `up --no-build`. Quick-start: unchanged. |
| `install.sh` `refresh_deploy_bundle` with a new sidecar tag | `docker build` | Appliance: the bundle's sidecar must equal the manifest's `CLAMAV_SIDECAR_REF` and, if present, resolve to `CLAMAV_SIDECAR_ID`; otherwise refuse (rc 3), nothing built or replaced. An approved-but-absent tag is adopted and restored from the archive at start, never built. Quick-start: builds as before. |
| Maintenance agent `compose.up` (apply, image rollback, inline rollback) | `up -d` | `compose_no_build = true` ⇒ `up -d --no-build`. On **apply and image rollback**, `preflight_dependencies` refuses before any pull/tag/up if a `local_only_images` entry is absent or, for an entry written `ref=sha256:<id>` (the installer writes the recorded ID), names other bytes, or its inspect fails without the absence signature (daemon down, permission, timeout): the identity the entry demands was not established, so it refuses as `local_image_unverified` (corrected after ASTRA 5978949299 08:15; it used to proceed). A presence-only entry keeps the older rule: such a failure does not refuse. **Inline rollback** has no preflight of its own: it runs only after an apply that passed one, and refusing there would strand the failed new image; its `up` is `--no-build`, so it can only fail explicitly, never build. |
| Agent sudoers | Plain `up -d` forms | A no-build host keeps **only** the `--no-build` forms, so the agent user cannot run a build-capable `up`. Other hosts are unchanged. |

**How an appliance is detected:** by the directories the OVA build installs (`/var/lib/culvert-appliance`, `/opt/culvert-appliance`, `/etc/culvert-appliance`), never by whether the metadata inside them is valid. An appliance whose manifest is missing, unreadable or damaged is still an appliance: it keeps `--no-build` and **refuses**. (Corrected from `a4101839`, which keyed identity on a valid recorded ID and so treated a damaged manifest as quick-start and built the sidecar — ASTRA 5978949299 C blocker 1.) An environment variable was not used because an operator re-running `install.sh` by hand carries no first-boot environment.

**What may be adopted or started:** only the sidecar the appliance was built with. Before adoption (refresh) and before the first `up`, the compose file's sidecar must equal the manifest's ref and resolve to its recorded ID. A locally present tag is not approval: presence proves nothing about which bytes it names (ASTRA C blocker 2).

**How the sidecar comes back:** `appliance/provision/culvert-clamav-image ensure`.
1. If the tag already names the recorded ID, the result is `present`.
2. Otherwise:
   - the baked archive's SHA-256 must equal build-info `application.clamav_baked_tar_sha256`;
   - then `docker load`;
   - then the loaded tag must name the recorded ID.

   All three passing gives `reloaded`.
3. Anything else is `refused`, with exit 2 and a reason recorded in `clamav-image.state`. The reasons are: `manifest_missing`, `manifest_incomplete`, `archive_missing`, `archive_hash_unrecorded`, `archive_hash_mismatch`, `load_failed`, `loaded_id_mismatch`.

The helper never builds or pulls. A refusal is **not** "nothing changed": a `loaded_id_mismatch` comes after `docker load`, which can retag. When a valid recorded ID proves the tag names other bytes (already, or after the load), the refusal removes the tag so `up --no-build` cannot start them. Whether that worked is decided by a re-inspect, not assumed: the state file records `tag=removed`, `tag=retained` (still there) or `tag=unconfirmed` (the daemon could not answer), and the last two print an explicit "Do NOT start the stack" with the command to remove the tag. So a refusal does **not** guarantee the tag is gone; it guarantees the operator is told the truth about it (corrected after ASTRA 5978949299 08:15: the earlier helper ignored a failed `image rm` and always said "removed"). A running container keeps running (Docker runs it by image ID). With damaged metadata nothing proves the tag wrong, so it is left alone.

**Accepted cost (refusal):** a stack that was stopped while the image was lost stays **down** until the verified image is restored, because the proxy `depends_on` a healthy sidecar. Measured: E5 step 52. It is never started on unscanned bytes. A sidecar that is still running keeps running (E2 step 21).

## 3. Real-docker end-to-end (sandbox dockerd 29.6.2, Compose 5.6.1 from the signed deb)

The sidecar bytes, archive and build-info are the **frozen OVA's** (`culvert.1`, ID `ea362f9b…`). Raw output: `workstream-c/e2e-real-docker.txt`, produced by script `workstream-c/e2e-c.sh`.

**Helper bytes tested vs submitted.** The E2E header records the helper it ran: SHA-256 `c843caa71fb66cf4bd5e4f8a85667565aa8754f3190e5a6d331200f95484e80f`. After the run, two text lines changed before commit (the header comment and one refusal log message, no logic), giving the `a4101839` blob `20dbd9db99adf38fb79df69838ceb841e89dc4ef25689480b978de8095fac9f5`. The tested bytes were reconstructed by reverting exactly those two lines and hash to `c843caa7…`; the delta is `workstream-c/helper-tested-to-a4101839.diff`. The current helper (`e3ac37cb11bfc3bf3ec8ad0f200864990b54fbd7d17983139ab60f1453b1c9ec`) adds the refusal un-tag and its re-inspected outcome described in §2 (`8715486471dec22afc523b990fd969f8b9f32ed13f3cc34540b812c62d449721` at `c297902d` claimed removal unconditionally); both changes are covered by `appliance_clamav_image_helper_test.go`, **not** by this E2E.

| Step | Result |
|---|---|
| Agent argv (`-f compose -f override up -d --no-build`): baseline | rc 0, clamav running EXPECTED ID |
| **Apply** (re-pin proxy a→b, agent argv) | rc 0; proxy is b; **the clamav container is untouched** (same container ID); volume marker kept |
| **Rollback** (re-pin b→a, agent argv) | rc 0; proxy is a; volume kept |
| Tag removed while running | The daemon says `Error response from daemon: No such image: …`, which matches the agent's `imageNotFoundRE` |
| Agent argv while the tag is missing | rc 1, **0 build calls**, running clamav untouched. (In production the agent preflight refuses before reaching `up`; that is unit-tested in the agent, not exercised by this E2E.) |
| **Maintenance path:** stop → tag lost → `ensure` → `up --no-build` | Reloaded, rc 0, clamav running EXPECTED, volume kept |
| **Whole image store lost:** down (volumes kept) → prune all → `ensure` → `up --no-build` | Reloaded, rc 0, EXPECTED, volume kept |
| **Refusal:** archive tampered | Helper exit 2 `archive_hash_mismatch`; `up --no-build` rc 1; 0 build calls; nothing started; volume kept |
| Refusal: archive missing | Exit 2 `archive_missing` |
| Recovery with the real archive | Reloaded, stack up, EXPECTED; **final volume marker equals the initial one** |

Build, session and pull calls were **0 on every step**.

## 4. musl 1.2.6-r3 (CVE-2026-107891) and the F-P2 delta

- `appliance/clamav/Dockerfile` pins `musl=1.2.6-r3` and `musl-utils=1.2.6-r3`, with in-build asserts. New bytes require a new tag: `culvert/clamav:1.5.4-culvert.2`.
- The local build upgraded **only** musl and musl-utils, r2→r3 (`workstream-c/sidecar-culvert.2-build-excerpt.txt`).
- **Dependency-float finding.** `apk add --upgrade pkg=ver` also upgrades dependencies. Rebuilding the *unchanged* `culvert.1` recipe today already yields musl -r3, while the frozen OVA carries -r2.
  - So the same tag would mean different bytes on a host that rebuilds it.
  - The explicit pin makes the musl move deliberate and asserted.
  - It does not stop a *future* dependency from floating. On the appliance, `--no-build` plus the hash-verified archive removes the rebuild entirely; quick-start hosts keep the float.

**F-P2 isolated reproduction.**
- Protocol: lab job `fp2-isolated` at lab commit `67694982`, transcribed in `workstream-c/fp2/fp2-arm.sh`:
  - stock `clamd.conf`, freshclam off;
  - one fixed signature set shared by every arm: main 63, daily 28162, bytecode 339;
  - a 256 MiB ext4 loop device as clamd's `/tmp`;
  - variants control, serial-full, serial-sweep, conc8 and conc8-full: **1,600 scans plus 72 fill events** per arm. (Corrected: the earlier "1672 requests" counted JSONL lines, fill events included; re-counted from each arm's `requests.jsonl`.)
- Verdict = count of EICAR streams answered with a bare clean.

| Arm | Image | musl | Wrong cleans | tmpdir errors | Expected | Verdict |
|---|---|---|---|---|---|---|
| Control: ClamAV 1.4.6 | `10f35c2c…` | (upstream) | **62** | 121 | non-zero | PASS (reproduces the defect) |
| Shipped `1.5.4-culvert.1` (**exact frozen-OVA bytes**, reloaded by the helper) | `ea362f9b…` | 1.2.6-r2 | **0** | 0 | 0 | PASS |
| New `1.5.4-culvert.2` | `fc44c3ca…` (local build) | 1.2.6-r3 | **0** | 0 | 0 | PASS |

Both 1.5.4 arms ran the same `clamd.conf` (`eaeee6ea…`) and the same signatures. Per-arm reports, packages and variants are in `workstream-c/fp2/<arm>/`. "None observed" is not proof the defect cannot occur; it is the same sample size and protocol as the lab job.

**Limit.** The `culvert.2` image here is a sandbox build: its BuildKit run carried a sandbox-CA bind mount (no layer, but recorded in history), so its ID is **not** the CI candidate's. The R4 `[fp2-isolated]` lab leg must still run on the real candidate's baked bytes.

## 5. Compose 5.6.1

`DOCKER_COMPOSE_PLUGIN_VERSION=5.6.1-1~ubuntu.24.04~noble`, from the same signed apt repository and key as the engine. The trust chain and scan deltas are recorded in `../r6-r7-security-dispositions.md` §R6.

It is not a zero-finding binary. Remaining govulncheck rows (`../r6-r7-security-dispositions.md` §R6):
- **symbol-level:** GO-2026-6603, GO-2026-6611, GO-2026-6612, GO-2026-6617;
- **package-only:** GO-2026-5932 (x/crypto `openpgp`, no fix), GO-2026-6610 (x/net).

The measured change is narrower than "HTTP/2 eliminated": `--no-build` removes the missing-tag **build** traffic observed in §1. It is not all-path HTTP/2 elimination, and it is not a waiver for these rows; their disposition stays with ASTRA's R6/R7 matrix.

## 6. Tests added or changed (all local, all green)

| Test | What it pins |
|---|---|
| `config_nobuild_test.go` (agent) | Defaults are off. `local_only_images` requires `compose_no_build`. Only local `repo:tag` entries, optionally `=sha256:<64 hex>`, at most 8. |
| `runner_test.go` `TestBuildArgv_ComposeNoBuild` | `--no-build` is the last token only on a no-build host, and never leaks onto other templates. |
| `preflight_local_image_test.go` (agent server) | Apply **and** image rollback refuse before pull/tag/up when the image is absent, or (ID-bound entry) when the tag names other bytes, the inspect answer cannot be read, or the inspect FAILS without the absence signature (permission denied, daemon unreachable, deadline, no stderr). Recorded bytes ⇒ the op succeeds and every `up` ends in `--no-build`. For a presence-only entry an inspect failure without the "No such image" signature does not refuse. A default host never probes and keeps plain `up -d`. |
| `install_script_maint_sudoers_nobuild_test.go` | The real render keeps exactly one `up` family per host type (with and without the override); `visudo -c` passes. `compose_no_build` accepts only absent/false/true. |
| `install_script_host_refresh_appliance_test.go` | An appliance refuses a different tag (absent **or present**), the baked tag naming other bytes, an invalid/missing manifest, and identity from `/opt` or `/etc` alone; nothing built or replaced. Controls: the approved sidecar (present with the recorded ID, or absent) is adopted without a build. Replaces the test that pinned "malformed manifest is quick-start". |
| `install_script_appliance_sidecar_start_test.go` | Before the first `up`: the helper runs, then the compose sidecar must equal the baked ref and ID; a damaged manifest keeps `--no-build` and refuses; quick-start skips all of it. |
| `install_script_agent_local_images_test.go` | The installer writes `compose_no_build = true` and `local_only_images = ["<ref>=<recorded ID>"]`, replacing any earlier entry, in the agent's accepted grammar. |
| `appliance_clamav_image_helper_test.go` | The real helper: present, reloaded (absent / wrong image under the tag), the six refusal reasons it reaches with fixtures, and refusal removing a tag that names unverified bytes (after a mismatched load, or pre-existing with the archive missing), recorded as `tag=removed`; a failed removal is reported as `tag=retained` or `tag=unconfirmed` with "Do NOT start the stack", never as removed; with damaged metadata the tag is left alone (`tag=unchanged`). It never builds, pulls or composes. |
| `appliance_os_update_clamav_image_test.go` + `power_test.sh` | `ensure` runs before every `up`, every `up` is `--no-build`, and a refusal starts nothing, keeps the marker, and goes through the existing docker-upgrade recovery. |
| `appliance_ci_lane_test.go` | The musl pin and asserts, and the `culvert.2` content→tag binding (`culvert.1` retired). |

**Mutation checks** (each reverted after):
- removing the agent refusal ⇒ 2 server tests fail;
- dropping the argv token ⇒ 3 fail;
- dropping sudoers Pass 3 ⇒ 2 render cases fail;
- removing the appliance refresh guard ⇒ the refresh test fails;
- identity back to manifest validity ⇒ 3 tests fail; dropping the start binding ⇒ 2 fail; dropping the present-tag ID check ⇒ 2 fail;
- dropping the agent's ID comparison ⇒ the mismatch test fails;
- dropping the ID-bound inspect-error refusal ⇒ `TestNoBuildHost_IDBoundRefusesWhenInspectFails` fails;
- restoring the helper's unconditional `image rm … || true` + "removed" line ⇒ both `FailedRemovalIsReportedTruthfully` cases fail.

**Gates.** On `a4101839` (original delivery):
- agent `go vet` + `go test -race ./...`: pass;
- root `go build`/`go vet`: pass;
- root `go test ./...`: 118 packages ok. The root package had one load-induced failure (`TestChaos64_StaleServesDoNotStackRefreshes`; it ran concurrently with lint and the agent race suite; no DNS file is touched). That test passes 10/10 in isolation, and the root package rerun on its own passes (`ok`, 423 s). Both outcomes are kept.
- golangci-lint v2.5.0 `--new-from-rev`: 0 issues in both modules;
- Deep Gate shellcheck set + installer: clean.

On the correction commit (ASTRA 5978949299 items), run on its own tree:
- root `go vet ./...` + `go test .`: pass (`ok`, 418 s, no concurrent load);
- agent `go vet` + `go test -race ./...`: all packages ok;
- golangci-lint v2.5.0 `--new-from-rev HEAD`: 0 issues in both modules;
- helper shellcheck `-S warning`: clean; `power_test.sh`: pass.

Exact command/environment/exit receipts bound to the commit and tree are published separately (`workstream-c/receipts/`).

## 7. NOT RUN

- **No OVA was built.** The helper, `--no-build` and `culvert.2` have never booted on an appliance. They need the R4 replacement candidate plus:
  - exact-byte scans of the `culvert.2` sidecar and Compose 5.6.1 as baked;
  - first boot;
  - reboot ×3;
  - agent apply/rollback through the real agent process and sudoers;
  - `[fp2-isolated]` on the baked bytes;
  - F-DISK.
- **Real agent process:** apply/rollback were exercised through the server with a fake exec layer (unit tests) and by replaying the agent's exact argv on real docker (§3). The full sudo + socket + agent path on a guest was not run.
- **CI:** no PR, so no Fast/Deep/QA/Security/CodeQL.
- Signing and distribution are future work; an unsigned OVA never goes to a customer.
