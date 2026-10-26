# M1 — Docker engine / containerd pin bump: provenance + before/after (owner 6400728126)

**Scope:** steps 1–3 of the owner's M1 authorization:

1. Verify the signed vendor packages.
2. Compare the exact binaries before and after.
3. Make one pin-only patch on a dedicated branch.

**Not done here** (each needs a separate go-ahead): lab compatibility runs, OVA build, ESXi, merge.

## The change

The branch is `review/1528-m1-engine-pins`, the parent is the frozen `b9105086` (tree `b6b80fc5`), and the frozen history is not rewritten. Only `appliance/build/manifest.env` changes (the three values plus their comment):

| Pin | Before (OVA 61c46d6d) | After |
|---|---|---|
| `DOCKER_CE_VERSION` | `5:29.9.0-1~ubuntu.24.04~noble` | `5:29.9.2-1~ubuntu.24.04~noble` |
| `DOCKER_CE_CLI_VERSION` | `5:29.9.0-1~ubuntu.24.04~noble` | `5:29.9.2-1~ubuntu.24.04~noble` |
| `CONTAINERD_IO_VERSION` | `2.4.1-2~ubuntu.24.04~noble` | `2.4.2-3~ubuntu.24.04~noble` |
| `DOCKER_COMPOSE_PLUGIN_VERSION` | `5.6.1-1~ubuntu.24.04~noble` | unchanged |

`prepare-guest.sh` installs all three by exact `pkg=version` with `--no-install-recommends` and holds them, so no other consumer needed a change. `docker-ce` 29.9.2 declares `Depends: containerd.io (>= 2.1.5)`, which 2.4.2-3 satisfies.

## Provenance (signed Docker noble APT)

The signature chain is anchored on the fingerprint already pinned in `manifest.env`:

- **Key:** `docker.gpg.asc` from `DOCKER_APT_GPG_URL`. Its primary fingerprint is `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`, equal to `DOCKER_APT_KEY_FPR`. Signing subkey `D3306A018370199E527AE7997EA0A9C3F273FCD8`.
- **`dists/noble/InRelease`:** gpg reports `GOODSIG` / `VALIDSIG D3306A01…`, with primary `9DC85822…` (`raw/inrelease-verify.txt`). The metadata is dated `2026-10-26 04:05:01 UTC`.
- **`stable/binary-amd64/Packages`:** sha256 `18e93294…add665fd`, which equals the SHA256 entry inside the signed InRelease.
- **Each DEB:** sha256 equals its `Packages` stanza (`raw/packages-stanzas.txt`, `raw/debs.sha256`):

| DEB | sha256 |
|---|---|
| `docker-ce_29.9.2-1~ubuntu.24.04~noble_amd64.deb` | `95ddf7a2d8b8c0eb82d8597d4d604e294dcf741081f2e228524d5ab9bfd7c8ae` |
| `docker-ce-cli_29.9.2-1~ubuntu.24.04~noble_amd64.deb` | `74747b5c99000279b9b2c7eb82543b4121d8436a58aa3be7e78ac6681d74794f` |
| `containerd.io_2.4.2-3~ubuntu.24.04~noble_amd64.deb` | `f811ab57d1f4bb0cce19df7d526da8c711d8ebea0447cc83da1999188e664122` |

The stanzas for `containerd.io` 2.4.2-1 and 2.4.2-2 are included only to show that those revisions exist and were not chosen.

**Upstream stamps** (`raw/go-version-m.txt`):

| Binary | Version stamp | Commit |
|---|---|---|
| dockerd | `dockerversion.Version=29.9.2` | `0367cbe` |
| docker (CLI) | `version.Version=29.9.2` | `a82e528` |
| containerd | `v2.4.2` | `b7a25261e029d68978bbf290df0a62fc819b3c51` |
| runc | (no version stamp) | same source revision as before (`29dd3dc2…`), rebuilt with go1.27.3 |

## "Before" is the exact shipped bytes

The old DEBs (29.9.0-1, 2.4.1-2) were fetched from the same signed repository and scanned **in the same run, with the same database**. That way the delta reflects only the package change, not database drift. All 7 old engine binaries are byte-identical to the ones in the exact-OVA scan of 61c46d6d (`raw/old-equals-ova.tsv`, 7/7 MATCH against run 40200275913's `go-binaries.tsv`).

## Before → after

Go toolchains (`go version`):

| Binary | Before | After |
|---|---|---|
| dockerd, docker, docker-proxy | go1.26.9 | **go1.26.10** |
| containerd, ctr, containerd-shim-runc-v2, runc | go1.27.2 | **go1.27.3** |

**govulncheck v1.8.0, binary mode** (DB 2026-10-21; `govulncheck-delta.txt`, raw JSON in `raw/govulncheck-binary.tar.gz`):

- GO-2026-6809 was found in all 7 binaries before: symbol-level in 6, and module-level in docker-proxy. **After the bump it is absent from all 7**, because each binary's stdlib is now at or above the fixed version.
- **Every other row is unchanged**, at the same level:
  - x/net GO-2026-6603/6610/6611/6612/6617 in containerd, ctr, shim and runc.
  - cilium/ebpf GO-2026-6238.
  - moby/sys/user GO-2026-6686 (runc).
  - x/net GO-2026-5942 (runc).
  - x/crypto GO-2026-5932 (no fix).

**Trivy 0.69.3** (DB 2026-10-26 07:15Z; `raw/trivy-{old,new}.json.gz`):

| Severity | Before | After |
|---|---|---|
| HIGH | 12 | 5 |
| MEDIUM | 18 | 18 |
| LOW | 4 | 4 |
| UNKNOWN | 2 | 2 |

- **Removed:** CVE-2026-111943 (HIGH, stdlib) from all 7 binaries.
- **Only other difference:** dockerd's x/crypto moved v0.57.0 → v0.58.0. It still carries the same no-fix GO-2026-5932 at module level.
- **The 5 remaining HIGH were already present before:**
  - CVE-2026-78669 (x/net v0.58.0 → fixed in 0.60.0) in containerd, shim and ctr.
  - CVE-2026-78669 and CVE-2026-46600 (x/net v0.55.0) in runc.

**Not claimed:** the bump does **not** resolve the containerd/runc x/net HTTP/2 advisories, because containerd.io 2.4.2-3 still vendors x/net v0.58.0 and runc v0.55.0. It also does not touch Compose 5.6.1.

**Reachability of GO-2026-6809:**

- **Before:**
  - *Statically called*: in dockerd, docker, containerd and ctr. Source mode, OVA scan: TLS clientHandshake → `Certificate.Verify`.
  - *Required only*: docker-proxy, shim, runc.
  - *Observable runtime path*: registry TLS on `docker pull repo@digest` by the maintenance agent (apply/rollback) and containerd's own fetches.
- **After:** the finding is absent at every level, so no runtime-path claim remains for it.

## Compatibility checks done here

- **Manifest parses** (`bash -n`, sourced): the four pins resolve to the values above.
- **Root tests that consume `manifest.env` or the appliance install path** (archive closure, CI lane, ClamAV image helper, first boot, scan closeout, cosign pin, installer local-images / sidecar-start / host-refresh) pass **76/76** under go1.27.3 (`raw/root-tests.log`). That includes the opt-in live sudoers precedence proof, run as root with `CULVERT_SUDO_POLICY_LIVE=1`, which cleaned up its temporary user.

## Not done here (lab, separate go-ahead)

These need a guest with the new engine:

- offline baked-image load on the containerd snapshotter;
- the local-only sidecar with `--no-build`;
- maintenance-agent sudo/socket/apply/rollback;
- signed/pinned image flows;
- state/volume/backup retention;
- reboot;
- F-DISK ENOSPC recovery.

There is no Docker daemon in this environment. The lab workflow's F-P2 sidecar job also installs its **runner** engine with a hard-coded `29.9.0` (test/appliance-lab `appliance-lab.yml`, the "Docker 29.9.0 on the containerd image store" step). That pin must move with this one before the next lab round.
