# R10 — Docker engine / containerd / Compose pin bump: provenance + before/after (owner decision 17 Nov 2026)

**Why.** The exact-byte scan of the R10 candidate OVA `9e31f226` (lab run 43964288041) reported GO-2026-6859 / CVE-2026-97054 (`net/http` `MaxBytesReader` header race, HTTP/1 server crash) in all eight engine binaries. The engine binaries were built with go1.27.3 / go1.26.10; the fix is in go1.27.4 / go1.26.11.

**Owner decision (17 Nov 2026, PR #1528).** "Choose the upgrade path: Docker CE/CLI 29.10.0, Compose 5.7.1 and containerd.io 2.4.2-4, subject to ASTRA verifying the exact packages and compatibility. … Pin exact package versions and hashes; avoid unrelated upgrades. … Do not claim the upgrade eliminates every finding."

## The change (`appliance/build/manifest.env`)

| Pin | Before (OVA 9e31f226) | After |
|---|---|---|
| `DOCKER_CE_VERSION` | `5:29.9.2-1~ubuntu.24.04~noble` | `5:29.10.0-1~ubuntu.24.04~noble` |
| `DOCKER_CE_CLI_VERSION` | `5:29.9.2-1~ubuntu.24.04~noble` | `5:29.10.0-1~ubuntu.24.04~noble` |
| `CONTAINERD_IO_VERSION` | `2.4.2-3~ubuntu.24.04~noble` | `2.4.2-4~ubuntu.24.04~noble` (same upstream 2.4.2) |
| `DOCKER_COMPOSE_PLUGIN_VERSION` | `5.6.1-1~ubuntu.24.04~noble` | `5.7.1-1~ubuntu.24.04~noble` |

Plus the four `*_DEB_SHA256` values below. `prepare-guest.sh` installs each by exact `pkg=version` with `--no-install-recommends`, verifies the acquired `.deb` against its pin, and holds it; `build-ova.sh` refuses a Docker index that lists another hash for a pinned version. No consumer needed a change.

## Provenance (signed Docker noble APT), `raw/`

- **Key.** Docker's key from `DOCKER_APT_GPG_URL`: primary fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` = `DOCKER_APT_KEY_FPR`; signing subkey `D3306A018370199E527AE7997EA0A9C3F273FCD8`.
- **`dists/noble/InRelease`.** Fetched twice, byte-identical. `gpgv` reports `GOODSIG` / `VALIDSIG D3306A01…`, primary `9DC85822…` (`raw/inrelease-gpgv.txt`).
- **`stable/binary-amd64/Packages`.** Its sha256 equals the SHA256 entry inside that InRelease (`raw/packages-index.txt`).
- **Each `.deb`.** Its sha256 equals its `Packages` stanza (`raw/packages-stanzas.txt`, `raw/debs.sha256`).

| `.deb` | sha256 |
|---|---|
| `docker-ce_29.10.0-1~ubuntu.24.04~noble_amd64.deb` | `85abe031338e48e9cb157238732b2c40aeb4f1741d399f64042abcca2950c951` |
| `docker-ce-cli_29.10.0-1~ubuntu.24.04~noble_amd64.deb` | `a9d3801c3efd3c78786948e8dd1c023796c9145aca8c882818664e79402578f1` |
| `containerd.io_2.4.2-4~ubuntu.24.04~noble_amd64.deb` | `15cc3d6c64422ed278f60cb3c9a5df760a3de38055affc335c6ee40c12411b75` |
| `docker-compose-plugin_5.7.1-1~ubuntu.24.04~noble_amd64.deb` | `c2f6549958ca64466da9e31a6d488e19f5a1bf475a4425df9e4c3a010d5950ac` |

The stanzas for 29.9.3 and Compose 5.7.0 are recorded only to show why they were not chosen: 29.9.3 is still go1.26.10, and Compose 5.7.0 is go1.26.10.

## Packaging compatibility (old pins → new pins)

| Check | Result |
|---|---|
| `Depends` / `Pre-Depends` / `Conflicts` / `Breaks` / `Replaces` / `Recommends` | identical for all four packages, so no new Ubuntu package |
| file list | identical, except `docker-ce-cli` adds `usr/share/doc/docker-ce-cli/README.md` |
| conffiles | identical |
| `docker.service`, `docker.socket`, `containerd.service`, `/etc/containerd/config.toml` (`disabled_plugins = ["cri"]`) | byte-identical |

The appliance's `/etc/docker/daemon.json` (`prepare-guest.sh`) is unchanged.

**Behaviour is NOT established here.** Engine/Compose behaviour belongs to the qualification campaign: first boot, Compose/agent wiring, image upgrade and rollback, backup/restore, container networking, and Q7 recovery. Compose's rebuild-on-missing-tag behaviour is part of that, because every appliance `compose up` carries `--no-build`.

## The exact binaries before and after (`binaries.tsv`, `raw/go-version-m.txt`)

Read from the `.deb` payloads (`dpkg-deb -x`, no maintainer scripts run):
- Go and module versions from `go version -m` (go1.27.4);
- function presence from `.gopclntab` via the lab's `test/e2e/appliance/lab/pclnfuncs`;
- the old binaries' sha256 equal the `go-binaries.tsv` of the `9e31f226` scan.

| Binary | Before | After | otel (sdk/trace) after | `(*maxBytesReader)` / `(*Server).Serve*` funcs |
|---|---|---|---|---|
| dockerd | go1.26.10 | **go1.27.4** | **v1.47.0** (was v1.46.0) | 2 / 5 |
| docker-proxy | go1.26.10 | **go1.27.4** | — | 0 / 0 |
| docker | go1.26.10 | **go1.27.4** | — | 0 / 0 |
| containerd | go1.27.3 | **go1.27.4** | v1.46.0 / v1.46.0 (**unchanged**) | 2 / 6 |
| ctr | go1.27.3 | **go1.27.4** | — / v1.46.0 (**unchanged**) | 0 / 0 |
| containerd-shim-runc-v2 | go1.27.3 | **go1.27.4** | — | 0 / 0 |
| runc | go1.27.3 | **go1.27.4** | — | 0 / 0 |
| docker-compose | go1.26.10 | **go1.27.4** | v1.46.0 / v1.46.0 (**unchanged**) | 2 / 0 |

**What this is expected to change.**
- **Removed:** the stdlib rows GO-2026-6859 / CVE-2026-97054 on all eight binaries (fixed in go1.27.4), and CVE-2026-128085 on dockerd (otel v1.47.0).
- **Stays:** CVE-2026-128085 on containerd, ctr and compose (otel v1.46.0); the module-level x/net / x/crypto rows recorded earlier; and anything a newer vulnerability DB adds.

This is a prediction. The exact-byte scan of the built OVA is the authority, and every remaining row is dispositioned on the shipped bytes.
