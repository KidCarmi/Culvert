# Culvert appliance — SBOM and CVE evidence (appliance build `1.0.259-ova.1`)

Everything in this directory was **executed** on 2026-10-02 in the appliance build environment
(commands below). Nothing here claims "zero vulnerabilities": it records *what was scanned, with which
tool and database, what was found, and how each finding was triaged against the vendor's own advisory data*.

| Tool | Version | Vulnerability DB |
|---|---|---|
| trivy | 0.75.0 | `trivy-db` v2, `UpdatedAt 2026-10-02T06:55:51Z` (downloaded 09:32Z) |
| grype | 0.119.0 | schema v6.1.9, built `2026-10-02T06:31:53Z` (`grype.anchore.io`) |
| syft | 1.54.0 (local SBOMs); release SBOMs were produced by syft 1.51.1 in CI | — |
| cosign | v3.1.3 | Sigstore public-good TUF root |

## 1. Component inventory (SBOMs)

| Layer | Artifact | File | Components | How obtained |
|---|---|---|---|---|
| Application binary (release-published) | `culvert.sbom.cdx.json` from GitHub release `v1.0.259` | `release-v1.0.259-culvert.sbom.cdx.json` | 102 (Go modules) | downloaded; `cosign verify-blob --bundle … --new-bundle-format` against `release_identity.env` → **Verified OK** (sha256 `484be35a…0ab2`) |
| Maintenance agent (release-published) | `culvert-maint.sbom.cdx.json` | `release-v1.0.259-culvert-maint.sbom.cdx.json` | 5 | same; **Verified OK** (sha256 `86d4149e…6116`) |
| Container image (OS packages + binaries), exact digest | `ghcr.io/kidcarmi/culvert@sha256:238ba99b…347e` (Alpine 3.24.2) | `culvert-1.0.259.image.cdx.json` | 126 | `trivy image --format cyclonedx` |
| ClamAV container image | `clamav/clamav:1.4` = `sha256:57deb108…6f23` (Alpine 3.24.2) | `clamav-1.4.image.cdx.json` | 42 | `trivy image --format cyclonedx` |
| Guest OS packages (as shipped by the pinned cloud image) | Ubuntu 24.04 cloud image release 20260926 | `guest-cloudimage-20260926.dpkg-manifest.tsv` | 664 dpkg entries | Canonical's published `.manifest` for the image (sha256 recorded in the build record). The baked guest's own `dpkg-query` list is at `/etc/culvert-appliance/dpkg-list.tsv` inside the appliance and in `guest-baked.dpkg-list.tsv` here once the bake is recorded (see ASTRA-STATUS.md). |
| Host components added at bake | docker-ce / containerd / compose + deps | `host-docker-debs.sha256.tsv` | 15 .debs | the exact payload the bake installed, with sha256 |
| Host components installed at first boot | `culvert-maint` binary, sudoers, unit, compose files | — | — | all come out of the container image above (`/app/deploy`); identity = the image digest; the agent's SBOM is the release one |

Cross-check: `syft` run locally on the same image produced `culvert-1.0.259.image.syft.cdx.json` (934
components — syft enumerates Go package-level entries, trivy module-level); kept out of git for size,
regenerable with the command in §4.

## 2. Vulnerability scans

### 2.1 Application image `ghcr.io/kidcarmi/culvert@sha256:238ba99b…347e`

| Scanner | Result | File |
|---|---|---|
| trivy (vuln, all severities) | alpine 3.24.2 packages: **0**; `app/culvert`: **1** (`GO-2026-5932`, severity UNKNOWN); `app/deploy/bin/culvert-maint`: **0** | `culvert-1.0.259.image.trivy.{txt,json}` |
| grype | **4** matches: `CVE-2026-85091` zlib 1.3.2-r0 (High), `CVE-2025-60876` busybox / busybox-binsh / ssl_client 1.37.0-r31 (Medium) | `culvert-1.0.259.image.grype.{txt,json}` |

Triage (vendor-advisory aware):

| Finding | Package | Triage | Status |
|---|---|---|---|
| `GO-2026-5932` | `golang.org/x/crypto` v0.57.0 — "the `openpgp` package is unmaintained/unsafe by design" | Module-level match. The **package is not linked**: `strings /app/culvert \| grep -c x/crypto/openpgp` → `0`, and `go list -deps ./...` in the repo shows no `x/crypto/openpgp` import. No fixed version exists (advisory, not a bug). | Not applicable (unreachable). Re-check on every release. |
| `CVE-2026-85091` | zlib 1.3.2-r0 | grype match type `cpe-match` from the NVD namespace; **not present in Alpine's secdb for 3.24** (`https://secdb.alpinelinux.org/v3.24/main.json` has no secfix entry for this CVE), no fixed version in any index. trivy (which uses the Alpine secdb) reports nothing. | Open, unfixed upstream/vendor at scan time. **Monitor**: a new `zlib` secfix in Alpine 3.24 or a new Culvert image closes it. Exposure: zlib in the proxy's Alpine base, used by the Go runtime only through the static binary's own (Go-native) compression — the Alpine `zlib` package is not loaded by the statically linked Go binary. |
| `CVE-2025-60876` | busybox 1.37.0-r31 (3 packages) | `cpe-match`, NVD namespace, not in Alpine secdb for 3.24, no fix. busybox provides the image's `/bin/sh` and the healthcheck `wget`; it is not on the request path. | Open, unfixed. **Monitor** (same closure path). |
| (ClamAV image) `CVE-2026-103111` | pcre2 10.48-r0 → fixed **10.49-r0** | Alpine secdb lists the fix (`pcre2 10.49-r0`). The image `clamav/clamav:1.4` was built 2026-09-28 before the fix landed. HIGH, OOB write via crafted regex; reachable only through ClamAV's own signature engine (signatures come from ClamAV, not from clients). | **Fix available**: rebuild/pull of `clamav/clamav:1.4` once Docker Hub publishes an updated image (same tag moves), or pin a newer tag — compose owner's call (Fable); recorded in ASTRA-STATUS.md. |
| (ClamAV image) `CVE-2026-58055` | nghttp2-libs 1.69.0-r0 → fixed **1.70.0-r0** | Alpine secdb lists the fix. MEDIUM, HTTP/1.1 upgrade smuggling in a library ClamAV links for freshclam (client side). | **Fix available** — same action as above. |

Severity note: trivy and grype disagree on the Alpine packages because trivy consults the distribution's
security database (which encodes "fixed/not affected" per package version) while grype also reports plain
NVD CPE matches. Both are kept: the Alpine secdb is the authority on *fixed*, NVD is the authority on
*exists*.

### 2.2 ClamAV image `clamav/clamav:1.4` (`sha256:57deb108…6f23`)

trivy: **2** (1 HIGH, 1 MEDIUM, both with fixed versions — see table). grype: **6** matches (the same 2 plus
the zlib/busybox NVD matches as above). Files: `clamav-1.4.image.{trivy,grype}.{txt,json}`.

### 2.3 Guest OS

The guest OS scan is run against the **baked disk** (`trivy vm` on the streamOptimized VMDK, or `trivy
rootfs` inside the running appliance) and against the pinned cloud-image manifest. Result file:
`guest-baked.trivy.txt` — **see ASTRA-STATUS.md Track D for whether this was executed for this build**
(it depends on the OVA build finishing in the qualification environment). Ubuntu findings are triaged with
USNs (`ubuntu-security-status`, `pro fix`-style data) — the cloud image is Canonical's release of the day, so
anything open on the scan date is open on the whole 24.04 LTS stream until the next USN.

## 3. Coverage limitations (what the scans do NOT prove)

* Databases are a snapshot of the scan date; re-run before every delivery.
* Go binaries are scanned by **module** version; a vulnerable function may be unreachable (as with
  `GO-2026-5932`), and conversely a vulnerable *vendored copy* of code is invisible. `govulncheck` in the
  repo's own CI (Fast PR Gate) covers call-graph reachability for the application; it is not re-run here.
* `cpe-match` findings are name/version heuristics and can be false positives; secdb entries are
  authoritative for Alpine but lag NVD.
* ClamAV **signature** content is not an SBOM subject; it updates continuously via freshclam.
* No DAST / configuration scan is included; the appliance's host hardening is in the runbooks, not here.

## 4. Reproduce

```bash
IMG=ghcr.io/kidcarmi/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e
trivy image --format cyclonedx --output culvert-1.0.259.image.cdx.json "$IMG"
trivy image --format json --output culvert-1.0.259.image.trivy.json --scanners vuln "$IMG"
grype -o json "$IMG" > culvert-1.0.259.image.grype.json
syft -o cyclonedx-json=culvert-1.0.259.image.syft.cdx.json "$IMG"
# release SBOM + signature
curl -fsSLO https://github.com/KidCarmi/Culvert/releases/download/v1.0.259/culvert.sbom.cdx.json{,.sigstore.json}
. release_identity.env && cosign verify-blob --bundle culvert.sbom.cdx.json.sigstore.json --new-bundle-format \
  --certificate-oidc-issuer "$CULVERT_RELEASE_SIGSTORE_ISSUER" --certificate-identity-regexp "$CULVERT_RELEASE_SIGSTORE_SAN_REGEX" culvert.sbom.cdx.json
# guest disk
trivy vm --scanners vuln culvert-appliance-<ver>-disk1.vmdk          # or, inside the appliance: trivy rootfs /
```

## 5. Operational ownership and cadence

| What | Who | When |
|---|---|---|
| Re-scan the three images (app, clamav, guest) with fresh DBs; update this directory | Appliance engineering (Astra) at every OVA build; appliance operator monthly | Every build; monthly window (`os-maintenance-runbook.md` §4) |
| Triage new HIGH/CRITICAL with a fixed version | Application owner for the app image (new release through the catalog); compose owner for ClamAV tag; appliance engineering for the guest/engine layer | Within the emergency-patch process (`os-maintenance-runbook.md` §3) |
| Guest OS security updates | unattended-upgrades on the appliance (automatic) | daily |
| Docker engine / containerd advisories | appliance operator, apt in a window | on advisory |
| Verify release SBOM signatures before trusting them | whoever consumes the SBOM | every release |
