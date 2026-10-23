# On-prem appliance pilot — requirements matrix

Status legend: **Confirmed** = verified against the repository or executed
here; **Provisional** = the pilot proceeds on this assumption until the
customer answers; **Question** = needs the customer's answer (see
`customer-questionnaire.md`); **Blocker** = not deliverable until resolved.

This matrix declares ONE bounded, testable pilot configuration. Anything not
listed as Confirmed is not qualified. HA, mixed-version clusters, offline
(air-gapped) operation, private registry mirrors and directory/SSO
integrations are NOT part of the pilot unless a row says so.

**Current gate decision: MERGE / LIMITED PILOT / PRODUCTION RELEASE are all
NO-GO.** The canonical candidate is `4524311b` / OVA `27006cf4…`. What blocks
each gate is in `readiness-report.md` §0. This matrix declares the pilot's
*scope*; it does not say the pilot is ready.

## 1. Declared pilot configuration

| Area | Pilot value | Status | Evidence / note |
|---|---|---|---|
| Form factor | Single-node virtual appliance (OVA), one proxy + admin UI, no cluster | Confirmed (design) | `appliance/`, `docs/appliance/first-boot.md`; HA / CP+DP topologies are OUT of the pilot |
| Hypervisor | VMware ESXi (OVA import, VMX-13). Qualified on **ESXi 8.0.1 build 21813344 only**, with the exact candidate OVA `27006cf4…` (2 vCPU / 4 GiB / 40 GiB, E1000). ESXi 7.0, other 8.x builds, vCenter-managed import, VirtualBox and KVM are unqualified | Confirmed (ESXi 8.0.1, exact candidate only) | `vsphere-qualification.md`; ASTRA review 5592731454 (E1). Supersedes the earlier "OVA boot BLOCKED" status |
| Architecture | x86_64 only | Confirmed | arm64 images exist for the container, the OVA is x86_64 only |
| Guest OS | See `docs/appliance/ova-build.md` (minimal cloud image, pinned by SHA512, support horizon recorded there) | Confirmed (design) | Astra track |
| vCPU / RAM / disk | 2 vCPU, 4 GB RAM, 40 GB thin disk minimum; 4 vCPU / 8 GB recommended with ClamAV | Provisional | ClamAV keeps ~600 MB of signatures resident; installer warns below 1.5 GB (`scripts/install.sh`) |
| Expected workload | ≤ 250 concurrent users, ≤ 500 req/s sustained, SSL inspection on a subset of destinations | Question | capacity is a customer question; not benchmarked for this pilot |
| Networking | One NIC. Management (admin UI :9090/TCP) and proxy (:8080/TCP) on the same interface; DHCP by default, static IPv4 configurable from the console | Confirmed (design) | `appliance/provision/`; a second management-only NIC is OUT |
| DNS | Appliance resolves client destinations with the customer's resolver (DHCP or static); DNS failures degrade geo rules only (CHAOS-64) | Confirmed | `dns_health.go` |
| NTP | Required: catalog signature freshness, Sigstore verification and TOTP all depend on a sane clock | Confirmed | `docs/operator/catalog-bootstrap-install-runbook.md` |
| Management TLS | Self-signed per boot by default (fingerprint changes on every restart); customer cert via `-tls-cert/-tls-key` or the admin upload; CA for SSL inspection is per-install, generated at first boot | Confirmed | `ui_tls_custom.go`, `internal/uitls`; replacement documented in `first-boot.md` |
| Internet egress needed | **First boot:** none if the OVA pre-bakes images; otherwise ghcr.io (proxy image), registry-1.docker.io (ClamAV), download.docker.com (Docker CE). **Runtime:** ClamAV signatures (database.clamav.net), threat feeds (abuse.ch, openphish), category feed, catalog.culvertlabs.com (release catalog), ghcr.io (updates), Sigstore (fulcio/rekor/tuf) for installer verification | Confirmed | `scripts/install.sh`, `docker-compose.yml`, `release_wiring.go` |
| Restricted egress / mirrors | Private registry mirror via `CULVERT_RELEASE_PROXY_REPO` + `CULVERT_PROXY_SEED_REF` is supported by code but **NOT qualified** in this pilot; air-gapped is OUT | Provisional | GAP-APP-03; signature verification is identical for mirrors (trust never follows the URL) |
| Authentication (admin) | Local admin account created by the operator at first visit (setup wizard); TOTP second factor only via roster file (no in-band enrolment — recorded gap) | Confirmed | `ui_auth.go`; no shared/default admin password exists anywhere in the artifacts |
| Authentication (users/proxy) | **None.** The pilot is an unauthenticated proxy with policy by destination (`defaultAuthOutcome=Exempt`, `first-boot.md` step 8). First boot configures no identity provider. LDAP/AD, OIDC and SAML exist in the code but are **not in the pilot and not qualified on the appliance**: live provider tests are BLOCKED/OPEN (E1). Enabling any provider takes the deployment outside the declared pilot. **LDAP does not imply Kerberos SSO**; transparent SSO is OUT | Confirmed (scope) | `auth_ldap_provider.go` (ADR-0027); `readiness-report.md` §0 R8 |
| Artifact trust | The qualified OVA is an **unsigned candidate** built from a CI image (`-candidate.g<sha12>`, labelled CANDIDATE in the OVF and on the console): internal evaluation only, **never for customers**. No workflow signs or publishes an OVA today. A customer pilot needs the signed release path described in `readiness-report.md` §0 R9, or an explicit owner policy change after security review | Blocker (customer pilot) | `ova-build.md` §Candidate builds; E1 "Release signing/provenance: BLOCKED" |
| Policy posture at first boot | Appliance first boot sets `CULVERT_DEFAULT_ACTION=deny`: a fresh gateway refuses proxy traffic until a rule allows it. Quick-start compose installs keep the historical passthrough | Confirmed (new) | `rewrite_default_action_startup.go`; readiness rows `setup_complete`/`policy_posture` |
| Logging / SIEM | Local rotating process log + JSONL audit + request log on `/data`; syslog UDP/TCP forwarding configurable from the UI | Confirmed | `syslog.go`; SIEM target is a customer question |
| Diagnostics / support | Redacted, tamper-evident support bundles (`/api/support/*`, `culvert --support-bundle`), `/api/diagnose/*` | Confirmed | `internal/support` |
| Backup | `cli` service: encrypted tar.gz on the `culvert-backups` volume; scope + exclusions in `state-and-key-custody-matrix.md` | Confirmed | `docs/operator/docker-compose-backup-restore.md` |
| Restore | Offline in-place commit on the mounted volume (fixed in this PR), explicit interrupted-restore recovery | Confirmed (executed) | `test/e2e/appliance/lifecycle-qualify.sh` scenarios D/E |
| Recovery expectations | RPO = last backup; RTO = restore (minutes) + re-entry of excluded credentials; VM snapshot is NOT an application-consistent backup | Confirmed | `state-and-key-custody-matrix.md` |
| Upgrades | Signed release catalog → maintenance agent → image swap; supported transitions enforced by `min_upgrade_from` (floor `1.0.250`) | Confirmed (new) | `upgrade-transition-matrix.md` |
| Downgrade | Unsupported except the frozen schema-v2 predecessor path (`--prepare-downgrade`); dispatch refuses downgrades without break-glass | Confirmed | `upstream_downgrade.go`, `release_dispatch.go` |
| OS patching | unattended-upgrades (security pocket), operator-controlled reboot window, `culvert-os-update` | Confirmed (design) | `docs/appliance/os-maintenance.md` |
| Maintenance windows | Upgrade and OS reboot each cost one proxy restart (≤ 60 s graceful stop + boot); clients see connection resets during it | Confirmed | `docker-compose.yml` `stop_grace_period`, CHAOS-56 |
| HA | OUT of the pilot | Confirmed | ADR-0004/0005 exist but are not qualified here |

## 2. Confirmed facts about the current product (from source inspection)

- The admin API is unauthenticated with admin authority until first-time
  setup completes (`ui_middleware.go`). Appliance first boot closes that
  window with a per-instance setup token (`CULVERT_SETUP_TOKEN`, shown only
  on the VM console and by `culvert-status`): `POST /api/setup/complete` is
  refused with 403 without it. Verified on ESXi with the exact candidate
  (E1: unauthenticated setup 403, authorized 200). Quick-start compose
  installs that set no token keep the historical open window.
- `/ready` historically reported 200 for "services running", "setup not
  done" and "passthrough proxy" alike; this PR adds `setup_complete` and
  `policy_posture` rows (report-only; gating under `?strict=1`).
- Container writes cluster state (`cluster.json`, `cluster-ca.*`) into the
  container's working directory `/app`, NOT `/data`, when `-cluster-db` is
  not set (the default compose). For the single-node pilot this state is
  not needed; it is listed as a gap for any future CP/DP topology.
- The session-signing key is random per process unless
  `CULVERT_SESSION_SECRET` is set: every restart logs admins out.

## 3. Customer questions (summary — full list in `customer-questionnaire.md`)

Hypervisor version and template store; sizing/expected throughput; DHCP vs
static and the management VLAN; DNS/NTP servers; certificate authority for
the admin UI; egress policy (direct, via corporate proxy, or restricted —
which hosts can be allowed); SIEM target; backup destination (NFS/SMB mount
vs. copying the `culvert-backups` volume); maintenance windows; who owns OS
patching; whether ClamAV scanning and SSL inspection are in scope.

## 4. Blockers

The earlier blockers B1 (OVA boot needs a hypervisor), B2 (ClamAV needs
signature egress) and B3 (no setup token) are **resolved**. The exact
candidate booted, enforced and scanned on ESXi 8.0.1 (E1), and first boot
mints a setup token.

The current blockers are the exit criteria in `readiness-report.md` §0
(R1–R10, from ASTRA comment 6364575740). The ones that block the declared
pilot are:
- R1, the category-store writer-ownership defect in the frozen bytes;
- R4, a corrected replacement OVA that has not been built or qualified;
- R6/R7, the Compose CVE and sidecar/OS disposition;
- R9, the trusted distribution path.

R5 (live failed-unit display) and R2 (physical I/O and power loss) need either
closure or a specific owner residual decision.
