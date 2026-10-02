# Pilot requirements matrix and declared pilot configuration

Purpose: separate what is CONFIRMED (evidence in this repository or
executed here), what is PROVISIONAL (an assumption the pilot proceeds
on until the customer answers), what is a CUSTOMER QUESTION (see
`customer-questionnaire.md`), and what is a BLOCKER.

Evidence classes used below: `src` = source inspection with file:line,
`test` = an existing test asserts it, `exec` = executed in this work
(command and output recorded in `qualification-evidence.md`), `vm` = VM
qualification executed by the appliance track, `doc` = documented only.

The authoritative prerequisite tables live in
`docs/enterprise/ENTERPRISE-PREREQUISITES.md`; this matrix only records
the pilot's declared choices and the facts that changed in this work.
Gap identifiers (`GAP-*`) refer to
`docs/engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md`.

## 1. Declared pilot configuration (testable)

| Area | Pilot declaration | Class | Evidence / notes |
|---|---|---|---|
| Topology | ONE standalone node. No HA, no CP/DP cluster, no mixed-version cluster. | Provisional | HA/cluster are not qualified in this work; GAP-POL-02 / cluster findings are recorded, not fixed (see §4). |
| Hypervisor | VMware vSphere/ESXi 7.0U3+ as the delivery target (OVF 2.x). Qualified in this work only on what the appliance track could execute (see `hypervisor-qualification.md`). | Provisional | OVA import on ESXi itself is a customer-side or lab-side step; recorded as BLOCKED until executed on real vSphere. |
| Architecture | x86-64 only for the OVA. (The container image is also published for arm64, but no arm64 OVA is built.) | Confirmed | `Dockerfile` multi-arch; OVA build is amd64. |
| Guest OS | Ubuntu 24.04 LTS (standard support to 2029-04, ESM to 2034). Minimal cloud image, unattended security updates for the guest, Docker CE + Compose plugin from Docker's repository (the same source `scripts/install.sh` already uses). | Provisional | `scripts/install.sh:313-359` installs Docker CE from download.docker.com on the Debian family. See `os-maintenance-runbook.md`. |
| vCPU / RAM / disk | 2 vCPU, 4 GB RAM, 40 GB thin disk for the pilot VM. Application minimum is 2 vCPU / 1.5 GB (ClamAV resident signatures ~600 MB) / 2.5 GB; the rest is guest OS, Docker images (~3 GB headroom), logs and backups. | Provisional | `docs/enterprise/ENTERPRISE-PREREQUISITES.md` §1-2 (engineering estimates, not benchmarks). |
| Workload assumption | ≤ 500 proxy users, ≤ 1 Gbps aggregate, explicit-proxy (PAC or browser setting) on port 8080; no transparent interception. | Provisional | Sizing boundary from `docs/enterprise/ENTERPRISE-DEPLOYMENT-GUIDE.md:42`. |
| Networking | One management+proxy interface (the product has no bind-interface option, GAP-NET-04). Static IPv4 address, gateway, DNS and NTP set at the guest level by the appliance's first-boot provisioning (console or seed file), never by the application (GAP-APP-02). | Confirmed (gap) + Provisional (mechanism) | `docs/enterprise/ENTERPRISE-PREREQUISITES.md` §3-5. |
| Management access | Admin UI on 9090/tcp (HTTPS). Must be reachable ONLY from the customer's admin network during setup; `-ui-allow-ip` is set after setup. | Provisional | GAP-APP-04 (trust-on-first-use). This work closes the API-wide pre-setup admin window; the wizard race itself remains a placement concern. |
| TLS/PKI | Admin UI: auto self-signed at first boot, to be replaced by a customer-issued certificate via `POST /api/certs/upload target=ui` (persisted). Inspection CA: auto-generated ECDSA P-256 under `CULVERT_CA_PASSPHRASE`; bring-your-own CA is NOT in the pilot (GAP-PKI-01/02/03). | Confirmed | `ui_tls_custom.go`, `rootca_startup.go`. |
| Internet access | NOT air-gapped. Required egress for the pilot: GHCR (image pull for updates), `catalog.culvertlabs.com` (signed release catalog), Ubuntu + Docker apt repositories (guest patching), `urlhaus.abuse.ch` / `openphish.com` only if threat feeds are enabled. First boot of the OVA needs NO internet: the application image and deploy bundle are preloaded in the OVA. | Provisional | GAP-APP-03 / GAP-UPD-01 are not closed; restricted egress is supported only to the extent documented in `install-runbook.md`. |
| Private mirrors | Not qualified. A private registry/catalog mirror is unsupported in the pilot (GAP-NET-02/03). | Confirmed | Recorded, not implemented. |
| Authentication | Admin accounts: local bcrypt (+ optional TOTP). Proxy users: LDAP(S) against the customer's directory (profile via the IdP registry), OR no proxy authentication. Kerberos/transparent SSO is NOT provided by LDAP support and is out of scope. | Confirmed | `auth_ldap_provider.go` (ADR-0027); no Kerberos/SPNEGO in the tree. |
| Logging / diagnostics | Audit JSONL + request JSONL on `/data` (shipped compose flags), optional syslog forwarding, redacted support bundle (`culvert --support-bundle`). | Confirmed | `docker-compose.yml:149-166`, `docs/operator/support-bundles-and-diagnostics.md`. |
| Support access | Operator console (hypervisor console) + SSH for the customer's own administrators; no vendor remote access channel. | Provisional | No remote-command channel exists or is added. |
| Backup | `docker compose --profile cli run --rm cli -backup ...` with `--encrypt`, written to the `culvert-backups` volume and copied off-host by the customer's backup job. Restore is offline (`down` → `cli --restore --confirm` → `up`). | Confirmed (mechanism) | Restore on the real volume topology did not work before this PR; see `recovery-runbook.md`. |
| Maintenance windows | Application image updates and guest OS kernel updates each need a short service interruption (seconds to ~2 minutes); reboots are operator-scheduled (no automatic reboot). | Provisional | `os-maintenance-runbook.md`. |
| Scanning features in the pilot | ClamAV (shipped compose sidecar) ON. YARA/DPI only if the customer supplies rules. CDR (Sluice) OFF. MCP gateway OFF. | Provisional | Only ClamAV is exercised in qualification; nothing is claimed for features not exercised. |

## 2. Confirmed facts that drive the pilot (from this work)

| Fact | Class | Evidence |
|---|---|---|
| Restore commit could not work on the shipped volume topology (sibling staging dir on `/` not creatable by the container user; mount point not renameable). | exec | `restore.go:983-1031` (pre-fix); `restore_mountpoint_test.go` was a defect-proof test required to pass in CI; executed `mount --bind` + rename → EBUSY. Fixed in this PR. |
| `min_upgrade_from` was parsed but never enforced and never populated by CI; the dispatcher identified the running version by image digest against a single-release catalog. | src + exec | `release_dispatch.go:44-52,337-365`, `release_spec.go:168-184`; signed v1.0.259 manifest carries `""`. Fixed in this PR. |
| Agent interruption recording was not recovery; `reconcileDecision` had no production caller; rollback began with a registry pull even when the prior image was local. | src + test | `cmd/culvert-maint/main.go:148-170`, `reconcile_decision.go`, `rollback_stages.go:70-95`. Fixed in this PR (minimal, conservative). |
| Before setup completes, every admin API route answered anonymous callers with admin authority, and a fresh install proxied traffic allow-all. Any unrelated settings save latched the allow default durably. | exec | `ui_middleware.go:257-259`, `rewrite_default_action_startup.go:25-33`, `admin_settings.go:975,418-419`; executed against the real binary. Fixed in this PR. |
| In control-plane mode the shipped compose keeps the cluster CA and roster in the container layer (`-cluster-db` defaults to a relative path), outside the volume and the backup. | src | `cluster_startup_config.go:81`, `main.go:1458-1462`. Compose default corrected in this PR; not a pilot (single-node) risk. |
| The admin session key is regenerated at every restart unless `CULVERT_SESSION_SECRET` is set; the installer did not generate one. | exec | `session.go:41-77`; installer change in the appliance track. |
| Backups deliberately exclude node-local keys (`*.kek`, `.alert_webhook_key`, `.upstream_cred_key`) and strip upstream credentials; archived `admin_settings.json` carries other secrets in plaintext unless `--encrypt` is used. | src + test | `backup.go:198-201,357-360,386-395`; see `state-backup-key-custody.md`. |

## 3. Provisional assumptions the pilot proceeds on

1. The customer can place port 9090 behind a management ACL before first boot.
2. The customer's hypervisor is vSphere; if it is Hyper-V or Proxmox, the OVA is importable but unqualified.
3. The pilot runs explicit-proxy clients; no PAC/WPAD fail-open topology is relied on for enforcement.
4. The customer accepts a short interruption for application updates and a scheduled reboot for kernel updates.
5. The customer's directory is reachable over LDAPS and group membership is readable by a service account.

## 4. Blockers and unsupported items (recorded, not hidden)

| Item | Status | Where recorded |
|---|---|---|
| OVA import/boot on real vSphere | BLOCKED until executed on customer or lab vSphere | `hypervisor-qualification.md` |
| Air-gapped install/update, private mirrors | Unsupported in pilot | GAP-APP-03, GAP-UPD-01, GAP-NET-02/03 |
| Bring-your-own inspection CA (RSA, persisted import) | Unsupported in pilot | GAP-PKI-01/02/03 |
| HA / cluster / mixed-version upgrades | Unsupported in pilot | this file §1 |
| Transparent Kerberos SSO | Unsupported | this file §1 |
| In-band admin recovery without host access | Unsupported | GAP-IAM-01 |
| Cluster-mode DP identity files are CWD-relative (`dp_enrollment.json`, `dp-node.*`) and not in the volume | Finding, not fixed (cluster only) | `dp_enrollment.go:37,192` |
