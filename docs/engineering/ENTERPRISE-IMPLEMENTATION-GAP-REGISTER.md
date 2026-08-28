# Enterprise Implementation Gap Register

**Status:** Draft — produced by the overnight Enterprise Deployment audit (2026-07-11).
**Method:** Evidence-first. Every gap is anchored to a code path, test, config key, API route, or command that was read directly during the audit. Where a conclusion is inference rather than observed behaviour, it is labelled **(inference)**.
**Scope:** Zero-to-production deployment of Culvert as it exists in this repository today, for an on-prem enterprise customer with no source access, restricted egress, enterprise IdP, change control, and limited/prohibited SSH.

> This register is the primary output of the audit. The companion narrative guides
> (`docs/enterprise/*`) reference these gap IDs at the exact deployment step where each
> one blocks. Severities were assigned per the rubric below; every P0/P1 was
> independently re-reviewed (see **Verification** column).

## Severity rubric

| Severity | Definition |
|---|---|
| **P0** | Customer cannot deploy securely, recover safely, or avoid irreversible failure. |
| **P1** | Production deployment requires unacceptable manual risk or developer/host-shell intervention. |
| **P2** | Deployment is possible but operationally weak. |
| **P3** | Usability, automation, or documentation improvement. |

## Gap category legend

`Documentation` · `UX` · `API` · `Product capability` · `Security` · `Operational` · `Appliance lifecycle` · `Automation` · `Validation` · `Unsupported enterprise requirement`

## Summary index

| ID | Title | Category | Severity | Deployment type affected |
|---|---|---|---|---|
| GAP-APP-01 | No ISO / OVA / appliance image; delivery is Docker Compose on a customer host | Appliance lifecycle | P1 | Appliance |
| GAP-APP-02 | No customer-facing first-boot network/DNS/hostname/NTP/timezone configuration | Product capability / Appliance lifecycle | P2 | Appliance / no-SSH |
| GAP-APP-03 | Install requires outbound internet; no first-class air-gapped install path | Operational | P1 | Air-gapped / restricted |
| GAP-APP-04 | Setup wizard is trust-on-first-use — first network arrival claims admin | Security | P2 | All |
| GAP-IAM-01 | No in-band administrator recovery; break-glass requires host shell | Security / Operational | P1 | no-SSH / all |
| GAP-IAM-02 | No admin SSO / no IdP-group-driven admin RBAC (least privilege) | Product capability | P2 | All |
| GAP-IAM-03 | Administrator recovery / lockout procedure is undocumented | Documentation | P2 | All |
| GAP-IAM-04 | Persistent audit log is OFF by default (forensic loss on restart) | Operational / Security | P2 | All |
| GAP-PKI-01 | Imported (bring-your-own) inspection CA is not persisted — lost on restart | Product capability / Security | P1 | TLS inspection |
| GAP-PKI-02 | Inspection CA import is ECDSA-only; RSA internal PKIs are rejected | Product capability | P1 | TLS inspection |
| GAP-PKI-03 | CA auto-rotation overwrites an imported CA with an auto-generated one | Product capability / Security | P1 | TLS inspection |
| GAP-PKI-04 | No PKCS#12/DER import; private key must be exported as PEM | UX | P3 | TLS inspection |
| GAP-PKI-05 | No independent CA-expiry watchdog; documented startup alert not implemented | Documentation / Operational | P2 | TLS inspection |
| GAP-PKI-06 | Origin mTLS unsupported for inspected hosts | Product capability | P2 | TLS inspection |
| GAP-NET-01 | Default outbound to `catalog.culvertlabs.com` on a stock install | Operational | P2 | Restricted / air-gapped |
| GAP-NET-02 | Threat-feed source URLs are hard-coded; cannot point at an internal mirror | Product capability | P2 | Restricted / air-gapped |
| GAP-NET-03 | Internal release-catalog mirror on a private IP is rejected by the SSRF guard | Product capability | P2 | Air-gapped |
| GAP-NET-04 | Listeners bind `0.0.0.0` only; no bind-interface option | Operational | P3 | All |
| GAP-POL-01 | No monitor-only / shadow enforcement mode for a policy pilot | Product capability | P1 | All |
| GAP-POL-02 | No node-group/label-scoped policy for node-level staged rollout | Product capability | P2 | Cluster |
| GAP-POL-03 | Policy Tester cannot simulate a candidate (unsaved) ruleset | UX | P3 | All |
| GAP-POL-04 | Rollback/import is whole-config, not policy-scoped | Operational | P2 | All |
| GAP-BAK-01 | No GUI/API self-service backup or restore (host-CLI only) | Product capability / Operational | P1 | no-SSH / all |
| GAP-BAK-02 | No scheduled/automated backup; RPO is operator-owned | Automation | P2 | All |
| GAP-BAK-03 | Restore commit is destructive in place; no non-destructive functional restore test | Operational | P2 | All |
| GAP-BAK-04 | No documented post-restore verification or disk-loss DR runbook | Documentation | P2 | All |
| GAP-MON-01 | No support bundle / single diagnostic artifact | Operational / UX | P2 | no-SSH / all |
| GAP-MON-02 | Audit log has no GUI bulk export | UX | P3 | All |
| GAP-MON-03 | `/metrics` is unauthenticated by default; logging destination is flags-only (GUI-parity gap) | Security / UX | P3 | All |
| GAP-UPD-01 | No offline update bundle; air-gapped image update effectively unsupported | Product capability / Operational | P1 | Air-gapped |
| GAP-UPD-02 | No customer-triggered (non-failure) image or `/data` rollback via CP/GUI | Product capability / Operational | P1 | no-SSH / all |
| GAP-UPD-03 | Update trust-root management is env-only (no GUI/API) | Product capability | P2 | Change-controlled / all |
| GAP-UPD-04 | Maintenance-agent install is a one-time root/SSH operation; self-fencing socket drop without compose override | Operational | P2 | no-SSH / all |

---

## Detailed gaps

<!-- Each entry: blocked step, customer requirement, current behaviour, evidence, category,
severity, affected deployment type, security impact, operational impact, workaround,
workaround acceptability, recommended capability, suggested API, suggested UI, target
component, acceptance criteria, dependencies, estimated PR size, priority. -->

### GAP-APP-01 — No ISO / OVA / appliance image

- **Blocked deployment step:** Appliance installation (step 12) — importing a bootable VM image into vSphere/Hyper-V/KVM.
- **Customer requirement:** Deploy through an ISO, OVA, or supported appliance image.
- **Current behaviour:** Culvert ships as a Go binary and a Docker image (`culvert/proxy:pinned`). The only turnkey install is `scripts/install.sh`, which provisions Docker Engine + Compose on a customer-supplied Linux host and runs `docker compose up -d`. There is no ISO/OVA/packer/cloud-init/kickstart artifact anywhere in the repo. The word "appliance" in the tree refers to the Compose stack, not an image.
- **Evidence:** No `*.ova/*.ovf/packer/cloud-init/kickstart/preseed/autoinstall` files (exhaustive search, agent-confirmed). `scripts/install.sh:1-233` (Docker Compose installer). `docker-compose.yml:31-233`. `.github/workflows/appliance-catalog-update-e2e.yml` installs via `docker compose up -d`. No systemd unit ships for the proxy process (only `packaging/systemd/culvert-maint.service` for the Maintenance Agent).
- **Category:** Appliance lifecycle · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** Appliance / on-prem VM.
- **Security impact:** Neutral. A customer-baked golden VM has no signed provenance, unlike a vendor-signed OVA — mild supply-chain weakening if the customer improvises.
- **Operational impact:** High. The stated deployment model (ISO/OVA) is unavailable; the customer must own host provisioning, patching, and hardening of the underlying Linux OS. Docker Compose on a hardened host is a *valid* customer workflow, but it is not the requested appliance form factor and shifts OS lifecycle onto the customer.
- **Workaround:** Pre-bake a golden VM (install Docker + run `install.sh`, snapshot to an OVA/template) internally; or run the Compose stack on a managed VM.
- **Workaround acceptability:** Acceptable for customers comfortable operating Docker on their own hardened Linux; **not** acceptable for customers whose procurement/security model requires a vendor-signed appliance image.
- **Recommended product capability:** A reproducible appliance-image build (e.g. an OVA built by a `packer`/`mkosi` pipeline that bakes the pinned image + Compose + a first-boot console), signed and published alongside releases.
- **Suggested API surface:** none (build pipeline).
- **Suggested UI surface:** a first-boot console/wizard (see GAP-APP-02).
- **Target component:** new `packaging/appliance/` + CI release job.
- **Acceptance criteria:** A signed OVA that boots to a first-boot console, runs the pinned image offline, and passes the existing `/readyz` smoke; provenance attached to the GitHub release.
- **Dependencies:** GAP-APP-02, GAP-APP-03.
- **Estimated PR size:** XL (new pipeline).
- **Priority:** P1 (first enterprise customer if appliance form factor is contractually required; otherwise document Compose-on-VM as the supported path and downgrade).

### GAP-APP-02 — No customer-facing first-boot network / DNS / hostname / NTP / timezone configuration

- **Blocked deployment step:** First boot + management network configuration (steps 13–14).
- **Customer requirement:** Set management IP, subnet, gateway, DNS, hostname, NTP, and timezone from a supported customer interface (appliance console or setup GUI), without host SSH.
- **Current behaviour:** None of these are configurable through Culvert. The container inherits host/Docker networking and the host clock. The only in-product knobs are `CULVERT_PUBLIC_IP` (env — a TLS-SAN hint only) and `TZ` (env). There is no NTP client, no hostname setter, no L3 configuration surface. Culvert makes no NTP calls of its own.
- **Evidence:** Agent-confirmed negative search for gateway/subnet/netmask/static-ip/DNS/hostname/NTP config surfaces. `docker-compose.yml:88` (`TZ=UTC`), `:91` (`CULVERT_PUBLIC_IP`). `internal/uitls/uitls.go` (public-IP used only for cert SANs).
- **Category:** Product capability / Appliance lifecycle · **Severity:** P2 · **Verification:** independent review pending.
- **Affected deployment type:** Appliance / no-SSH.
- **Security impact:** Low directly; indirectly, time skew (no enforced NTP) can break SAML/OIDC assertion validity windows and TLS/cert checks.
- **Operational impact:** Medium-High for a no-SSH customer: bringing the box onto the network is a host-OS task (cloud-init/DHCP/host installer), i.e. exactly the SSH/console access the customer wants to avoid.
- **Workaround:** Configure the host OS out of band (cloud-init, DHCP reservations, host installer, `timedatectl`, `chrony`).
- **Workaround acceptability:** Standard and acceptable for a Docker-on-VM model; **not** acceptable if the customer expects to configure the network from an appliance console.
- **Recommended product capability:** Only meaningful alongside GAP-APP-01 — a first-boot console (text or web) that writes host network/DNS/hostname/NTP/TZ. For the Compose model, document clearly that L3/time is host-owned.
- **Suggested API surface:** `GET/POST /api/system/network`, `/api/system/time` (appliance builds only).
- **Suggested UI surface:** first-boot console.
- **Target component:** appliance image (GAP-APP-01).
- **Acceptance criteria:** On an appliance image, an admin sets a static IP + DNS + NTP from the console and the box joins the network with no shell.
- **Dependencies:** GAP-APP-01.
- **Estimated PR size:** L (appliance only).
- **Priority:** P2 (bundled with the appliance decision).

### GAP-APP-03 — Install requires outbound internet; no first-class air-gapped install path

- **Blocked deployment step:** Restricted-network / air-gapped deployment (steps 20–21).
- **Customer requirement:** Install from offline media into an air-gapped segment.
- **Current behaviour:** `install.sh` hard-fails its preflight if it cannot reach `download.docker.com`, and pulls the proxy image from `ghcr.io`. The documented air-gap fallback is a local `docker build` from a source checkout — which the target customer (no source access) does not have. There is no offline install bundle (pre-staged images + compose + agent) published as a supported artifact.
- **Evidence:** `scripts/install.sh:203-208` (internet preflight, `error` on failure), `:541` (`ghcr.io/kidcarmi/culvert`), `:755-808` (build-from-source fallback), `:646-668` (GHCR tag resolution). The `/app/deploy` bundle is inside the image, so it presupposes a successful image pull.
- **Category:** Operational · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** Air-gapped / restricted egress.
- **Security impact:** Positive intent (signed images) but the practical path pushes customers to improvise (manual `docker save`/`load`), which is unsigned and error-prone.
- **Operational impact:** High. A true air-gapped first boot requires the customer to pre-stage images into a private registry and set `CULVERT_PROXY_SEED_REF`/`CULVERT_PROXY_REPO` — significant registry engineering, not a turnkey path.
- **Workaround:** `docker pull` the pinned image + sidecars on a connected host, `docker save` → transfer → `docker load` into the air-gapped host or a private registry; provide the compose files manually; set `CULVERT_PROXY_SEED_REF`.
- **Workaround acceptability:** Acceptable only for customers with mature offline-registry tooling; not turnkey.
- **Recommended product capability:** A published, signed **offline install bundle** (tarball of pinned image + clamav image + compose files + agent packaging + checksums) and an `install.sh --offline <bundle>` path that never touches the internet.
- **Suggested API surface:** none.
- **Suggested UI surface:** none.
- **Target component:** `scripts/install.sh` + a CI packaging job.
- **Acceptance criteria:** On a host with no egress, `install.sh --offline culvert-offline-<ver>.tar.gz` brings the stack to `/readyz=200` with no outbound connections (verified by network namespace isolation in CI).
- **Dependencies:** none.
- **Estimated PR size:** L.
- **Priority:** P1 for any restricted/air-gapped customer.

### GAP-APP-04 — Setup wizard is trust-on-first-use

- **Blocked deployment step:** Initial administrator access (step 15).
- **Customer requirement:** The first admin account is claimed by an authorized operator via an out-of-band credential (console OTP, serial-bound token), not by whoever reaches the network first.
- **Current behaviour:** On first boot with no admin, `POST /api/setup/complete` (public, one-time) sets the admin username/password for whoever calls it first. There is no console-printed one-time token, no MAC/serial binding. Rate-limiting and a mutex guard the endpoint, but not first-arrival takeover.
- **Evidence:** `ui_auth.go:381-472` (`apiSetupComplete` consumes only `body.User`/`body.Pass`; no token issuance/verification), public allowlist `ui_auth.go:928-934`. `GET /api/setup/status` public (`ui_auth.go:371-379`).
- **Category:** Security · **Severity:** P2 · **Verification:** independent review pending.
- **Affected deployment type:** All (worse on shared/flat networks).
- **Security impact:** Medium. On a reachable network during the boot window, an attacker can claim the admin account before the legitimate operator.
- **Operational impact:** Low once claimed.
- **Workaround:** Firewall UI port 9090 until the operator completes setup from a trusted host; or complete setup before exposing the box.
- **Workaround acceptability:** Acceptable with disciplined network isolation; it is a procedural control, not an enforced one.
- **Recommended product capability:** A first-boot setup token — printed to the container/appliance console log and required by `apiSetupComplete` — so only an operator who can read the console can claim admin.
- **Suggested API surface:** `apiSetupComplete` accepts and verifies a `setup_token`; `GET /api/setup/status` reports `token_required:true`.
- **Suggested UI surface:** setup wizard prompts for the token.
- **Target component:** `ui_auth.go`, startup (print token).
- **Acceptance criteria:** With the feature on, `apiSetupComplete` rejects a request lacking the console-printed token; test covers the reject + accept paths.
- **Dependencies:** none.
- **Estimated PR size:** S-M.
- **Priority:** P2 (first enterprise customer).

### GAP-IAM-01 — No in-band administrator recovery; break-glass requires host shell

- **Blocked deployment step:** Break-glass recovery (step 24); administrator lockout recovery.
- **Customer requirement:** A supported way to recover administrator access when the sole admin loses their password, without SSH, file edits, or source access.
- **Current behaviour:** The only code-supported recovery is the one-shot CLI flag `--reset-password username:newpassword`, which runs the binary on the host (e.g. `docker exec`/`compose run`) and rewrites `ui_users.json`. There is no API, GUI, network, email, or console reset. There is no default/emergency credential. External IdPs never govern admin login (admin UI is local-bcrypt only), so there is no IdP-based admin recovery either. Brute-force lockout state is in-memory and cleared by a process restart.
- **Evidence:** `main.go:381-404` (`--reset-password`, read directly). `ui_auth.go:65,114,468` (admin login/setup use local bcrypt only). `internal/lockout/lockout.go:35` ("an operator restart is the documented break-glass for a stuck lock"). Exhaustive negative search for `break-glass|recover|reset-admin|default admin|emergency-admin` found only the CLI flag.
- **Category:** Security / Operational · **Severity:** P1 (P0 under a strict no-SSH mandate) · **Verification:** independent review pending.
- **Affected deployment type:** no-SSH; all.
- **Security impact:** Positive that there is no network reset surface to abuse; but availability risk is high — a lost sole-admin password is unrecoverable without host access.
- **Operational impact:** High. Under a strict no-SSH policy, recovery requires container replacement/redeploy.
- **Workaround:** (a) provision ≥2 admin accounts at go-live; (b) retain `docker exec`/`compose run` access for `--reset-password`; (c) keep an encrypted `/data` backup.
- **Workaround acceptability:** Acceptable only if the customer accepts container-exec as break-glass and enforces multi-admin by policy — neither is enforced or documented by the product.
- **Recommended product capability:** A supported low-privilege recovery channel that does not require SSH — e.g. a console-gated recovery mode (appliance), or a signed break-glass token generated at install and stored offline that re-enables a named recovery admin; plus enforce a minimum of two admin accounts before enabling default-deny.
- **Suggested API surface:** none network-exposed by default; an appliance-console recovery action.
- **Suggested UI surface:** setup/recovery console.
- **Target component:** `ui_auth.go`, appliance console, `main.go`.
- **Acceptance criteria:** A documented, tested recovery path that a no-SSH operator can execute; and a warning/guard when the deployment has a single admin.
- **Dependencies:** GAP-IAM-03 (docs), GAP-APP-01/02 (console) for the no-SSH variant.
- **Estimated PR size:** M (docs+guard) to L (console recovery).
- **Priority:** P1 — required before the first enterprise customer with a recovery SLA.

### GAP-IAM-02 — No admin SSO / no IdP-group-driven admin RBAC

- **Blocked deployment step:** Administrator roles / least privilege (steps 23, 26–27).
- **Customer requirement:** Admin RBAC driven by corporate IdP group membership; admin login via the enterprise IdP; privileged access lifecycle managed centrally.
- **Current behaviour:** The admin UI authenticates only local bcrypt accounts. IdP group membership feeds proxy **policy** (Stage-2 `authSource`/`SourceGroup`), never admin roles. Admin roles (admin/operator/viewer) are assigned manually via `/api/auth/users`.
- **Evidence:** `ui_auth.go:65,114,468`; IdP callbacks set the proxy cookie `ps_session`, not the admin cookie `ps_ui_session` (`session.go:119`, `ui_rbac.go:19-22`). Role CRUD `ui_auth.go:187-258`.
- **Category:** Product capability · **Severity:** P2 · **Verification:** independent review pending.
- **Affected deployment type:** All.
- **Security impact:** Orphaned admin accounts survive IdP deprovisioning; no central MFA/conditional-access on admin login (product-local TOTP only).
- **Operational impact:** Medium — a separate admin identity store to provision/deprovision/offboard.
- **Workaround:** Keep the admin roster small, enable TOTP, and tie account lifecycle to a manual process.
- **Workaround acceptability:** Acceptable for a handful of operators; not acceptable where policy mandates all privileged access flow through the IdP.
- **Recommended product capability:** OIDC/SAML login for the admin UI with a group→role mapping table; keep local accounts as break-glass.
- **Suggested API surface:** `/api/auth/admin-idp` mapping config; admin-side OIDC/SAML callback.
- **Suggested UI surface:** "Admin SSO" panel with group→role mapping.
- **Target component:** `ui_auth.go`, `auth_idp.go`, session layer.
- **Acceptance criteria:** An admin logs into the UI via the corporate IdP and receives a role derived from a mapped group; local break-glass still works.
- **Dependencies:** none.
- **Estimated PR size:** L.
- **Priority:** P2 (first enterprise customer with an IdP-mandate).

### GAP-IAM-03 — Administrator recovery / lockout procedure is undocumented

- **Blocked deployment step:** Operational handoff (step 50); break-glass (step 24).
- **Customer requirement:** A documented runbook for admin lockout / forgotten password.
- **Current behaviour:** `docs/operator/` has catalog/HA/backup runbooks but nothing for `--reset-password`, forgotten password, or lockout. Operators will not discover the CLI flag or the "restart clears lockout" behaviour under pressure.
- **Evidence:** `docs/operator/` listing (agent-confirmed); `--reset-password` only in `main.go:381-404`; lockout self-heal only in `internal/lockout/lockout.go`.
- **Category:** Documentation · **Severity:** P2.
- **Security/Operational impact:** Operational — slow recovery, ad-hoc improvisation under incident pressure.
- **Workaround:** This audit's `OPERATIONS-RUNBOOK.md` documents it.
- **Workaround acceptability:** Acceptable once the runbook ships.
- **Recommended change:** Add an "Administrator recovery" runbook to `docs/operator/`.
- **Acceptance criteria:** A runbook covering `--reset-password`, multi-admin guidance, and lockout self-heal, linked from the deployment guide.
- **Estimated PR size:** S (docs). **Priority:** P2. **This audit ships a first version (see OPERATIONS-RUNBOOK.md).**

### GAP-IAM-04 — Persistent audit log is OFF by default

- **Blocked deployment step:** Logging and auditing (step 37).
- **Customer requirement:** A durable admin-action audit trail that survives restarts, on by default.
- **Current behaviour:** Without `-audit-log`/`audit_log_file`, audit is a 500-entry in-memory ring lost on restart. The persistent JSONL path exists but is opt-in and not GUI-settable. The shipped `docker-compose.yml` **does** pass `-audit-log /data/audit.jsonl`, so the canonical Compose install is covered — but a hand-rolled deployment that omits it silently loses history.
- **Evidence:** `internal/audit/audit.go:75-107` (JSONL when path set), `:48` (ring 500); `docker-compose.yml:127` (`-audit-log /data/audit.jsonl`). Config is flags/YAML only (`config.go:87-89`); GUI shows read-only.
- **Category:** Operational / Security · **Severity:** P2.
- **Security impact:** Forensic history loss on restart for deployments that omit the flag.
- **Operational impact:** Medium.
- **Workaround:** Ensure `-audit-log` is set (the shipped compose does) and/or forward audit to syslog/SIEM (`store.go:184`).
- **Workaround acceptability:** Acceptable given the shipped compose sets it; risky for bespoke deployments because it is not enforced or GUI-visible.
- **Recommended change:** Default the audit path to `<dataDir>/audit.jsonl` when a data dir is configured; surface a diagnostics `warn` when audit is in-memory-only.
- **Acceptance criteria:** A default install persists audit without an explicit flag; diagnostics warns when it is not persisted.
- **Estimated PR size:** S. **Priority:** P2.

### GAP-PKI-01 — Imported inspection CA is not persisted (lost on restart)

- **Blocked deployment step:** TLS inspection enablement / CA import (steps 31–32).
- **Customer requirement:** An inspection CA imported from the internal PKI becomes the durable signing CA.
- **Current behaviour:** `POST /api/certs/upload` with `target=mitm` calls `LoadCustomCA`, which sets the in-memory CA only — it never calls `SaveCA`. On restart the proxy reverts to the on-disk `ca.bundle` (auto-generated or `-ca-path`). The code comment declares it a "forward-only trust mutation." This is not surfaced to the operator as a limitation.
- **Evidence:** `ui_security.go:284-292` (upload → `LoadCustomCA` + `auditEvent`, no `SaveCA`), `internal/ca/ca.go:458-484` (`LoadCustomCA` sets in-memory `caCert/caKey`). **(inference, high confidence — no persistence hook found; not empirically restart-tested.)**
- **Category:** Product capability / Security · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** TLS inspection.
- **Security impact:** Silent trust regression — after any restart, inspection uses a different CA than endpoints trust; users see TLS errors or (if bypassed) unscanned traffic.
- **Operational impact:** High — the import must be repeated after every restart/redeploy.
- **Workaround:** Pre-stage the EC cert+key as a plain-PEM bundle at `-ca-path` on disk (`LoadCA`/`ImportBundle`) via host access — contradicts the GUI/limited-SSH model and is EC-only.
- **Workaround acceptability:** Poor for the target customer.
- **Recommended product capability:** Persist an uploaded MITM CA to `ca.bundle` (re-encrypting under `CULVERT_CA_PASSPHRASE`) on `target=mitm` upload; or reject the upload with a clear error if persistence is intentionally disabled.
- **Suggested API surface:** `apiCertsUpload` calls `SaveCA` after `LoadCustomCA`.
- **Suggested UI surface:** confirmation that the imported CA is now durable.
- **Target component:** `ui_security.go`, `internal/ca`.
- **Acceptance criteria:** After importing a custom CA and restarting, the proxy still signs leaves with the imported CA; a test covers the round-trip.
- **Dependencies:** GAP-PKI-02 (RSA), GAP-PKI-03 (rotation) interact.
- **Estimated PR size:** M.
- **Priority:** P1 — required before any TLS-inspection customer using their own PKI.

### GAP-PKI-02 — Inspection CA import is ECDSA-only

- **Blocked deployment step:** CA import (step 32).
- **Customer requirement:** Import an RSA-keyed intermediate from an internal PKI (common with Microsoft ADCS).
- **Current behaviour:** `LoadCustomCA` rejects non-ECDSA keys: "only ECDSA private keys are supported for MITM CA."
- **Evidence:** `internal/ca/ca.go:470-473`; test `security_audit_test.go:345` (`TestCertManager_LoadCustomCA_RejectsRSA`).
- **Category:** Product capability · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** TLS inspection with an RSA internal PKI.
- **Security impact:** Neutral (P-256 is fine cryptographically); the impact is availability of the feature.
- **Operational impact:** High for RSA-PKI shops — they cannot bring their own CA at all.
- **Workaround:** Mint a dedicated ECDSA P-256 sub-CA from the internal root.
- **Workaround acceptability:** Acceptable only if the PKI can issue EC intermediates; many enterprise PKIs are RSA-only by policy.
- **Recommended product capability:** Support RSA (2048/3072/4096) signing CAs for MITM leaf issuance, or clearly document the EC-sub-CA requirement in the TLS deployment guide.
- **Suggested API surface:** `LoadCustomCA` accepts RSA keys; leaf signing selects the algorithm from the CA key.
- **Target component:** `internal/ca`.
- **Acceptance criteria:** An RSA intermediate can be imported and used to sign leaves; test covers RSA import + leaf verify.
- **Dependencies:** GAP-PKI-01.
- **Estimated PR size:** M.
- **Priority:** P1 (or P2 if documented as an EC-sub-CA requirement).

### GAP-PKI-03 — CA auto-rotation overwrites an imported CA

- **Blocked deployment step:** Certificate rotation (step 31 ongoing).
- **Customer requirement:** Rotation preserves the internal-PKI trust chain (re-issue from the customer PKI, or don't auto-rotate an imported CA).
- **Current behaviour:** Auto-rotation (24h check, rotate ≤30 days before expiry) and manual rotate both call `InitCA`, which generates a fresh `Culvert Root CA`. For an imported CA, rotation silently replaces it with an auto-generated CA. No opt-out flag was found.
- **Evidence:** `internal/ca/ca.go:507-552` (`RotateIfNeeded`→`InitCA`), `:145-186` (`InitCA` generates a new CA), `:59-79` (24h loop). **(inference for the imported-CA interaction; mechanics verified.)**
- **Category:** Product capability / Security · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** TLS inspection with a bring-your-own CA.
- **Security impact:** Silent trust replacement — endpoints trust the original (now-secondary, expiring) CA, not the new auto-generated one.
- **Operational impact:** High if it fires unnoticed.
- **Workaround:** Import a CA with a long validity and monitor expiry externally; there is no flag to disable auto-rotation.
- **Workaround acceptability:** Poor.
- **Recommended product capability:** Disable auto-rotation for imported CAs (or add an explicit `-ca-auto-rotate=false`), and alert instead of silently regenerating.
- **Target component:** `internal/ca`, `rootca_startup.go`.
- **Acceptance criteria:** An imported CA is never auto-replaced; rotation of an imported CA is either operator-driven or blocked with an alert.
- **Dependencies:** GAP-PKI-01.
- **Estimated PR size:** M.
- **Priority:** P1.

### GAP-PKI-04 — No PKCS#12/DER import

- **Blocked step:** CA import (step 32) / accepted certificate formats (step 11).
- **Current behaviour:** Import is PEM-only (`tls.X509KeyPair`); the private key must be supplied unencrypted in PEM.
- **Evidence:** `internal/ca/ca.go:459`; GUI expects pasted PEM (`static/index.html:1806-1807`).
- **Category:** UX · **Severity:** P3.
- **Impact:** Friction for PKIs that export `.pfx`/`.p12`.
- **Workaround:** `openssl pkcs12 -nodes` off-box. **Acceptable.**
- **Recommended change:** Accept PKCS#12 upload with a passphrase field.
- **Estimated PR size:** M. **Priority:** P3.

### GAP-PKI-05 — No independent CA-expiry watchdog

- **Blocked step:** Certificate expiry monitoring (step 31).
- **Current behaviour:** The `cert_expiry` alert fires only when rotation occurs (`ca.go:45`). The documented "fired on startup if ≤30 days" behaviour (`internal/alerts/store.go:17`) is not implemented. If the CA is in-memory only or the rotation loop is disabled, there is no independent expiry warning.
- **Evidence:** `internal/ca/ca.go:45-53`; `internal/alerts/store.go:17` (doc claim with no backing code — doc/impl drift).
- **Category:** Documentation / Operational · **Severity:** P2.
- **Impact:** Low-Medium — a silent expiry in a non-`-ca-path` posture.
- **Workaround:** Poll `GET /api/ca/status` `expiresIn` externally.
- **Workaround acceptability:** Acceptable with external monitoring.
- **Recommended change:** Implement the startup + periodic ≤30-day expiry check that fires `cert_expiry` independently of rotation; fix the doc.
- **Acceptance criteria:** A CA ≤30 days from expiry fires `cert_expiry` at startup regardless of rotation; test covers it.
- **Estimated PR size:** S. **Priority:** P2.

### GAP-PKI-06 — Origin mTLS unsupported for inspected hosts

- **Blocked step:** TLS inspection of mTLS-protected internal services (step 33 edge case).
- **Current behaviour:** For inspected tunnels Culvert dials the origin with no client certificate; an origin requiring mutual TLS returns `502`.
- **Evidence:** `proxy_tunnel.go:577-584`.
- **Category:** Product capability · **Severity:** P2.
- **Workaround:** SSL-bypass those hosts (opaque relay preserves the client's own mTLS). **Acceptable if inspecting them is not required.**
- **Recommended change:** Per-rule origin client-cert configuration for inspected mTLS destinations.
- **Estimated PR size:** M. **Priority:** P2.

### GAP-NET-01 — Default outbound to `catalog.culvertlabs.com`

- **Blocked step:** Restricted-network deployment (step 20); firewall rules (step 6).
- **Customer requirement:** No unsolicited egress from a stock install; all destinations reviewable/overridable.
- **Current behaviour:** In enforce mode with the baked default origin, the Control Plane fetches the signed release catalog at startup and on a ~6h loop to `https://catalog.culvertlabs.com/release-catalog`. It is disable-able (`CULVERT_RELEASE_CATALOG_URL=off|none|disabled`, trust-safe opt-out) but that is env-only.
- **Evidence:** `release_wiring.go:136,209` (default origin + loop); `docker-compose.yml:108-112` (env). CLAUDE.md release-catalog section.
- **Category:** Operational · **Severity:** P2 · **Verification:** independent review pending.
- **Security impact:** Low — signed, verified fetch; but unexpected egress can trip egress-monitoring and violate "no unapproved outbound" change control.
- **Operational impact:** Medium — must be consciously disabled/allowlisted before go-live.
- **Workaround:** Set `CULVERT_RELEASE_CATALOG_URL=off` (documented), or allowlist the host in the firewall.
- **Workaround acceptability:** Acceptable; clean kill-switch, but env-only (no GUI) — see GAP-UPD (update source not GUI-configurable).
- **Recommended change:** Document the egress in the prerequisites/firewall section (this audit does); consider a GUI toggle for catalog origin/enable.
- **Acceptance criteria:** Prerequisites doc lists the destination + kill-switch; optional GUI toggle.
- **Estimated PR size:** S (docs) / M (GUI). **Priority:** P2.

### GAP-NET-02 — Threat-feed source URLs are hard-coded

- **Blocked step:** Threat-feed configuration (step 34) in a restricted/air-gapped network.
- **Customer requirement:** Point threat feeds at an internal mirror.
- **Current behaviour:** URLhaus (`https://urlhaus.abuse.ch/downloads/text/`) and OpenPhish (`https://openphish.com/feed.txt`) are compile-time constants with no override. Enabling the security scanner or setting a threat-feed DB turns on this egress.
- **Evidence:** `internal/threatfeed/threatfeed.go:103-104`; enable gate `scanning_startup.go:38`.
- **Category:** Product capability · **Severity:** P2 · **Verification:** independent review pending.
- **Security/Operational impact:** A restricted customer cannot use threat feeds with an internal mirror; enabling scanning forces public egress.
- **Workaround:** Leave threat feeds disabled.
- **Workaround acceptability:** Partial — the feature is opt-in, but there is no way to use it with an internal mirror.
- **Recommended product capability:** Make feed URLs configurable (flag/YAML/GUI) so they can point at an internal mirror.
- **Suggested API surface:** `/api/threat-feed/sources` config.
- **Target component:** `internal/threatfeed`, `threatfeed.go`.
- **Acceptance criteria:** An operator sets custom feed URLs (internal mirror) and feeds sync from them; SSRF guard still applies appropriately.
- **Estimated PR size:** M. **Priority:** P2.

### GAP-NET-03 — Internal catalog mirror on a private IP rejected by SSRF guard

- **Blocked step:** Update source configuration for air-gapped mirror (step 19).
- **Current behaviour:** `CULVERT_RELEASE_CATALOG_URL` pointing at an RFC1918 mirror is rejected by the SSRF guard (`isPrivateHost` resolves then checks). An internal mirror must resolve to a non-private IP or the fetch must be disabled.
- **Evidence:** CLAUDE.md ("SSRF guard still rejects private-IP origins (recorded constraint for internal mirrors)"); inline guard in `release_wiring.go`. **(design-level; not line-verified in the auto-seed path.)**
- **Category:** Product capability · **Severity:** P2.
- **Impact:** Air-gapped customers cannot host the catalog mirror on a private address.
- **Workaround:** Host the mirror on a non-private-resolved name, or set the origin to `off` and manage the on-disk catalog directly.
- **Workaround acceptability:** Marginal — conflicts with typical internal addressing.
- **Recommended change:** An allowlist/opt-in to permit a configured internal-mirror host to bypass the private-IP rejection (with a logged, explicit trust decision).
- **Acceptance criteria:** An operator can designate a trusted internal mirror on a private IP; SSRF protection remains for all other origins.
- **Estimated PR size:** M. **Priority:** P2 (air-gapped only).

### GAP-NET-04 — Listeners bind `0.0.0.0` only

- **Blocked step:** Network design / management-plane isolation (steps 5, 14).
- **Current behaviour:** All listeners bind `:<port>` (all interfaces). No bind-address/interface flag.
- **Evidence:** `main.go:878`, `ui.go:97`, `socks5.go:51` (`fmt.Sprintf(":%d")`).
- **Category:** Operational · **Severity:** P3.
- **Impact:** Cannot bind the admin UI to a management VLAN in-product.
- **Workaround:** `-ui-allow-ip` CIDR allowlist + host firewall + Docker port publishing to a specific host IP.
- **Workaround acceptability:** Acceptable with compensating controls.
- **Recommended change:** Add optional bind-address flags.
- **Estimated PR size:** S. **Priority:** P3.

### GAP-POL-01 — No monitor-only / shadow enforcement mode

- **Blocked step:** Policy rollout / pilot (steps 28, 47).
- **Customer requirement:** Run a candidate policy in observe-only during a pilot, logging what *would* be blocked without blocking.
- **Current behaviour:** The per-rule `LogTraffic` flag gates only whether an *allowed* request produces a feed entry; blocking actions (`Drop`/`Block_Page`) always block. The global default-action `allow` opens only *unmatched* traffic. There is no way to run a policy set in observe-only.
- **Evidence:** `policy.go:107,157-159` (`LogTraffic`), `proxy.go:505-508` (action unchanged), `ui_policy.go:1355-1383` (`apiDefaultAction` allow|deny only).
- **Category:** Product capability · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** All (staged enforcement).
- **Security impact:** Encourages risky "flip to enforce and hope" rollouts, or long passthrough windows.
- **Operational impact:** High — no safe observation window before enforcing a new deny policy.
- **Workaround:** Author intended deny rules as `Allow`+`LogTraffic=true`, observe the feed, then flip actions.
- **Workaround acceptability:** Marginal — laborious, error-prone (edit every rule twice), and does not cleanly capture "would this deny have fired."
- **Recommended product capability:** A per-rule or per-policy "monitor" action that evaluates and logs the would-be decision but allows the request; surface would-block counts.
- **Suggested API surface:** rule `Action: Monitor` or a policy-level `enforcement_mode: monitor|enforce`.
- **Suggested UI surface:** a policy "Monitor mode" toggle + would-block dashboard.
- **Target component:** `policy.go`, `proxy.go`, metrics.
- **Acceptance criteria:** In monitor mode, a would-block request is allowed and logged with `would_block=true`; a metric counts would-blocks; test covers it.
- **Dependencies:** none.
- **Estimated PR size:** M-L.
- **Priority:** P1 — a top request for safe enterprise rollout.

### GAP-POL-02 — No node-group/label-scoped policy for staged rollout

- **Blocked step:** Staged rollout across nodes (step 30, 47).
- **Current behaviour:** Policy rules carry no node dimension; the Control Plane pushes the same ruleset to all Data Plane nodes. Node-group labels drive bandwidth/QoS only. Pilot scoping is only possible *within* rules via source IP/CIDR/identity/group.
- **Evidence:** `policy.go:91-143` (no node field); `internal/bandwidth/bandwidth.go` (labels → bandwidth only); CLAUDE.md ConfigSnapshot sync (identical to all DPs).
- **Category:** Product capability · **Severity:** P2 · **Verification:** independent review pending.
- **Impact:** No node-level canary; pilots must be expressed as user/IP populations.
- **Workaround:** Scope the pilot by `SourceIP`/CIDR/`SourceGroup`/`SourceIdentity`.
- **Workaround acceptability:** Acceptable when the pilot population is identifiable by IP range or IdP group; not acceptable when the pilot must be a subset of proxy *nodes*.
- **Recommended product capability:** Optional node-group selector on policy rules (or per-group policy sets) so a ruleset applies to a pilot node subset first.
- **Target component:** `policy.go`, `nodegroup.go`, ConfigSnapshot.
- **Acceptance criteria:** A rule/ruleset scoped to a node group applies only to those nodes; test covers CP→DP targeting.
- **Estimated PR size:** L. **Priority:** P2.

### GAP-POL-03 — Policy Tester cannot simulate a candidate ruleset

- **Blocked step:** Policy validation before apply (step 46).
- **Current behaviour:** `POST /api/policy/test` evaluates the live store only. Config-version dry-run gives a field diff, not per-request simulation of a draft.
- **Evidence:** `ui_policy.go:1286-1351` (live store); `configversion.go:143-188` (dry-run diff).
- **Category:** UX · **Severity:** P3.
- **Impact:** Medium — cannot preview a proposed policy per-request before applying.
- **Workaround:** Validate on a test appliance, then export→import to prod. **Acceptable given a test environment.**
- **Recommended change:** Accept a candidate ruleset in the tester payload and evaluate against it.
- **Estimated PR size:** M. **Priority:** P3.

### GAP-POL-04 — Rollback/import is whole-config, not policy-scoped

- **Blocked step:** Policy rollback / promotion (steps 45–46).
- **Current behaviour:** Config-version rollback restores the entire config surface atomically; a policy rollback also reverts unrelated changes. Replace-mode import won't wipe on an empty list. Some fields (AlertWebhooks, BlockPageHTML, UpstreamProxies, ConnLimit) are intentionally off the rollback surface.
- **Evidence:** `configversion.go:274-405`; `ui_config.go:665` (non-empty guard); CLAUDE.md config-surface registry.
- **Category:** Operational · **Severity:** P2.
- **Impact:** Rolling back a bad policy reverts unrelated config since that version.
- **Workaround:** Promote/roll policy in isolation via `GET /api/config/export?section=policy` + `POST /api/config/import?mode=replace`.
- **Workaround acceptability:** Acceptable for forward promotion; rollback isolation still unavailable.
- **Recommended change:** A policy-scoped rollback (restore only the policy section from a version).
- **Estimated PR size:** M. **Priority:** P2.

### GAP-BAK-01 — No GUI/API self-service backup or restore

- **Blocked step:** Backup configuration + restore validation (steps 41–42).
- **Customer requirement:** Take a backup and restore from a supported interface without host SSH (the repo's own GUI-parity rule).
- **Current behaviour:** Full `/data` backup/restore exists only as a host CLI via `docker compose --profile cli run`. There are zero backup/restore routes in the admin API/UI; the UI redirects operators to the CLI. The maintenance agent has `/v1/backups`, `/v1/restores/*` but only on a local Unix socket (SO_PEERCRED), not network/GUI-exposed.
- **Evidence:** `ui_routes_meta.go` (no backup routes); `static/index.html:1937` (redirect to CLI); `cmd/culvert-maint/.../server.go:280-284` (agent routes), `config.go:150` (unix socket), `auth/peer_linux.go` (SO_PEERCRED); `docker-compose.yml:214-226` (`cli` service).
- **Category:** Product capability / Operational · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** no-SSH; all.
- **Security impact:** Neutral; the CLI path keeps backups off the proxy container (by design).
- **Operational impact:** High — a no-SSH admin cannot back up or recover; violates the deployment constraint and the repo's GUI-parity convention.
- **Workaround:** Grant an operator host/`docker exec` access, or a docker-socket bastion, to run the `cli` service.
- **Workaround acceptability:** Not acceptable for a strict no-SSH/change-controlled shop.
- **Recommended product capability:** An admin-gated GUI/API backup+restore that drives the maintenance agent over its socket (agent already implements the primitives) — backup runtime-OK, restore commit still offline-gated with clear warnings.
- **Suggested API surface:** `POST /api/backup`, `GET /api/backups`, `POST /api/restore/dryrun`, `POST /api/restore/commit` (admin), proxied to the agent socket.
- **Suggested UI surface:** "Backup & Restore" panel.
- **Target component:** new admin handlers + agent client; `cmd/culvert-maint` already exposes the primitives.
- **Acceptance criteria:** An admin takes an encrypted backup and runs a restore dry-run from the GUI with no host shell; commit still requires the offline gate.
- **Dependencies:** maintenance-agent socket wiring (exists).
- **Estimated PR size:** L.
- **Priority:** P1 — required for a no-SSH customer.

### GAP-BAK-02 — No scheduled/automated backup

- **Blocked step:** Backup configuration (step 41).
- **Current behaviour:** Backup is 100% manual; scheduling and remote storage are explicit non-goals. No cron/timer code references backup.
- **Evidence:** `roadmap/D1.3a-backup-design.md:134`; `roadmap/D1.5-...:296`; negative search for schedule/cron/periodic in backup code.
- **Category:** Automation · **Severity:** P2.
- **Impact:** RPO depends entirely on operator-built cron + off-host copy.
- **Workaround:** External cron invoking the `cli` container + off-host sync (compounds GAP-BAK-01's host-access need).
- **Workaround acceptability:** Acceptable only if the customer accepts owning the schedule.
- **Recommended product capability:** Built-in scheduled backup (cadence + retention + optional remote target) driven by the maintenance agent.
- **Suggested API/UI:** schedule config in the Backup & Restore panel.
- **Target component:** maintenance agent + admin UI.
- **Acceptance criteria:** An operator sets a nightly encrypted backup with retention from the GUI; backups appear on schedule.
- **Estimated PR size:** L. **Priority:** P2.

### GAP-BAK-03 — Restore commit is destructive in place; no non-destructive functional test

- **Blocked step:** Restore validation (step 42).
- **Current behaviour:** A restore *dry-run* validates structure read-only (good, runtime-safe), but a *functional* restore overwrites live `/data` (rollback only via the preserved `.bak`). Dry-run does not KEK-decrypt the encrypted cluster-CA key, so it cannot fully prove an encrypted-key restore will boot.
- **Evidence:** `restore.go:819-913` (commit swap), dry-run `restore.go:158`; docs note the encrypted-key validation caveat.
- **Category:** Operational · **Severity:** P2.
- **Impact:** No "prove-it-boots" rehearsal short of a spare host.
- **Workaround:** Restore onto a separate staging host from the same encrypted backup. **Acceptable with a staging environment.**
- **Recommended change:** A non-destructive restore-to-scratch-and-boot rehearsal mode; extend dry-run to KEK-decrypt keys.
- **Estimated PR size:** M-L. **Priority:** P2.

### GAP-BAK-04 — No documented post-restore verification / disk-loss DR runbook

- **Blocked step:** Failure recovery (step 49).
- **Current behaviour:** No documented post-restore success check; no bare-metal disk-loss DR runbook (interrupted-restore recovery is documented, but not disk-loss).
- **Evidence:** docs/operator/docker-compose-backup-restore.md (vague "verify"); no disk-loss runbook file.
- **Category:** Documentation · **Severity:** P2.
- **Workaround:** This audit's `OPERATIONS-RUNBOOK.md` supplies a post-restore checklist and a disk-loss procedure.
- **Recommended change:** Add both to `docs/operator/`.
- **Estimated PR size:** S (docs). **Priority:** P2. **This audit ships a first version.**

### GAP-MON-01 — No support bundle / single diagnostic artifact

- **Blocked step:** Diagnostics and support bundles (step 40); escalation.
- **Customer requirement:** One redacted archive (system log + audit + config + health + versions) for a support ticket, generated from a supported interface.
- **Current behaviour:** No support-bundle endpoint or CLI exists. A support engineer must stitch together `/api/diagnostics`, `/api/audit?source=file`, `/api/export` (traffic log), `/api/config/export`, plus out-of-band host access for the system log file and `/data`.
- **Evidence:** Exhaustive negative search for `supportbundle|collect.*logs|diag.*tar` (agent-confirmed). Piecemeal endpoints: `diagnostics.go:988`, `ui_config.go:23-55`, `ui_policy.go:1386-1421`, `ui_config.go:511`.
- **Category:** Operational / UX · **Severity:** P2 · **Verification:** independent review pending.
- **Affected deployment type:** no-SSH; all.
- **Impact:** Slow, error-prone support round-trips; the system log file is not GUI-reachable at all.
- **Workaround:** Script the API calls + `--backup` via the `cli` service.
- **Workaround acceptability:** Partial for API-capable operators; not acceptable as GUI self-service.
- **Recommended product capability:** `GET /api/support-bundle` (admin) that streams a redacted tar.gz: diagnostics JSON, audit JSONL, config export (creds excluded), version/build info, recent system log, health snapshots.
- **Suggested UI surface:** "Download support bundle" button in Diagnostics.
- **Target component:** new handler aggregating existing sources; reuse existing redaction.
- **Acceptance criteria:** One authenticated call returns a redacted archive containing logs+audit+config+health+versions; a test asserts secrets are absent.
- **Estimated PR size:** M.
- **Priority:** P2 (strongly wanted before the first supported enterprise customer).

### GAP-MON-02 — Audit log has no GUI bulk export — **RESOLVED**

- **Blocked step:** Logging/auditing (step 37); compliance handoff.
- **Current behaviour (as audited):** The Audit panel offers Filter + Refresh only; bulk export is API-only (`GET /api/audit?source=file`). The traffic log has ⬇CSV/⬇JSON, so the UX is asymmetric.
- **Evidence:** `static/index.html:3137-3144`; `ui_config.go:23-55`.
- **Category:** UX · **Severity:** P3.
- **Workaround:** `curl /api/audit?source=file` or rely on syslog forwarding. **Acceptable for scripted SIEM.**
- **Recommended change:** Add ⬇CSV/⬇JSON to the Audit panel.
- **Estimated PR size:** S. **Priority:** P3.
- **Resolution:** `apiAudit` (`ui_config.go`) now accepts `?format=csv|json`, streaming the same `Content-Disposition: attachment` download shape as `apiExport`'s traffic-log CSV/JSON (defaulting to the persistent `source=file` history and a 10000-entry cap on export, both still overridable). The Audit Log panel (`static/index.html`) gained CSV/JSON buttons beside Refresh, calling the new `exportAuditLog(format)`. No route, role, or method change — purely an additive query parameter and a GUI affordance for an export the API already supported.

### GAP-MON-03 — `/metrics` unauthenticated by default; logging destination flags-only

- **Blocked step:** Monitoring integration (step 38); hardening.
- **Current behaviour:** `/metrics` is open unless `-metrics-token` is set (token IS runtime-settable in the GUI). `log_file`/`log_format`/`audit_log_file` are startup-only; the GUI shows them read-only — a GUI-parity gap for a documented convention.
- **Evidence:** `metrics.go:249-267`; `ui_config.go:1285-1287`.
- **Category:** Security / UX · **Severity:** P3.
- **Impact:** Low-Medium — info exposure on an open `/metrics`; log-destination changes require a restart.
- **Workaround:** Set the metrics token in the GUI; set log flags at deploy; firewall `/metrics`.
- **Workaround acceptability:** Acceptable operationally; a stated-convention violation.
- **Recommended change:** Default-deny `/metrics` (or warn in diagnostics when open); optionally allow log format changes at runtime.
- **Estimated PR size:** S-M. **Priority:** P3.

### GAP-UPD-01 — No offline update bundle; air-gapped image update effectively unsupported

- **Blocked deployment step:** Air-gapped deployment / update procedure (steps 21, 43).
- **Customer requirement:** Download a signed catalog + images bundle on a connected host, transfer it, verify it, and install offline (`docker load` + install), with no runtime registry pull.
- **Current behaviour:** There is no offline update bundle. The signed-tarball import path (`POST /api/update/load`) is design-only and not implemented — a source comment states plainly "NO air-gap bundle." Every update pulls the image from a live registry via `docker pull repo@sha256:<digest>`. The catalog side *can* be air-gapped (place a signed catalog in `<dataDir>/release_catalog/` + `CULVERT_RELEASE_CATALOG_URL=off`), but the image side cannot: the CP dispatch planner refuses (`RefusedRepoMismatch`) unless the catalog ref repo equals the configured `ProxyRepo`, and the official catalog names `ghcr.io/kidcarmi/culvert@sha256:…`. The repo-rewrite capability (`RepoRewrite{From→To}`) that would remap the official repo to an internal registry is implemented and tested but wired to no config surface (constructed as `nil`).
- **Evidence:** `release_catalog_http.go:20` ("NO air-gap bundle"); `templates_upgrade.go:293-307` (`docker pull`); `release_dispatch.go:275-283` (`RefusedRepoMismatch`), `:112-157` (`RepoRewrite` implemented), `release_dispatch_test.go:188-222` (tested); `release_wiring.go:369` (`RepoRewrite` hardcoded nil); design-only import in `roadmap/D1.6d-release-management-plan.md:225-240`. **(strong inference for the "no supported air-gap image path" conclusion; mechanics verified.)**
- **Category:** Product capability / Operational · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** Air-gapped.
- **Security impact:** Pushes customers toward improvised, unsigned `docker save`/`load` transfers, weakening the otherwise-strong signed supply chain.
- **Operational impact:** High — a truly air-gapped customer has no turnkey update path.
- **Workaround:** Self-generate and self-sign a private catalog (via `release_gen.go` + `CULVERT_RELEASE_CATALOG_TRUST_KEYS`) whose `PinnedRef` already names a public-resolving internal registry; mirror images to that repo path; set `CULVERT_RELEASE_CATALOG_URL=off`, place the catalog on disk, and set matching `proxy_repo` on CP and agent.
- **Workaround acceptability:** Poor — heavy, undocumented, and requires the customer to run the catalog-signing pipeline themselves.
- **Recommended product capability:** (a) Wire `RepoRewrite` to a config surface (`CULVERT_RELEASE_REPO_REWRITE` + GUI) so the official signed catalog can target an internal registry at the same digest; and/or (b) implement + publish a signed offline update bundle with an `install`/`/api/update/load` path.
- **Suggested API surface:** `POST /api/update/load` (offline bundle); repo-rewrite config in Release Management.
- **Suggested UI surface:** "Offline update" upload in the Release panel.
- **Target component:** `release_wiring.go`, `release_dispatch.go`, `cmd/culvert-maint`.
- **Acceptance criteria:** An air-gapped operator updates from a signed offline bundle (or the official catalog remapped to an internal registry) with no outbound connection; verified in a network-isolated test.
- **Dependencies:** GAP-NET-03 (internal-mirror SSRF).
- **Estimated PR size:** L (repo-rewrite wiring) to XL (offline bundle).
- **Priority:** P1 for any air-gapped customer.

### GAP-UPD-02 — No customer-triggered (non-failure) image or `/data` rollback via CP/GUI

- **Blocked deployment step:** Rollback procedure (step 45); failure recovery (step 49).
- **Customer requirement:** Deliberately roll back to the previous image version, or roll `/data` back, from a supported interface without host SSH (change-controlled ops require a tested manual rollback).
- **Current behaviour:** Automatic rollback-on-failed-upgrade is implemented and GUI-exposed (default on; a dispatch-modal "Disable auto-rollback" toggle). But a *standalone* rollback is not reachable from the CP/GUI: the maintenance agent implements `POST /v1/rollbacks` (`mode=image` re-pin prior digest, `mode=data` restore `/data`), yet the CP registers no `/api/releases/rollback` route and the Release panel has no rollback button. A deliberate version rollback or `/data` rollback requires calling the agent socket directly on the host. (Config-version rollback in the UI restores proxy *settings*, not the image.)
- **Evidence:** `handlers_upgrade_apply.go:59-62,345-347` (auto-rollback default-on), `static/index.html:3847-3851` (GUI toggle); `handlers_rollback.go:37-116` + `cmd/culvert-maint/.../server.go:289` (`/v1/rollbacks` exists); `release_api.go:288-293` (only dispatch/resume/status/refresh registered — no rollback route). **(inference for "not customer-accessible"; route absence verified.)**
- **Category:** Product capability / Operational · **Severity:** P1 · **Verification:** independent review pending.
- **Affected deployment type:** no-SSH; change-controlled.
- **Security impact:** Neutral.
- **Operational impact:** High for change control — the required "tested manual rollback" is a host-shell operation, contradicting the no-SSH goal.
- **Workaround:** Host-level direct agent call (`/v1/rollbacks`), or `docker compose --profile cli` offline `/data` restore.
- **Workaround acceptability:** Marginal — defeats the no-SSH objective for the rollback case.
- **Recommended product capability:** `POST /api/releases/rollback` (admin) proxied to the agent's `/v1/rollbacks`, with image and data modes, plus a GUI "Roll back" action showing the prior digest.
- **Suggested API surface:** `POST /api/releases/rollback {mode:image|data}`.
- **Suggested UI surface:** "Roll back to previous release" button in the Release panel.
- **Target component:** `release_api.go`, `release_dispatch*.go`, Release panel.
- **Acceptance criteria:** An admin rolls back to the previous image (and, gated/offline, `/data`) from the GUI with no host shell; test covers the CP→agent path.
- **Dependencies:** none (agent primitive exists).
- **Estimated PR size:** M.
- **Priority:** P1.

### GAP-UPD-03 — Update trust-root management is env-only

- **Blocked deployment step:** Update source configuration / update trust roots (step 19).
- **Customer requirement:** Rotate/add release-signing trust roots (or change the pinned Sigstore identity for a fork/mirror) via GUI/API under change control.
- **Current behaviour:** Trust roots and Sigstore identity/root are set only via read-once env vars (`CULVERT_RELEASE_CATALOG_TRUST_KEYS`, `CULVERT_RELEASE_SIGSTORE_IDENTITY`, `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT`), requiring a container-env edit + restart. The GUI displays the resulting verify mode/trust schemes read-only.
- **Evidence:** `release_wiring.go:44-78` (env-only, documented "GUI-parity deferral"); `static/index.html:10889-10905` (display-only trust badge).
- **Category:** Product capability · **Severity:** P2 · **Verification:** independent review pending.
- **Security impact:** A security-critical control lives outside the audited GUI/API change-management surface.
- **Operational impact:** Medium — restart-required change for a GUI-only admin.
- **Workaround:** Edit container env + restart.
- **Workaround acceptability:** Marginal for GUI-only operators; acceptable where env changes are themselves change-controlled (e.g. GitOps on the compose file).
- **Recommended product capability:** Admin API/UI to manage additional (public) trust roots and the pinned identity, persisted and applied without a full restart, with an audit trail.
- **Suggested API surface:** `GET/POST /api/releases/trust-roots` (admin).
- **Suggested UI surface:** "Release trust" panel with root management.
- **Target component:** `release_wiring.go`, Release panel.
- **Acceptance criteria:** An admin adds a public trust root from the GUI; the change is audited and takes effect; break-glass verify modes remain env-only.
- **Estimated PR size:** M-L. **Priority:** P2.

### GAP-UPD-04 — Maintenance-agent install is a one-time root/SSH operation; self-fencing socket drop

- **Blocked deployment step:** Update source configuration (step 19); first update.
- **Customer requirement:** Stand up the update path without host shell; updates must not disconnect the update channel mid-apply.
- **Current behaviour:** The maintenance agent is a host systemd service (root/privileged service account) with a path-locked sudoers allowlist; installing it (systemd unit + sudoers + `culvert-maint` user) is a one-time root/SSH operation. After install, routine updates need no per-update SSH. A known residual: without a wired `compose_override_file`, an agent-driven container recreate drops the agent's mounted socket → "Agent unreachable" until re-wired (the quick-start installer wires it automatically; hardened/custom deployments must do so manually).
- **Evidence:** `roadmap/D1.6-maintenance-agent-design.md:99-104,122-128`; `docs/operator/release-management-agent.md:24-53`; `handlers_upgrade_apply.go:111-127` (self-heal preflight warning); `packaging/culvert-maint/install.sh`.
- **Category:** Operational · **Severity:** P2.
- **Security impact:** Positive (least-privilege sudoers, no docker.sock in the proxy); the cost is a root install step.
- **Operational impact:** Medium — initial provisioning requires host access; the socket-drop pitfall needs the override wired.
- **Workaround:** Use the quick-start installer (wires the override), or follow the manual-wiring doc; perform agent install during the (SSH-permitted) build phase.
- **Workaround acceptability:** Acceptable — a one-time provisioning step is normal even for no-SSH steady-state operation, provided it is documented.
- **Recommended change:** Ensure every install path wires `compose_override_file`; document the agent-provisioning step as a build-phase (not steady-state) task in the deployment guide.
- **Acceptance criteria:** A fresh install always has the override wired; the deployment guide calls out agent provisioning as a one-time root step.
- **Estimated PR size:** S (docs + installer guard). **Priority:** P2.

---

## Verification log (independent review of P0/P1)

Each P1 (and the no-SSH-P0 case of GAP-IAM-01) was re-reviewed against primary evidence.
The two P1s that rested on inference (absence of code) were sent to a dedicated adversarial
verifier instructed to refute them.

| Gap | Basis | Verification result |
|---|---|---|
| GAP-IAM-01 | Direct read | **Confirmed.** `main.go:381-404` read directly by lead auditor; `--reset-password` is the only recovery, host-shell-bound; no API/GUI route exists. |
| GAP-PKI-01 | Inference (no `SaveCA`) | **Confirmed (high).** Adversarial verifier found the mitm upload branch (`ui_security.go:284-292`) calls only `LoadCustomCA`+`auditEvent`; `LoadCustomCA` (`ca.go:458-484`) sets in-memory state + fires `CAChangedObserver` (rotates ticket keys, no disk I/O); the only `SaveCA` callers are `LoadOrInitCA`/`RotateIfNeeded`/`apiCARotate`. Non-persistence is intentional per the `ui_security.go:256-259` comment; operator-facing loss-on-restart is real and unsurfaced. |
| GAP-PKI-02 | Direct test | **Confirmed.** `TestCertManager_LoadCustomCA_RejectsRSA`; `ca.go:470-473`. |
| GAP-PKI-03 | Verified mechanics + inference | **Confirmed (mechanics).** `RotateIfNeeded`→`InitCA` generates a new CA; imported-CA interaction is a strong inference. |
| GAP-POL-01 | Direct read | **Confirmed.** `LogTraffic` gates logging only (`proxy.go:505-508`); no monitor action exists. |
| GAP-BAK-01 | Route/flag absence | **Confirmed.** No backup/restore routes in `ui_routes_meta.go`; agent primitives are UDS-only. |
| GAP-UPD-01 | Inference (`RepoRewrite` unwired) | **Confirmed (high).** Adversarial verifier: `RepoRewrite` appears only in `release_dispatch.go` (type + nil-guarded logic); the sole production `DispatchConfig` construction (`release_wiring.go:369`) leaves it `nil`; no env/API sets it; `RefusedRepoMismatch` (`release_dispatch.go:277-284`) forces catalog-repo==`ProxyRepo`, so the official ghcr catalog cannot target an internal registry. `CULVERT_RELEASE_PROXY_REPO` cannot substitute (proven by the verifier). |
| GAP-UPD-02 | Route absence | **Confirmed.** `/v1/rollbacks` exists on the agent; no `/api/releases/rollback` CP route. |
| GAP-APP-01 / APP-03 | Negative search + direct read | **Confirmed.** No ISO/OVA artifacts; `install.sh:203-208` internet preflight. |

No refutations were found. Severities stand as recorded.

## Evidence provenance

Findings were produced by eight parallel domain investigations (appliance/first-boot,
networking, identity/recovery, TLS/PKI, policy rollout, updates/rollback, backup/restore,
monitoring/diagnostics), each required to cite file:line/test/route evidence and to separate
fact from inference. The lead auditor independently re-read the highest-severity code paths
(`main.go` `--reset-password`, `healthcheck.go`, `docker-compose.yml`, `scripts/install.sh`,
PAC routing, CA routes) before recording them here.
