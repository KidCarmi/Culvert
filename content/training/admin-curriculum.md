# Culvert administrator training curriculum

A structured course that takes a new Culvert administrator from first boot to
confident day-2 operations. Every module maps to a published, evidence-verified
article in this content set; the curriculum adds sequencing, learning
objectives, hands-on labs, and assessment checkpoints. It does not introduce any
product claim not already verified in the linked articles.

**Audience:** enterprise administrators and security engineers who will deploy
and operate Culvert.
**Format:** instructor-led or self-paced; ~1.5 days.
**Prerequisite skills:** TLS, HTTP proxying, identity federation basics,
container operations.

---

## Course map

| # | Module | Primary reference | Outcome |
|---|---|---|---|
| 0 | Orientation | [What is Culvert](../docs/01-overview/what-is-culvert.md), [Architecture](../docs/01-overview/architecture.md) | Explain what Culvert is and how a request flows |
| 1 | Deploy & first boot | [Quick start](../docs/02-getting-started/quick-start.md) | Stand up a node and verify readiness |
| 2 | Policy & Zero Trust | [Policy engine](../docs/03-policy/policy-engine.md) | Author rules and enforce default-deny |
| 3 | TLS inspection | [TLS inspection](../docs/04-tls-inspection/tls-inspection.md) | Enable inspection and manage the CA |
| 4 | Identity & access | [Identity & access](../docs/05-identity/identity-and-access.md) | Federate an IdP; set up 2FA and RBAC |
| 5 | Content security | [Content security](../docs/07-content-security/content-security.md) | Turn on scanning; understand the inspection dependency |
| 6 | Observability | [Observability](../docs/06-observability/observability.md) | Wire metrics, logs, syslog, alerts |
| 7 | Scale & HA | [Control Plane / Data Plane](../docs/08-distributed/control-plane-data-plane.md), [High availability](../docs/08-distributed/high-availability.md) | Enroll DP nodes; understand fencing failover |
| 8 | Operations | [Backup & restore](../docs/10-operations/backup-and-restore.md), [PAC](../docs/09-pac/pac-traffic-steering.md) | Back up, restore, and steer clients |

---

## Module 0 — Orientation

**Objectives:** state what Culvert is (self-hosted SWG / identity-aware forward
proxy, single Go binary); name the request-pipeline stages and where each
control blocks; distinguish supported from planned capabilities.

**Key concepts:** default-deny, first-match policy, opt-in TLS inspection,
Control Plane / Data Plane, the honest limitations (OCSP-only, non-tamper-evident
audit).

**Lab:** none (reading + discussion).

**Checkpoint:** trace a CONNECT request through the pipeline and name the stage
that would block an unauthenticated user.

## Module 1 — Deploy & first boot

**Objectives:** deploy via compose; complete the setup wizard; verify `/ready`;
interpret gating vs report-only checks.

**Lab:**
1. Seed `culvert/proxy:pinned`; `docker compose up -d`.
2. Complete the setup wizard (create the first admin).
3. `curl -i http://localhost:8080/ready` — confirm `200` and read the checks map.

**Checkpoint:** explain why `policy_loaded: "no rules"` does not make the node
not-ready, and why a fresh install runs in passthrough.

## Module 2 — Policy & Zero Trust

**Objectives:** author priority-ordered rules across the 8 condition types; use
the Policy Tester; enforce `default_action: deny` without lockout.

**Lab:**
1. Author an allow rule (`*.github.com`, Allow, Inspect).
2. Dry-run it with `POST /api/policy/test`.
3. Set `default_action: deny`; re-test an unlisted host.

**Checkpoint:** given two overlapping rules, predict the outcome and identify a
conflict warning.

## Module 3 — TLS inspection

**Objectives:** provision the CA (`CULVERT_CA_PASSPHRASE`, `-ca-path`);
distribute the CA to clients; set Inspect vs Bypass; understand rotation.

**Lab:**
1. Start with a CA passphrase and path.
2. Download the CA (`/api/ca/download`) and trust it on a test client.
3. Add an Inspect rule; verify the presented issuer is Culvert's CA.

**Checkpoint:** identify a destination that should be Bypassed and explain why
(cert pinning, regulated category).

## Module 4 — Identity & access

**Objectives:** add an IdP with email-domain routing; enroll TOTP 2FA; assign
RBAC roles; understand session security and lockout.

**Lab:**
1. `POST /api/idp` (optionally `/api/idp/discover` for OIDC); set `EmailDomains`.
2. Enroll 2FA for an admin; observe the `totp_required` step-up.
3. Create a viewer and an operator; confirm write restrictions.

**Checkpoint:** explain the two-layer RBAC (metadata middleware + `requireRole`)
and why both remain.

## Module 5 — Content security

**Objectives:** enable ClamAV/YARA/DPI/file-blocking/threat-feeds; understand
that body scanning requires an Inspect rule; scope bypass deliberately.

**Lab:**
1. Attach a ClamAV sidecar; set `-clamav-addr`; confirm the readiness check.
2. Request the EICAR test file through an Inspect rule; confirm the block and the
   metric increment.

**Checkpoint:** explain why a Bypass rule is a body-scan blind spot.

## Module 6 — Observability

**Objectives:** scrape `/metrics`; read the live dashboard; forward syslog;
configure signed webhook alerts; understand the audit trail's integrity scope.

**Lab:**
1. `curl /metrics | grep culvert_`.
2. Configure syslog (`/api/syslog`) and send a test message.
3. Create a signed webhook (`/api/alerts/webhooks`) and test-fire it.

**Checkpoint:** state why the audit trail is append-only, not tamper-evident, and
what to do if tamper-evidence is required.

## Module 7 — Scale & HA

**Objectives:** split into CP/DP; enroll a DP node with token + CA-fingerprint
pinning; understand config-snapshot sync and the etcd fencing lease.

**Lab:**
1. Start a CP (`-cp-grpc-addr` + mTLS); mint an enrollment token.
2. Enroll a DP with the `-enroll` URL; confirm on `/api/cluster/nodes`.
3. (Optional) arm the fencing lease with etcd; inspect `/api/cluster/ha`.

**Checkpoint:** explain how the fencing lease prevents split-brain, and why
`-ha-auto-failover` is off by default without a witness.

## Module 8 — Operations

**Objectives:** take an encrypted backup; run a restore dry-run; perform an
offline restore commit; steer clients with PAC.

**Lab:**
1. `docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE cli --encrypt --backup /backup/…`.
2. Restore dry-run against the archive.
3. Configure PAC (`/api/pac-config`) with an internal-domain exclusion; fetch
   `/proxy.pac`.

**Checkpoint:** describe the offline-only restore-commit sequence and why the
proxy cannot read its own backups.

---

## Final assessment

A capstone exercise combining the modules:

1. Deploy a node and verify readiness.
2. Author a Zero-Trust policy (allow a small set; deny by default) and prove it
   with the Policy Tester.
3. Enable TLS inspection with a trusted CA and one Bypass rule.
4. Federate an IdP and require 2FA for admins.
5. Turn on ClamAV and confirm a block on the EICAR file.
6. Wire metrics + a syslog target.
7. Take an encrypted backup and validate a restore dry-run.

**Pass criteria:** all seven demonstrated on a real instance, with the candidate
able to explain the fresh-install passthrough, the inspection dependency for body
scanning, and the audit-trail integrity scope.

## Instructor notes

- Emphasize the **safe order** in Module 2 (allow → test → enforce) — the most
  common self-inflicted outage is enforcing deny before authoring allow rules.
- Reinforce **honest limitations** throughout; they build operator trust and
  prevent misconfiguration (e.g. assuming Bypassed traffic is scanned).
- Each module's checkpoint doubles as a knowledge-retention probe; use the
  linked article's *Failure modes* table as a source of scenario questions.

## Source material

This curriculum references only published, evidence-verified content articles
(see the [content index](../README.md)); no new product claims are introduced.
Each module's claims are backed by that article's `*.evidence.md` ledger.
