# Culvert Content Foundation

Verified, evidence-grounded content for the Culvert documentation website,
YouTube channel, administrator training, product demonstrations, and enterprise
onboarding. Every material product claim here is traceable to source, tests,
API/config contracts, an architecture decision, or a reproduced lab run — see
[`../CONTENT-STANDARD.md`](../CONTENT-STANDARD.md).

This tree is the audience-facing content layer. It is distinct from the
in-repo engineering/operator docs under [`../docs/`](../docs/), which it draws
evidence from but does not mirror.

## Layout

| Path | Contents |
|---|---|
| `docs/` | Documentation-website articles, grouped by topic area. |
| `youtube/` | YouTube video packages (one directory per video). |
| `training/` | Administrator-training outlines and curricula. |
| `evidence/` | Claim-evidence ledgers for content units (when kept separate). |

## Documentation map

| Section | Article | Status |
|---|---|---|
| Overview | [What is Culvert](docs/01-overview/what-is-culvert.md) | published |
| Overview | [Architecture](docs/01-overview/architecture.md) | published |
| Getting started | [Quick start & first boot](docs/02-getting-started/quick-start.md) | published |
| Policy | [Policy engine & Zero-Trust authoring](docs/03-policy/policy-engine.md) | published |
| TLS inspection | [TLS inspection administration](docs/04-tls-inspection/tls-inspection.md) | published |
| Identity | [Identity & access (SSO, 2FA, RBAC)](docs/05-identity/identity-and-access.md) | published |
| Observability | [Metrics, dashboard, logs, audit](docs/06-observability/observability.md) | published |
| Content security | [ClamAV, YARA, threat feeds, DPI, file blocking, CDR](docs/07-content-security/content-security.md) | published |
| Distributed | [Control Plane / Data Plane](docs/08-distributed/control-plane-data-plane.md) | published |
| Distributed | [High availability (etcd fencing lease)](docs/08-distributed/high-availability.md) | published |

## YouTube packages

| Package | Status |
|---|---|
| [What is Culvert (intro)](youtube/01-what-is-culvert/package.md) | published |
| [Deploy in 5 minutes (quick-start demo)](youtube/02-deploy-in-5-minutes/package.md) | published |

The authoritative, prioritized queue is [`../CONTENT-BACKLOG.yaml`](../CONTENT-BACKLOG.yaml);
live progress is in [`../RUN-STATE.md`](../RUN-STATE.md); the session summary is
in [`../reports/CONTENT-FACTORY-SUMMARY.md`](../reports/CONTENT-FACTORY-SUMMARY.md).

## Authoring rules (summary)

1. Verify before you write — no claim without evidence.
2. Separate supported from planned; never blur the line.
3. Write for enterprise administrators and security engineers.
4. Keep a claim-evidence ledger with every content unit.
