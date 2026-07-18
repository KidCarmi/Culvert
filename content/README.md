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
| Getting started | Quick start & first boot | _planned_ |
| Policy | Policy engine & Zero-Trust authoring | _planned_ |
| TLS inspection | TLS inspection administration | _planned_ |
| Identity | Identity & access (SSO, 2FA, RBAC) | _planned_ |
| Observability | Metrics, dashboard, logs, audit | _planned_ |

The authoritative, prioritized queue is [`../CONTENT-BACKLOG.yaml`](../CONTENT-BACKLOG.yaml);
live progress is in [`../RUN-STATE.md`](../RUN-STATE.md).

## Authoring rules (summary)

1. Verify before you write — no claim without evidence.
2. Separate supported from planned; never blur the line.
3. Write for enterprise administrators and security engineers.
4. Keep a claim-evidence ledger with every content unit.
