# YouTube package — "What is Culvert?"

A ~3–4 minute product introduction. Every claim in the narration is drawn from
the verified capability inventory in
[`../../docs/01-overview/what-is-culvert.md`](../../docs/01-overview/what-is-culvert.md)
and its evidence ledger. This package contains no synthetic screenshots and does
not claim any demonstration was recorded.

---

## Video objective

Explain, accurately, what Culvert is and what it verifiably does, so a security
or platform engineer can decide in four minutes whether to evaluate it.

## Target viewer

Security engineers, network/platform engineers, and technical evaluators
comparing Secure Web Gateways. Assumes familiarity with TLS, HTTP proxying, and
containers.

## Expected viewer outcome

The viewer can state: what Culvert is (a self-hosted SWG / identity-aware forward
proxy shipped as one Go binary), its main capability domains, the default-deny
posture, and where to go next (the quick start).

## Title options

1. What is Culvert? A self-hosted Secure Web Gateway in one Go binary
2. Culvert: identity-aware forward proxy with TLS inspection, explained
3. Zero-Trust egress control you self-host — meet Culvert

## Thumbnail brief

- Left: the Culvert wordmark on a dark background.
- Right: three stacked chips — "TLS inspection", "Identity-aware policy",
  "Single binary".
- Avoid superlatives and numbers that aren't in the docs. No fabricated UI.

## Full narration script

> **[0:00 — Hook]**
> If you run outbound web traffic for an organization, you already know the
> shape of the problem: you need to decide what egress is allowed, inspect it,
> and record it — usually with a commercial appliance. Culvert does that job as
> a single, self-hosted Go binary.

> **[0:20 — What it is]**
> Culvert is a Secure Web Gateway: a policy-enforcing forward proxy that sits
> between your users and the internet. It speaks HTTP, HTTPS with full CONNECT
> tunneling, SOCKS5, and WebSocket. It ships as one statically linked binary
> with no runtime service dependencies — the release build is compiled with CGO
> disabled. The only optional companion is a ClamAV sidecar, and only if you
> turn on antivirus scanning.

> **[0:50 — Policy]**
> At its core is a policy engine. Rules are evaluated in priority order, and the
> first match wins. Each rule can combine up to eight condition types — source
> IP, authenticated identity, IdP group, auth source, destination host, URL
> category, destination country by GeoIP, and a time schedule. When no rule
> matches, the default is deny — Zero Trust. One caveat the project is honest
> about: a brand-new install with no rules starts in passthrough so you can't
> lock yourself out. You enforce deny explicitly.

> **[1:30 — TLS inspection]**
> For traffic you choose to inspect, Culvert performs opt-in TLS interception:
> it mints on-the-fly ECDSA P-256 leaf certificates signed by its internal CA,
> decrypts, scans, and re-originates TLS. The CA's private key is encrypted at
> rest with AES-256-GCM and PBKDF2. And for sensitive destinations — banking,
> health — you set a rule to Bypass and never decrypt them.

> **[2:00 — Identity and content security]**
> Culvert is identity-aware. It authenticates users against local accounts,
> OIDC with PKCE, SAML, or LDAP, and routes across multiple identity providers
> by email domain. On decrypted traffic it can run ClamAV, a pure-Go YARA
> engine, regex DPI, file-type blocking, and URLhaus and OpenPhish threat feeds.

> **[2:35 — Observability and scale]**
> Every decision is measurable: Prometheus metrics, a live dashboard, structured
> logs, syslog forwarding, and signed webhook alerts. To scale, you split it
> into a Control Plane that owns configuration and stateless Data Plane nodes
> that pull the full config over mutual TLS.

> **[3:05 — Honest edges]**
> A couple of honest edges: certificate revocation is OCSP only, not CRL. And
> the admin audit trail is append-only, not cryptographically tamper-evident —
> if you need that, forward it to a write-once SIEM.

> **[3:25 — Close]**
> That's Culvert: Zero-Trust egress control, TLS inspection, identity-aware
> policy, and content scanning, self-hosted in one binary. The quick start gets
> a working proxy and admin console running with `docker compose up`. Links are
> in the description.

## Demonstration plan

This is an explainer; visuals are supporting, not a live demo. Suggested B-roll,
none of which requires fabricating results:

1. The capability table from the product overview page on screen.
2. The architecture request-pipeline Mermaid diagram.
3. The admin UI **Policy** panel (real, from an actual instance — do not mock).
4. A terminal showing `curl http://localhost:8080/health` returning
   `{"status":"ok", …}` (reproduced output is available in the quick-start lab
   evidence).

> If any screen is not available from a real instance at record time, keep the
> diagram/table on screen instead — do not stage a fake console.

## Exact commands / UI actions

- `curl http://localhost:8080/health`
- Admin UI → **Policy** (show the rule list and the first-match ordering).
- Admin UI → **Overview** dashboard (live SSE feed).

## Lab prerequisites

- One host with Docker + Compose; a running Culvert instance (see
  [Quick start](../../docs/02-getting-started/quick-start.md)).
- A completed setup wizard (first admin created).

## Expected results

- `/health` returns `{"status":"ok", …}` (see quick-start lab evidence for the
  exact shape).
- The Policy panel lists rules in priority order.

## Failure and recovery path

- If `docker compose up` fails with `pull access denied for culvert/proxy`, the
  local `culvert/proxy:pinned` tag was not seeded — build or pull-and-retag it
  (see the quick start). Show this once as the honest failure, then the fix.

## Chapter timestamps (proposal)

| Time | Chapter |
|---|---|
| 0:00 | The problem |
| 0:20 | What Culvert is |
| 0:50 | Policy engine & Zero Trust |
| 1:30 | TLS inspection |
| 2:00 | Identity & content security |
| 2:35 | Observability & scale |
| 3:05 | Honest limitations |
| 3:25 | Next steps |

## Video description

```
Culvert is a self-hosted Secure Web Gateway and identity-aware forward proxy —
HTTP/HTTPS/SOCKS5/WebSocket — shipped as a single Go binary. This video explains
what it verifiably does: priority-ordered default-deny policy, opt-in TLS
inspection with an internal CA, identity via OIDC/SAML/LDAP, content scanning
(ClamAV, YARA, DPI, threat feeds), and a Control Plane / Data Plane model for
scale.

Chapters:
0:00 The problem
0:20 What Culvert is
0:50 Policy engine & Zero Trust
1:30 TLS inspection
2:00 Identity & content security
2:35 Observability & scale
3:05 Honest limitations
3:25 Next steps

Docs: <link: What is Culvert>
Quick start: <link: Quick start & first boot>
Source: https://github.com/KidCarmi/Culvert
```

## Pinned comment

```
Quick facts from the video, all verifiable in the repo:
• Default-deny once a rule exists or default_action: deny is set (fresh install
  starts in passthrough by design).
• TLS inspection is opt-in per rule; sensitive hosts can Bypass.
• Revocation is OCSP-only (no CRL); the audit trail is append-only, not
  cryptographically tamper-evident.
Start here → <link: Quick start>
```

## Related documentation (placeholders)

- `<link: What is Culvert>` → `content/docs/01-overview/what-is-culvert.md`
- `<link: Architecture>` → `content/docs/01-overview/architecture.md`
- `<link: Quick start & first boot>` → `content/docs/02-getting-started/quick-start.md`

## Short-form version (≤60s)

> Culvert is a Secure Web Gateway you self-host as one Go binary. It's a
> forward proxy with a priority-ordered, default-deny policy engine — allow only
> what you sanction. It does opt-in TLS inspection with its own CA, so it can
> scan decrypted traffic with ClamAV, YARA, and threat feeds — while letting you
> Bypass banking and health. It's identity-aware over OIDC, SAML, and LDAP, and
> scales with a Control Plane and stateless Data Plane nodes. No agents, no
> external database. `docker compose up` and you're running.

## Claim-evidence ledger

Every narration claim maps to the verified inventory. See
[`../../docs/01-overview/what-is-culvert.evidence.md`](../../docs/01-overview/what-is-culvert.evidence.md).
Key mappings:

| Narration claim | Evidence |
|---|---|
| One static Go binary, CGO disabled, ClamAV optional | `Dockerfile:20,37`; overview §"How it is delivered" |
| HTTP/HTTPS/CONNECT/SOCKS5/WebSocket | `proxy.go`, `socks5.go`, `proxy_tunnel.go` |
| First-match, 8 conditions, default-deny, fresh-install passthrough | `policy.go:1083`; `proxy.go:19`; README Limitations |
| TLS inspection: ECDSA P-256 leaves, CA key AES-256-GCM+PBKDF2, Bypass | `internal/ca/ca.go:763,138,352,358`; `internal/sslbypass` |
| Identity: local/OIDC-PKCE/SAML/LDAP, email-domain routing | `auth_*.go`; `auth_idp.go:487-501` |
| Content: ClamAV, YARA, DPI, file-type, URLhaus/OpenPhish | `internal/clamav`, `internal/yara`, `internal/scanner`, `internal/threatfeed` |
| Metrics, SSE, syslog, signed webhooks | `metrics.go`, `events.go`, `syslog.go`, `alerts.go` |
| Control Plane / stateless Data Plane over mTLS | `controlplane.go`, `controlplane_tls.go` |
| OCSP-only (no CRL); audit append-only (not tamper-evident) | README Limitations; `internal/audit/audit.go:49` |
