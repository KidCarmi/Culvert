# YouTube package — "Deploy Culvert in 5 minutes"

A hands-on quick-start demo: from nothing to a running proxy with an admin
account and a verified-ready node. Commands mirror the verified
[Quick start](../../docs/02-getting-started/quick-start.md). The `/health` and
`/ready` outputs shown were **actually reproduced** against a built binary and
are recorded in
[`../../evidence/quick-start-lab-run.md`](../../evidence/quick-start-lab-run.md).
The `docker compose` flow is validated against the shipped compose file and
README but was not reproduced in the content-factory environment — see the
[claim-evidence ledger](#claim-evidence-ledger).

---

## Video objective

Show a viewer how to stand up Culvert, create the first admin, and confirm the
node reports ready — honestly, including the one common failure and its fix.

## Target viewer

Administrators and platform engineers doing a first evaluation. Comfortable with
Docker and the shell.

## Expected viewer outcome

The viewer can bring up Culvert with `docker compose up`, complete the setup
wizard, verify `/ready` returns `200`, and knows that a fresh install runs in
passthrough until Zero Trust is enforced.

## Title options

1. Deploy Culvert in 5 minutes: self-hosted Secure Web Gateway
2. From zero to a running proxy + admin console — Culvert quick start
3. Stand up Culvert with docker compose (and verify it's actually ready)

## Thumbnail brief

- A terminal with `docker compose up -d` and a green `ready` badge.
- Chip: "5 minutes". No fabricated dashboards.

## Full narration script

> **[0:00 — Setup]**
> Let's get Culvert running from scratch. You need one Linux host with Docker
> and Compose. Culvert ships as a single container image plus an admin console —
> no external database, no message bus.

> **[0:20 — Seed the image and start]**
> One detail up front: the compose file resolves a local-only image tag,
> `culvert/proxy:pinned`, because the proxy image is pinned at the sudo boundary
> and never pulled by name. So we seed that tag first — either build it, or pull
> the public image and retag it — then `docker compose up -d`. If you skip the
> seed, compose fails with "pull access denied for culvert/proxy"; that's the
> single most common first error, and now you know the fix.

> **[1:10 — Endpoints]**
> Compose brings up two ports: the proxy on 8080 and the admin UI on 9090 over
> HTTPS with a self-signed cert. Health, readiness, metrics, and the PAC file
> are all served on the proxy port, not the admin port — that trips people up.

> **[1:40 — First admin]**
> Open the admin UI on 9090 and accept the self-signed certificate. The setup
> wizard appears because no admin exists yet — the browser checks
> `/api/setup/status`. Create the first admin. The password needs at least eight
> characters, mixed case, and a digit. Until this admin exists, the console and
> API are gated.

> **[2:30 — Verify readiness]**
> Now the important part — don't just assume it's up, verify it. Curl the
> readiness endpoint on the proxy port. You get HTTP 200 and a JSON checks map.
> Out of the box, the two gating checks — the session key and the config
> validator — are OK, so the node is ready. You'll also see `policy_loaded`
> reporting "no rules"; that's informational and does not hold the node back —
> an empty policy is a valid Zero-Trust posture.

> **[3:20 — The default posture]**
> Here's the thing to understand before you point real users at it: a fresh
> install with no rules runs in passthrough — it allows traffic — so you can't
> lock yourself out on first boot. The startup log says exactly this. To enforce
> Zero Trust, add policy rules or set `default_action: deny`.

> **[4:00 — Diagnostics]**
> Last step: in the admin UI, open Infrastructure, then Diagnostics. It shows
> the operator contract — storage, policy load, the root CA, the session key,
> cluster TLS. Clear any red rows before you take traffic.

> **[4:30 — Close]**
> That's a working Culvert: a proxy, an admin console, a verified-ready node.
> From here, author your first policy rule and, when you're ready, flip the
> default to deny. Links below.

## Demonstration plan

Record against a **real** instance. Reproduce each step live; do not stage
output. The readiness JSON shown must match the real response (a verified
reference is in the lab-evidence file).

1. Seed the image and start the stack.
2. Show the endpoints table / the two ports responding.
3. Complete the setup wizard (create first admin).
4. Curl `/ready`, highlight the checks map.
5. Show the startup log's passthrough line.
6. Open Diagnostics.

## Exact commands / UI actions

```bash
# 1. Seed the local-only pinned tag (build, or pull+retag)
docker build -t culvert/proxy:pinned .
#   or: docker pull ghcr.io/kidcarmi/culvert:latest \
#         && docker tag ghcr.io/kidcarmi/culvert:latest culvert/proxy:pinned

# 2. Start
docker compose up -d

# 3. First admin: browser → https://<host>:9090 → accept cert → setup wizard

# 4. Verify readiness (proxy port, not the UI port)
curl -i http://localhost:8080/ready

# 5. Liveness
curl http://localhost:8080/health
```

UI: **Infrastructure → Diagnostics**; later, **Policy** to author the first rule.

## Lab prerequisites

- One Linux host with Docker Engine + Compose v2.
- Network access to pull `ghcr.io/kidcarmi/culvert` (or a local build).
- A browser to reach the admin UI.

## Expected results

Reproduced against the built binary (exact JSON in the lab-evidence file):

```json
// GET /health
{"status":"ok","uptime":"0m 4s","version":"dev","clamav":"disabled","ca_expires_days":3649,"ssl_inspection":"ready","threat_feed_entries":0}

// GET /ready  → HTTP 200
{"status":"ready","checks":{"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"fail","detail":"no rules"},"session_secret":{"status":"ok"}}}
```

## Failure and recovery path

| Failure | What the viewer sees | Fix (show on camera) |
|---|---|---|
| Image tag not seeded | `pull access denied for culvert/proxy` on `up` | Build or pull-and-retag `culvert/proxy:pinned` |
| Hitting `/ready` on the UI port | Connection/handshake confusion | Use the proxy port `8080` for health/ready/metrics |
| `/ready` returns `503` | A gating check failed (e.g. `session_secret`) | Read the checks map; restart to re-init the session key |

## Chapter timestamps (proposal)

| Time | Chapter |
|---|---|
| 0:00 | Prerequisites |
| 0:20 | Seed the image & start |
| 1:10 | Endpoints |
| 1:40 | Create the first admin |
| 2:30 | Verify readiness |
| 3:20 | Default posture (passthrough) |
| 4:00 | Diagnostics |
| 4:30 | Next steps |

## Video description

```
Stand up Culvert — a self-hosted Secure Web Gateway — with docker compose, in
about five minutes. We seed the local pinned image tag, start the stack, create
the first admin through the setup wizard, and — importantly — verify the node
actually reports ready before trusting it. We also cover the fresh-install
passthrough posture and how to enforce Zero Trust.

Chapters:
0:00 Prerequisites
0:20 Seed the image & start
1:10 Endpoints
1:40 Create the first admin
2:30 Verify readiness
3:20 Default posture (passthrough)
4:00 Diagnostics
4:30 Next steps

Quick start docs: <link: Quick start & first boot>
Source: https://github.com/KidCarmi/Culvert
```

## Pinned comment

```
Gotchas from the video:
• The compose file resolves the LOCAL tag culvert/proxy:pinned — seed it first
  (build or pull+retag), or you'll hit "pull access denied".
• Health/readiness/metrics/PAC are on the PROXY port (8080), not the admin UI
  port (9090).
• A fresh install runs in passthrough. Add rules or set default_action: deny to
  enforce Zero Trust.
Full steps → <link: Quick start & first boot>
```

## Related documentation (placeholders)

- `<link: Quick start & first boot>` → `content/docs/02-getting-started/quick-start.md`
- `<link: Policy engine>` → `content/docs/03-policy/policy-engine.md`
- `<link: What is Culvert>` → `content/docs/01-overview/what-is-culvert.md`

## Short-form version (≤60s)

> Deploy Culvert in five minutes. Seed the local image tag — `docker build -t
> culvert/proxy:pinned .` — then `docker compose up -d`. Open the admin UI on
> 9090, accept the cert, create your first admin. Then verify: curl `/ready` on
> the proxy port, port 8080 — you want HTTP 200 and green gating checks. One
> thing to know: a fresh install runs in passthrough so you can't lock yourself
> out. Add rules or set `default_action: deny` for Zero Trust. Done.

## Claim-evidence ledger

| Claim in the video | Type | Evidence |
|---|---|---|
| Compose resolves local-only `culvert/proxy:pinned`; bare `up` → pull denied | code/doc | `docker-compose.yml`; README quick-start note. **Not reproduced** (no Docker in the content-factory env) |
| Ports 8080 (proxy) / 9090 (UI); health/ready/metrics/PAC on proxy port | code | `main.go:502-503`, `main.go:892-900` |
| Setup wizard gate via `/api/setup/status`; first admin via `/api/setup/complete` | code | `ui_auth.go:371-411` |
| Password complexity 8+/mixed-case/digit | code | `store.go:644-663` |
| `/health` and `/ready` output shown | **lab (reproduced)** | `../../evidence/quick-start-lab-run.md` (real binary run) |
| `/ready` 200 out of the box; gating = session_secret + config_snapshot_validator; policy_loaded report-only | code/lab | `healthcheck.go:180-207`; lab run |
| Fresh install = passthrough; enforce with `default_action: deny` | code/lab | `proxy.go:19`; startup log in lab run |
| Diagnostics surfaces the operator contract | doc | README first-run checklist; `diagnostics.go` |

**Honesty note:** the on-camera `docker compose up` sequence must be recorded
against a real Docker host; it was not executed in the content-factory
environment. The `/health` and `/ready` payloads, however, are genuine output
from a built binary and may be shown verbatim.
