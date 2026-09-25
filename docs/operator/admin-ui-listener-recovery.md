# Admin UI listener — degradation and recovery

**Applies to:** CHAOS-57 (`admin_ui_health.go`, `ui.go`).

## The rule this implements

> **A management-plane fault must never terminate the enforcement plane.**

Culvert is an in-line secure web gateway. Its reason to exist is enforcing
policy on live traffic; the admin UI is the plane you manage that enforcement
*from*. The admin UI may degrade without the proxy going with it — never the
reverse.

Before CHAOS-57 the reverse is exactly what happened. `startUI` spawned a
listen goroutine whose only error branch was `logFatalf`, which `os.Exit(1)`s
the process — so any failure of the **admin** listener killed the **proxy**,
SOCKS5, and the control/data plane with it.

## What changed

| | Before | After |
|---|---|---|
| Admin port already bound | process exits 1 | proxy keeps serving; listener rebinds with backoff |
| `-tls-cert`/`-tls-key` unreadable | process exits 1 | proxy keeps serving; pair re-read on every attempt |
| Recovery | restart (in practice, a crash loop under `restart: unless-stopped`) | automatic, no restart |
| Visibility | one log line, then the process is gone | `/health`, `/ready`, `/metrics`, diagnostics row, alert |

The listener now rebinds for as long as the process lives, at a **bounded rate**
(1 s doubling to a 30 s ceiling, ±20 % jitter, interruptible by shutdown). The
attempt count is deliberately unbounded: the terminal state of "give up" is an
appliance nobody can manage, which is the outcome this change exists to remove.
The retry is never silent — see *Visibility* below.

## Two reproduced triggers

**1. The admin port is occupied.** A predecessor container still draining, a
host-network service on 9090, an operator collision. `validatePortCollisions`
only checks Culvert's own three ports against *each other*; it cannot see
anything else on the host.

**2. The custom UI certificate cannot be loaded.** The pair is read at listen
time, so a rotation that briefly truncates, replaces or re-permissions those
files — certbot, cert-manager, a Docker secret whose mount is not ready — used
to be a boot that ended in exit 1. Because the pair is now re-read on **every**
attempt, a rotation that momentarily breaks it self-heals with no restart.

Both are routine operational events. Under `restart: unless-stopped` each used
to become an unattended crash loop: no proxy, no admin UI, no health endpoint,
recoverable only with shell access.

> **Note on posture.** Process death is *not* "fail closed". An explicit-proxy
> fleet loses all egress (total outage); a PAC/WPAD fleet with a `DIRECT`
> fallback, or a transparent deployment that bypasses a dead next hop, sends
> traffic straight out **unfiltered**. Exiting picks neither posture
> deliberately — it delegates the choice to your network topology.

## Visibility

Everything below is served on the **proxy** port. That is the point: the admin
port's own `/healthz` cannot tell you the admin port is unreachable.

| Surface | Field | Values |
|---|---|---|
| `GET /health` | `admin_ui` | `ready` · `degraded` · `unavailable` · `stopped` · `disabled` |
| `GET /ready` | `checks.admin_ui` | report-only row (see below) |
| `GET /metrics` | `culvert_admin_ui_up` | 1 while accepting, 0 otherwise |
| | `culvert_admin_ui_unavailable` | 1 once the fault passes 30 s |
| | `culvert_admin_ui_listen_failures_total` | cumulative bind/serve failures |
| | `culvert_admin_ui_binds_total` | successful binds (flap counter) |
| | `culvert_admin_ui_listen_backoff_seconds` | current rebind backoff |
| `GET /api/diagnostics` | `admin_ui_listener` row | ok / warn / **fail** + operator action |
| Alerts | `admin_ui_unavailable` | fire-once per episode |

**The `/ready` row is REPORT-ONLY and must stay that way.** A node whose admin
UI cannot bind is proxying traffic perfectly. Gating the default readiness
verdict on it would eject a fully-functional gateway from the load balancer
because of a fault in the plane that has nothing to do with serving traffic —
converting a management outage into the traffic outage this change prevents.
Operators who *do* want such nodes ejected opt in with `/ready?strict=1`.

### Recommended alerting rule

```promql
# The admin plane has been unreachable for longer than the threshold.
# NOT a traffic incident — the proxy is still enforcing policy.
culvert_admin_ui_unavailable == 1
```

Do **not** page on `culvert_admin_ui_up == 0` alone: it is 0 for the few
seconds of rebinding that follow any ordinary redeploy. The `_unavailable`
gauge is latched only after the fault has persisted past 30 s.

The series are emitted only when an admin UI was configured — a `0` on a node
that never had one is indistinguishable from a dead listener, and the paging
rule is `== 0`.

## Log lines

Rate-limited: the **first** failure of an episode always logs, then at most one
line per 60 s, then one recovery line naming the suppressed count.

```
ERROR admin UI listener on port 9090 unavailable (port_in_use): listen tcp :9090:
  bind: address already in use — retrying in 1.187s; the proxy data plane is
  unaffected and is still enforcing policy
...
admin UI listener recovered on :9090 (3 further failure log lines were suppressed
  while it was down)
UIHTTP: http://localhost:9090
```

The success line is emitted **after** the bind succeeds. Before CHAOS-57 it was
printed before the attempt, so the log actively claimed the admin UI was
listening on a port it had never acquired.

The **full** error text appears only in the log. The contract row, the alert and
the readiness detail carry a bounded reason class (`port_in_use`,
`permission_denied`, `address_unavailable`, `descriptors_exhausted`,
`tls_certificate`, `network_error`, `listen_failed`) because `/health` and
`/ready` are unauthenticated on the proxy port and because an unbounded reason
would give the alert dedup key one distinct value per failure.

## Runbook

**You are paged with `admin_ui_unavailable`.**

1. **Confirm traffic is unaffected first.** `curl http://<node>:8080/health` —
   `status: ok` means the gateway is still enforcing policy. This is a
   management incident, not a traffic incident.
2. **Read the reason class** from `GET /api/diagnostics` → `admin_ui_listener`.

| Reason | Cause | Action |
|---|---|---|
| `port_in_use` | another process holds the admin port | `ss -lptn 'sport = :9090'` — stop the squatter or move the UI port. **Check what is squatting**: an unexpected listener on the admin port could be an impersonator harvesting credentials. |
| `tls_certificate` | `-tls-cert`/`-tls-key` unreadable or not valid PEM | verify the pair (`openssl x509 -in … -noout`) and its permissions. The listener picks up a repaired pair on its own. |
| `permission_denied` | binding a privileged port without the capability | grant `CAP_NET_BIND_SERVICE` or use a port ≥ 1024 |
| `address_unavailable` | the configured bind address is not on this host | fix the address; usually a stale static IP after a re-IP |
| `descriptors_exhausted` | process/system FD exhaustion | this is a whole-node resource incident — see `docs/operator/socks5-listener-health.md`, same root cause |

   **A note on expiry, which is NOT one of the reason classes above.**
   Go's server-side TLS stack does not check a certificate's `NotAfter` at
   load or bind time — that is purely a CLIENT-side check during the
   handshake — so an admin-UI certificate that expires while it is
   *already* bound produces none of the failures in this table: no
   `tls_certificate` reason, no retry, nothing for the rebind loop to pick
   up. The process keeps serving the expired certificate indefinitely;
   only browsers start refusing it. Replacing the file therefore has **no
   effect** until something forces a fresh bind — ordinarily a restart.
   This is exactly why `GET /api/settings/network` →
   `ui_tls_cert_not_after`/`ui_tls_cert_days_remaining` (also shown on the
   Certificates panel) exists as a **proactive** signal — check it
   *before* expiry, since there is no reactive detection for this cause
   the way there is for the others above. This is the admin UI's own
   serving certificate, separate from the MITM inspection root CA and the
   outbound upstream mTLS client cert, each of which has its own expiry
   surface elsewhere in the product.
3. **No restart is required for any of the table's reason classes** (the
   already-expired case above is the one exception — it needs a restart,
   since nothing forces a rebind on its own). The listener rebinds
   automatically within 30 s of the fault clearing. Confirm with
   `culvert_admin_ui_up == 1`, or the `admin UI listener recovered` log line.
4. If you must restart anyway, note that a restart is now strictly *worse* than
   waiting: it drops in-flight tunnels, whereas the rebind does not.

## Related

- `docs/operator/socks5-listener-health.md` — CHAOS-54, the same treatment for
  the SOCKS5 accept loop, whose vocabulary this reuses.
- `docs/operator/ha-lease-recovery.md` — CHAOS-55, the source of the
  rate-bounded/never-count-bounded jittered retry pattern.
- `docs/operator/category-store-recovery.md` — CHAOS-50 §19, the boot-path
  precedent: a non-authoritative subsystem must not take the appliance down.
