# SOCKS5 listener health

*Applies to nodes started with `-socks5-port` (or `proxy.socks5_port` in
`config.yaml`). On a node without it, every surface below reports the feature as
absent and no metrics are emitted.*

Culvert's SOCKS5 listener owns its whole lifecycle: bind, accept, rebind. Since
CHAOS-54 the accept loop backs off on accept failures instead of retrying at
syscall speed; since CHAOS-66 a **bind** failure is no longer fatal to the
process and the listener rebinds on its own. This page is what to do when one of
its surfaces goes non-green.

> **Changed in CHAOS-66.** A SOCKS5 bind failure used to call `logFatalf`, which
> exits the process — and it did so *before* the HTTP/HTTPS proxy listener and
> the admin UI started. An occupied SOCKS5 port therefore took down the entire
> appliance, and under `restart: unless-stopped` became an unattended crash
> loop. It is now contained to the SOCKS5 service. **No SOCKS5 fault requires a
> node restart any more.**

---

## The two states, and why they are different

| State | Meaning | Recovers by itself? | What you do |
|---|---|---|---|
| **degraded** (accept) | `accept(2)` has been failing continuously for more than 30 s. The loop is still retrying, backed off to at most one attempt per second. | **Yes** — the moment the underlying condition clears | Raise or investigate the descriptor limit; no restart needed |
| **degraded** (bind) | The listener cannot bind its port and is retrying, backed off to at most one attempt per 30 s. Under 30 s old — usually a predecessor process still holding the port. | **Yes** — as soon as the port frees | Nothing, unless it persists |
| **down** (bind) | The listener has been unable to bind for more than 30 s. SOCKS5 is unavailable. | **Yes**, once the cause clears | Find what owns the port, or whether the process may bind it — see below |
| **down** (accept) | The listening socket itself became invalid. The loop closed it, so clients get connection-refused rather than hanging, and a rebind is pending. | **Yes** — the supervisor rebinds | Check the logs for the socket fault |

Do not collapse these. They point at different actions.

**The HTTP/HTTPS proxy and the admin UI are unaffected by every row in this
table.** A node whose SOCKS5 listener is down is still proxying and still
enforcing policy.

---

## Where it shows up

**`/api/diagnostics`** — the `socks5_listener` row (viewer role). `warn` while
degraded, `fail` while down, and it carries the consecutive-error count, the
reason class and a suggested action.

**`/readyz`** — a `socks5` row. **Report-only**: a node whose SOCKS5 listener is
dead still proxies HTTP, HTTPS and PAC perfectly, so it does not fail the
default readiness verdict. If you want such nodes ejected from a load-balancer
pool, point the probe at `/readyz?strict=1`.

**`/healthz`** (proxy port) — the `socks5` field: `disabled`, `ready`,
`degraded` or `down`.

**`/metrics`** — emitted only on a node with a configured listener:

| Series | Meaning |
|---|---|
| `culvert_socks5_listener_up` | `1` while the listener is bound and accepting; `0` once the accept loop has stopped **or** the bind has been failing past the threshold |
| `culvert_socks5_accept_errors_total` | Cumulative accept errors since startup |
| `culvert_socks5_accept_degraded` | `1` while accepts have been failing for longer than the threshold |
| `culvert_socks5_accept_backoff_seconds` | Current accept retry backoff; `0` when accepts are succeeding |
| `culvert_socks5_unavailable` | `1` while the listener has been unable to **bind** for longer than 30 s |
| `culvert_socks5_bind_failures_total` | Cumulative failed bind attempts since startup |
| `culvert_socks5_binds_total` | Cumulative successful binds; a climbing value means the listener is flapping |
| `culvert_socks5_bind_backoff_seconds` | Current rebind backoff; `0` while bound |

**Alerts** — `socks5_listener_down`, fired **once per episode** (not once per
retry) when the listener degrades or dies. Subscribe to it in the webhook
editor: *"SOCKS5 listener not accepting connections"*.

### Suggested paging rules

```
# SOCKS5 is not serving. No longer implies a restart: the listener is retrying.
culvert_socks5_listener_up == 0

# The listener cannot get its port at all.
culvert_socks5_unavailable == 1

# Sustained accept failure — usually descriptor exhaustion.
culvert_socks5_accept_degraded == 1

# Leading indicator: transient accept errors that keep coming back.
rate(culvert_socks5_accept_errors_total[15m]) > 0

# Flapping: the listener keeps having to rebind.
increase(culvert_socks5_binds_total[1h]) > 3
```

Note the gauges are **absent**, not zero, on a node without SOCKS5 — so
`== 0` never fires on an appliance that simply does not use the feature.

---

## The usual cause: descriptor exhaustion

`process_fd_limit` (EMFILE) and `system_fd_limit` (ENFILE) are by far the most
likely reason classes.

1. **Check the process limit.**
   ```
   cat /proc/$(pgrep -f '/app/culvert')/limits | grep 'open files'
   ls /proc/$(pgrep -f '/app/culvert')/fd | wc -l
   ```
2. **Check the system-wide table** if the reason class is `system_fd_limit`:
   ```
   cat /proc/sys/fs/file-nr
   ```
3. **Raise the limit.** In `docker-compose.yml`:
   ```yaml
   services:
     proxy:
       ulimits:
         nofile:
           soft: 65536
           hard: 65536
   ```
4. **Find what is consuming descriptors.** Long-lived tunnels and a distributed
   connection flood are the usual suspects; the per-IP connection limiter
   (`/api/connlimit`, Security panel) is the lever, and it ships **disabled**.

The listener recovers on its own as soon as descriptors free up — no restart,
no operator action beyond fixing the cause. `culvert_socks5_accept_degraded`
returns to 0 on the first successful accept, never on a timer.

---

## Reading the logs

The accept-error line is **rate-limited**: the first error of an episode is
logged immediately, then at most one line every 30 s, then one recovery line.

```
SOCKS5 accept error (process_fd_limit): accept tcp [::]:1080: accept4: too many open files; retrying in 1s
SOCKS5 accept recovered after backing off to 1s (2841 further error lines suppressed)
```

The suppressed count is the magnitude — `culvert_socks5_accept_errors_total`
carries the exact figure. A `FATAL` line means the accept loop stopped; the supervisor then rebinds:

```
SOCKS5 accept FATAL (listener_socket_invalid): ... — listener closed, SOCKS5 is unavailable until restart
```

The bind-failure line is rate-limited the same way — first failure immediately,
then at most one line per 60 s, then a recovery line carrying the suppressed
count:

```
ERROR SOCKS5 listener on port 11080 could not bind (port_in_use): listen tcp :11080: bind: address already in use — retrying in 878ms; the HTTP/HTTPS proxy data plane and the admin UI are unaffected
SOCKS5: listener on port 11080 bound and accepting again (4 suppressed bind-failure log line(s))
```

---

## Reason classes

The reason is a bounded classification, not the raw error (the raw error is in
the log line; it is kept out of the alert so webhook dedup works, and out of
`/readyz` because that endpoint is unauthenticated).

| Reason | errno | Retried? |
|---|---|---|
| `process_fd_limit` | EMFILE | yes |
| `system_fd_limit` | ENFILE | yes |
| `kernel_memory` | ENOBUFS, ENOMEM | yes |
| `connection_aborted` | ECONNABORTED | yes |
| `listener_socket_invalid` | EBADF, ENOTSOCK, EINVAL, EFAULT, ENOTCONN | **no** — loop stops |
| `accept_error` | anything else | yes (fail-safe default) |
| `listener_closed_unexpectedly` | — the listening socket was closed outside the shutdown path | **no** — loop stops |

`listener_closed_unexpectedly` is not a kernel error: it means the accept loop
found the listener already closed without a shutdown having been requested. It
is reported DOWN rather than treated as a clean stop, so a dead listener can
never leave every probe green. A normal shutdown produces no row, no alert and
no `listener_up 0`.

---

## When the listener cannot bind

Reason classes for a bind failure (same vocabulary as the admin UI listener, so
either runbook reads the same):

| Reason | errno | What it usually is |
|---|---|---|
| `port_in_use` | EADDRINUSE | A predecessor container still draining, a host-network service, a second Culvert, or an operator port collision |
| `permission_denied` | EACCES, EPERM | A privileged port (<1024) on a deployment that dropped `CAP_NET_BIND_SERVICE` or stopped running as root |
| `address_unavailable` | EADDRNOTAVAIL | Binding before the interface is up — an ordinary host-boot race that clears itself |
| `descriptors_exhausted` | EMFILE, ENFILE | See the descriptor section above |
| `network_error` | — a genuine network timeout | Rare for a bind |
| `listen_failed` | anything else | Check the log line for the raw error |

What to do:

1. **Find the owner of the port.**
   ```
   ss -ltnp 'sport = :1080'      # or: lsof -iTCP:1080 -sTCP:LISTEN
   ```
2. **If it is a predecessor Culvert**, it is still draining; the listener binds
   on its own within 30 s. Nothing to do.
3. **If the reason is `permission_denied`**, either move SOCKS5 to a port above
   1024 (`-socks5-port`, or `proxy.socks5_port`) or grant the capability:
   ```yaml
   services:
     proxy:
       cap_add: [NET_BIND_SERVICE]
   ```
4. **Check `validatePortCollisions` is not the answer you are looking for.** It
   only compares Culvert's own proxy / UI / SOCKS5 ports to each other. It
   cannot see anything else on the host, which is why a collision with an
   unrelated service surfaces here rather than at startup validation.

Retries are bounded in **rate** (1 s doubling to 30 s, ±20% jitter), never in
count: the listener keeps trying for the life of the process, and every attempt
is accounted for by the counter even though only one line per minute is logged.

---

## See also

- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-23.md` — the full finding
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §22 (accept loop, CHAOS-54) and §36
  (bind, CHAOS-66), register rows PX-16 … PX-20
- `docs/operator/admin-ui-listener-recovery.md` — the same finding on the admin
  plane (CHAOS-57); the two listeners share a reason vocabulary
