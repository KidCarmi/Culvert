# SOCKS5 listener health

*Applies to nodes started with `-socks5-port` (or `proxy.socks5_port` in
`config.yaml`). On a node without it, every surface below reports the feature as
absent and no metrics are emitted.*

Culvert's SOCKS5 listener runs its own accept loop. Since CHAOS-54 that loop
backs off on accept failures instead of retrying at syscall speed, and reports
its state on four surfaces. This page is what to do when one of them goes
non-green.

---

## The two states, and why they are different

| State | Meaning | Recovers by itself? | What you do |
|---|---|---|---|
| **degraded** | `accept(2)` has been failing continuously for more than 30 s. The loop is still retrying, backed off to at most one attempt per second. | **Yes** — the moment the underlying condition clears | Raise or investigate the descriptor limit; no restart needed |
| **down** | The listening socket itself is no longer valid. The loop has stopped and closed the socket, so clients now get connection-refused rather than hanging. | **No** | Restart the node; check the logs for the socket fault |

Do not collapse these. They point at opposite actions.

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
| `culvert_socks5_listener_up` | `1` while the accept loop is running; `0` once it has stopped |
| `culvert_socks5_accept_errors_total` | Cumulative accept errors since startup |
| `culvert_socks5_accept_degraded` | `1` while failing for longer than the threshold |
| `culvert_socks5_accept_backoff_seconds` | Current retry backoff; `0` when accepts are succeeding |

**Alerts** — `socks5_listener_down`, fired **once per episode** (not once per
retry) when the listener degrades or dies. Subscribe to it in the webhook
editor: *"SOCKS5 listener not accepting connections"*.

### Suggested paging rules

```
# Dead listener — restart required.
culvert_socks5_listener_up == 0

# Sustained accept failure — usually descriptor exhaustion.
culvert_socks5_accept_degraded == 1

# Leading indicator: transient accept errors that keep coming back.
rate(culvert_socks5_accept_errors_total[15m]) > 0
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
carries the exact figure. A `FATAL` line means the loop stopped:

```
SOCKS5 accept FATAL (listener_socket_invalid): ... — listener closed, SOCKS5 is unavailable until restart
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

## See also

- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-23.md` — the full finding
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §22, register rows PX-16 … PX-20
