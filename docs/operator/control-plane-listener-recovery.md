# Control Plane gRPC listener — recovery and health

CHAOS-71. Companion runbooks: `admin-ui-listener-recovery.md` (the same fault
class on the admin UI listener) and `socks5-listener-health.md` (on the SOCKS5
listener).

## What changed, and why you may have seen this as a crash loop

Before CHAOS-71, **every** way the Control Plane's gRPC listener could fail to
come up terminated the whole appliance. The bind ran from `initCluster`, which
executes *before* the admin UI and the proxy data plane start, so the process
exited with:

- no HTTP/HTTPS proxy,
- no admin UI,
- no health endpoint,

recoverable only with shell access — and, under `restart: unless-stopped`, as
an unattended crash loop. Reproduced against the real binary:

```
WARN ControlPlane: gRPC :19443 (insecure — all cluster data unencrypted!)
ControlPlane gRPC: gRPC listen: listen tcp :19443: bind: address already in use
→ exit 1,  proxy http_code=000,  admin UI http_code=000
```

A Control Plane listener that cannot bind now **degrades instead of exiting**.
The node keeps proxying, its admin UI stays reachable, and a supervisor retries
the bind in the background until it succeeds.

### What an operator should expect now

| | Before | After |
|---|---|---|
| This node's proxy | **dead** | serving |
| This node's admin UI | **dead** | reachable |
| Health/metrics endpoints | **dead** | serving, and reporting the fault |
| Enrolled Data Planes | last-good policy | last-good policy (unchanged) |
| Node enrollment | unavailable | unavailable (unchanged) |
| Recovery | manual, shell only | automatic on the next successful bind |

The Data Plane consequence is unchanged, and it is the posture the register
already documents as deliberate (HA-1): a Data Plane that cannot reach its
Control Plane keeps enforcing its last-good policy. Process death produced the
*same* DP outcome while additionally destroying this node's data plane and your
ability to see or fix anything.

> **Process death is not "fail closed."** It picks no posture — it delegates
> the choice to your topology. An explicit-proxy fleet loses all egress; a
> PAC/WPAD fleet with a `DIRECT` fallback, or a transparent deployment, goes
> **unfiltered**.

## Where to look

All of these ride the **proxy** port, deliberately: the Control Plane's own
gRPC endpoint cannot tell you that the Control Plane's gRPC endpoint is
unreachable.

### `/health` (proxy port) — `control_plane_grpc`

A fixed five-value enum:

| Value | Meaning |
|---|---|
| `disabled` | this node is not configured as a Control Plane |
| `ready` | the listener is bound and serving |
| `degraded` | the bind is failing and is being retried |
| `unavailable` | failing continuously for longer than 30s, or terminally down |
| `stopped` | the listener was shut down cleanly |

### `/ready` (proxy port) — the `control_plane_grpc` row

**Report-only.** A node whose Control Plane listener cannot bind is proxying
perfectly, so this row never fails the default readiness verdict — gating it
would eject a healthy gateway from your load balancer over its
cluster-configuration plane, turning a management outage into a traffic
outage. Opt in with `/ready?strict=1` if you want the stricter verdict.

The row is **absent** on a node that is not a Control Plane. Its detail strings
are fixed (`listener rebinding`, `listener unavailable`, `listener down, not
retrying`) because `/ready` is unauthenticated on the proxy port.

### `/api/diagnostics` — the `control_plane_grpc` contract row

Carries the bounded reason class, the consecutive failure count, the episode
duration, and a **per-class** operator action (see the table below).

### `/metrics`

```
culvert_cp_grpc_up                     1 while serving, 0 otherwise
culvert_cp_grpc_unavailable            1 past the 30s threshold, or terminally down
culvert_cp_grpc_bind_failures_total    counter
culvert_cp_grpc_binds_total            counter
culvert_cp_grpc_bind_backoff_seconds   current rebind backoff; 0 while serving
```

These are emitted **only when a CP gRPC address is configured**. A `0` on a
standalone proxy that never asked to be a Control Plane would be
indistinguishable from a broken one, and the paging rule below is `== 0`.

**Suggested alerting rule:**

```promql
# The listener has been down long enough that it is not an ordinary redeploy.
culvert_cp_grpc_unavailable == 1
```

Do **not** page on `culvert_cp_grpc_up == 0` alone: it is also 0 during the few
seconds of rebinding that follow a normal restart in which a predecessor
container still holds the port.

### Alert

`controlplane_grpc_unavailable`, fired **once per episode** (not per retry).
Its payload states explicitly that the proxy and admin UI are unaffected —
before CHAOS-71 this condition meant the whole gateway was gone, so if you
remember the old behaviour, do not go looking for a dead data plane.

Subscribe to it on a webhook in **Alerts → Webhooks**.

## Diagnosing by reason class

The reason class is matched from the kernel errno (`errors.As` on
`syscall.Errno`), never from error text. Each class has its own remedy,
because a node out of descriptors and a node with an occupied port need
different actions.

| Class | What happened | What to do |
|---|---|---|
| `port_in_use` | something already holds the port | `ss -ltnp` — commonly a predecessor container still draining, a second Culvert, or another service |
| `permission_denied` | this process may not bind it | grant `CAP_NET_BIND_SERVICE`, run as a user that may bind it, or move above port 1023 |
| `address_unavailable` | the address is not available on this host yet | an interface that has not come up, or an address not local to this machine |
| `descriptors_exhausted` | the process is out of file descriptors | raise `LimitNOFILE` / `ulimit -n` and look for a leak — other subsystems are degrading too, whatever their own rows say |
| `tls_certificate` | the mTLS cert/key pair could not be loaded | **if a rotation is in flight, do nothing** — it clears on the next attempt; otherwise check `-cp-grpc-cert` / `-cp-grpc-key` exist, are readable, and are a matching PEM pair |
| `network_error`, `listen_failed` | unrecognised | check the server log, which is the only place the raw error is written |

In every case the listener **rebinds automatically** once the fault clears — no
restart required.

### Certificate rotation needs no action

`-cp-grpc-cert` / `-cp-grpc-key` are read **on every attempt**, so a
certbot / cert-manager / Docker-secret rotation that briefly truncates or
re-permissions the pair self-heals. Pre-CHAOS-71 that window was a fatal boot:

```
ControlPlane gRPC: gRPC TLS: tls: failed to find any PEM data in key input
→ exit 1
```

## Retry cadence

- 1s, doubling to a 30s ceiling, with ±20% jitter (a fleet restarting together
  must not aim a synchronised herd of rebind attempts at the same instant).
- **Rate-bounded, never count-bounded.** The retry never gives up, because the
  terminal state of "give up" is a Control Plane that will not return without a
  restart — the outcome this change exists to remove. It is never *silent*: the
  first failure logs immediately, then at most one line per 60s, then one
  recovery line naming the suppressed count.
- The sleep is interruptible, so a shutdown never waits out a backoff.
- Recovery is declared on **observed evidence only** — a listener that actually
  bound. Elapsed time never clears the state.

A successful rebind logs:

```
ControlPlane: gRPC listener bound and serving again on :19443
  (3 suppressed bind-failure log line(s)) — Data Planes can sync config
```

## Port collisions are now refused before boot

`-cp-grpc-addr` is validated against the proxy, admin UI and SOCKS5 ports.
Previously a collision with the **proxy** port was invisible to the validator,
and because the Control Plane binds first, the *proxy* died instead:

```
Proxy error: listen tcp :18082: bind: address already in use    ← pre-fix
```

— sending you to hunt for an external squatter on a port Culvert itself had
just taken. Now:

```
Invalid port configuration: proxy port and ControlPlane gRPC port must not both be 18082
```

This stays a pre-boot refusal: a collision between Culvert's own listeners is
an unambiguous misconfiguration that no retry can resolve.

## Known limits (deliberate, recorded)

- **A listener whose `Serve` ends is not rebound**, only recorded (the row and
  `/health` report it terminally down and name the restart). Owning the full
  bind→serve→rebind lifecycle would restructure `clusterRole.grpcSrv` and
  `StopControlPlaneGRPC`, which CHAOS-56's shutdown gates pin. Register row
  **CL-21**.
- **HA role semantics are unchanged.** A node whose listener is down still runs
  the ADR-0004 resume. In lease mode the fence arbitrates; in legacy
  auto-failover mode a reachable-but-unservable leader is the partition case
  RISK-001 already documents and the resume path already warns about.
- **The rebind supervisor's own panic is terminal** — nothing else retries the
  bind, so the row says so and names the restart that is genuinely required.
