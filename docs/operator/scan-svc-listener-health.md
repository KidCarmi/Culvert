# Scan sidecar listener — down, flapping, and recovery

**Applies to:** CHAOS-113 and CHAOS-114 (`scan_svc.go`, `scan_svc_listener.go`,
`metrics.go`, `healthcheck.go`, `diagnostics.go`).

This is the fourth and last of the listener runbooks, after
[`admin-ui-listener-recovery.md`](admin-ui-listener-recovery.md) (CHAOS-57),
[`socks5-listener-health.md`](socks5-listener-health.md) (CHAOS-66/102) and
[`cp-grpc-listener-recovery.md`](cp-grpc-listener-recovery.md) (CHAOS-71).

## Why this listener is not like the other three

For the other three, a dead listener costs the availability of that surface.
For this one it costs **a security control on every other node in the
deployment**.

A node started with `-scan-svc-listen` (or `scan_svc.listen`) runs the scan
sidecar: the process other Culvert nodes call to scan response bodies. When
that sidecar is not answering, the callers' `internal/secscan` path classifies
the failure as a transport fault and takes its **fail-OPEN** branch
(`remoteScanFail`, recorded owner decision WK-2b) — the fleet forwards bodies
**unscanned** and keeps serving traffic.

That posture is deliberate and this runbook does not change it. What it means
for you is simple: **on a sidecar host, "the listener is unhealthy" and
"scanning is off for the fleet" are the same sentence.** Treat these signals
with the urgency of a security control that has been disabled, not of a
degraded surface.

## The two failure shapes

| | **Down** | **Flapping** |
|---|---|---|
| What the socket does | will not come back | will not stay |
| Typical cause | another process holds the address; a typo'd `scan_svc.listen`; no permission to bind; descriptors exhausted | the sidecar process dies after binding: scanner-engine init failure (ClamAV socket, YARA rule compile), OOM kill, a container supervisor restart loop |
| `/healthz` `scan_svc` | `down` (or `degraded` inside the threshold) | `flapping` |
| `culvert_scan_svc_listener_up` | `0` | `0` |
| `culvert_scan_svc_listener_flapping` | `0` | `1` |
| Declared after | `30 s` of not serving | `3` serve generations that each died before lasting `60 s`, over at least `30 s` |
| Where to look | the address: `ss -ltnp`, the config, the capabilities | the sidecar's own process log |

**Why the distinction is worth a separate signal.** Until CHAOS-114 a flap had
no signal at all. A flapping sidecar *binds successfully on every cycle*, so
the unavailability predicate every CHAOS-113 surface was keyed on read healthy
for the whole of every serve generation, and the alert — which only fires from
the bind-failure path — was never reached. Measured on the pre-fix tree, a
sidecar that bound and died after 10 ms, for twenty cycles across ten minutes:
**0 alerts**, `/healthz` = `ready` in 20/20 mid-serve samples,
`culvert_scan_svc_listener_up` = `1` in 20/20, while every caller failed open on
every gap. The sidecar's host reported a clean bill of health throughout.

## What to alert on

```promql
# The sidecar cannot serve — scanning is OFF for every caller pointed here.
# Covers both shapes; this is the page.
culvert_scan_svc_listener_up == 0

# Which shape it is, for routing: the port vs. the process.
culvert_scan_svc_listener_flapping == 1

# Durable evidence that survives recovery. A sidecar that flapped and then
# settled leaves the gauges clean and this counter climbing.
increase(culvert_scan_svc_serve_exits_total[15m]) > 3
```

`culvert_scan_svc_listener_up` and `culvert_scan_svc_listener_down` are exact
complements and both account for a flap, so an existing alert on either keeps
working and now catches the flap too. All of these metrics are **absent** on a
node that was never given `scan_svc.listen` — an ordinary proxy exports nothing
here, so `up == 0` can never fire from a node that has no sidecar.

`culvert_scan_svc_unstable_serves` is the current run of serve generations that
died before proving stable. It goes back to `0` the moment one lasts, which
makes it the right thing to graph beside the counter: the counter tells you it
happened, this tells you whether it is happening now.

## The alert

Event `scan_svc_listener_down`, subscribable in **Alerts** as *"Scan sidecar
listener down (this node cannot serve scans)"*. Both shapes use that event,
with a bounded `detail` that distinguishes them:

| `detail` | Meaning |
|---|---|
| `port_in_use`, `permission_denied`, `address_unavailable`, `descriptors_exhausted`, `listen_failed`, `network_error` | a bind failure of that class, sustained past the threshold |
| `flapping` | the address binds and the serve then ends, repeatedly |

One alert per episode, not per retry — a flap that cycles every 30 s pages once,
and is allowed to page again only after a serve generation has lasted `60 s` and
then failed later. The `detail` is a bounded class and never the raw bind error,
because the error text embeds the listen address and the store's dedup key is
`event:detail`; a per-attempt address there is a key that cannot dedup.

## The other surfaces

**`/api/diagnostics`** — the `scan_svc_listener` row (viewer role). This is the
role-gated surface and therefore the detailed one: it names the address, the
bind class or the flap rate, the fail-open consequence, and a remedy chosen for
the actual fault. `warn` while the supervisor is rebinding inside the threshold;
`fail` once down or flapping; `ok` when serving, carrying the cumulative bind
failure and serve exit counts so a history of transient faults stays visible
after recovery.

**`/healthz`** — the `scan_svc` field, one word from a fixed set: `disabled`,
`stopped`, `flapping`, `down`, `degraded`, `ready`. Omitted entirely on a node
that never asked for a sidecar.

**`/ready` on the proxy port** — the `scan_svc` row, **report-only**. A node
whose sidecar listener is unhealthy is proxying its own traffic perfectly, so
gating the default readiness verdict on it would pull a fully-functional gateway
out of the load balancer because the plane that scans for *other* nodes is
down — converting a scanning outage into a traffic outage. Operators who do want
such nodes ejected opt in with `/ready?strict=1`. The detail strings here are
fixed per branch and name no address or error class, because `/ready` is served
unauthenticated on the proxy port.

## Recovery

**Automatic, and it is the supervisor's whole job.** The bind → serve → rebind
loop retries for as long as the process lives: `1 s` doubling to a `30 s`
ceiling with ±25 % jitter, interruptible by shutdown. The ladder is *retained*
across a serve generation that did not last `60 s`, so a crash-looping sidecar
settles at one attempt per 30 s rather than hammering at the floor.

The retry is deliberately unbounded rather than terminal. A sidecar that gives
up is a fleet that fails open until somebody notices, which is exactly the
outcome this supervision exists to remove — and the process also serves its own
proxy, which must keep running.

**Manual steps, by shape:**

*Down.* The remedy string on the diagnostics row names the class. For
`port_in_use`, find the holder (`ss -ltnp | grep <port>`) — most often a
draining predecessor container, in which case the next rebind succeeds on its
own. For `permission_denied`, use a port above 1024 or grant
`CAP_NET_BIND_SERVICE`. For `address_unavailable`, the interface in
`scan_svc.listen` does not exist on this host; correct the setting. For
`descriptors_exhausted`, raise `LimitNOFILE` and investigate the leak — this one
is a symptom of a process-wide condition, not of the sidecar.

*Flapping.* The address is fine; the sidecar process is not. Read its log
around a `ScanSvc: serve loop on … ended after …` line, which carries how long
the generation lasted and the classified reason. Check the scanner engines the
sidecar initializes (the ClamAV socket, YARA rule compilation), then memory —
a sidecar OOM-killed under scan load produces exactly this shape.

**While either lasts**, the fleet is forwarding bodies unscanned. If that is not
acceptable for the window, the lever is at the **callers**, not here: point them
at a healthy sidecar, or switch them to in-process scanning. See
[`scan-capacity-and-timeouts.md`](scan-capacity-and-timeouts.md).

## What is deliberately not reported

- **A graceful stop is not an outage.** `Shutdown` marks the listener stopped;
  the row returns to `ok`, the `/ready` row disappears and nothing alerts. A
  rolling restart of a sidecar host is silent.
- **A single lost socket is not a flap.** One serve generation that dies and is
  replaced by one that lasts is the fault the supervisor exists to heal; it is
  counted on `culvert_scan_svc_serve_exits_total` and nothing pages. The flap
  verdict needs three consecutive short generations precisely so this case
  cannot reach it.
- **A slow redeploy does not page a flap.** A predecessor holding the address
  past the `30 s` threshold legitimately raises the *down* signals while it
  lasts; once the bind succeeds and the serve lasts, every surface returns to
  healthy. The flap episode is tracked separately from the unavailability
  episode specifically so that a bind outage, however long, cannot be
  misreported as a crash loop.

## Residual risk

The posture is still **fail-open**. A supervised, alerting, self-rebinding
sidecar that is genuinely down still means the fleet forwards unscanned bodies.
Supervision shortens the window and these signals make it visible; neither
closes it. The decision to fail open lives at the caller
(`internal/secscan`, WK-2b) and is out of scope here.

The **caller** has no contract row of its own: a node that fails open because
its configured sidecar is unreachable reports a clean diagnostics report. The
signals in this runbook all live on the sidecar's host.
