# Graceful shutdown — the envelope, the phases, and what a stall costs

Audience: operators and SREs restarting, upgrading, or draining a Culvert node.

Culvert's SIGTERM path is not a single `Stop()` — it is 17 ordered hooks that
stop accepting traffic, drain what is in flight, and then flush durable state.
This page explains the enforced envelope, what happens when a step stalls, and
what you lose if the process is killed before it finishes.

Related: [`ha-lease-failover.md`](ha-lease-failover.md),
[`ha-lease-recovery.md`](ha-lease-recovery.md),
[`category-store-recovery.md`](category-store-recovery.md).

---

## 1. The envelope

| Phase | Budget | What runs | Cost of losing it |
|---|---|---|---|
| **Early** | 12s | HA stop, gRPC graceful stop, CDR client, lifecycle cancel, rate-limit cleanup | A peer retries. Nothing durable. |
| **Drain** | remainder (≈23s) | cluster-store flush, scan sidecar, MCP listeners + telemetry, policy-learning flush, admin UI, SOCKS5, proxy server, H2 GOAWAY, tunnel drain | In-flight requests and tunnels are cut. Clients retry. |
| **Flush** | 10s reserved | syslog, category feed DB (badger), log store, request log, audit log, process log sink | **Durable.** Lost writes, and an unclean badger close the next boot has to quarantine. |

Total envelope **45s**; worst case **51s** (one 3s watchdog grace per late
phase). `docker-compose.yml` sets `stop_grace_period: 60s` to sit above that.

The flush reserve is carved out **up front**. A drain step that will not
return cannot spend it — that is the whole reason the late phase is split.

## 2. What a stall looks like

Every phase carries a real deadline and every hook runs under a watchdog. A
hook that does not return inside its phase (plus the grace) is **abandoned and
named**:

```
Shutdown: hook "community-db-close" did not return after 13.0s — abandoning it and continuing
```

That line is written at the moment of abandonment, not at the end of the
phase, so it reaches the log file even when the stalled hook is near the end
of the sequence.

Abandoning a hook is deliberate and is never worse than the alternative: the
alternative is the container's `stop_grace_period` expiring and SIGKILL
abandoning that hook *plus everything behind it*.

Other lines worth knowing:

| Line | Meaning |
|---|---|
| `ControlPlane: gRPC drain exceeded 8s — force-closed connections` | A Data Plane held a stream open past the graceful budget. Harmless: DPs re-sync on reconnect. Repeated occurrences point at a wedged DP, or at a stalled volume on the CP blocking an `Enroll`/`RenewCert`/`PushAuditEvents` handler. The listeners are shut at this point; the force-close of any remaining transport is asynchronous and completes as the process exits. |
| `Drain budget exhausted: N tunnel(s) still active (force-closed M inspected H2, K hijacked [class=n, …])` | The drain phase ran out before the tunnels finished. The K hijacked tunnels are still force-closed, but the brief settle that lets their `TUNNEL_CLOSED` accounting reach the request log is skipped — investigate the slow hook ahead of the drain, not the tunnels. |
| `Drain timeout: N tunnel(s) still active (force-closed M inspected H2, K hijacked [class=n, …])` | The tunnel drain's own 15s ceiling was reached first. The per-class breakdown says which kind of session held the node (`socks5` is usually somebody's SSH or database tunnel; `websocket` is an application). See `tunnel-drain-on-shutdown.md`. |
| `Shutdown: drained; flushing durable state…` | The last line guaranteed to reach the log. Anything after it races the log sink's own close. |

## 3. Stopping a shutdown that is taking too long

Send **a second SIGTERM or SIGINT**. Until CHAOS-56 this did nothing at all —
`signal.Notify` had taken the Go runtime's default terminate behaviour away
and nothing read the channel again, so the only escalation was `SIGKILL`.

A second signal now exits immediately with status **1**, after flushing the
process log:

```
Second terminated during shutdown — exiting immediately; in-flight tunnels and unflushed state are dropped
```

Use it when you know the delay is a wedged volume and you would rather take
the loss now. Do **not** use it as routine practice — it drops exactly the
durable flushes the flush reserve exists to protect. Exit status 1 is
deliberate: an orchestrator must not record a forced teardown as a clean stop.

## 4. What a SIGKILL costs

If the process is killed before the flush phase completes:

- **Cluster store** — `LastSeen`/`Status` mutations since the last 10th
  heartbeat are lost. Self-corrects on the next heartbeat.
- **Request log** — the queued tail of `requests.jsonl` is lost. This is the
  durable audit record; the in-memory ring is gone too.
- **Audit log** — writes already issued are on disk (the audit path is
  synchronous), but the file descriptor is not released cleanly.
- **Process log** — the in-flight batch in the async sink is lost, *including
  the lines explaining why shutdown stalled*. This is why the envelope matters
  more than it looks: without it, the evidence dies with the process.
- **Category feed DB** — an unclean badger close can leave a torn `MANIFEST`.
  The next boot detects this and quarantines the store rather than
  crash-looping (see [`category-store-recovery.md`](category-store-recovery.md)),
  but categorisation degrades to Layer 1 until the feed re-syncs.

## 5. Tuning

There is deliberately **no runtime knob**. The envelope is a set of constants
in `main_shutdown.go` (`defaultShutdownBudget`) and `runtime_shutdown.go`
(`shutdownHookGrace`), and its only meaningful consumer is the orchestrator's
stop grace. If you raise the envelope you must raise
`stop_grace_period` with it — `TestChaos56_EnvelopeFitsTheContainerStopGrace`
fails the build if the two drift apart.

If you run Culvert under something other than the shipped compose file
(systemd, Kubernetes), set the equivalent grace above **51s**:

- systemd: `TimeoutStopSec=60`
- Kubernetes: `terminationGracePeriodSeconds: 60`

## 6. Deliberately not covered

- **Shutdown metrics.** `/metrics` is scraped on an interval; a process that
  is exiting will not be scraped again, so a `culvert_shutdown_*` series would
  describe a shutdown nobody can read. The log is the record.
- **An unclean-shutdown breadcrumb.** A marker file written at boot and
  removed on a clean stop would let the *next* boot report that the previous
  one was killed — the one signal a SIGKILL cannot destroy. Recorded as a
  follow-up (SD-5); not shipped here.
- **In-flight tunnel handoff.** Long-lived tunnels are cut, not migrated.
  Draining a node before a restart is the operator's job. CHAOS-57 made the cut
  deterministic, accounted and observable across every hijacked-tunnel class
  (`tunnel-drain-on-shutdown.md`) — it did not make it avoidable.
