# Control Plane gRPC listener health

*Applies to nodes started with `-cp-grpc-addr` (or `cluster.grpc_addr` in
`config.yaml`), and to a standby that has been promoted to leader. On a
standalone proxy or a Data Plane node every surface below reports the feature as
absent and no `culvert_cp_grpc_*` metrics are emitted — a flat zero there would
be indistinguishable from a dead Control Plane.*

The Control Plane's gRPC listener is how the whole fleet reaches this node:
every Data Plane fetches its config, enrolls, renews its client certificate and
pushes its audit events over it. Since CHAOS-73 the listener owns its whole
lifecycle — bind, serve, rebind — and neither half of a failure is fatal to the
process or silent.

> **Changed in CHAOS-73, two things.**
>
> **A bind failure used to call `logFatalf`, which exits the process** — and
> `initCluster` runs *before* the HTTP/HTTPS proxy listener, SOCKS5 and the
> admin UI start. An occupied gRPC port, or a certificate pair caught
> mid-rotation, therefore took down the **entire appliance**: no proxy, no admin
> UI, no health endpoint, and under `restart: unless-stopped` an unattended
> crash loop recoverable only with shell access. Reproduced against the real
> binary: exit 1, with the proxy, the admin UI and `/health` all unreachable.
>
> **A serve-loop death used to be one log line and nothing else.** If the
> accept loop died on a non-recoverable fault, the goroutine exited while this
> node kept reporting `role: "control-plane"` on `/api/cluster/status`, with its
> grpcAddr and its full enrolled-node list, while no Data Plane could reach it.
> Every probe was green on a dead listener.
>
> **No CP gRPC listener fault requires a node restart any more** — with one
> exception, `tls_required`, which is a configuration problem and is reported as
> its own state precisely so the two are not confused.

---

## What is and is not affected

This is the single most important thing to get right when one of these surfaces
goes non-green, because the instinct is to reach for the wrong lever.

| | Affected? |
|---|---|
| This node's HTTP/HTTPS proxying | **No.** Policy is still enforced, traffic still flows. |
| This node's SOCKS5 listener | **No.** |
| This node's admin UI | **No.** You can still log in and configure this node. |
| Data Plane config sync | **Yes.** DPs cannot fetch config and run on last-known-good, which ages for the length of the outage. |
| New node enrollment | **Yes.** `Enroll` is served over this listener. |
| DP client-certificate renewal | **Yes.** A long outage risks DP certificates expiring — see below. |
| Centralized audit trail | **Yes.** DPs queue audit events and eventually drop the oldest; `culvert_audit_cluster_push_drops_total` on the DP counts the gap. |

**Do not take this node out of the load balancer.** The `/ready` `cp_grpc` row
is deliberately *report-only* for exactly this reason: a Control Plane whose
gRPC listener is down is still a perfectly good gateway, and ejecting it would
turn a cluster-control outage into a traffic outage. If you *do* want such nodes
ejected, probe `/ready?strict=1`.

---

## The states

| `/health` `cp_grpc` | Meaning | Recovers by itself? | What you do |
|---|---|---|---|
| `disabled` | Not a Control Plane node. | — | Nothing. |
| `ready` | The listener is serving. | — | Nothing. |
| `degraded` | The listener cannot bind (or has just stopped serving) and is retrying, backed off to at most one attempt per 30 s. Under 30 s old. | **Yes**, as soon as the cause clears | Usually nothing — a predecessor container still draining clears on its own. |
| `unavailable` | The same, for more than 30 s. The fleet is now affected. | **Yes**, once the cause clears | Work the reason class below. |
| `stopped` | The loop exited because the node is shutting down. | — | Nothing. |

Degradation is a **duration, not a count**: the backoff reaches its 30 s ceiling
in well under a minute, so paging on attempts would page on every ordinary
redeploy. Recovery is declared only on an **observed successful bind** — never
on elapsed time, because a loop that has stopped failing because it stopped
attempting looks identical to a healthy one.

---

## Surfaces

All of them are served on the **proxy port**, not the gRPC port. That is
deliberate: a listener cannot report that it is unreachable, and the Data Plane
side of this link already has `cp_poll` to say *"I cannot reach my Control
Plane"* while the Control Plane side had nothing to say *"my listener is
dead"*. If every DP in your fleet reports a `cp_poll` failure and the CP looks
healthy, that asymmetry is what you were seeing — check `cp_grpc` first.

| Surface | Where |
|---|---|
| Posture | `GET /health` → `cp_grpc` (unauthenticated; fixed enum, no resolution detail) |
| Readiness row | `GET /ready` → `checks.cp_grpc` (report-only; fixed detail strings) |
| Operator contract row | `GET /api/diagnostics` → `cp_grpc_listener` (role-gated; carries the reason class, attempt count and the remedy) |
| Cluster panel / API | `GET /api/cluster/status` → `cpGRPCStatus`, `cpGRPCServeExits`, `cpGRPCListenFailures`, `cpGRPCReason` |
| Metrics | `GET /metrics` → `culvert_cp_grpc_*` |
| Alert | `cp_grpc_listener_down`, fire-once per episode (subscribe in **Alert Webhooks**) |
| Logs | One line at onset, then at most one per minute, then a recovery line naming how many were suppressed |

### Metrics

```
culvert_cp_grpc_up                      1 while serving, 0 while not (including while rebinding)
culvert_cp_grpc_unavailable             1 once the fault has persisted past 30s
culvert_cp_grpc_listen_failures_total   bind/serve failures since startup
culvert_cp_grpc_binds_total             successful binds since startup
culvert_cp_grpc_serve_exits_total       serve-loop exits that were not a shutdown
culvert_cp_grpc_listen_backoff_seconds  current rebind backoff; 0 while serving
```

**Page on `culvert_cp_grpc_unavailable == 1`**, not on `up == 0`: `up` goes to 0
for the few seconds of rebinding that follow an ordinary redeploy, whereas
`unavailable` is latched only after the fault has persisted. Both series are
absent on a node that is not a Control Plane, so write the rule so that absence
is not an alert.

`culvert_cp_grpc_serve_exits_total` is worth a separate, low-urgency rule even
when `up` is 1. A non-zero value means the accept loop died and was rebuilt —
before CHAOS-73 that was one log line and no durable evidence at all.

---

## Reason classes and what each one means

The reason class appears on the `/api/diagnostics` row, in the alert and in the
log line. It is a **bounded** vocabulary: the raw error only ever goes to the
log. Each class carries its own remedy — if you are reading a generic one, you
are on an older build.

| Class | Cause | Fix |
|---|---|---|
| `port_in_use` | Something else holds the port. A draining predecessor container, a second Culvert, an unrelated service. | `ss -lptn 'sport = :50051'` (or `lsof -i :50051`) and stop it, or move Culvert with `-cp-grpc-addr`. A draining predecessor clears on its own. |
| `permission_denied` | The process may not bind this port — typically a privileged port (<1024) without root and without `CAP_NET_BIND_SERVICE`. | Grant the capability, or pick a port above 1024. |
| `address_unavailable` | The configured address does not exist on this host — an interface not up yet, or an IP this node does not own. | Check `-cp-grpc-addr` against the host's real addresses. Binding `:PORT` (all interfaces) avoids it. |
| `descriptors_exhausted` | The process is out of file descriptors and cannot create the socket. | Raise `LimitNOFILE` / `ulimit -n`, and look for a descriptor leak — the process log records what exhausted them. |
| `tls_certificate` | `-cp-grpc-cert`/`-cp-grpc-key` could not be loaded. | Check both files exist, are readable by this process and contain valid PEM. **A rotation that briefly truncates them self-heals** — the pair is re-read on every attempt. |
| `tls_required` | No Control Plane TLS material was configured and `--cluster-insecure` was not set. | **This one does NOT recover on its own.** Supply `-cp-grpc-cert`/`-cp-grpc-key` (production), or `--cluster-insecure` for development only, and restart. |
| `network_error` | A genuine network timeout. | Transient; investigate if it persists. |
| `listen_failed` | Something the classifier does not recognise. | Read the full error on the log line naming this class. |

---

## Certificate rotation

The gRPC certificate pair is re-read on **every** bind attempt. A rotation that
momentarily truncates, replaces or re-permissions the files produces a few
seconds of `degraded` with reason `tls_certificate`, and then the listener binds
with the new material on its own. No restart, no manual step.

Before CHAOS-73 that same window killed the process, and because the window was
over by the time the container restarted it usually looked like a one-off crash
with no cause — or, if the rotation left the pair broken, a permanent crash loop.

---

## How long do I have?

The outage is bounded in practice by whichever of these comes first:

1. **Config staleness.** DPs keep enforcing last-known-good config, so an edit
   you make on the CP during the outage does not reach the fleet. The DP side
   reports this as its `cp_poll` row and `dp_last_known_good_config`.
2. **DP client-certificate expiry.** Renewal runs over this listener. Check the
   DP-side `node_cert` row for the margin you actually have; this is the one
   that turns a recoverable outage into a re-enrollment exercise.
3. **Centralized audit gaps.** A DP's push queue is capped at 1000 entries and
   drops the **oldest** first, counted by `culvert_audit_cluster_push_drops_total`
   on the DP. The node's own local audit file is unaffected.

None of these is affected by this node's own proxying, which continues
throughout.

---

## HA interaction

**Leadership follows the listener.** If a node persisted as HA *leader* restarts
into a bind failure, it does not assert leadership while it cannot be reached —
it serves proxy traffic, retries the listener, and resumes leadership once the
listener is actually up. The two alternatives were both worse: dropping the
resume means the pair ends up with no leader at all (with auto-failover off, the
default), and resuming it anyway means asserting leadership, the fencing epoch
and the persisted role on a node no Data Plane can reach — and, in a
fencing-lease deployment, holding the lease that stops anyone else leading.

A standby's **promotion** is unchanged: if its `onPromote` cannot start the gRPC
listener, the promotion fails, the node stays standby and stays retryable. That
behaviour predates CHAOS-73 and is deliberately untouched.

---

## If a serve loop dies and comes back

`culvert_cp_grpc_serve_exits_total` increments and the listener rebinds. A node
whose listener dies immediately after each successful bind escalates its backoff
monotonically rather than resetting it, so the pathological case is bounded at
one bind attempt per 30 s rather than a tight bind-die-bind loop. The
`/api/diagnostics` row keeps the serve-exit count visible after recovery, which
is how you tell "one blip at 03:00" from "this has happened forty times".

---

## What is still a real restart

- `tls_required` — a configuration refusal. Nothing on the host will change to
  make it succeed.
- The supervisor goroutine itself panicking. It is contained (the process
  survives) and reported, but nothing rebinds afterwards.

Everything else rebinds on its own.
