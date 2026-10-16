# Control Plane gRPC listener — degradation and recovery

**Applies to:** CHAOS-71 (`cp_grpc_bind.go`, `cp_grpc_health.go`,
`cluster_startup.go`).

## The rule this implements

> **A cluster-plane fault must never terminate this node's enforcement plane.**

This is the third application of one rule, after CHAOS-57 (the admin UI
listener) and CHAOS-66 (the SOCKS5 bind):

| Sweep | What used to kill what |
|---|---|
| CHAOS-57 (§33) | the **management** plane killed the **data** plane |
| CHAOS-66 (§36) | a **secondary, opt-in** data plane killed the **primary** one |
| **CHAOS-71 (§41)** | the **cluster** plane — whose job is serving config to *other* nodes — killed this node's data plane, management plane and health endpoints, before any of them existed |

Before this change the Control Plane boot path was:

```go
if err := enableControlPlane(...); err != nil {
        logFatalf("ControlPlane gRPC: %v", err)   // ← os.Exit(1)
}
```

called from `initCluster`, which `main.go` runs **before** `initSOCKS5`,
`startAdminUI` and `buildAndStartProxyServer`. So any failure of the cluster
plane's listener meant the proxy, SOCKS5, the admin UI and `/health` never
started at all.

## What changed

| | Before | After |
|---|---|---|
| gRPC address already bound | process exits 1 | proxy keeps serving; listener rebinds with backoff |
| `-cp-grpc-cert`/`-key`/`-ca` unreadable | process exits 1 | proxy keeps serving; material re-read on every attempt |
| `Serve` returns after a successful bind | one log line, no rebind, **every surface still reported a healthy Control Plane** | counted, classified, rebound |
| Node role while unbindable | n/a (process gone) | `standalone` — never a CP claim without a socket |
| Recovery | restart (in practice a crash loop under `restart: unless-stopped`) | automatic, no restart |
| Visibility | nothing: no metric, no `/health` field, no `/ready` row, no diagnostics row, no alert | all five |

The listener rebinds for as long as the process lives, at a **bounded rate**
(1 s doubling to a 30 s ceiling, ±20 % jitter, interruptible by shutdown). The
attempt count is deliberately unbounded: the terminal state of "give up" is a
fleet whose config plane is gone until somebody restarts it, which is the
outcome this change exists to remove. The retry is never silent — see
*Visibility*.

## Two reproduced triggers

Both were reproduced against the real binary, not reasoned about.

**1. The gRPC address is already bound.** A predecessor container still
draining, a second Culvert, a host service. Note that this is *less* guarded
than the admin UI case: `validatePortCollisions` compares the proxy, UI and
SOCKS5 ports to each other, and the Control Plane gRPC address is not even
among the three it knows about.

```
ControlPlane: config v1791151952 published
ClusterCA: generated new cluster CA (expires 2036-10-01)
ControlPlane gRPC: gRPC listen: listen tcp 127.0.0.1:19443: bind: address already in use
EXIT CODE: 1
proxy  http_code=000      ← the HTTP proxy port never listened
adminui http_code=000     ← the admin UI port never listened
```

**2. The mTLS material cannot be loaded.** `cpServerOption` reads the pair at
call time, so a cert-manager/certbot rotation that briefly truncates, replaces
or re-permissions those files used to be a boot that ended in exit 1. Because
the material is now re-read on **every** attempt, such a rotation self-heals
with no restart.

```
ControlPlane gRPC: gRPC TLS: tls: failed to find any PEM data in key input
EXIT CODE: 1
```

> **Note on posture.** Process death is *not* "fail closed". An explicit-proxy
> fleet loses all egress (total outage); a PAC/WPAD fleet with a `DIRECT`
> fallback, or a transparent deployment that bypasses a dead next hop, sends
> traffic straight out **unfiltered**. Exiting picks neither posture
> deliberately — it delegates the choice to your network topology.

## What is degraded while the listener is down

The blast radius is the **fleet's management**, not anyone's traffic:

* **Unavailable:** config distribution (`GetConfig`/`GetConfigDelta`), node
  enrollment, Data-Plane certificate renewal, DP metric/audit push, HA sync.
* **Unaffected:** this node's HTTP/HTTPS proxy, SOCKS5, admin UI and health
  endpoints — all still enforcing policy.
* **Unaffected:** every enrolled Data Plane keeps serving its **last-good
  config** indefinitely (that is the documented HA-1 posture), so the fleet
  keeps enforcing while the Control Plane is unreachable.

That asymmetry is why the readiness row is report-only and why the alert says
so explicitly.

## The node's role is a claim, and it is only made for a real socket

While the bind is failing this node reports `standalone`, not
`control-plane`. `GET /api/cluster/status`, `/api/diagnostics` and every
internal `role == "control-plane"` gate therefore say what is true.

This preserves an invariant the pre-change code stated in a comment — *"Only
set role after gRPC is successfully started"*. A supervisor that claimed the
role optimistically would have fixed the crash loop by replacing it with an
operational lie, which is precisely the third defect this sweep closed (a dead
listener reporting a healthy Control Plane with its address, forever).

The HA leadership resume rides the same rule: a persisted leader asserts its
term only once the listener has actually bound, because a "leader" no Data
Plane can reach cannot serve `HASync`. On a healthy boot (the bind succeeds on
the first attempt) the ordering is unchanged, and a later rebind never re-runs
the resume.

### HA: a dark leader stops renewing its fencing lease

With the etcd fencing lease armed (ADR-0005), a leader whose CP gRPC listener
has been **unavailable for more than 30 s** — the same threshold that fires
`cp_grpc_listener_down` — or whose listener supervisor has stopped, **withholds
its lease renewal**. It logs `HA: WITHHOLDING fencing-lease renewal …` once,
keeps its write authority only for the remainder of the window etcd last
confirmed, then self-fences (`ha_self_fenced`) before the backend lease lapses.
The standby then acquires the free lease through its normal fence-gated
promotion. If the listener serves again before the window ends, the next
keepalive renews and logs `resuming fencing-lease renewal`.

A listener that is merely rebinding inside the 30 s threshold (an ordinary
rollout) keeps the lease. In legacy mode (no etcd lease) nothing changes.

A self-fenced ex-leader whose listener is still dark is not **auto**-promoted
back (`HA: auto-promotion refused — "Control Plane gRPC listener unavailable …"`),
which would only re-acquire the lease to withhold it again. Manual promotion is
unchanged (break-glass).

A self-fenced node keeps its Control Plane listener (ADR-0005), but with HA
enabled **only the leader answers Control Plane RPCs**: a standby refuses Data
Planes with a retriable `Unavailable`, so they fail over to the new leader
rather than staying on the standby's non-advancing config.

The Control Plane address list that Data Planes use for failover is
republished on every HA transition. A leader whose listener bound late (after a
restart) therefore still publishes its standby's address once HA resumes, and no
manual republish is needed.

That republish can be rejected at commit. Usually this is a config already at
its cluster-sync size cap, which the longer list would push over. When that
happens, the HA transition **still stands**:
- A self-fence or standby entry is never undone, because fencing is the safety
  property.
- Enable, resume and promote keep leadership, because write authority comes from
  the fencing lease and the list is only the Data Planes' failover hint.

Instead, the `config_snapshot_rejected` alert fires and the `cp_address_list`
diagnostics row reports **fail** until a republish succeeds. The node retries in
the background every 1–30 s, so reducing the oversized collection is enough to
clear it; no restart or HA change is needed. While the row is failing, Data
Planes still hold the last committed list.

On the **promote** path the listener is started synchronously: if it cannot
bind, the promotion fails and the node stays a retryable standby rather than
becoming a leader nobody can reach. Once the role is committed the config is
merged into the latest published config so Data Planes receive a CP address
list naming the new leader; if that publish is rejected the promotion fails
instead of reporting success. Because the first bind can land long after boot,
the leadership resume re-reads the persisted HA config at that moment, and no
resume runs once shutdown has begun.

### Rebind backoff

1 s doubling to 30 s (±20% jitter). It is **not** reset by a bind alone — a
socket that dies right after every bind stays at one attempt per 30 s — but it
**is** reset to 1 s after a serve that stayed up for 60 s, so a one-off socket
loss after a long healthy run rebinds promptly.

## Visibility

Everything below is served on the **proxy** port. That is structural, not
incidental: the Control Plane's own gRPC port is the thing being measured, so a
probe against it reports nothing when it is down.

| Surface | Field | Values |
|---|---|---|
| `GET /health` | `cp_grpc` | `ready` · `rebinding` · `unavailable` · `stopped` · `not_configured` (field omitted entirely on a non-CP node) |
| `GET /ready` | `checks.cp_grpc` | report-only row (see below) |
| `GET /metrics` | `culvert_cp_grpc_up` | 1 while serving, 0 otherwise |
| | `culvert_cp_grpc_unavailable` | 1 once the fault passes 30 s |
| | `culvert_cp_grpc_bind_failures_total` | cumulative bind/TLS/serve failures |
| | `culvert_cp_grpc_binds_total` | successful binds (flap counter) |
| | `culvert_cp_grpc_bind_backoff_seconds` | current rebind backoff |
| `GET /api/diagnostics` | `cp_grpc_listener` row | ok / warn / **fail**, with a per-reason operator action |
| | `cp_address_list` row | ok, or **fail** (warn for a transient commit race) while a CP address-list republish is pending |
| Alerts | `cp_grpc_listener_down` | fire-once per episode |

**Every metric in this family is emitted only on a node that asked to be a
Control Plane.** A flat `culvert_cp_grpc_up 0` from every standalone proxy and
every Data Plane in the fleet would be indistinguishable from a broken Control
Plane, and the paging rule below is `== 0`.

### Paging rule

```
culvert_cp_grpc_unavailable == 1
```

Not `culvert_cp_grpc_up == 0`: `up` drops to 0 for the few seconds of rebinding
that follow an ordinary Control Plane rollout. `unavailable` latches only once
the fault has persisted past 30 s.

### The readiness row is report-only, deliberately

`checks.cp_grpc` never gates the default `/ready` verdict. This is the
strongest case in the set: a Control Plane whose gRPC listener cannot bind is
proxying its *own* traffic perfectly, so failing readiness would pull a
fully-functional gateway out of the load balancer because the plane that serves
config to *other* nodes is down — converting a fleet-management outage into the
traffic outage this whole change exists to prevent.

If you *do* want such nodes ejected, call `/ready?strict=1`.

A `cp_grpc_listener_down` page raised during boot, before the alert webhooks
load, is held until they do. If the listener binds in the meantime, the held
page is **dropped**, not delivered late, so you are not paged for a listener
that is already serving. The log records the drop.

### You will need to subscribe to the new alert event

`cp_grpc_listener_down` is a **new** event name. Existing alert webhooks will not
receive it until you add it to their subscriptions — the house rule is that a
new name is silently unsubscribed everywhere. There was no existing event for
this plane to reuse (`admin_ui_unavailable` and `socks5_listener_down` are
specific to their own listeners, and folding the Control Plane into either
would page under the wrong name with the wrong operator action). The name
follows the `<contract-row>_down` convention used by `socks5_listener_down` and
`mcp_gateway_down`. Subscribe in the admin UI (**Alert Webhooks** panel → **+ Add Webhook** or edit → **Control Plane
gRPC listener down**) or via the webhook API. Until you subscribe, the
diagnostics row and `culvert_cp_grpc_unavailable` carry the state.

## Reason classes and what to do about each

The reason is a **bounded class**, never a raw error — the raw error goes to the
rate-limited log line and nowhere else. Each class has its own operator action,
because a node out of file descriptors must not be sent to hunt the owner of a
port nobody holds.

| Class | Meaning | Action |
|---|---|---|
| `port_in_use` | `EADDRINUSE` | Find what holds the address: a predecessor container still draining, a second Culvert, a host service. |
| `permission_denied` | `EACCES`/`EPERM` | A privileged port needs `CAP_NET_BIND_SERVICE`, or use a port above 1024. |
| `address_unavailable` | `EADDRNOTAVAIL` | The address does not exist on this host yet — an interface that is not up, or a literal IP this node does not own. |
| `descriptors_exhausted` | `EMFILE`/`ENFILE` | Out of file descriptors; this affects far more than the Control Plane. Raise the limit and look for a leak. |
| `tls_certificate` | the mTLS pair would not load | Check `-cp-grpc-cert`/`-cp-grpc-key`/`-cp-grpc-ca`. A rotation window clears on its own. |
| `network_error` | a genuine timeout | Network-level investigation. |
| `listen_failed` | nothing above matched | See the rate-limited `ControlPlane gRPC listener` log line for the underlying error. |
| `serve_ended` | the listener was serving and stopped | The listener rebinds. If it recurs, check `culvert_cp_grpc_binds_total` for flapping. |
| `address_publish_rejected` | the socket bound, but publishing the CP address list to the fleet was rejected at commit | See `config_snapshot_rejected` / LastPublishError — usually a config at its sync size cap. Activation is refused (role rolled back) rather than leaving Data Planes on a stale address list; it retries. |

Classes are matched in a fixed order: the explicit stage tags
(`tls_certificate`, `address_publish_rejected`) come before the errno classes. So
an unreadable certificate file, which is a wrapped `EACCES`, reports
`tls_certificate` and not the bind-port `permission_denied`.

In **every** class two things are true and the operator action says so: the
listener rebinds by itself (so a restart costs an outage to achieve what is
already in progress), and this node's proxy data plane and admin UI are
unaffected.

### Recovery means a stable serve, not a bind

A bind after a failure does **not** close the outage. The listener reports
"bound and serving again, stabilizing" (diagnostics row ok, `/health` `ready`),
and the outage closes only once it has served for 60 s. If its socket keeps
dying right after each bind, the cycles count as one outage: it crosses the
30 s threshold, pages once and, in lease mode, stops renewing the fencing lease
so the standby takes over.

## The one state that does *not* recover on its own

If the supervisor goroutine itself panics, nothing rebinds. The same terminal
state is used — reason `role_conflict` — when a delayed bind finds that this node
has meanwhile become a **Data Plane**: the Control Plane listener refuses to
replace an established role and stops (fix the CP/DP configuration, then
restart). The reverse also holds: if the Control Plane claimed the role first,
Data-Plane startup is refused and the DP client does not start. In both orders
the role claimed FIRST wins, and the `cluster_posture` diagnostics row reports
*"cluster role conflict"* as FAIL until the node is reconfigured and
restarted. Either way it is reported distinctly:

* diagnostics row: *"supervisor stopped … and will **NOT** rebind"*, and its
  operator action is the only one in this family that tells you to **restart
  the node**;
* the alert says the same.

The two states are kept separate precisely because they point at opposite
actions. Do not restart a node whose row says the listener is rebinding. If a
listener that was already paged as *retrying* then turns terminal, you are
paged **again** with the restart instruction — the terminal alert has its own
latch. On a terminal exit the node also gives up the Control Plane role and
the fleet's address list stops naming it.

## Runbook

**You are paged with `cp_grpc_listener_down`.**

1. Confirm the blast radius first — it is almost certainly *not* a traffic
   incident:
   ```
   curl -s http://<node>:<proxy-port>/health | jq '{status, cp_grpc}'
   ```
   `status: "ok"` with `cp_grpc: "unavailable"` means this node is proxying
   normally and only the cluster plane is down.
2. Get the reason class and the remedy:
   ```
   curl -s -u <admin> http://<node>:<ui-port>/api/diagnostics \
     | jq '.checks[] | select(.code=="cp_grpc_listener")'
   ```
3. If the row says the **supervisor stopped and will not rebind**, restart the
   node. Otherwise do **not** restart — fix the underlying fault and the
   listener picks it up within 30 s.
4. Check the fleet is still enforcing (it should be — Data Planes serve
   last-good config):
   ```
   curl -s http://<dp-node>:<proxy-port>/ready | jq '.checks'
   ```
5. The underlying error is in the node's log, rate-limited to one line per
   minute:
   ```
   docker compose logs proxy | grep 'ControlPlane gRPC listener'
   ```

**A Data Plane reports it cannot reach its Control Plane.** Check the CP node's
`cp_grpc` field as in step 1 before investigating the network: the listener may
simply not be bound.

## Deliberately not changed

* **`logFatalf("Proxy error")` (main.go).** Correct and must stay. The proxy
  *is* the product, and a gateway that cannot serve must exit loudly rather
  than linger as a black hole. The asymmetry between the cluster plane and the
  primary data plane is the whole finding.
* **`armHALease`'s fatal.** Also correct. A malformed fencing-lease config that
  silently fell back to legacy would be an invisible safety *downgrade* — the
  operator asked for fencing and would not get it. That is a fault whose only
  safe resolution is refusing to run, which is exactly the test this sweep
  applies to the listener and the listener fails.
* **The Data Plane's own boot fatals** (`dp_enrollment.go`). The same class one
  plane over, and a different posture decision: *may a node that cannot reach
  its Control Plane serve traffic at all?* Recorded as register row **CL-23**.
