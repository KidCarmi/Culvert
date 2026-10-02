# Control Plane gRPC listener: bind faults and recovery

**Audience:** operators running Culvert in a Control Plane / Data Plane cluster.
**Scope:** what happens when a Control Plane node cannot open its cluster gRPC
listener, how it recovers, and what each surface means. Finding: CHAOS-71
(`roadmap/CHAOS-ENGINEERING-REVIEW.md` §41).

---

## 1. What changed, and why you care

Before this change, **every** way the Control Plane's gRPC listener could fail
to come up terminated the whole appliance. The activation runs early in startup
— before the proxy listener, the admin UI, the SOCKS5 listener and every health
endpoint exist — so the outcome was an unattended crash loop with no proxy, no
admin UI, no `/health`, and no way in except a shell.

Two routine events triggered it:

- the gRPC port already held by something else (a predecessor container still
  draining, a host service, a second Culvert, an operator collision);
- the mTLS pair momentarily unreadable, which is what a certbot / cert-manager
  / Docker-secret rotation looks like between truncate and write.

Now the listener is **supervised**: a bind fault degrades the cluster control
plane alone. This node keeps proxying, keeps its admin UI, and retries the bind
until it succeeds.

> **The cluster semantics did not change.** A Control Plane that is not serving
> gRPC looks to the fleet exactly like one that is unreachable — a state Data
> Planes already handle: they back off, report it on `/ready cp_poll`, and
> **keep enforcing their last-known configuration**. A node that has not bound
> deliberately does **not** take the control-plane role or resume leadership,
> so a standby's automatic failover behaves precisely as it did when the old
> code exited: one leader, no ambiguity.

---

## 2. What is affected while the listener is down

| Affected | Not affected |
|---|---|
| Config distribution to Data Planes (they keep their last-known config) | This node's HTTP/HTTPS/SOCKS5 proxying and policy enforcement |
| Enrollment of **new** nodes | This node's admin UI and admin API |
| Data Plane certificate **renewal** | `/health`, `/ready`, `/metrics` on the proxy port |
| DP→CP audit push and metrics push (queued on the DP, bounded) | Existing DP mTLS sessions until their certificates expire |

**Do not restart the node to fix this.** A restart costs this node's egress and
achieves nothing the supervisor is not already doing. The one exception is a
supervisor panic — see §6.

---

## 3. Surfaces

All of these are emitted **only on a node configured as a Control Plane**. On an
ordinary standalone appliance they are absent, so a zero can never be confused
with a dead listener.

### `/health` (proxy port, unauthenticated)

`cluster_grpc` carries a fixed five-value posture:

| Value | Meaning |
|---|---|
| `disabled` | this node is not a Control Plane |
| `ready` | the listener is serving |
| `degraded` | not serving, retrying, under the 30 s unavailability threshold |
| `unavailable` | not serving for longer than 30 s |
| `stopped` | the supervisor exited because the node is shutting down |

The posture is public; the *resolution* (attempt count, reason class) is not —
it stays on the role-gated diagnostics row, the alert and the logs.

### `/ready` (proxy port)

A `cluster_grpc` row appears, and it is **report-only**: it never changes the
default verdict. That is deliberate. A node whose cluster listener cannot bind
is proxying perfectly, so gating readiness on it would eject a fully working
gateway from the load balancer over a plane that has nothing to do with serving
traffic — turning a control-plane fault into a traffic outage. Callers that *do*
want such nodes ejected opt in with `/ready?strict=1`.

### `/api/diagnostics` (admin, role-gated)

The `cluster_grpc` operator-contract row. Severity:

- **ok** — not a Control Plane, shutting down, or serving (carrying the
  cumulative transient-failure count, so a history of blips stays visible).
- **warn** — failing but under 30 s. Still retrying; a draining predecessor
  clears on its own.
- **fail** — unavailable for longer than 30 s, with the reason class, the
  consecutive attempt count, whether the role has been asserted, and a remedy
  chosen **per reason class**.

### `/metrics` (proxy port)

```
culvert_cluster_grpc_up                    1 while serving, 0 otherwise
culvert_cluster_grpc_unavailable           1 past the 30 s threshold
culvert_cluster_grpc_role_asserted         1 once the control-plane role is held
culvert_cluster_grpc_bind_failures_total   cumulative bind failures
culvert_cluster_grpc_binds_total           cumulative successful binds
culvert_cluster_grpc_bind_backoff_seconds  current rebind backoff; 0 while serving
```

These ride the **proxy** port, which is what makes them reachable at all while
the cluster plane is down — the cluster gRPC endpoint cannot report that the
cluster gRPC endpoint is unreachable.

**Paging rule:** alert on `culvert_cluster_grpc_unavailable == 1`, not on
`up == 0`. `up` is 0 during the few seconds of rebinding that follow any
ordinary redeploy of a CP container; `unavailable` latches only after the fault
has persisted past the threshold.

A sustained `culvert_cluster_grpc_up 0` **with**
`culvert_cluster_grpc_role_asserted 0` is the signal that this node is a
configured Control Plane that has never served. That pair is what distinguishes
"came up and fell over" from "never came up at all".

### Alert

`cluster_grpc_unavailable`, **fired once per episode** and cleared only by an
observed bind, so a second incident pages again. The payload carries the bounded
reason class and the blast radius in both directions. It never carries the
listener address or the raw error — the alert store deduplicates on the detail
text, so an address-bearing detail would mint one key per failure and crowd out
real security alerts.

> **If you have existing webhook subscriptions, they will not receive this
> event** until you add it: subscriptions match the event name exactly. The
> diagnostics row, the readiness row and the metrics above are the signal in the
> meantime.

### Log

The onset of an episode is always logged, then at most one line per minute, then
one recovery line naming how many lines were suppressed. The **full** error
appears only here; every other surface carries the bounded class.

```
ERROR ControlPlane: gRPC listener on 10.0.0.5:50051 could not start (port_in_use):
  gRPC listen: listen tcp 10.0.0.5:50051: bind: address already in use — retrying in 1.113s.
  This node is NOT acting as a Control Plane until it binds, so a standby is free to lead.
  The proxy data plane and the admin UI are unaffected, and Data Planes keep enforcing
  their last-known config.
...
ControlPlane: gRPC listener on 10.0.0.5:50051 is serving again (3 suppressed bind-failure log line(s))
ControlPlane: enabled via startup (gRPC 10.0.0.5:50051)
```

---

## 4. Retry cadence

1 s on the first failure, doubling to a 30 s ceiling, with ±20% jitter so a
cluster restarting together does not aim a synchronised herd of rebind attempts
at one instant. Retries are bounded in **rate**, never in count: giving up would
mean a fleet that never receives configuration again until someone restarts the
appliance, which is the outcome this change exists to remove. The backoff is not
reset on a successful bind, so a socket that dies immediately after every bind
settles at one attempt per 30 s rather than hammering.

The mTLS pair is re-read on **every** attempt, so a rotation that completes
self-heals with no restart.

The retry sleep is interruptible: shutdown never waits out a backoff.

---

## 5. Reason classes and what to do

| Class | Cause | Action |
|---|---|---|
| `port_in_use` | something else holds the address | `ss -ltnp` / `lsof -i` to find the owner — commonly a predecessor container still draining, a host-network service, or a second Culvert. Free the address or move the Control Plane. |
| `permission_denied` | this process may not bind the address | A privileged port needs `CAP_NET_BIND_SERVICE`, or use a non-privileged address. Check whether the deployment stopped running as root or dropped the capability. |
| `address_unavailable` | the address does not exist on this host | Usually a bind racing an interface still coming up, or an address that moved. Confirm the interface is up and the address is local. |
| `descriptors_exhausted` | out of file descriptors | Raise `LimitNOFILE` / `ulimit -n` and look for a descriptor leak. The cluster listener is a symptom here, not the cause. |
| `tls_certificate` | the mTLS material could not be loaded | Most often a rotation caught mid-write, which needs no intervention. If it persists, check that `-cp-grpc-cert` / `-cp-grpc-key` are readable and are a valid matching pair. |
| `network_error` | a bind that genuinely timed out | Rare. See the log line. |
| `listen_failed` | not a cause this build classifies | See the full error on the `ControlPlane: gRPC listener` log line. |

Every remedy also states the two things that are true in all cases: the listener
rebinds by itself, and this node's proxy and admin UI are unaffected.

---

## 6. Recovery paths

**Automatic (the normal case).** The supervisor binds as soon as the fault
clears, takes the control-plane role, resolves leadership, and logs the recovery
line. Nothing else is required.

**Manual, if you want to force it.** The admin API's enable endpoint
(`POST /api/cluster/mode`, admin-only) is reachable throughout — that is one of the
things this change buys — and the supervisor notices when it succeeds and stops
retrying.

**Supervisor panic (terminal).** A contained panic in the supervisor is the one
state that does **not** self-heal: nothing rebinds. It is logged as

```
ERROR ControlPlane: gRPC listener supervisor panicked — the cluster control plane is
  unavailable until this node is restarted. ...
```

and this is the only case where restarting the node is the right move. The
proxy and admin UI are still unaffected, so you can schedule it.

---

## 7. HA interaction

- **Role and leadership are taken only on an observed bind.** A node that has
  not bound stays `standalone`, so it cannot be a black hole that claims the
  leader role while distributing nothing.
- **Leadership is resolved against the persisted HA state at the moment the
  bind succeeds**, not against a snapshot taken at boot. This matters because
  the admin UI is now reachable during the retry window: if you change this
  node's HA posture while it is retrying, the supervisor honours the change. If
  the persisted role has moved to `standby`, it logs that and does **not** claim
  leadership; restart the node to enter standby against its peer.
- **With an etcd fencing lease armed (ADR-0005)**, the fence arbitrates
  leadership as usual — a deferred resume goes through the same lease
  acquisition as any other.
- **A promote that used to hang now completes.** Before this change,
  `enableControlPlane` deadlocked whenever HA was already enabled — which is
  definitionally the case on a promoting standby — holding the cluster-role lock
  forever. The symptom was a **failover that never finished**: the standby
  reported itself promoting, no leader served gRPC, and the node's cluster-role
  surfaces (`/api/cluster/status`, the support bundle) stopped answering. The
  same hang reached `POST /api/cluster/mode` on any node where HA was already
  enabled: the request never returned and the role lock stayed held. An ordinary
  Control Plane **boot** was not affected (HA is not yet enabled at that point),
  which is why this went unnoticed. If you have ever seen a failover stop like
  that, this was why; nothing needs to be done beyond running this build.
- **Without a lease (legacy ADR-0004)**, a deferred resume is the ordinary
  restarted-leader path, with the same `ADR-0004/RISK-001` warning the node
  already prints on every restart-as-leader with automatic failover enabled.
  Verify via `/healthz` or the HA panel and reconcile.

---

## 8. Related

- `docs/operator/admin-ui-listener-recovery.md` — the same finding on the admin
  UI listener (CHAOS-57, §33).
- `docs/operator/socks5-listener-health.md` — the same finding on the SOCKS5
  listener's bind and accept loop (CHAOS-54 / CHAOS-66, §§22/36).
- `docs/operator/ha-lease-failover.md`, `docs/operator/ha-lease-recovery.md` —
  leadership and fencing.
- `docs/operator/graceful-shutdown.md` — the bounded shutdown sequence the
  supervisor's stop participates in.
