# ADR-0065: An explicit node lifecycle, and a control-plane listener that says "starting"

- Status: Proposed for review with the implementation PR (2026-11-28).
- Numbering: ADR-0062 is the highest merged. ADR-0063 (state-authority
  contract) and ADR-0064 (HA restart authority and publication gate) are held
  by open branches; this takes the next free number.
- Related: ADR-0004 (HA split-brain fencing), ADR-0005 (lease-witness
  failover, commit-before-advertise), ADR-0064 (which supplies the real
  leadership and publication answers this ADR consumes). No package boundary
  changes: everything here is start-up composition in package main.

## Context

Start-up activates the cluster role — a control plane's first publish,
listener bind and HA leadership resume — only after every configuration store
has loaded (CLU-005). That closed a defect (a restarting control plane served
an empty blocklist, no rules and default deny) and opened a window: the
control-plane port stayed CLOSED for the whole store-loading phase. Measured on
the real binary, the port opened 0.1 s after process start before the reorder
and 3.7 s after it with a two-million-host blocklist.

A closed port on a restarting leader is indistinguishable, to a peer, from a
dead leader. A standby ticks every 5 s and acts after three failed rounds; in
legacy mode with automatic failover it promotes, and the restarted node then
resumes as leader as well. In lease mode the peer takes the lease and the
restarted node comes back as a standby: safe, but leadership flips on a
routine restart. The owner's decision: bind the listener early, with explicit
start-up, liveness, readiness and leadership semantics; an early listener must
not be able to authorize publishing, mutations or leadership-dependent
operations; leadership acquisition and publishing authorization are separate
concepts.

## Decision

### 1. One lifecycle, owned in one place (`node_lifecycle.go`)

| Phase | Entered by | Cluster listener answers |
|---|---|---|
| `unmanaged` | zero value (one-shot commands, tests that call a piece directly) | real handlers |
| `identity` | `enterStartupIdentityPhase` — first statement of `runStartupSequence` | `CULVERT_NODE_STARTING` |
| `loading-stores` | `enterStartupStoresPhase` | `CULVERT_NODE_STARTING` |
| `activating` | `enterStartupActivationPhase` | `CULVERT_NODE_STARTING` |
| `ready` | `markNodeReady` — after the activation, before any traffic gate | real handlers |

The phase only moves forward. Four orthogonal answers are read through
accessors, never inferred from a side effect such as "the listener is bound":

- `nodeLive()` — the process is running (true from phase 1).
- `nodeReady()` — stores loaded and role active; real data may be served.
- `haLeadershipHeld()` — this node holds leadership (`ha_authority.go`).
- `haPublishAuthorized()` — this node may distribute a snapshot
  (`ha_authority.go`).

`ha_authority.go` is a stub on this change — both answer what the code did
before the call sites existed — and is the single file ADR-0064 replaces.

Consumers:

- **Serving** (`gatedUnary` → `nodeServingRefusal`, in front of every
  ConfigService handler): not ready ⇒ `CULVERT_NODE_STARTING`; ready but a
  snapshot method (`GetConfig`, `GetConfigDelta`, `HASync`) without
  publication authorization ⇒ `CULVERT_PUBLISH_NOT_AUTHORIZED`. The existing
  leader gate (`haServingAllowed`) follows unchanged.
- **Publishing** (`publishCurrentConfigSnapshot`): refused before the
  `activating` phase (no snapshot can be captured from half-loaded stores),
  and refused without leadership. `pacReconcileAllLifecycles`, the one
  start-up step that can publish, therefore runs after the activation — its
  position before the reorder.
- **Health**: `/health` reports `startup` (liveness stays "ok" from phase 1);
  `/ready` has a gating `startup` row that fails until `ready`; `/healthz`
  and `/api/cluster/status` report phase, readiness, leadership and
  publication authority as separate fields. No endpoint is added.

### 2. The wire statuses

Both are gRPC `Unavailable` — the code every released data plane and standby
already retries on — with a fixed token leading the message:

| Meaning | Message |
|---|---|
| alive, still starting | `CULVERT_NODE_STARTING: control plane is starting (phase=<phase> elapsed_seconds=<n>); <Method> is not served until the node is ready` |
| ready, may not distribute | `CULVERT_PUBLISH_NOT_AUTHORIZED: <reason>; <Method> is not served` |

`isCPStartingStatus` / `isCPPublishNotAuthorizedStatus` classify them
(code Unavailable AND the message starts with the token);
`cpStartingStatusFields` extracts phase and elapsed seconds.

### 3. The early listener is a separate, minimal server (`cp_starting_listener.go`)

A control plane binds its gRPC address in phase 1, right after its identity and
cluster CA are established, with the same transport credentials as the real
server and a ConfigService whose every method (taken from `cpRPCPolicies`, the
table already pinned complete) returns `CULVERT_NODE_STARTING`. It registers no
real handler: there is no code path from it to a store, a publish, enrolment or
leadership. It claims no role, publishes no address and reports no HA status.

Immediately before the activation, the early listener is stopped and the
UNCHANGED CHAOS-71 activation runs: publish, bind (supervised, retried), role
claim on an observed bind, address publish, HA resume.

**Rejected: binding the real supervised listener early and deferring its
commit.** The supervisor commits (role claim, address publish, `onActivated`)
on its own goroutine between adopting a bind and serving it; deferring that
changes CHAOS-71's ownership model and ADR-0005's order. A separate server
leaves both untouched.

**Cost: a hand-over gap.** Stop-then-bind leaves the port closed for a moment
(well under a millisecond of our own work). A peer that connects in that
moment gets one connection error. A long-lived gRPC connection then sits in
its reconnect backoff (about a second) before it redials. Nothing can be
served a configuration in the gap: the real server's handlers are behind the
same lifecycle gate until `markNodeReady`. If the real bind then fails, the
node behaves as it did before: the resilient boot path retries in the
background and the listener health surfaces report it; the lifecycle still
reaches `ready` because the node itself is serving.

### 4. ADR-0005 commit-before-advertise still holds

Nothing that advertises leadership happens before the commit. The early
listener advertises nothing. Inside the activation the order is unchanged:
the first publish commits; the listener binds; the role is claimed; the
address list is published; the HA resume commits the fencing epoch onto the
committed snapshot (`commitGrant` → `RestampFenceEpoch`) and only then exposes
it. A snapshot is served only after `markNodeReady`, which follows all of it.

### 5. Lease mode

A starting node neither acquires nor renews the lease: the lease is touched
only by the resume inside the activation, as before. If the store load
outlasts the lease TTL and the peer takes the lease, the restarted node's
resume is denied by the fence and it comes up as a standby that never serves
a snapshot. Two leaders are not possible; a stale former leader is fenced by
the epoch.

## Compatibility

| Peer | On `CULVERT_NODE_STARTING` |
|---|---|
| Data plane, any release | `Unavailable`: a failed poll. It keeps its last-good configuration, backs off, and after several failures may fail over to another configured control plane. Unchanged behaviour. |
| Standby on this release, legacy mode | An ANSWERED round (`ha_leader_answer.go`): the leader is alive. It does not count toward the failover threshold and does not refresh the last-sync time, for at most `haStartingGrace` (half the promote freshness window, 5 minutes) of an unbroken run of such answers, measured on the standby's own clock from the first one. Past that the answers count as failures again, so a leader hung in start-up cannot block failover forever. |
| Standby on this release, lease mode | Unchanged: every round that does not apply counts; the lease arbitrates the promotion. |
| Standby on an older release | Counts it as a failure, as it counted a closed port. Upgrade the standby first. |

## Consequences

- A restarting control plane is reachable, and says what it is doing, from
  about 0.1 s after process start regardless of store size; it is ready when
  its stores have loaded.
- "May this node serve / publish / lead" has one owner and four explicit
  answers; a future listener cannot become an authority by being bound.
- A legacy standby no longer fails over because its leader took more than
  three ticks to load its stores. This had to ship in the same change: with
  the reorder and without the standby reading the answer, a slow restart
  promoted the standby under a live leader, which then resumed as well — two
  unfenced leaders, worse than before either change. The legacy restart
  revalidation (a restarting leader proving its authority before resuming) and
  the publication safety gate remain ADR-0064.

## Known limits

- **At the end of the grace a legacy pair can have two leaders.** When a
  leader is still loading its stores after `haStartingGrace` (5 minutes) of
  starting answers, a legacy standby promotes. The old leader is alive: when
  its load finishes it resumes leadership as well, and both lead until the
  authority revalidation of ADR-0064 lands (a restarting legacy leader proving
  its authority before it resumes). The grace run is one run across rounds
  that get no answer at all — only a reply from the leader or an applied sync
  ends it — so a leader that answers intermittently is bounded the same way.
  Before the start-up reorder this promotion did not happen on a slow start,
  but only because the leader bound and served within a fraction of a second
  — serving the state of its still-empty stores.

- **The MCP runtime listener is not behind the activation.** `initMCPRuntime`
  binds it in phase 2, before a data plane's last-good replay. It is off by
  default and enforces its own durable, node-local distribution state, not the
  replayed SWG snapshot. "Before any traffic gate opens" in this ADR and in
  CLU-006 means the SOCKS5 pre-posture gate and the proxy listener (and the
  admin UI); gating the MCP listener the same way is a separate change.
- **The health rows cannot read "starting" today.** `/health` and `/ready` are
  served by the proxy listener and `/healthz` by the admin UI, both of which
  open after `markNodeReady`. Their `startup` fields therefore always report
  `ready` in this build; they exist so that a listener opened earlier in a
  future change cannot report ready by omission. During start-up the phase is
  visible in the cluster listener's `CULVERT_NODE_STARTING` answer and in the
  log.
- **Feed-status label.** A control plane's signed-feed runtime resolves its
  authority during phase 2, while the node's role is still `standalone` (the
  role is claimed on an observed bind). The two authorities behave the same;
  only the label reads `standalone` until the next resolution.
