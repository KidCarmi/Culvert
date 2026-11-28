# ADR-0064: HA restart authority (legacy) and the publication safety gate

- **Status:** Part C implemented. Part D implemented as the detection-and-hold safety net with operator
  release; automatic reconciliation and replicate-before-distribute are NOT implemented — see
  "Implementation record" at the end for what was decided, what was stopped and why.
- **Builds on:** ADR-0004 (legacy HA), ADR-0005 (fencing lease; its commit semantics are NOT changed here),
  contract `CLU-004`. Composes with ADR-0063 (state authority, draft).
- **Owner decisions (verbatim, abridged):** (C) "In legacy mode, a restarting leader must revalidate its
  authority before resuming leadership-dependent operations. Peer reachability alone must not be treated
  as proof of exclusive leadership. … If exclusive authority cannot be established in legacy mode, fail
  closed for leadership-dependent operations while preserving independent services wherever safe."
  (D) "Automatic state reconciliation with a publication safety gate: consistent state proceeds
  automatically; recoverable, verifiably authoritative state is reconciled automatically; conflicting,
  ambiguous or unrecoverable state holds publishing and exposes an actionable diff. Never silently
  overwrite newer fleet state or publish an unauthorized rollback. Leadership acquisition and publishing
  authorization must be separate concepts."

## Two concepts

| Concept | Lease mode | Legacy mode |
|---|---|---|
| **LeadershipHeld** | the etcd lease (ADR-0005, unchanged) | restart revalidation (part C) |
| **PublishAuthorized** | the publication gate (part D) | the publication gate (part D) |

A node may hold leadership and not be publish-authorized. The lifecycle surface owned by the early
listener work reads both from here: `haLeadershipHeld()` and `haPublishAuthorized() (ok, reason)`.

## Part C — legacy restart revalidation

**Today.** `resumeLeadershipAttempt` reads `role=leader` from `ha_config.json` and resumes. If the standby
promoted while the node was down, both lead ("BOTH may now lead").

**What can prove exclusive authority without a lease.** A standby that has not promoted runs no Control
Plane listener, so the restarted leader cannot ask it anything; an unanswered dial is equally a healthy
standby, a dead peer or a partition and proves nothing. The evidence that exists:

1. **No standby has ever synced** (`standby_addr` empty in the persisted config). No other node holds this
   cluster's state or CA, and CLU-004 forbids automatic promotion of such a node. → authority established.
2. **The peer polls us.** A standby only ever calls `HASync` while it is a standby; a node that promoted
   stops. An authenticated `HASync` from the recorded peer, received after this restart, is the peer's own
   statement "I am standby, of term ≤ T". The request now also carries `role` and `term` (additive). The
   resume completes inside that RPC and the same RPC is answered, so the poll that proves it is not counted
   as a failure by the standby. → authority established.
3. **The peer leads.** The restarted node dials the recorded standby address with `HASync`. An answer
   carrying `leader_term` ≥ ours means the peer promoted. → the node joins it as standby automatically
   (`enterStandbyResync`), idempotently, with no operator act. A term below ours is ignored (not leader of
   a later term).
4. **Neither.** → authority NOT established. The node stays in the existing HA-gated state (`intentGate`):
   no HA role, leader-gated RPCs refused, CA issuance refused, `/healthz` 503, admin mutations refused with
   an explicit reason, HA status shows `authority: revalidating`. Proxying with the last configuration,
   the admin UI (read), diagnostics and logs keep working. The attempt is retried with the existing capped
   backoff and paged once per episode (`ha_resume_unfenced`). An operator whose standby is permanently gone
   asserts leadership with the existing promote endpoint (audited, with a warning).

Residual, stated: a standby whose three polls are all lost in transit while the leader hears them is the
ADR-0004 asymmetric-partition case; only a fence closes it. Lease mode is unchanged; tests are added for
expiry during a slow start, a returning stale leader, asymmetric connectivity and partition heal.

## Part D — publication safety gate

**The defect.** A promoted node seeds its version above everything the old leader issued and publishes
what it holds. A data plane that had applied versions the standby never replicated is handed older
content at a higher version: a silent rollback.

**ADR-0005 constraint.** A promotion must commit a snapshot stamped with the new epoch before the epoch is
advertised. The gate therefore never blocks a commit into the store. It gates **distribution** (what
`GetConfig`, `GetConfigDelta` and `HASync` hand out) and **operator mutations**.

**Evidence.** `W`, the replicated watermark (`replicatedLeaderConfigVersion`, today memory-only); `P0`, the
first version this node committed as leader; both persisted in `ha_publish_gate.json` at promotion with
the term/epoch. Per data plane: `known_version` on every `GetConfig`/`GetConfigDelta`, and
`config_version`, `epoch`, `synced_fp` (blocklist only) on every heartbeat. From the previous leader, when
reachable: its committed snapshot, version, term and epoch over a new token-authenticated RPC
(`HAPeerSnapshot`). **Not available:** a whole-snapshot fingerprint from data planes, the epoch a version
was committed under, and any way to fetch a snapshot from a data plane.

**Classification, per data plane request with known version `k`.**

| Case | Meaning | Action |
|---|---|---|
| `k ≤ W` or `P0 ≤ k ≤ current` | consistent with this node's lineage | serve normally — no hold, no operator |
| `W < k < P0`, or `k > current` | the data plane holds state this node does not | answer **unchanged** to that data plane (it keeps what it has; never rolled back), record the evidence, enter **HOLD** |
| heartbeat epoch above ours | a newer leader exists | this node is stale: stop serving (lease: self-fence path; legacy: part C) |
| `known_version` absent while HOLD | old data plane, unknown state | `Unavailable` (keeps last-good); served normally when not held |

**HOLD.** Data planes consistent with this node keep being served its committed snapshot (never frozen).
Operator mutations are refused with the reason. `HASync` to standbys is refused, so a demoted leader's
newer state is not overwritten. Status, diagnostics and one alert carry the diff: watermark, own range,
and per node the reported version, epoch and blocklist fingerprint.

**Automatic reconciliation (RECOVERABLE).** While held, fetch `HAPeerSnapshot` from the previous leader.
Adopt iff the reply is authenticated, its term/epoch is the one this node last replicated from (below our
own), and its version is ≥ every version reported in `(W, P0)`. Adoption applies it through the normal
`applyHABundle` path, republishes at a new version, re-verifies the blocklist fingerprint against nodes
that reported it, sets `W` to the adopted version and releases the hold. Every step is idempotent: the
gate file records the phase; a restart resumes at the fetch.

**UNRECOVERABLE.** Peer unreachable, older build (`Unimplemented`), version below a reported one, two
fingerprints reported for one version, or a version above `current`: the hold stays, reconciliation is
retried, and the operator has one explicit, audited action — *publish as authoritative* (accept this
node's state; data planes ahead of it are then served and roll back). *Adopt from node X* is not
implementable: data planes cannot serve their snapshot (new evidence needed; see Open).

**One gate.** `haPublishAuthorized()` is the single predicate; ADR-0063's "no undeclared emptying" check
is consulted by the same function when that work lands, not a second gate beside it.

**Wire compatibility.** New request fields and the new RPC are additive. An old data plane that omits
`known_version` is served as today unless a hold is active. An old standby/ex-leader lacks
`HAPeerSnapshot`: the state is unrecoverable-automatically and held. The gate arms only on an HA
promotion; a standalone or never-promoted control plane behaves exactly as before.

**Availability cost.** Healthy failover: none. Data planes ahead of the promoted node: unchanged until
reconciled. Operator edits: refused during a hold. Old leader gone for good: operator release.

## Open (needs new evidence, not guessed)

- A data-plane whole-snapshot fingerprint and the epoch each version was committed under would let the
  gate verify adoption end to end instead of by version plus blocklist fingerprint.
- A data-plane "serve my last-good snapshot" RPC would make *adopt from node X* possible.

## Implementation record (2026-11-28)

**Implemented.** Part C as designed (`ha_legacy_authority.go`, `ha_write_gate.go`, contract `CLU-005`).
Part D: the gate (`ha_publish_gate.go`, contract `CLU-006`) with these refinements over the note above:

- The unaccounted range is a list of **gaps**, one per promotion, `(watermark, first own version)`. The
  first own version is recorded by the store at the promotion's first commit, not read afterwards, so a
  data plane that fetched that commit is never misread as ahead.
- **HASync stays served during a hold** and the bundle carries the gate. A standby keeps it and starts from
  it when promoted, so a hold and every open gap survive a second failover. Refusing HASync would have made
  the standby stale after 10 minutes and removed failover capacity exactly when the cluster is degraded.
- **Operator release** (`POST /api/cluster/ha/publish-release`): shows the diff, is audited and idempotent,
  publishes above every reported version (a data plane ignores a version not above its own), and is refused
  with `ha_reconciliation_possible` while the previous leader is reachable unless `force` is set.

**Limit of detection.** A gap exists only when the promotion's first version is more than one above the
watermark, which the wall-clock seed normally guarantees. A promoted node whose clock is behind the old
leader's version counter numbers its first version `watermark+1` and cannot tell an ahead data plane from
its own; that case is undetected, as today.

**Not implemented — automatic reconciliation (`HAPeerSnapshot`).** In lease mode the previous leader
self-fences and resyncs from the new leader within one sync interval, overwriting the very state that would
be adopted. Preserving it needs the demoted leader to refuse bundles that do not cover what it led through,
the new leader to pull and adopt that state, and a rule for the case where the new leader has accepted
edits of its own in the meantime. That is a protocol of its own; it was not started rather than half-built.
Until it exists every hold ends by operator release.

**Not implemented — replicate-before-distribute.** Evaluated, and stopped on two points that need an owner
decision:

1. *It moves an ADR-0005 invariant.* ADR-0005 advertises a new epoch only once a COMMITTED snapshot carries
   it, because data planes ratchet to the epoch and reject snapshots stamped below it. If the leader
   distributes an older, standby-acknowledged snapshot while the committed one carries a new epoch, data
   planes are handed a snapshot stamped below the epoch they have just ratcheted to and reject it until the
   standby catches up. The rule would have to become "…once a DISTRIBUTABLE snapshot carries it".
2. *It is complete only if the standby's freshness window is tied to the leader's wait bound.* The leader
   must stop waiting for a silent standby at some bound `T`, or one dead standby stalls all distribution.
   After `T` it distributes current; a standby that is still eligible to promote (today: for 10 minutes)
   can then take over without those versions. Prevention is complete only if a standby stops being
   eligible before the leader stops waiting, i.e. the S4 freshness window drops from 10 minutes to below
   `T`. With `T` = 10 minutes an urgent block is delayed up to 10 minutes whenever the standby is down;
   with a short `T` the window must shrink to about a minute, which is a lease-path change and removes
   automatic failover for standbys that lost contact slightly earlier. A standby that polls but refuses
   bundles needs the same bound.

   What it would buy: the common failure — the leader dies within one sync interval of a publish — would
   leave no data plane ahead, so no hold and no operator. Costs: one extra retained snapshot (about one
   marshalled snapshot at 2 M hosts), delta chains truncated at the acknowledged version, and distribution
   latency of one sync interval unless the standby long-polls.

**Possible future evidence (not built; adopting state from a data plane is a security-boundary change):**
a whole-snapshot fingerprint and the commit epoch per version in the heartbeat; a data-plane RPC that
serves its last-good snapshot.

**Standby accounting of a live leader's refusals (interface with the early listener).** A legacy standby
classifies a failed `HASync` (`haLeaderAnswerOf`): `CULVERT_NODE_STARTING` — alive, does not count toward
the failover threshold and does not refresh the last-sync time, for at most `haPromoteFreshnessWindow/2`
of an unbroken run of such answers, after which they count as failures (a leader hung in start-up must
not block failover; the bound keeps a standby that was synced when the leader went down eligible; the late
leader then revalidates and joins the promoted peer); `CULVERT_PUBLISH_NOT_AUTHORIZED` — a live leader
holding, does not count, no bound; `PermissionDenied` — alive. Lease mode counts every failed round, as
before: `Acquire` decides.

**Open interface point.** The listener must not refuse `GetConfig`, `GetConfigDelta` or `HASync` merely
because `haPublishAuthorized()` is false: during a hold the gate itself answers each data plane (consistent
ones are served, ahead ones are told unchanged) and `HASync` stays served so the standby stays eligible and
inherits the hold. A blanket `CULVERT_PUBLISH_NOT_AUTHORIZED` refusal there would freeze consistent data
planes, which the owner ruled out.
