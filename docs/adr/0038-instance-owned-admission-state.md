# ADR-0038: Instance-owned distributed admission state

- Status: Proposed with implementation, 2026-09-30; recorded before code changes.
- Baseline: `60f127389d7a1004a6af7dd4dd352b908b8ad313` (merged #1522).
- Number checked in both `docs/adr/` and `docs/support/rfc/`, and all 30 open PR file inventories.
- Scope: package-isolation step 2; **no package extraction or admission-policy change**.

## Ownership and synchronization

Each `RateLimiter` owns its remote count store (map/RWMutex and atomic applied-at
stamp), atomic cluster-enable flag, stale-episode counter and log-once latch.
Embed these by value: `newRateLimiter`, `new(RateLimiter)` and composite literals
cannot accidentally share them or fall back to a process singleton. The zero
value retains its existing disabled/configuration/read behavior; local shard
maps for active admission are initialized by `newRateLimiter` as before.

The existing shard and exemption locks/immutable read views stay intact. Remote
publication retains the existing order: replace map under its mutex, release,
then atomically publish receipt time. The decoded broadcast map is transferred
to that owner and must not be mutated by the caller after publication, as before.
No additional hot-path lock, allocation, clock source or combined configuration
transaction. Freshness stays derived at read time from that owner's window and
receipt stamp; the episode/latch record is diagnostic, never admission authority.
Disabling gossip or Configure does not clear counts, local history or episodes;
re-enabling may use still-fresh retained counts. Future stamps and ages >= the
window contribute zero. Nil/empty broadcasts are successful fresh publications.

Each `IPFilter` owns its optional atomic publication-observer slot. The callback
runs under that filter's writer lock, after publishing its immutable view; it
must not re-enter a locking filter method. Tests own each recorder and callback
lifetime. No global hook, recorder registry, initialization-once or fallback.
The existing stack attribution, new-view proof and negative controls remain.

## Production composition and lifecycle

`main` retains `rl`/`ipf` as the application composition handles. All live config
writers mutate `rl` in place. `DataPlaneClient.Run` explicitly supplies that
limiter to its gossip loop; the loop's enable, export, apply, freshness and stop
paths use that same captured owner. No optional dependency with global fallback.
HTTP/SOCKS5 admission, metrics, cluster status, snapshot/config application and
rollback keep using the application owner. Tests may bind a local owner into the
composition handle only when exercising those real adapters.

Production composes one gossip loop per application limiter, as before.
The gossip loop still owns its ticker and follows its supplied context; stopping
it disables only its limiter. Constructors create no goroutines. The app-parented
five-minute cleanup loop and shutdown cancel registration remain unchanged.
Transient counts/timestamps/flags/episodes are not persisted or added to a wire
DTO; JSON fields, defaults, auth decisions and persistence paths do not change.
The CP's `globalRLAggregator` remains a separate application-level fleet aggregate,
not a second authority for one DP limiter's last received broadcast.

## Complete boundary map

| State/path | Writers and construction | Readers/tests |
|---|---|---|
| Remote counts + stamp | Former `clusterCounts`; only production writer is successful `rateLimitGossipLoop` JSON decode/apply; tests use timestamped publication | `AllowClusterAware`, freshness, `apiClusterRateLimits` map size; `distributed_rl_test`, CHAOS-61 |
| Cluster enable | Former `clusterRateLimitEnabled`; gossip entry=true, context stop=false; zero=false | `AllowAuto`, freshness Armed, cluster status; standalone/distributed and CHAOS-61 controls |
| Stale episodes / log latch | Former `clusterRLStaleEpisodes` / `clusterRLFreshnessLog`; gossip observes before each tick's RPC, including failed/disabled paths | Freshness status, Prometheus, cluster API; CHAOS-61 transitions/default-off/rollback tests. Replace global reset fixtures with new owners |
| IP publication observer | Former `ipFilterPublishHook`; tests install on their own receiver; production nil, including replacement filter in snapshot apply | `publishView`; all mutator attribution tests and wrong-receiver/dead-code/new-view negative controls. Remove global `sync.Map`/`sync.Once` |
| Local limit/window/exemptions | `newRateLimiter`; bare literals in `controlplane_extra_test` and exemption tests; Configure/Add/Replace; startup `main.go`, `connlimit_startup.go`, `admin_settings.go`; admin `ui_security.go`; import `ui_config.go`; rollback `configversion.go`; full/delta snapshot `controlplane_snapshot.go` | `proxy.go`/`socks5.go` AllowAuto; cleanup; config export/current snapshot, metrics/OTLP/status. No production reassignment of rl |
| Gossip wire | CP `SyncRateLimits` verifies node, replaces its latest aggregate contribution and excludes requesting node; DP loop decodes broadcast | Existing wire structs unchanged; new integration covers successful application, admission, health and cancellation using production paths |
| Test construction/reset | `newRateLimiter`, explicit composite literals, application fixture swaps in proxy/startup/config tests | New distributed fields need no initialization beyond their zero values; only adapter tests swap `rl`, restoring the entire old owner, never clearing its state |

Open overlaps: #1485 edits unrelated security helpers in `security.go`; #1437
and #1414 touch other gossip/audit paths in `controlplane_client.go`; #1414 also
adds audit tests to the mixed CHAOS-61 file; #1399 touches the unchanged cleanup
composition. Preserve those sections and recheck heads before handoff.

## Proof and next boundary

Keep every existing test name/assertion. Convert pure distributed/CHAOS-61 cases
to local owners, retaining application-bound metrics tests. Add concurrent-owner
count/enable/health and observer isolation, construction/defaults, retained-count
re-enable, fresh/stale/future and real gossip/config/admission/diagnostic wiring
checks with bounded cancellation waits. Keep all source-contract negative controls,
hot-path allocation gates, race/shuffle, coverage floors and CI discovery.

Next PR moves filter/limiter/shared CIDR matching plus their engine tests into one
cohesive internal admission package. Leave app globals, config/persistence, wire
DTOs, CP aggregation, gossip transport, diagnostic logging and cleanup lifecycle
in main. Deliberately migrate security.go's 70% floor and benchmark/source-contract
selectors with the implementation, preserving their strength. No generic common
package and no duplicate engine during transition.

## Existing limitations, not changed here

Code inspection at the baseline found that a bare `RateLimiter{}` can be
configured/read but active non-exempt admission writes a nil shard map. Existing
composite-literal callers only configure/read; active callers use the constructor.
This PR preserves that contract instead of adding lazy initialization to the hot
path. Also, `ExportHotDeltas`' comment says “reset/delta”, but its implementation
exports absolute live counts and CP `Update` replaces a node snapshot. Preserve
the implementation and record that documentation defect separately; changing it
would change cluster accounting. Map and timestamp publication remain separate,
as before; this PR does not claim a transactional snapshot across those reads.
