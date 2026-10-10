# Admission: current contract

Read this for IP filtering, per-IP rate limiting, cluster-count freshness, or their root adapters. This is a current source-backed guide; historical measurements and pre-extraction file locations are not implementation authority. MCP auxiliary execution admission is a separate contract in [internal/mcp/execution](../../../internal/mcp/execution/auxiliary_admission_test.go).

## Ownership and lifecycle

[ADR-0039](../../adr/0039-admission-engine-package.md) and the [package contract](../../../internal/admission/doc.go) define the boundary:

- `internal/admission` owns `IPFilter`, `RateLimiter`, shared prefix matching, immutable views, sliding windows, and each limiter's remote counts, receipt timestamp, enablement and freshness episode history. Keep engine logic, white-box tests and hot-path benchmarks here. Do not add shared mutable owners or application/persistence dependencies; [boundary tests](../../../internal/admission/boundary_test.go) pin this boundary.
- Main owns configuration, persistence/rollback, gossip transport and DTOs, CP aggregation, HTTP/SOCKS5 adapters, cleanup scheduling/cancellation and diagnostic rendering. [admission.go](../../../admission.go) contains permanent composition aliases and constructors, not a second implementation. Do not expose mutable engine internals to retain a root white-box test.
- Constructors start no goroutines. Use `NewRateLimiter` for active local admission; the zero limiter supports disabled admission, configuration and distributed-state diagnostics, but does not initialize local shard maps. Use `NewIPFilter` before adding individual addresses; existing zero-filter reads and mode/CIDR operations remain supported.
- `Configure` and `SetClusterEnabled` retain local counts, the last remote broadcast and diagnostic history. A configuration change must not replace the limiter and reset its budget. Distinct limiter instances must remain isolated. See [ownership tests](../../../internal/admission/security_admission_ownership_test.go) and [production integration](../../../controlplane_admission_ownership_test.go).

## Remote counts and freshness

The implementation is in [engine.go](../../../internal/admission/engine.go) (`clusterCountStore`, `AllowAuto`, `AllowClusterAware`) and [freshness.go](../../../internal/admission/freshness.go).

- `ApplyRemoteCounts` transfers ownership of the supplied map; callers must not mutate it afterward. Publication replaces the map under its mutex, unlocks, then stores the receipt timestamp atomically. Preserve that order. These are ordered publications, not an atomic map-and-timestamp snapshot of one generation.
- An absent receipt, a future-dated receipt (negative age), or age **at least** the current limiter window contributes zero remote requests. The nonpositive-window defensive fallback is one minute. Expired broadcasts degrade to local enforcement: they must neither deny indefinitely using frozen counts nor disable the local budget.
- A successful nil/empty broadcast is a fresh receipt and clears the old map. A failed RPC is not an empty broadcast: the [gossip loop](../../../controlplane_client.go) keeps the last receipt/counts, which remain usable until their own expiry. `RemoteIPCount` reports the last map's size even when stale; it is not a freshness verdict.
- `AllowAuto` selects local or cluster-aware admission using the cluster flag; both paths honor disabled limiting and exemptions. Freshness is armed only when **both** `ClusterEnabled()` and `Enabled()` are true. An unarmed node is never reported stale, but `Applied` and `Age` still describe what arrived.
- `ClusterFreshness` derives live status without changing episode history. `ObserveClusterFreshness` additionally records a new stale episode once and a recovery transition; it stays off the request path. Main serializes observation/log rendering in the gossip loop, including failed-RPC ticks. Metrics/API reads must not advance episodes. See [engine freshness tests](../../../internal/admission/cluster_ratelimit_freshness_chaos_test.go), [root diagnostics tests](../../../cluster_ratelimit_freshness_chaos_test.go) and [rendering adapter](../../../cluster_ratelimit_freshness.go).

`ExportHotDeltas` returns **absolute qualifying in-window counts**, not increments since the previous export. It expires old timestamps but never clears/deducts live accounting. Qualifying counts meet `max(1, limit * HotThresholdPercent / 100)`; limiting disabled means no export. Preserve the existing [wire DTO conversion](../../../cluster_ratelimit_wire.go), including nil serialization. [Distributed tests](../../../internal/admission/distributed_rl_test.go) pin repeated-export accounting.

## Immutable views, exemptions and bulk mutation

Every successful filter/exemption mutation publishes a replacement read view under the writer lock before releasing it. Published state must not alias writer-mutated maps or slice storage. `Allowed` and `IsExempt` read the immutable view without acquiring the writer lock. Update mutator inventories and publication/race tests when adding mutators: [filter tests](../../../internal/admission/security_ipfilter_view_test.go), [exemption tests](../../../internal/admission/security_ratelimit_exempt_view_test.go).

Preserve the deliberate difference between exact-address gates: filter singles canonicalize addresses, while exemption singles probe the **raw caller string** against the stored canonical string. `::ffff:198.51.100.7` must not gain the single-IP exemption for `198.51.100.7` through incidental normalization. CIDR matching uses the shared `prefixSet`/`PrefixFromIPNet`; mapped CIDRs retain `net.IPNet.Contains` family semantics. Keep differential controls rather than copying the normalizer.

Use `AddAll` / `AddExemptions` for bulk append/restore, rather than per-entry publication loops that rebuild the whole view quadratically. Single admin edits may correctly use `Add` / `AddExemption`. Full exemption replacement uses `ReplaceExemptions`; nil/empty clears at that engine API. The [snapshot adapter](../../../controlplane_snapshot.go) deliberately has a different wire-presence rule: nil skips an absent legacy field, empty clears, populated replaces. Preserve [snapshot tests](../../../controlplane_ratelimit_exempt_sync_test.go), [rollback tests](../../../configversion_rate_limit_exempt_test.go), and boot/import bulk callers in [admin_settings.go](../../../admin_settings.go) / [ui_config.go](../../../ui_config.go).

## Sliding window

Keep lazy ring growth and prefix expiry. A timestamp equal to the cutoff expires. Sampling before the shard lock can produce out-of-order samples; `clientBucket.add` clamps an earlier sample **up** to the newest retained stamp, maintaining nondecreasing order. Relative to that earlier sample, expiry is **later or equal**, conservatively retaining the count longer. Older comments also compare with later true arrival/append time, a different reference frame. Read the [timestamp clarification](../errata.md#timestamp-clamp-direction); do not change the algorithm to reconcile ambiguous prose. [Window tests](../../../internal/admission/security_ratelimit_window_test.go) cover differential verdicts, the exact expiry boundary, growth and ordering.

## Verification

Run from the repository root with the toolchain declared in [go.mod](../../../go.mod). Choose tests for the changed contract; these commands are focused checks, not a complete CI verdict:

```sh
# Engine ownership, race safety and order isolation.
go test -race -shuffle=on -count=2 ./internal/admission

# Root composition/diagnostics and package ownership/freshness contracts.
go test -race -run 'Test(AdmissionMigration|DistributedAdmission|Chaos61)_' -count=1 . ./internal/admission

# Tagged gates MUST select both packages and disable result caching.
go test -tags benchgate -run 'TestBenchGate_' -count=1 -timeout=10m -v . ./internal/admission
```

Snapshot/rollback edits additionally need the linked root integration tests. `TestChaos61_` needs no chaos tag. Most admission `TestBenchGate_` tests are in default-tag files; the two rate-window gates require `benchgate`. Do not infer build tags from test names.

The [coverage script](../../../.github/scripts/coverage-floor.sh) requires global 55% plus function-average per-file floors of 70% for root `security.go`, admission `engine.go` and `freshness.go`, alongside its other floors. Missing implementation files must fail; a package-only percentage is not a substitute. [Migration checks](../../../admission_contract_test.go) protect coverage omissions and both-package CI selectors. Use the [verification workflow](../workflows/verification.md) for wider change-dependent checks and honest completion reporting.

## Historical rationale

The [preserved admission evidence](../history/admission-and-connection-limits.md)
contains the original freshness incident, immutable publication decisions, ring
measurements and exemption/bulk-load controls. Reconcile relevant failure cases
with the current owner/tests; see [errata](../errata.md) for explanatory conflicts.
