# Culvert Collector Contract

- **Status:** Proposed (design).
- **Depends on:** `SUPPORTABILITY-ARCHITECTURE.md`, `SUPPORT-BUNDLE-SPEC.md`, `REDACTION-MODEL.md`.
- **Home:** `internal/support` (engine + registry + runner); collectors register from their owning domain.

A collector produces **one section** of a CSB. The framework is a **plugin registry of small, isolated, budgeted, self-redacting collectors** — never one monolithic "collect everything" function. This is the direct answer to the architectural rule "do not create one giant shell script."

---

## 1. Interface

```go
// internal/support/collector.go
type Collector interface {
    Meta() CollectorMeta
    // Collect writes exactly one section into sink. It MUST:
    //  - respect ctx cancellation / deadline (the runner sets the timeout)
    //  - read only via safe accessors (no store internals, no disk writes outside sink)
    //  - redact AT SOURCE via the injected Redactor before writing any value
    //  - never panic to the caller (the runner recovers, but collectors should not rely on it)
    //  - return a Result describing status/truncation, not an error for "subsystem down"
    Collect(ctx context.Context, in CollectInput, sink SectionSink) Result
}

type CollectInput struct {
    Window    TimeWindow          // requested evidence window
    Level     DebugLevel          // L0..L4 in effect
    Redactor  redaction.Redactor  // the ONLY sanctioned masking path
    Runtime   RuntimeInfo         // compose|k8s|host|unknown, cluster role
    HostAgent HostCollectClient   // nil when the maintenance agent is unavailable
    Clock     func() time.Time    // injected for determinism/testing
}

type SectionSink interface {
    // WriteJSON/WriteStream enforce the section's byte budget and compute the SHA-256.
    WriteJSON(v any) error
    WriteStream(name string, r io.Reader) (n int64, truncated bool, err error)
}

type Result struct {
    Status    SectionStatus  // ok|partial|skipped|unavailable|failed
    ClassMax  DataClass      // highest class actually written (post-redaction)
    Truncated bool
    Note      string         // redacted, human-readable
}
```

### Meta

```go
type CollectorMeta struct {
    ID              string        // stable snake_case; == manifest section id; unique
    Path            string        // section path in the tar (e.g. "sections/diagnostics.json")
    Owner           string        // subsystem team ("observability","security","cluster",…)
    SchemaVersion   int           // per-section schema; bumped on shape change
    Description     string

    // Execution contract
    Timeout         time.Duration // hard cap; runner cancels ctx at this
    ByteBudget      int64         // section size cap; sink truncates past it
    Mandatory       bool          // mandatory collectors gate bundle "health"; optional don't
    MinLevel        DebugLevel    // collector runs only at/above this level (L0 always)

    // Gating
    Runtime         RuntimeCap    // any|compose|k8s|host-systemd
    Platform        PlatformCap   // any|linux|…
    FeatureGate     func() bool   // e.g. cluster-only; nil == always

    // Governance
    MaxClass        DataClass     // asserted upper bound; runner rejects a section exceeding it
    RequiresHost    bool          // needs HostCollectClient (agent); degrades if nil
    Sensitivity     DataClass     // declared default class of this section's raw data

    // Ordering
    DependsOn       []string      // collector IDs that must complete first (rare; most are independent)
}
```

---

## 2. Execution model

- **Concurrency:** the runner executes collectors concurrently with a bounded worker pool (default `min(8, GOMAXPROCS)`), respecting `DependsOn` as a partial order. Most collectors are independent; dependencies are the exception (e.g. the cluster-correlation collector depends on the local health collector).
- **Failure isolation (P2):** each `Collect` runs inside a goroutine with `recover()`; a panic → `collection-errors.json` entry + section `failed`; the runner continues. A collector cannot abort the bundle. Only an engine-level error (out of disk before any section) fails the bundle, and even then it finalizes a `FAILED` manifest.
- **Timeout:** the runner sets `ctx` deadline to `Meta().Timeout`; on expiry the section is finalized as `partial` (if any bytes written) or `failed`. A collector that ignores `ctx` is killed at a hard grace margin and recorded as `timeout`.
- **Resource budget:** `ByteBudget` bounds output; the sink stops writing and sets `truncated`. A global bundle budget bounds the sum; collectors run in `MinLevel`-then-`Owner` order so the most important sections claim budget first.
- **Determinism:** collectors take `Clock` from input and must not call `time.Now()` directly (mirrors the engine-test discipline used by `internal/autoexclude`). JSON keys sorted. `TestCollectorDeterministic` per collector.

---

## 3. Redaction is the collector's job (source-side)

Every value a collector writes goes through `in.Redactor` first (ADR-0029). A collector MUST NOT:
- read a store's raw accessor when a redacted one exists (`Entries()` → use `List()`; raw `URL` → `URL.Redacted()`);
- write a `SECRET`/`NEVER_EXPORT` field at all;
- construct free-form text (log lines) without passing it through the free-form scrubber.

The runner **re-validates** each finished section against the classifier and rejects (drops + errors) any section whose actual `ClassMax` exceeds `Meta().MaxClass` — defense-in-depth, but the primary guarantee is that the collector redacted at source. `TestCollectorRedactsAtSource` asserts each collector, fed a fixture containing planted secrets, emits none.

---

## 4. Permissions & sensitivity classification

| Collector class | Reads | RBAC to trigger a bundle containing it | Notes |
|---|---|---|---|
| **PUBLIC** (product, readiness, metrics) | version/build/probe | viewer | safe for anyone |
| **INTERNAL** (diagnostics, health, config, policy, audit, logs, timeline) | in-proc safe accessors | operator | default bundle content |
| **HOST** (container/host facts) | maintenance agent `/v1/collect` | admin | privileged path; agent-side redaction |
| **RUNTIME** (goroutine/heap) | `runtime`/`pprof` | admin | L2/L3; perf-sensitive |
| **CLUSTER** (fan-out correlation) | peer `/healthz`,`/api/cluster/*` | admin | cluster-only |

The **role required to *request* a bundle** is the max of its collectors' RBAC (a standard bundle is operator; anything with host/runtime/cluster sections is admin). This is declared in `uiRoutes` metadata for the request endpoint and enforced by `requireRole` + C2.

---

## 5. Mandatory vs optional collectors

- **Mandatory** collectors (`product`, `health`, `readiness`, `diagnostics`, `collection-errors`) always run and their failure downgrades the bundle's self-reported completeness but never aborts it. A CSB missing a mandatory section is invalid (validator rejects).
- **Optional** collectors run when their level/scope/runtime/feature gates pass; a gated-out optional collector produces a `skipped` section entry (present in the manifest with a reason), not an omission — so a reader can always tell "not collected" from "collected empty."

---

## 6. Platform / runtime / feature gating

The runner evaluates, in order: `FeatureGate()` (e.g. cluster-only) → `Runtime` capability (does the current runtime satisfy it?) → `Platform`. Any failure → `skipped` with `note: "gated:<reason>"`. This is how the same bundle spec serves Compose today and OVA/k8s later without code changes to existing collectors (P8). Runtime-specific host collectors (`host_facts_compose`, future `host_facts_k8s`) share the section id `host` and are mutually exclusive by `Runtime` gate.

---

## 7. Host collectors and the agent boundary

A `RequiresHost` collector uses `in.HostAgent` (`POST /v1/collect`). If `HostAgent == nil` (agent absent, non-privileged runtime, or agent returned an error), the collector returns `unavailable` with a reason — the bundle still completes (P5). Host collectors never shape raw agent output into the section directly; the agent returns **already field-allowlisted, size-bounded, line-scrubbed** data (ARCHITECTURE §6), and the collector re-runs it through `in.Redactor` before writing. No collector can cause the agent to run anything outside its fixed template registry.

---

## 8. Collector test contract (mandatory per collector)

Every collector ships with tests proving:

| Test | Asserts | Reference pattern |
|---|---|---|
| `Test<ID>_Schema` | Output matches the pinned golden JSON schema for its `SchemaVersion` | golden-file |
| `Test<ID>_RedactsAtSource` | Fed a fixture with planted secrets of every class, emits zero | secret-leak |
| `Test<ID>_Deterministic` | Two runs over identical frozen state (injected clock) → byte-identical | autoexclude clock pattern |
| `Test<ID>_Timeout` | Honors `ctx` deadline; finalizes `partial`/`failed`, never hangs | context-cancel |
| `Test<ID>_Panic` | An induced panic becomes a `failed` section + error entry, bundle continues | recover |
| `Test<ID>_Budget` | Oversized input is truncated (`truncated:true`), not expanded | budget |
| `Test<ID>_Gating` | Skipped correctly when runtime/feature/level gate fails | gating |
| `Test<ID>_Unavailable` | Dependency-down (nil agent / DB down) → `unavailable`, not a crash | degradation |

The **registry parity test** (`support_registry_test.go`, mirroring `config_surfaces_test.go`) asserts: every registered collector has a unique `ID`, a `Path` no other collector claims, a golden schema on disk, a `MaxClass ≤ INTERNAL` for any collector in the "shareable" set, and a test file — so a collector cannot be added without its coverage. This is the CI wall required by the prompt ("prevent new components from being added without diagnostic coverage").

---

## 9. Registration

```go
// each domain registers its collector at init/startup, mirroring register*Routes
func init() { support.Register(&DiagnosticsCollector{}) }
```

`support.Register` rejects duplicate IDs/paths at startup (fatal — a wiring bug, not a runtime condition). The set of registered collectors is itself collectible (`product.json` lists collector IDs + versions) so a bundle self-describes which collectors produced it.

---

## 10. Example: the diagnostics collector (thinnest reuse)

```go
type DiagnosticsCollector struct{}
func (c *DiagnosticsCollector) Meta() CollectorMeta {
    return CollectorMeta{
        ID: "diagnostics", Path: "sections/diagnostics.json", Owner: "observability",
        SchemaVersion: 1, Timeout: 3 * time.Second, ByteBudget: 256 << 10,
        Mandatory: true, MinLevel: L1, Runtime: RuntimeAny, MaxClass: INTERNAL,
        Sensitivity: INTERNAL, Description: "Operator contract diagnostic verdict",
    }
}
func (c *DiagnosticsCollector) Collect(ctx context.Context, in CollectInput, sink SectionSink) Result {
    oc := buildOperatorContract()            // existing, side-effect-free, already secret-omitting
    red := in.Redactor.Struct(oc)            // defense-in-depth pass
    if err := sink.WriteJSON(red); err != nil { return Result{Status: Failed, Note: "write"} }
    return Result{Status: OK, ClassMax: INTERNAL}
}
```

This shows the intended altitude: collectors are thin adapters over existing safe accessors, with redaction and budgeting handled by the framework — not new data-gathering logic.
