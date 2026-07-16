// Package support is the support-bundle engine (SUPPORT-BUNDLE-SPEC.md,
// COLLECTOR-CONTRACT.md): a plugin registry of small, isolated, budgeted,
// self-redacting collectors plus a runner that assembles a deterministic,
// integrity-hashed `csb/1` bundle. Collectors live in their owning package and
// register here; the engine owns orchestration, redaction hand-off, budgeting,
// failure isolation, and serialization — never data-gathering logic.
package support

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// DebugLevel gates collectors (L0 always runs; richer levels unlock more).
type DebugLevel int

const (
	L0 DebugLevel = iota // always-on: product, readiness
	L1                   // standard bundle: diagnostics, config, policy, logs…
	L2                   // runtime/host (goroutine, container facts)
	L3                   // heap profile (gated)
	L4                   // maximal
)

// SectionStatus is the per-section outcome recorded in the manifest.
type SectionStatus string

const (
	StatusOK          SectionStatus = "ok"          // complete
	StatusPartial     SectionStatus = "partial"     // budget/timeout-truncated but usable
	StatusSkipped     SectionStatus = "skipped"     // level/runtime/feature gated out
	StatusUnavailable SectionStatus = "unavailable" // dependency down (DB, agent)
	StatusFailed      SectionStatus = "failed"      // collector error/panic
)

// RuntimeInfo describes the appliance's execution context.
type RuntimeInfo struct {
	Runtime string // compose|k8s|host|unknown
	Role    string // standalone|control-plane|data-plane|ha-standby
	NodeID  string
}

// CollectInput is handed to every collector. Redactor is the ONLY sanctioned
// masking path; Clock is injected so collectors never call time.Now directly
// (determinism, mirroring the autoexclude engine-test discipline).
type CollectInput struct {
	Level    DebugLevel
	Redactor redaction.Redactor
	Runtime  RuntimeInfo
	Clock    func() time.Time
}

// SectionSink receives exactly one section's bytes and enforces its byte budget
// while computing the integrity hash.
type SectionSink interface {
	// WriteJSON marshals v (already redacted by the collector) deterministically
	// into the section, enforcing the byte budget.
	WriteJSON(v any) error
}

// Result is what a collector returns. A "subsystem down" is a Status, never an
// error — the runner keeps going; only the framework can fail a bundle.
type Result struct {
	Status    SectionStatus
	ClassMax  redaction.DataClass // highest class actually written (post-redaction)
	Truncated bool
	Note      string // redacted, human-readable
}

// CollectorMeta is a collector's static contract.
type CollectorMeta struct {
	ID            string // stable snake_case; == section id; unique
	Path          string // section path in the tar (e.g. "sections/diagnostics.json")
	Owner         string // subsystem team
	SchemaVersion int    // per-section schema; bumped on shape change
	Description   string
	Timeout       time.Duration       // hard cap; runner cancels ctx at this
	ByteBudget    int64               // section size cap
	Mandatory     bool                // mandatory collectors gate completeness, never abort
	MinLevel      DebugLevel          // runs only at/above this level (L0 always)
	MaxClass      redaction.DataClass // asserted ceiling; a section exceeding it is dropped
	Sensitivity   redaction.DataClass // declared default class of this section's raw data
}

// Collector produces one section of a CSB.
type Collector interface {
	Meta() CollectorMeta
	// Collect writes exactly one section into sink. It MUST respect ctx,
	// redact at source via in.Redactor, and return a Result (not an error) for
	// "subsystem down". It should not rely on the runner's panic recovery.
	Collect(ctx context.Context, in CollectInput, sink SectionSink) Result
}
