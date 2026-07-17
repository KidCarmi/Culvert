package main

import (
	"context"
	"runtime"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// Slice-1 support collectors. Collectors live in package main (they read main's
// safe accessors) and register into the internal/support engine at init,
// mirroring the register*Routes wiring. They are thin adapters: gather via an
// existing side-effect-free accessor, hand off to in.Redactor, write one section.

// classifyAndWriteSection is the shared tail of a collector's Collect method:
// redact sec via in.Redactor, write it to sink, and map the outcome to a
// support.Result. Extracted so structurally-identical collectors (e.g.
// configVersionsCollector/upstreamCollector) don't duplicate this boilerplate.
func classifyAndWriteSection(in support.CollectInput, sink support.SectionSink, sec any) support.Result {
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// productSection is the PUBLIC product/build/runtime identity. Every field is
// PUBLIC by construction — no hostname/identity here (those live in manifest.node
// and are classified INTERNAL there), so product.json stays a shareable ceiling
// of PUBLIC.
type productSection struct {
	Product                string `json:"product" redact:"public"`
	Version                string `json:"version" redact:"public"`
	Go                     string `json:"go" redact:"public"`
	OS                     string `json:"os" redact:"public"`
	Arch                   string `json:"arch" redact:"public"`
	Uptime                 string `json:"uptime" redact:"public"`
	CollectorEngineVersion int    `json:"collector_engine_version" redact:"public"`
}

type productCollector struct{}

func (productCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "product", Path: "sections/product.json", Owner: "core", SchemaVersion: 1,
		Description: "Product, build and runtime identity", Timeout: 2 * time.Second,
		ByteBudget: 32 << 10, Mandatory: true, MinLevel: support.L0,
		MaxClass: redaction.ClassPublic, Sensitivity: redaction.ClassPublic,
	}
}

func (productCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	ps := productSection{
		Product: "culvert", Version: version, Go: runtime.Version(),
		OS: runtime.GOOS, Arch: runtime.GOARCH, Uptime: uptime(),
		CollectorEngineVersion: support.CollectorEngineVer,
	}
	res := in.Redactor.Classify(ps)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

type diagnosticsCollector struct{}

func (diagnosticsCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "diagnostics", Path: "sections/diagnostics.json", Owner: "observability", SchemaVersion: 1,
		Description: "Operator-contract diagnostic verdict", Timeout: 3 * time.Second,
		ByteBudget: 256 << 10, Mandatory: true, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (diagnosticsCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	// buildOperatorContract is side-effect-free and already secret-omitting; the
	// redactor pass is defense-in-depth (COLLECTOR-CONTRACT §10).
	oc := buildOperatorContract()
	res := in.Redactor.Classify(oc)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

type healthCollector struct{}

func (healthCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "health", Path: "sections/health.json", Owner: "observability", SchemaVersion: 1,
		Description: "Liveness + subsystem posture snapshot", Timeout: 2 * time.Second,
		ByteBudget: 32 << 10, Mandatory: true, MinLevel: support.L0,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (healthCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	res := in.Redactor.Classify(computeHealth())
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

type readinessCollector struct{}

func (readinessCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "readiness", Path: "sections/readiness.json", Owner: "observability", SchemaVersion: 1,
		Description: "Readiness probe snapshot", Timeout: 2 * time.Second,
		ByteBudget: 32 << 10, Mandatory: true, MinLevel: support.L0,
		MaxClass: redaction.ClassPublic, Sensitivity: redaction.ClassPublic,
	}
}

func (readinessCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	rep, _ := computeReadiness() // the HTTP status code is not part of the section
	res := in.Redactor.Classify(rep)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

type crashCollector struct{}

func (crashCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "crash", Path: "sections/crash.json", Owner: "observability", SchemaVersion: 1,
		Description: "Most-recent recovered panic (redacted; seeds the crash timeline)", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L0,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (crashCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	rec, ok := lastCrashSnapshot()
	if !ok {
		if err := sink.WriteJSON(map[string]any{"last_crash": nil}); err != nil {
			return support.Result{Status: support.StatusFailed, Note: "write"}
		}
		return support.Result{Status: support.StatusOK, ClassMax: redaction.ClassPublic}
	}
	res := in.Redactor.Classify(rec) // masks Summary/Stack; counts feed the redaction report
	if err := sink.WriteJSON(map[string]any{"last_crash": res.Value}); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

func init() {
	support.Register(productCollector{})
	support.Register(diagnosticsCollector{})
	support.Register(healthCollector{})
	support.Register(readinessCollector{})
	support.Register(crashCollector{})
}
