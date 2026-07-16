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

func init() {
	support.Register(productCollector{})
	support.Register(diagnosticsCollector{})
}
