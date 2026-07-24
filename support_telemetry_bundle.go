package main

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// supportMetricsSection is the support bundle's health section fed directly
// by supportMetricRegistry — proving §6's "shared source for support-bundle
// evidence, telemetry preview, and send" claim is a real code path, not only
// a metadata assertion (InSupportBundle=true on a descriptor). RegistryHash
// lets an operator or TAC correlate a bundle's health section against a
// telemetry preview/send from the same node.
type supportMetricsSection struct {
	RegistryHash string             `json:"registry_hash" redact:"public"`
	Metrics      map[string]float64 `json:"metrics" redact:"public"`
}

// computeSupportMetricsSection reads every InSupportBundle descriptor in
// supportMetricRegistry — the exact same registry and Read closures the
// telemetry preview (and, unchanged, a future sender) use.
func computeSupportMetricsSection() (supportMetricsSection, error) {
	metrics, err := supportMetricRegistry.BundleSnapshot()
	if err != nil {
		return supportMetricsSection{}, err
	}
	return supportMetricsSection{RegistryHash: supportMetricRegistry.Hash(), Metrics: metrics}, nil
}

type supportMetricsCollector struct{}

func (supportMetricsCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "support_metrics", Path: "sections/support_metrics.json", Owner: "core", SchemaVersion: 1,
		Description: "M7 scoped support-metric registry snapshot (own-health bits/buckets only — the same registry and values a telemetry preview/send would use)",
		Timeout:     2 * time.Second, ByteBudget: 8 << 10, Mandatory: false, MinLevel: support.L0,
		MaxClass: redaction.ClassPublic, Sensitivity: redaction.ClassPublic,
	}
}

func (supportMetricsCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	sec, err := computeSupportMetricsSection()
	if err != nil {
		return support.Result{Status: support.StatusFailed, Note: "registry invalid"}
	}
	return classifyAndWriteSection(in, sink, sec)
}

func init() {
	support.Register(supportMetricsCollector{})
}
