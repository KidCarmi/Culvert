// Package supportmetrics implements the M7 scoped support-metric registry
// (roadmap/M7-proactive-telemetry-plan.md §6). It is deliberately NOT a
// canonical mirror of every culvert_* Prometheus/OTLP metric — it governs
// only the small support-health scalar set shared by three surfaces:
// support-bundle evidence, the telemetry preview, and the future telemetry
// sender. Metric values themselves live wherever the real subsystem state
// lives (package main); this package owns only the descriptor schema, the
// default-deny/justification/label-free invariants, the deterministic
// registry_hash, and the pure sample builder.
package supportmetrics

import (
	"fmt"
	"regexp"
	"strings"
)

// MetricType is the wire kind of a governed metric. Every value is a
// label-free scalar regardless of kind — Counter is reserved for a future
// monotonic support-health signal; Slice 1 uses Gauge exclusively.
type MetricType int

// MetricType values.
const (
	Gauge MetricType = iota
	Counter
)

func (t MetricType) String() string {
	switch t {
	case Gauge:
		return "gauge"
	case Counter:
		return "counter"
	default:
		return "unknown"
	}
}

// PrivacyClass records why a metric is (or would be) safe to leave the
// appliance. Public/LocalOnly are defined for completeness and future
// entries; Slice 1's entire eligible set is Aggregate (appliance-own-health,
// non-identifying).
type PrivacyClass int

// PrivacyClass values.
const (
	Public PrivacyClass = iota
	Aggregate
	LocalOnly
)

func (c PrivacyClass) String() string {
	switch c {
	case Public:
		return "public"
	case Aggregate:
		return "aggregate"
	case LocalOnly:
		return "local_only"
	default:
		return "unknown"
	}
}

// idPattern constrains metric IDs to a closed, delimiter-safe vocabulary
// (lowercase snake_case) — the same discipline that keeps them safe to use
// as canonical-hash field values and rules out anything label/template-shaped
// (no braces, commas, or per-entity suffixes).
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Descriptor is one governed support-health metric. Conceptually equivalent
// to the merged design's supportMetricDescriptor (§6): a stable ID, its wire
// type, its privacy classification, whether it belongs to the support
// bundle's health section, whether it is approved for telemetry (default
// DENY — the zero value is false), a mandatory justification when eligible,
// and the live read. Buckets is populated only for coarse-bucketed metrics
// and canonically names each bucket boundary — it participates in
// registry_hash so a bucket-boundary change is a governed schema change,
// not a silent behavior change.
//
// Descriptors are read-only after Registry construction: nothing in this
// package mutates a Descriptor once assembled into a Registry.
type Descriptor struct {
	ID                string
	Type              MetricType
	PrivacyClass      PrivacyClass
	InSupportBundle   bool
	TelemetryEligible bool
	TelemetryReason   string
	Buckets           []string
	Read              func() float64
}

// Registry is a scoped, immutable-after-construction set of support-health
// metric descriptors. It is NOT a general-purpose metrics registry — see the
// package doc comment.
type Registry []Descriptor

// Validate enforces the structural invariants every descriptor must satisfy:
// non-empty label-free-safe ID, no duplicate IDs, a live Read callback, and —
// the default-deny contract — a non-empty TelemetryReason on every
// TelemetryEligible entry, which must also be marked InSupportBundle (the
// telemetry-eligible set is always a subset of the support-bundle set, §15
// TestSupportTelemetrySubset).
func (r Registry) Validate() error {
	seen := make(map[string]bool, len(r))
	for _, d := range r {
		if d.ID == "" {
			return fmt.Errorf("supportmetrics: descriptor with empty ID")
		}
		if !idPattern.MatchString(d.ID) {
			return fmt.Errorf("supportmetrics: metric id %q is not a label-free scalar id (must match %s)", d.ID, idPattern.String())
		}
		if seen[d.ID] {
			return fmt.Errorf("supportmetrics: duplicate metric id %q", d.ID)
		}
		seen[d.ID] = true
		if d.Read == nil {
			return fmt.Errorf("supportmetrics: metric %q has no Read callback", d.ID)
		}
		if d.TelemetryEligible {
			if strings.TrimSpace(d.TelemetryReason) == "" {
				return fmt.Errorf("supportmetrics: metric %q is telemetry-eligible but has no TelemetryReason", d.ID)
			}
			if !d.InSupportBundle {
				return fmt.Errorf("supportmetrics: metric %q is telemetry-eligible but not marked InSupportBundle (telemetry_eligible must be a subset of in_support_bundle)", d.ID)
			}
		}
	}
	return nil
}

// Eligible returns the subset of descriptors approved for telemetry, in
// registry order.
func (r Registry) Eligible() []Descriptor {
	out := make([]Descriptor, 0, len(r))
	for _, d := range r {
		if d.TelemetryEligible {
			out = append(out, d)
		}
	}
	return out
}
