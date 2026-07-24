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
// monotonic support-health signal; Slice 1 uses Gauge exclusively. The zero
// value is MetricTypeUnknown (fails Validate) rather than a real kind like
// Gauge, so an omitted/forgotten classification is caught, not silently
// treated as valid (fail-closed).
type MetricType int

// MetricType values.
const (
	MetricTypeUnknown MetricType = iota
	Gauge
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

func (t MetricType) valid() bool { return t == Gauge || t == Counter }

// PrivacyClass records why a metric is (or would be) safe to leave the
// appliance. The zero value is PrivacyClassUnknown (fails Validate) rather
// than Public, so an omitted classification is caught instead of defaulting
// to the most permissive class (fail-closed). LocalOnly is defined for
// completeness/future entries that are support-bundle-only and must never
// be telemetry-eligible — enforced below.
type PrivacyClass int

// PrivacyClass values.
const (
	PrivacyClassUnknown PrivacyClass = iota
	Public
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

func (c PrivacyClass) valid() bool { return c == Public || c == Aggregate || c == LocalOnly }

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
// and is the SAME BucketLadder value the Read closure evaluates against
// (see buckets.go) — it participates in registry_hash so a threshold change
// is a governed schema change, not a silent behavior change.
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
	Buckets           *BucketLadder
	Read              func() float64
}

// Registry is a scoped, immutable-after-construction set of support-health
// metric descriptors. It is NOT a general-purpose metrics registry — see the
// package doc comment.
type Registry []Descriptor

// Validate enforces the structural invariants every descriptor must satisfy:
// non-empty label-free-safe ID, no duplicate IDs, a valid (non-Unknown) Type
// and PrivacyClass, a live Read callback, and — the default-deny contract —
// a non-empty TelemetryReason on every TelemetryEligible entry, which must
// also be marked InSupportBundle (the telemetry-eligible set is always a
// subset of the support-bundle set, §15 TestSupportTelemetrySubset) and must
// NOT be PrivacyClass LocalOnly (a LocalOnly classification is a positive
// declaration that the value must never leave the box; TelemetryEligible on
// such an entry is a contradiction, not a policy choice).
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
		if !d.Type.valid() {
			return fmt.Errorf("supportmetrics: metric %q has invalid/unclassified Type (%v)", d.ID, d.Type)
		}
		if !d.PrivacyClass.valid() {
			return fmt.Errorf("supportmetrics: metric %q has invalid/unclassified PrivacyClass (%v)", d.ID, d.PrivacyClass)
		}
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
			if d.PrivacyClass == LocalOnly {
				return fmt.Errorf("supportmetrics: metric %q is telemetry-eligible but classified LocalOnly (LocalOnly must never leave the box)", d.ID)
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

// InBundle returns the subset of descriptors marked InSupportBundle, in
// registry order.
func (r Registry) InBundle() []Descriptor {
	out := make([]Descriptor, 0, len(r))
	for _, d := range r {
		if d.InSupportBundle {
			out = append(out, d)
		}
	}
	return out
}

// BundleSnapshot reads every InSupportBundle descriptor's current value.
// This is what makes the registry an ACTUAL shared source for support-bundle
// health (§6) rather than only a metadata claim: the support bundle's
// health section (package main) calls this directly — the exact same
// Read closures and the exact same registry the telemetry sample/preview
// use — so a metric present in the bundle is provably the same metric (and
// the same live value) telemetry would show, not a separately-maintained
// mirror. Side-effect-free, like BuildSample.
func (r Registry) BundleSnapshot() (map[string]float64, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	inBundle := r.InBundle()
	out := make(map[string]float64, len(inBundle))
	for _, d := range inBundle {
		out[d.ID] = d.Read()
	}
	return out, nil
}
