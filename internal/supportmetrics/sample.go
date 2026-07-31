package supportmetrics

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"
)

// sampleEpochPattern is the wire format for sample_epoch (§5): exactly a
// 128-bit value as lowercase hex (32 hex characters).
var sampleEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Sample is one immutable support-telemetry sample: the governed schema
// identity (SchemaVersion + RegistryHash), the delivery-identity fields the
// merged wire contract carries in its inner sealed plaintext (SampleEpoch +
// Sequence, §5 — non-identifying: SampleEpoch is a random per-process-epoch
// token, Sequence a per-epoch counter; Slice 1 does not generate or persist
// these — the caller supplies them, see BuildSample), a generation
// timestamp, and the current value of every telemetry-eligible metric. It
// carries no stable appliance identity — no node id, hostname, IP, tenant
// id, or credential — by construction.
//
// EVERY field is unexported. Once BuildSample returns a Sample, there is no
// exported API — field, method, or otherwise — that can change what it
// reports: each accessor either returns an immutable value type (int,
// string, time.Time, uint64) or, for Metrics(), a fresh defensive copy of
// the internal map. MarshalJSON serializes the Sample's OWN internal state
// directly, never a copy a caller could have mutated in between. This is
// what lets the preview handler and a future sender share the exact same
// built Sample without either one being able to invalidate the other's view
// of it, and it is what makes "the preview is the exact sample" a provable
// claim rather than a comment.
type Sample struct {
	schemaVersion int
	registryHash  string
	generatedAt   time.Time
	sampleEpoch   string
	sequence      uint64
	metrics       map[string]float64
}

// SchemaVersion is the governed telemetry wire-schema version this sample
// was built against.
func (s Sample) SchemaVersion() int { return s.schemaVersion }

// RegistryHash is the registry_hash this sample's schema was built against.
func (s Sample) RegistryHash() string { return s.registryHash }

// GeneratedAt is the RFC3339 UTC timestamp this sample was built.
func (s Sample) GeneratedAt() time.Time { return s.generatedAt }

// SampleEpoch is the caller-supplied, non-identifying process/reset-epoch
// token (§5) — never a stable appliance fingerprint.
func (s Sample) SampleEpoch() string { return s.sampleEpoch }

// Sequence is the caller-supplied per-epoch delivery sequence number (§5).
func (s Sample) Sequence() uint64 { return s.sequence }

// Metrics returns a defensive copy of the sample's telemetry-eligible
// metric id → value map. Mutating the returned map never affects the
// Sample.
func (s Sample) Metrics() map[string]float64 {
	out := make(map[string]float64, len(s.metrics))
	for k, v := range s.metrics {
		out[k] = v
	}
	return out
}

// sampleWire is the exact JSON wire shape (§3.3) — a plain struct so
// encoding/json's normal reflection path handles it (Sample itself cannot
// export its fields without losing immutability).
type sampleWire struct {
	SchemaVersion int                `json:"schema_version"`
	RegistryHash  string             `json:"registry_hash"`
	GeneratedAt   time.Time          `json:"generated_at"`
	SampleEpoch   string             `json:"sample_epoch"`
	Sequence      uint64             `json:"sequence"`
	Metrics       map[string]float64 `json:"metrics"`
}

// MarshalJSON serializes the sample's own internal state directly (not a
// copy obtained through an accessor), so canonical-bytes comparisons
// (§8 TestSupportTelemetryPreviewMatchesBuiltSample) are comparing the one
// built Sample, not two independently-copied views of it. This IS the
// complete §3.3 inner-sample shape — a preview that renders a Sample via
// this method is losslessly rendering the exact sample a future sender
// would seal, not a partial projection of it.
func (s Sample) MarshalJSON() ([]byte, error) {
	return json.Marshal(sampleWire{
		SchemaVersion: s.schemaVersion,
		RegistryHash:  s.registryHash,
		GeneratedAt:   s.generatedAt,
		SampleEpoch:   s.sampleEpoch,
		Sequence:      s.sequence,
		Metrics:       s.metrics,
	})
}

// BuildSample constructs ONE immutable telemetry sample from the registry's
// current TelemetryEligible descriptors. It is side-effect-free: it only
// calls each eligible descriptor's Read() closure, performs no I/O, starts no
// goroutine, persists nothing, and never mutates the receiver.
//
// now, epoch, and sequence are all caller-supplied (never generated
// internally) — mirroring the merged design's conceptual
// buildSupportTelemetrySample(now, epoch, sequence) signature (§5). Slice 1
// has no persistent per-process epoch generator or delivery sequence
// counter (that machinery belongs to Slice 3's sender/spool); the preview
// caller supplies a process-lifetime epoch and sequence 0 (see
// support_telemetry_registry.go), and a future sender supplies its own
// real epoch/sequence through this same, unchanged function.
//
// Caller-supplied inputs are validated, not merely trusted: now must be
// non-zero, epoch must be exactly a 128-bit lowercase-hex token (the wire
// format, §5), and every eligible metric's Read() value must be finite (a
// NaN/Inf would serialize as invalid or misleading JSON and has no
// legitimate meaning for any of the §7 gauge/bucket metrics).
func (r Registry) BuildSample(now time.Time, epoch string, sequence uint64) (Sample, error) {
	if err := r.Validate(); err != nil {
		return Sample{}, err
	}
	if now.IsZero() {
		return Sample{}, fmt.Errorf("supportmetrics: BuildSample: now must be non-zero")
	}
	if !sampleEpochPattern.MatchString(epoch) {
		return Sample{}, fmt.Errorf("supportmetrics: BuildSample: epoch must be exactly 32 lowercase hex characters (128 bits), got %q", epoch)
	}
	eligible := r.Eligible()
	metrics := make(map[string]float64, len(eligible))
	for _, d := range eligible {
		v := d.Read()
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return Sample{}, fmt.Errorf("supportmetrics: metric %q returned a non-finite value (%v)", d.ID, v)
		}
		metrics[d.ID] = v
		if d.DeprecatedAlias != "" {
			metrics[d.DeprecatedAlias] = v
		}
	}
	return Sample{
		schemaVersion: SchemaVersion,
		registryHash:  r.Hash(),
		generatedAt:   now.UTC(),
		sampleEpoch:   epoch,
		sequence:      sequence,
		metrics:       metrics,
	}, nil
}
