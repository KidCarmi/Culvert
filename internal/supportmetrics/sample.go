package supportmetrics

import (
	"encoding/json"
	"time"
)

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
// metrics is unexported and Sample is used exclusively by value, so once
// built a Sample cannot be mutated through any exported API: Metrics()
// returns a fresh copy on every call, never the internal map, and
// MarshalJSON serializes that same internal map directly (never a copy a
// caller could have mutated in between). This is what lets the preview
// handler and a future sender share the exact same built Sample without
// either one being able to invalidate the other's view of it.
type Sample struct {
	SchemaVersion int
	RegistryHash  string
	GeneratedAt   time.Time
	SampleEpoch   string
	Sequence      uint64
	metrics       map[string]float64
}

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
// export `metrics` without losing immutability).
type sampleWire struct {
	SchemaVersion int                `json:"schema_version"`
	RegistryHash  string             `json:"registry_hash"`
	GeneratedAt   time.Time          `json:"generated_at"`
	SampleEpoch   string             `json:"sample_epoch"`
	Sequence      uint64             `json:"sequence"`
	Metrics       map[string]float64 `json:"metrics"`
}

// MarshalJSON serializes the sample's own internal metrics map directly
// (not a copy obtained through Metrics()), so canonical-bytes comparisons
// (§8 TestSupportTelemetryPreviewMatchesBuiltSample) are comparing the one
// built Sample, not two independently-copied views of it.
func (s Sample) MarshalJSON() ([]byte, error) {
	return json.Marshal(sampleWire{
		SchemaVersion: s.SchemaVersion,
		RegistryHash:  s.RegistryHash,
		GeneratedAt:   s.GeneratedAt,
		SampleEpoch:   s.SampleEpoch,
		Sequence:      s.Sequence,
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
func (r Registry) BuildSample(now time.Time, epoch string, sequence uint64) (Sample, error) {
	if err := r.Validate(); err != nil {
		return Sample{}, err
	}
	eligible := r.Eligible()
	metrics := make(map[string]float64, len(eligible))
	for _, d := range eligible {
		metrics[d.ID] = d.Read()
	}
	return Sample{
		SchemaVersion: SchemaVersion,
		RegistryHash:  r.Hash(),
		GeneratedAt:   now.UTC(),
		SampleEpoch:   epoch,
		Sequence:      sequence,
		metrics:       metrics,
	}, nil
}
