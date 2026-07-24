package supportmetrics

import "time"

// Sample is one immutable support-telemetry sample: the governed schema
// identity (SchemaVersion + RegistryHash) plus the current value of every
// telemetry-eligible metric (§3.3 inner sealed plaintext). It carries no
// stable appliance identity — no node id, hostname, IP, tenant id, or
// credential — by construction: Metrics contains only the label-free scalar
// values the registry's TelemetryEligible descriptors expose.
//
// Slice 1 scope: the merged design's wire contract also carries
// sample_epoch/sequence (§5) — non-identifying delivery-retry bookkeeping
// owned by Slice 3's sender/spool, which does not exist yet. Building those
// here would fabricate delivery state this slice has nowhere to use; a
// Sample is exactly the fields a read-only preview (and, unchanged, a future
// sealed send) needs: the governed schema identity, a generation timestamp,
// and the eligible metric values.
type Sample struct {
	SchemaVersion int                `json:"schema_version"`
	RegistryHash  string             `json:"registry_hash"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Metrics       map[string]float64 `json:"metrics"`
}

// BuildSample constructs ONE immutable telemetry sample from the registry's
// current TelemetryEligible descriptors. It is side-effect-free: it only
// calls each eligible descriptor's Read() closure, performs no I/O, starts no
// goroutine, persists nothing, and never mutates the receiver. now is
// caller-supplied (never time.Now() internally) so every caller — including
// tests and, later, the preview handler and the sender — gets a
// reproducible, injectable clock.
func (r Registry) BuildSample(now time.Time) (Sample, error) {
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
		Metrics:       metrics,
	}, nil
}
