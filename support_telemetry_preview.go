package main

import (
	"net/http"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportmetrics"
)

// supportTelemetryPreviewView is the admin-facing JSON shape for
// GET /api/support/telemetry/preview (roadmap/M7-proactive-telemetry-plan.md
// §8/§14 Slice 1). It is a straight, lossless projection of
// supportmetrics.Sample: schema version, registry hash, generation
// timestamp, and the current value of every telemetry-eligible metric. The
// preview renders the SAME immutable sample object a future sender would
// seal — never a second, independently-built one — so this type exists to
// keep "build" (buildSupportTelemetrySample) and "render" (this file)
// visibly separate, per the merged design's requirement that the sender be
// able to reuse the exact sample the preview showed.
//
// This route creates no persistent state, enables no telemetry, and sends
// nothing — there is no consent switch, no sender, and no egress anywhere in
// this build (see support_telemetry_noegress_test.go).
type supportTelemetryPreviewView struct {
	SchemaVersion int                `json:"schema_version"`
	RegistryHash  string             `json:"registry_hash"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Metrics       map[string]float64 `json:"metrics"`
}

// renderSupportTelemetryPreview projects an already-built Sample into the
// preview's wire shape. It does not rebuild, re-read, or mutate the sample —
// pure field-for-field projection.
func renderSupportTelemetryPreview(s supportmetrics.Sample) supportTelemetryPreviewView {
	return supportTelemetryPreviewView{
		SchemaVersion: s.SchemaVersion,
		RegistryHash:  s.RegistryHash,
		GeneratedAt:   s.GeneratedAt,
		Metrics:       s.Metrics(),
	}
}

// writeSupportTelemetryPreview is the preview serialization path: given one
// already-built sample, it writes exactly its rendered projection as JSON.
// Kept separate from apiSupportTelemetryPreview so tests can build a sample
// once and drive this same function directly, proving the HTTP handler does
// not rebuild a second, independently-timed sample before responding.
func writeSupportTelemetryPreview(w http.ResponseWriter, sample supportmetrics.Sample) {
	jsonOK(w, renderSupportTelemetryPreview(sample))
}

// apiSupportTelemetryPreview is the Slice 1 read-only preview route: GET
// only, admin, no persistent state, no consent, no sender. It builds one
// current sample from the live support-metric registry and renders it
// unchanged. Errors (an invalid registry — a build-time programmer error,
// never a runtime/user condition) surface as 503 with no internal detail.
func apiSupportTelemetryPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	sample, err := buildSupportTelemetrySample(supportTelemetryNow())
	if err != nil {
		http.Error(w, "support telemetry registry unavailable", http.StatusServiceUnavailable)
		return
	}
	writeSupportTelemetryPreview(w, sample)
}
