package main

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/supportmetrics"
)

// writeSupportTelemetryPreview is the preview serialization path: given one
// already-built sample, it writes the sample's OWN canonical JSON
// representation (supportmetrics.Sample.MarshalJSON) — the complete §3.3
// inner-sample shape: schema_version, registry_hash, generated_at,
// sample_epoch, sequence, and metrics. This is a lossless rendering, not a
// second, independently-maintained projection of the sample — "the preview
// is the exact sample that would be sealed and sent" is therefore literally
// true of the bytes on the wire, not just a comment. Kept as its own
// function (rather than inlined into the handler) so tests can build a
// sample once and drive this same function directly, proving the HTTP
// handler does not rebuild a second, independently-timed sample before
// responding.
func writeSupportTelemetryPreview(w http.ResponseWriter, sample supportmetrics.Sample) {
	jsonOK(w, sample)
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
