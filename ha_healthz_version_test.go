package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthz_ReportsRuntimeVersion pins the release-integrity invariant surfaced
// by the first LIVE authoritative MCP Observe Acceptance (v1.0.202): the live
// /healthz endpoint MUST self-report the build-time release identity, wired to the
// SAME package var the linker stamps (`-X main.version=vX.Y.Z`). The v1.0.202
// signed binary stamped main.version correctly but apiHealthz omitted the field
// entirely, so the acceptance harness read an empty version and the required
// `artifact.version` criterion failed. This test fails closed if /healthz ever
// stops surfacing the version or hard-codes a value instead of the linker SSOT.
func TestHealthz_ReportsRuntimeVersion(t *testing.T) {
	// Force a deterministic standalone HA posture (the LB-probe path the acceptance
	// harness reads) and a sentinel version, restoring both afterwards so the
	// process-global state is not leaked to other tests under -shuffle.
	origVer, origHA := version, globalHA
	t.Cleanup(func() { version, globalHA = origVer, origHA })
	version = "v9.9.9-healthz-test"
	globalHA = &HAState{}

	rec := httptest.NewRecorder()
	apiHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("standalone /healthz status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /healthz: %v", err)
	}
	got, ok := body["version"]
	if !ok {
		t.Fatal(`/healthz response has no "version" field: signed release identity is unverifiable at runtime`)
	}
	// Wired to the linker-stamped main.version SSOT, not a literal.
	if got != version {
		t.Fatalf("/healthz version = %v, want %q (must equal main.version, the linker-stamped SSOT)", got, version)
	}
}
