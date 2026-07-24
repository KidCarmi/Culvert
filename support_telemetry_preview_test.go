package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixedSupportTelemetryTime() time.Time {
	return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
}

// withSupportTelemetryNow swaps supportTelemetryNow for the test's duration.
func withSupportTelemetryNow(t *testing.T, now func() time.Time) {
	t.Helper()
	prev := supportTelemetryNow
	supportTelemetryNow = now
	t.Cleanup(func() { supportTelemetryNow = prev })
}

// TestSupportTelemetryPreviewMatchesBuiltSample — §8: build ONE immutable
// sample, render that SAME sample through the preview serialization path,
// and compare exact bytes; separately prove the real HTTP handler (given the
// same injected clock) renders byte-identical output, i.e. it does not
// substitute a different rendering path.
func TestSupportTelemetryPreviewMatchesBuiltSample(t *testing.T) {
	withSupportTelemetryNow(t, fixedSupportTelemetryTime)

	sample, err := buildSupportTelemetrySample(supportTelemetryNow())
	if err != nil {
		t.Fatalf("buildSupportTelemetrySample: %v", err)
	}

	direct := httptest.NewRecorder()
	writeSupportTelemetryPreview(direct, sample)

	req := withRole(httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody), RoleAdmin)
	viaHandler := httptest.NewRecorder()
	apiSupportTelemetryPreview(viaHandler, req)

	if viaHandler.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want 200; body=%s", viaHandler.Code, viaHandler.Body.String())
	}
	if !bytes.Equal(direct.Body.Bytes(), viaHandler.Body.Bytes()) {
		t.Fatalf("preview rendering diverges from the handler's response:\ndirect:  %s\nhandler: %s", direct.Body.String(), viaHandler.Body.String())
	}

	var view supportTelemetryPreviewView
	if err := json.Unmarshal(direct.Body.Bytes(), &view); err != nil {
		t.Fatalf("unmarshal rendered preview: %v", err)
	}
	if view.SchemaVersion != sample.SchemaVersion || view.RegistryHash != sample.RegistryHash {
		t.Fatalf("rendered preview does not match the built sample's schema identity: %+v vs sample %+v", view, sample)
	}
	if len(view.Metrics) != len(sample.Metrics) {
		t.Fatalf("rendered preview has %d metrics, sample has %d", len(view.Metrics), len(sample.Metrics))
	}
}

// TestSupportTelemetryPreviewReadOnly proves a preview call creates no
// persistent state: dataDir contents (and specifically the support/
// subtree) are unchanged after N calls, and no telemetry config/consent
// files appear.
func TestSupportTelemetryPreviewReadOnly(t *testing.T) {
	withSupportTelemetryNow(t, fixedSupportTelemetryTime)
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDir })

	before := listDirTree(t, dataDir)

	for i := 0; i < 5; i++ {
		req := withRole(httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody), RoleAdmin)
		rec := httptest.NewRecorder()
		apiSupportTelemetryPreview(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: status = %d", i, rec.Code)
		}
	}

	after := listDirTree(t, dataDir)
	if len(after) != len(before) {
		t.Fatalf("preview calls created filesystem state under dataDir: before=%v after=%v", before, after)
	}
}

func listDirTree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestSupportTelemetryPreviewRBAC — GET-only, admin-only (per §14 Slice 1:
// "GET /api/support/telemetry/preview, admin"); viewer/operator/unauthenticated
// and non-GET methods are rejected.
func TestSupportTelemetryPreviewRBAC(t *testing.T) {
	for _, role := range []UIRole{"", RoleViewer, RoleOperator} {
		req := httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody)
		if role != "" {
			req = withRole(req, role)
		}
		rec := httptest.NewRecorder()
		apiSupportTelemetryPreview(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %q: status = %d, want 403", role, rec.Code)
		}
	}

	req := withRole(httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody), RoleAdmin)
	rec := httptest.NewRecorder()
	apiSupportTelemetryPreview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := withRole(httptest.NewRequest(method, "/api/support/telemetry/preview", http.NoBody), RoleAdmin)
		rec := httptest.NewRecorder()
		apiSupportTelemetryPreview(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want 405", method, rec.Code)
		}
	}
}

// TestSupportTelemetryPreviewNoSensitiveFields proves the preview response
// never exposes credential state, a TAC endpoint, node id, or bundle
// content — none of which this route has access to in the first place, but
// pinned here so a future field addition to supportTelemetryPreviewView is
// forced to justify itself against this list.
func TestSupportTelemetryPreviewNoSensitiveFields(t *testing.T) {
	withSupportTelemetryNow(t, fixedSupportTelemetryTime)
	req := withRole(httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody), RoleAdmin)
	rec := httptest.NewRecorder()
	apiSupportTelemetryPreview(rec, req)

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	allowed := map[string]bool{"schema_version": true, "registry_hash": true, "generated_at": true, "metrics": true}
	for k := range raw {
		if !allowed[k] {
			t.Errorf("preview response has unexpected top-level field %q", k)
		}
	}
	forbidden := []string{"node_id", "credential", "credential_set", "origin", "tac_endpoint", "endpoint", "bundle", "path"}
	body := rec.Body.String()
	for _, f := range forbidden {
		if _, ok := raw[f]; ok {
			t.Errorf("preview response leaked forbidden field %q: %s", f, body)
		}
	}
}

// TestSupportTelemetryPreviewConcurrentReadsRaceSafe — repeated concurrent
// preview requests must not race (the registry/Read closures touch shared
// process state like certMgr/policyStore/globalYARA under their own locks;
// this proves the preview path adds no unguarded access of its own). Run
// with -race.
func TestSupportTelemetryPreviewConcurrentReadsRaceSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := withRole(httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody), RoleAdmin)
			rec := httptest.NewRecorder()
			apiSupportTelemetryPreview(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent call: status = %d", rec.Code)
			}
		}()
	}
	wg.Wait()
}

// TestSupportTelemetryPreviewCreatesNoAuditEvent — a read-only preview must
// not appear as a new audit entry (matches the uiRoutes AuditExpected:false
// metadata and the design's "creates no persistent state").
func TestSupportTelemetryPreviewCreatesNoAuditEvent(t *testing.T) {
	marker := "203.0.113.77" // TEST-NET-3 reserved range; won't collide with real actors
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/support/telemetry/preview", http.NoBody).WithContext(ctx)
	req.RemoteAddr = marker + ":12345"

	rec := httptest.NewRecorder()
	apiSupportTelemetryPreview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	for _, e := range auditGet() {
		if e.Actor == marker {
			t.Fatalf("preview call produced an audit entry: %+v", e)
		}
	}
}
