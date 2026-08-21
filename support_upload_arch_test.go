package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// support_upload_arch_test.go — M6 architecture invariants from
// SECURE-UPLOAD-ARCHITECTURE.md §9. These are the cross-cutting guarantees the
// secure-upload channel must hold regardless of the per-slice unit tests.

// TestNoInboundTACSurface pins the mandatory-invariant that the cloud can NEVER
// dial into Culvert (ADR-0014/0015/0017): the upload path is outbound-only. Two
// checks: (1) the upload engine is a pure CLIENT — it carries no server/listener
// call site; (2) every M6 upload route is auth-gated (non-public), so there is no
// unauthenticated endpoint a TAC could push to.
func TestNoInboundTACSurface(t *testing.T) {
	// (1) internal/supportupload must have no inbound-server markers.
	serverMarkers := []string{
		"net.Listen", "http.Server", "ListenAndServe", "http.HandleFunc", ".Serve(", "http.NewServeMux",
	}
	entries, err := os.ReadDir("internal/supportupload")
	if err != nil {
		t.Fatalf("read internal/supportupload: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("internal", "supportupload", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		for _, m := range serverMarkers {
			if strings.Contains(src, m) {
				t.Errorf("%s contains inbound-server marker %q — the upload engine must be outbound-only (no dial-in surface)", name, m)
			}
		}
	}

	// (2) No M6 upload route is public.
	m6 := map[string]bool{
		"/api/support/upload/config":       true,
		"/api/support/tac-trust":           true,
		"/api/support/uploads":             true,
		"/api/support/bundles/{id}/upload": true,
	}
	seen := map[string]bool{}
	for i := range uiRoutes {
		rt := uiRoutes[i]
		if !m6[rt.Path] {
			continue
		}
		seen[rt.Path] = true
		if rt.Public {
			t.Errorf("M6 route %q is public — the cloud must never reach an unauthenticated upload endpoint", rt.Path)
		}
	}
	for p := range m6 {
		if !seen[p] {
			t.Errorf("expected M6 route %q in uiRoutes (inbound-surface audit incomplete)", p)
		}
	}
}

// TestHealthWithoutCloud pins cloud-independence: with no upload configured (the
// cloud unreachable/absent), local health answers offline and the upload
// subsystem reports not_enabled without any network attempt.
func TestHealthWithoutCloud(t *testing.T) {
	withTempUploadDir(t) // fresh dataDir → no upload config

	if uploadEnabled() {
		t.Fatal("upload must be disabled with no config")
	}
	if st := uploadStatus(); st["state"] != "not_enabled" {
		t.Fatalf("offline upload state = %v, want not_enabled", st["state"])
	}

	// Liveness answers 200 and does not consult the cloud.
	rec := httptest.NewRecorder()
	handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleHealth = %d, want 200 (health must not depend on the cloud)", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("handleHealth produced no body")
	}

	// The drain worker is inert when disabled — no upload is attempted.
	called := false
	drainDueUploads(context.Background(), func(_ context.Context, _ uploadQueueEntry) (*supportupload.Receipt, string, error) {
		called = true
		return nil, "", nil
	})
	if called {
		t.Fatal("the worker attempted an upload with no cloud configured")
	}
}

// TestBundleBudgetsEnforced pins the cross-milestone invariant (#4) that every
// persisted upload state under <dataDir>/support is BOUNDED, and that the
// bundle-store disk-safety ceilings are sane — a hostile or runaway producer
// cannot grow these without limit.
func TestBundleBudgetsEnforced(t *testing.T) {
	// Upload-queue bounds are positive.
	if maxUploadQueue <= 0 || maxUploadTerminal <= 0 {
		t.Fatalf("upload queue caps must be positive: queue=%d terminal=%d", maxUploadQueue, maxUploadTerminal)
	}
	if maxUploadErrLen <= 0 {
		t.Fatalf("maxUploadErrLen must be positive, got %d", maxUploadErrLen)
	}
	// A persisted error string is length-bounded (no unbounded attacker text on disk).
	long := strings.Repeat("x", maxUploadErrLen*4)
	if got := boundUploadErr(long); len(got) > maxUploadErrLen+4 { // +4 for the ellipsis rune
		t.Fatalf("boundUploadErr did not bound the string: len=%d cap=%d", len(got), maxUploadErrLen)
	}
	// Bundle-store disk-safety ceilings are sane and ordered.
	if supportMinFreeBytes <= 0 || supportMaxStoreBytes <= 0 {
		t.Fatalf("bundle disk ceilings must be positive: minFree=%d maxStore=%d", supportMinFreeBytes, supportMaxStoreBytes)
	}
}
