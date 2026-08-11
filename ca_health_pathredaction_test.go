package main

// ca_health_pathredaction_test.go — the CHAOS-28 / CA-2 redaction boundary.
//
// Regression: the CA-2 persistence-failure record stored SaveCA's error text
// verbatim, and SaveCA wraps fileutil.AtomicWrite, whose message embeds the
// absolute bundle path AND the temp file beside it:
//
//	CA write: atomic write /data/ca.bundle: create temp:
//	          open /data/ca.bundle.tmp.24: permission denied
//
// That value is surfaced on /api/ca/status as `rotationPersistError`, and
// /api/ca/status is a VIEWER-role route (ui_routes_meta.go). Raw filesystem
// paths on a viewer surface are exactly what the standing guardrail
// TestApiDiagnostics_NoSensitiveValues forbids — the same defect class already
// caught once on the storage plane and pinned by
// TestStorageWriteFailure_NeverLeaksAbsolutePaths. The cause must survive; the
// path must not.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withCARuntimePath points caRuntime at path for the duration of the test.
func withCARuntimePath(t *testing.T, path string) {
	t.Helper()
	prevPath, prevPass := caRuntime.path, caRuntime.passphrase
	caRuntime.path, caRuntime.passphrase = path, "pw"
	t.Cleanup(func() { caRuntime.path, caRuntime.passphrase = prevPath, prevPass })
}

// TestCARotationPersistFailure_NeverLeaksAbsolutePaths drives the REAL failing
// write (not a hand-written error string) so the assertion tracks whatever
// AtomicWrite actually emits, and pins both halves of the contract: the
// directory is gone, the actionable part is not.
func TestCARotationPersistFailure_NeverLeaksAbsolutePaths(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	// Mirror the production shape: a bundle under a data directory whose parent
	// is a regular file, so every write fails ENOTDIR.
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	bundle := filepath.Join(blocker, "ca.bundle")
	withCARuntimePath(t, bundle)

	if persistRotatedCA() {
		t.Fatal("persistRotatedCA reported success writing through a regular file")
	}

	snap := caUsabilityFailures()
	if !snap.PersistDegraded {
		t.Fatal("a failed save did not degrade the persistence state")
	}
	if strings.Contains(snap.PersistErr, blocker) {
		t.Errorf("recorded error still carries the directory %q: %q", blocker, snap.PersistErr)
	}
	if strings.Contains(snap.PersistErr, dir) {
		t.Errorf("recorded error still carries the data directory %q: %q", dir, snap.PersistErr)
	}
	// The cause must stay actionable: the bundle file name survives redaction.
	if !strings.Contains(snap.PersistErr, "ca.bundle") {
		t.Errorf("redaction removed the file name too: %q", snap.PersistErr)
	}
}

// TestApiCAStatus_PersistErrorHasNoFilesystemPath is the end-to-end half: the
// VIEWER-role response body must carry no separator-prefixed path. This is the
// assertion that actually encodes the security property — the unit test above
// can pass while a second, unredacted sink is added to the handler.
func TestApiCAStatus_PersistErrorHasNoFilesystemPath(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	withCARuntimePath(t, filepath.Join(blocker, "ca.bundle"))

	if persistRotatedCA() {
		t.Fatal("persistRotatedCA reported success writing through a regular file")
	}

	r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/ca/status", http.NoBody))
	w := httptest.NewRecorder()
	apiCAStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if degraded, _ := body["rotationPersistDegraded"].(bool); !degraded {
		t.Fatal("viewer response did not report the degraded persistence state")
	}
	detail, _ := body["rotationPersistError"].(string)
	if detail == "" {
		t.Fatal("viewer response dropped the persistence cause entirely")
	}
	if strings.Contains(detail, dir) || strings.Contains(detail, blocker) {
		t.Errorf("viewer-role rotationPersistError leaks a filesystem path: %q", detail)
	}
	// Whole-body sweep: no other field may reintroduce the path either.
	if raw := w.Body.String(); strings.Contains(raw, dir) {
		t.Errorf("viewer-role /api/ca/status body leaks the data directory %q: %s", dir, raw)
	}
}

// TestCARotationPersistFailure_RedactionBoundaryCases covers the shapes that
// must NOT be mangled: an unconfigured bundle path (redactWritePath's no-op
// case, where filepath.Dir("") is "."), and a cause carrying no path at all.
func TestCARotationPersistFailure_RedactionBoundaryCases(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	cases := []struct {
		name    string
		caPath  string
		reason  string
		wantSub string
	}{
		{"no bundle path configured", "", "no space left on device", "no space left on device"},
		{"relative bundle path", "ca.bundle", "CA write: atomic write ca.bundle: read-only file system", "read-only file system"},
		{"cause carries no path", "/srv/culvert/data/ca.bundle", "CA encrypt: key derivation failed", "key derivation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCAUsabilityHealthForTest()
			withCARuntimePath(t, tc.caPath)

			noteCARotationPersistFailure(tc.reason)

			snap := caUsabilityFailures()
			if !strings.Contains(snap.PersistErr, tc.wantSub) {
				t.Fatalf("persist error lost its cause: got %q, want it to contain %q", snap.PersistErr, tc.wantSub)
			}
			if snap.PersistFailures != 1 {
				t.Fatalf("persist-failure counter = %d, want 1", snap.PersistFailures)
			}
		})
	}
}

// TestCARotationPersistFailure_SanitizesControlCharacters keeps the CWE-117
// barrier pinned alongside the new path barrier — the redaction wrapper must
// not displace sanitizeLog.
func TestCARotationPersistFailure_SanitizesControlCharacters(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	resetCAUsabilityHealthForTest()
	withCARuntimePath(t, filepath.Join(t.TempDir(), "ca.bundle"))

	noteCARotationPersistFailure("CA write: denied\ninjected: FAKE AUDIT LINE\r")

	snap := caUsabilityFailures()
	if strings.ContainsAny(snap.PersistErr, "\n\r") {
		t.Fatalf("recorded persist error still carries control characters: %q", snap.PersistErr)
	}
}

// TestReadyProbe_CARowLeaksNoBundlePath pins the OTHER, more exposed instance of
// the same class. /ready is served on the PROXY listener
// (routeProxyListenerBuiltin), unauthenticated, to every client on the network —
// and the `ca` row's failing detail was noteSSLInspectionUnavailable's text,
// which embeds the absolute CA bundle path. The row must keep failing (that is
// the CHAOS-06 signal) while carrying no path.
func TestReadyProbe_CARowLeaksNoBundlePath(t *testing.T) {
	prev := sslInspectionLoadFailure()
	t.Cleanup(func() { sslInspectionLoadError.Store(prev) })

	const bundle = "/srv/culvert/data/ca.bundle"
	withCARuntimePath(t, bundle) // the redaction anchor loadRootCA publishes
	sslInspectionLoadError.Store(
		"Root CA load/init failed for " + bundle + ": open " + bundle +
			": bad passphrase — SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)")

	checks := map[string]*readinessCheck{}
	appendCAReadinessCheck(checks)

	row, ok := checks["ca"]
	if !ok {
		t.Fatal("ca row missing after a recorded load failure (CHAOS-06 signal lost)")
	}
	if row.Status != "fail" {
		t.Fatalf("ca row status = %q, want fail", row.Status)
	}
	if strings.Contains(row.Detail, bundle) || strings.Contains(row.Detail, "/srv/culvert") {
		t.Errorf("unauthenticated /ready ca row leaks the bundle path: %q", row.Detail)
	}
	// The CAUSE is not sensitive and is what CHAOS-06 put on this row — the fix
	// reduces the path, it does not blank the detail.
	if !strings.Contains(row.Detail, "bad passphrase") {
		t.Errorf("redaction removed the operator-actionable cause too: %q", row.Detail)
	}
	if !strings.Contains(row.Detail, "ca.bundle") {
		t.Errorf("redaction removed the bundle base name too: %q", row.Detail)
	}

	// End-to-end through the real handler, so a future sink cannot reintroduce it.
	w := httptest.NewRecorder()
	handleReady(w, nil)
	if body := w.Body.String(); strings.Contains(body, bundle) || strings.Contains(body, "/srv/culvert") {
		t.Errorf("unauthenticated /ready body leaks the bundle path: %s", body)
	}

	// The full detail must still reach the admin-scoped record — this fix
	// redacts the PROBE, it does not discard the cause.
	if got := sslInspectionLoadFailure(); !strings.Contains(got, bundle) {
		t.Errorf("recorded load failure lost its path: %q", got)
	}
}
