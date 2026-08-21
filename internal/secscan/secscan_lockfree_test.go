package secscan

import (
	"testing"
	"time"
)

// The scanner gates the proxy consults on the request path must not read their
// enabled flag through the owning RWMutex. Property tests, not timing tests —
// see internal/threatfeed/threatfeed_lockfree_test.go for the full rationale.

func waitForGate(fn func()) (returned bool) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// TestScannerEnabled_IsLockFree pins the outermost gate. proxy.go's
// preDispatchBlocked calls Scanner.Enabled() before every threat check, on every
// proxied request, so it must not contend with (or wait on) a reconfiguration.
func TestScannerEnabled_IsLockFree(t *testing.T) {
	ss := New(Deps{})
	ss.Init("", 0, nil)

	// A concurrent Init/reconfiguration holds mu exclusively — and, when ClamAV
	// is configured, holds it across a TCP Ping.
	ss.mu.Lock()
	ok := waitForGate(func() { _ = ss.Enabled() })
	ss.mu.Unlock()

	if !ok {
		t.Fatal("Scanner.Enabled() blocked while the scanner write lock was held — it is " +
			"reading through mu again. It gates every proxied request and must stay " +
			"lock-free; see the Scanner.enabled field comment.")
	}
}

// TestScannerBodyScanEnabled_ShortCircuitsWhenDisabled pins the cheap half of
// BodyScanEnabled. It still takes mu to inspect the clam/yara collaborators —
// that part is deliberate — but an uninitialised scanner must answer without
// reaching the lock at all.
func TestScannerBodyScanEnabled_ShortCircuitsWhenDisabled(t *testing.T) {
	ss := New(Deps{}) // not Init'd → disabled

	ss.mu.Lock()
	ok := waitForGate(func() { _ = ss.BodyScanEnabled() })
	ss.mu.Unlock()

	if !ok {
		t.Fatal("BodyScanEnabled() blocked on mu with the scanner disabled — the enabled " +
			"check must short-circuit before the lock")
	}
	if ss.BodyScanEnabled() {
		t.Fatal("BodyScanEnabled() reported true on an uninitialised scanner")
	}
}

// TestRemoteScannerEnabled_IsLockFree pins the remote-sidecar gate, consulted
// once per plain-HTTP response in scanHTTPResponseBody. The common answer is
// "not configured", which should cost nothing.
func TestRemoteScannerEnabled_IsLockFree(t *testing.T) {
	rs := &RemoteScanner{}

	rs.mu.Lock()
	ok := waitForGate(func() { _ = rs.Enabled() })
	rs.mu.Unlock()

	if !ok {
		t.Fatal("RemoteScanner.Enabled() blocked while the write lock was held — it is " +
			"reading through mu again; see the RemoteScanner.enabled field comment.")
	}
	if rs.Enabled() {
		t.Fatal("a zero RemoteScanner must report disabled")
	}

	rs.Init("http://127.0.0.1:8484")
	if !rs.Enabled() {
		t.Fatal("RemoteScanner.Enabled() false after Init")
	}
}
