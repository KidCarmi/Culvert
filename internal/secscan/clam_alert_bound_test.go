package secscan

// Security regression gates for the scan_clam_error producer.
//
// clamScanError runs once per proxied response for as long as the ClamAV
// daemon is unwell, and it used to fire with `Detail: err.Error()`. Every error
// internal/clamav produces wraps a net.OpError whose text embeds the EPHEMERAL
// LOCAL PORT ("read tcp 127.0.0.1:54012->127.0.0.1:3310: connection reset by
// peer") or a daemon-supplied response string, so the alert store's
// "event:detail" dedup key (internal/alerts, Q17/CHAOS-27) was distinct on
// every request: dedup could not suppress a failing daemon BY CONSTRUCTION,
// and every one of those deliveries landed in the 500-entry retry queue, where
// a scanner fault evicts real threat_detected alerts (register rows
// WK-12/RS-5).
//
// It was also ungated, so in the default posture (no webhooks configured)
// every failing scan paid a goroutine, a payload build and a round trip
// through the process-wide dedup mutex to deliver an alert to nobody — the
// exact contract its own sibling, remoteScanFail, already applies one file
// over for the sidecar leg.

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// clamNetErr reproduces the shape internal/clamav returns for a transport
// fault: the package's own prefix wrapping a *net.OpError that carries the
// ephemeral local port.
func clamNetErr(prefix string, localPort int) error {
	op := &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		Addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3310},
		Err:    errors.New("connection reset by peer"),
	}
	return fmt.Errorf("%s%w", prefix, op)
}

// TestClamFailureClass_IsBoundedAcrossEphemeralPorts is the primary regression
// gate: the same fault seen on 200 different connections must produce ONE dedup
// key, not 200.
//
// Verified failing against the reintroduced `Detail: err.Error()` shape.
func TestClamFailureClass_IsBoundedAcrossEphemeralPorts(t *testing.T) {
	seen := map[string]bool{}
	for port := 40000; port < 40200; port++ {
		seen[clamFailureClass(clamNetErr("clamav: read response: ", port))] = true
	}
	if len(seen) != 1 {
		t.Fatalf("200 connections of one fault produced %d distinct alert dedup keys (%v); "+
			"a key per request means dedup cannot suppress a failing daemon", len(seen), seen)
	}
}

// TestClamFailureClass_CoversEveryProducedShape walks every error shape
// internal/clamav constructs, plus hostile and empty input, and requires each
// to land on a declared class. The default arm is the load-bearing one: an
// unknown shape must FOLD to one class, never mint a new key.
func TestClamFailureClass_CoversEveryProducedShape(t *testing.T) {
	cases := []struct {
		name, want string
		err        error
	}{
		{"connect failed", "connect_failed", clamNetErr("clamav: connect failed: ", 40001)},
		{"connect", "connect_failed", clamNetErr("clamav: connect: ", 40002)},
		{"scan aborted", "scan_aborted", fmt.Errorf("clamav: scan aborted: %w", deadlineErr())},
		{"command write", "write_failed", clamNetErr("clamav: command write: ", 40003)},
		{"write chunk", "write_failed", clamNetErr("clamav: write chunk: ", 40004)},
		{"terminate stream", "write_failed", clamNetErr("clamav: terminate stream: ", 40005)},
		{"read response", "read_failed", clamNetErr("clamav: read response: ", 40006)},
		{"empty response", "empty_response", errors.New("clamav: empty response (daemon may have closed connection)")},
		{"unexpected response", "protocol_error", fmt.Errorf("clamav: unexpected response: %q", "WAT")},
		{"daemon scan error", "daemon_scan_error", fmt.Errorf("clamav: scan error: %s", "INSTREAM size limit exceeded. ERROR")},
		{"unknown shape folds", "engine_error", errors.New("something nobody anticipated")},
		{"nil is a class too", "engine_error", nil},
		// Malformed / hostile: a daemon-supplied string that IMITATES another
		// class must not be able to choose its own key beyond the fixed set.
		{"embedded prefix does not match", "engine_error", errors.New("xx clamav: connect: nope")},
		{"newline-bearing text folds", "engine_error", errors.New("bogus\nclamav: connect: forged")},
	}
	declared := boundedClamClasses
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clamFailureClass(tc.err)
			if got != tc.want {
				t.Fatalf("clamFailureClass(%v) = %q, want %q", tc.err, got, tc.want)
			}
			if !declared[got] {
				t.Fatalf("class %q is not in the declared bounded set", got)
			}
		})
	}
}

// TestClamScanError_NoSubscriberNoDispatch pins the HasSubscriber gate.
//
// The gate is observed through the PROBE, not through a sink tally, and the
// reason is the same one internal/yara records at degradedRecorder.probes:
// clamScanError dispatches with `go alerts.Fire(...)`, alerts.Fire loads the
// process-global sink INSIDE that goroutine, and this package's other tests
// fire the same event — so under `-count=2 -shuffle=on` a straggler lands in a
// later test's recorder and a zero-assertion on the sink is not this
// invocation's to make. (clam_error_test.go's header records the same hazard;
// it could still filter on a unique marker in the Detail, which stopped being
// possible when the Detail became a bounded class.)
//
// A probe consultation is SYNCHRONOUS on the caller's goroutine, so it belongs
// to whoever called clamScanError, and a straggler — already past the gate —
// can never add one.
func TestClamScanError_NoSubscriberNoDispatch(t *testing.T) {
	rec := &alertRecorder{}
	var probes atomic.Int64
	alerts.SetSink(rec.sink)
	alerts.SetSubscriberProbe(func(event string) bool {
		if event == "scan_clam_error" {
			probes.Add(1)
		}
		return false
	})
	t.Cleanup(func() {
		alerts.SetSink(func(string, alerts.Payload) {})
		alerts.SetSubscriberProbe(func(string) bool { return true })
	})

	before := atomic.LoadInt64(&statClamScanError)
	const rounds = 25
	for i := range rounds {
		clamScanError(clamNetErr("clamav: read response: ", 41000+i))
	}

	// Every failure reached the subscriber gate, and the gate answered false —
	// the branch that returns before `go alerts.Fire`.
	if got := probes.Load(); got != rounds {
		t.Fatalf("HasSubscriber consulted %d times, want %d: every failure must reach "+
			"the subscriber gate", got, rounds)
	}
	// CONTROL: the gate must skip the DISPATCH, never the accounting — an
	// operator scraping culvert_clamav_scan_errors_total must still see the
	// fault on a node with no webhooks configured.
	if got := atomic.LoadInt64(&statClamScanError) - before; got != rounds {
		t.Fatalf("ClamScanError counter delta = %d, want %d: the gate must not cost the counter", got, rounds)
	}
}

// TestClamScanError_LogIsRateLimitedButCountIsExact pins the count-everything /
// gate-the-noise split under concurrency: clamScanError is reached from the
// request goroutine, so its accounting must be race-free and lossless while the
// line that carries the cause is bounded.
func TestClamScanError_LogIsRateLimitedButCountIsExact(t *testing.T) {
	alerts.SetSubscriberProbe(func(string) bool { return false })
	t.Cleanup(func() { alerts.SetSubscriberProbe(func(string) bool { return true }) })

	before := atomic.LoadInt64(&statClamScanError)
	const workers, each = 8, 40
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				clamScanError(clamNetErr("clamav: connect: ", 42000+w*each+i))
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&statClamScanError) - before; got != workers*each {
		t.Fatalf("ClamScanError delta = %d, want %d", got, workers*each)
	}
}

// TestClamScanError_DetailIsTheClassNotTheCause is the end-to-end form: what
// reaches the sink must be the bounded class.
func TestClamScanError_DetailIsTheClassNotTheCause(t *testing.T) {
	rec := &alertRecorder{}
	alerts.SetSink(rec.sink)
	alerts.SetSubscriberProbe(func(string) bool { return true })
	t.Cleanup(func() {
		alerts.SetSink(func(string, alerts.Payload) {})
		alerts.SetSubscriberProbe(func(string) bool { return true })
	})

	clamScanError(clamNetErr("clamav: read response: ", 43001))
	events := rec.waitForEvent(t, 1, "scan_clam_error")
	if len(events) == 0 {
		t.Fatal("no scan_clam_error alert reached the sink")
	}
	for _, ev := range events {
		if !boundedClamClasses[ev.detail] {
			t.Fatalf("Detail %q is not a bounded class", ev.detail)
		}
	}
}

// deadlineErr stands in for the error internal/clamav wraps on the
// aborted-scan path; kept local so the gate does not depend on the context
// package's exact wording.
func deadlineErr() error { return errors.New("context deadline exceeded") }
