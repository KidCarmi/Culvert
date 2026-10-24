package secscan

// CHAOS-88 — the sidecar's OWN scan window, as seen by the client.
//
// The client already enforces the doctrine that "a verdict must be AFFIRMATIVE"
// for every other shape of non-answer. The sidecar was the hole in it: it read
// the body only as far as its own window and then answered `clean: true` for
// the prefix, so a fleet whose proxies buffer more than the sidecar does had
// scanning silently off for every byte past the sidecar's limit — no counter,
// no log, no alert, on the deployment the capacity runbook recommends.
//
// The sidecar now refuses that read with 413. These gates pin what the client
// must then do with it: charge the SIZE-LIMIT counter the local path already
// uses, not the generic fail-open fault counter, so one phenomenon keeps one
// counter and one alert class whichever window clipped the object.

import (
	"net/http"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// captureScanSkipped records scan_skipped alerts only. Content is the only safe
// discriminator in this binary (see captureAlerts' STRAGGLERS note); the detail
// below is unique to the oversize path.
func captureScanSkipped(t *testing.T) *remoteAlertRecorder {
	t.Helper()
	rec := &remoteAlertRecorder{fired: make(chan alerts.Payload, 64)}
	alerts.SetSink(func(event string, p alerts.Payload) {
		if event != "scan_skipped" {
			return
		}
		p.Event = event
		select {
		case rec.fired <- p:
		default:
		}
	})
	alerts.SetSubscriberProbe(func(string) bool { return true })
	t.Cleanup(func() {
		alerts.SetSink(func(string, alerts.Payload) {})
		alerts.SetSubscriberProbe(func(string) bool { return true })
	})
	return rec
}

const oversizeDetail = "sidecar scan window exceeded"

// TestChaos88_OversizeRefusalIsASizeLimitNotAFault is the load-bearing gate.
// 413 must land on the local path's scan-skipped vocabulary, because it is the
// same event the local path reports there.
func TestChaos88_OversizeRefusalIsASizeLimitNotAFault(t *testing.T) {
	resetRemoteLogGates(t)
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "scan body exceeds this scanner's window", http.StatusRequestEntityTooLarge)
	})
	rs := newRemoteAt(t, srv.URL)

	before := Counters()
	res := rs.ScanBody([]byte("payload"), "")
	d := since(before)

	if res != nil {
		t.Fatalf("oversize keeps the local path's fail-open posture, got %+v", res)
	}
	if d.skipped != 1 {
		t.Errorf("ScanSkipped moved by %d, want 1 — the operator's existing scan_skipped signal must fire", d.skipped)
	}
	if d.fail != 0 {
		t.Errorf("RemoteScanFail moved by %d, want 0 — a size limit is not a sidecar fault", d.fail)
	}
	if d.timeout != 0 {
		t.Errorf("ScanTimeout moved by %d, want 0 — a size limit is not a budget refusal", d.timeout)
	}
	if d.saturated != 0 {
		t.Errorf("RemoteScanSaturated moved by %d, want 0 — a size limit is not capacity", d.saturated)
	}
}

// TestChaos88_OversizeFiresTheScanSkippedAlert pins the alert class, so an
// operator already alerting on scan_skipped does not have to learn that the
// process-isolated deployment reports the same event somewhere else.
func TestChaos88_OversizeFiresTheScanSkippedAlert(t *testing.T) {
	resetRemoteLogGates(t)
	rec := captureScanSkipped(t)
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
	})
	rs := newRemoteAt(t, srv.URL)

	if res := rs.ScanBody([]byte("payload"), ""); res != nil {
		t.Fatalf("want fail-open, got %+v", res)
	}
	p := rec.waitFor(t, oversizeDetail)
	if p.Source != "size_limit" {
		t.Errorf("alert Source = %q, want size_limit (the local path's value)", p.Source)
	}
}

// TestChaos88_OversizeDoesNotFireTheSidecarDownAlert is the negative control
// for the classification: misrouting 413 into the fault class would page the
// on-call for a sidecar that is healthy and answering correctly.
func TestChaos88_OversizeDoesNotFireTheSidecarDownAlert(t *testing.T) {
	resetRemoteLogGates(t)
	rec := captureAlerts(t) // scan_svc_down only
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
	})
	rs := newRemoteAt(t, srv.URL)

	if res := rs.ScanBody([]byte("payload"), ""); res != nil {
		t.Fatalf("want fail-open, got %+v", res)
	}
	rec.noneWith(t, 300*time.Millisecond, statusClass(http.StatusRequestEntityTooLarge))
}

// TestChaos88_OtherStatusesAreStillFaults is the second negative control: the
// new branch must be narrow. 413 is the only status that means "the body was
// too large for the scanner"; everything else keeps the fault classification
// the sweep that added it argued for.
func TestChaos88_OtherStatusesAreStillFaults(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusNotFound, http.StatusBadRequest} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			resetRemoteLogGates(t)
			srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", code)
			})
			rs := newRemoteAt(t, srv.URL)

			before := Counters()
			res := rs.ScanBody([]byte("payload"), "")
			d := since(before)

			if res != nil {
				t.Fatalf("status %d keeps the fail-open posture, got %+v", code, res)
			}
			if d.fail != 1 {
				t.Errorf("RemoteScanFail moved by %d, want 1 for status %d", d.fail, code)
			}
			if d.skipped != 0 {
				t.Errorf("ScanSkipped moved by %d, want 0 — only 413 is a size limit", d.skipped)
			}
		})
	}
}

// TestChaos88_OversizeLogIsRateLimitedWhileTheCounterStaysExact: the producer's
// rate is set by traffic, so the line is throttled and the counter is not —
// the same split the fault path uses.
func TestChaos88_OversizeLogIsRateLimitedWhileTheCounterStaysExact(t *testing.T) {
	resetRemoteLogGates(t)
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
	})
	rs := newRemoteAt(t, srv.URL)

	before := Counters()
	const n = 5
	for i := 0; i < n; i++ {
		if res := rs.ScanBody([]byte("payload"), ""); res != nil {
			t.Fatalf("call %d: want fail-open, got %+v", i, res)
		}
	}
	if d := since(before); d.skipped != n {
		t.Errorf("ScanSkipped moved by %d, want %d — every refusal is charged", d.skipped, n)
	}
}
