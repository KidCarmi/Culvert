package secscan

// Chaos gates for the REMOTE scan sidecar — the second body-scanning back end,
// and the one the scan-capacity runbook recommends as the remedy for the local
// path's saturation behaviour.
//
// The headline defect is a posture INVERSION. The local path bounds a scan by
// ScanBodyTimeout and fails CLOSED when it expires (CHAOS-52 / WK-15). The
// remote path bounded a scan by a private 30 s context — three times that
// budget — and surfaced its expiry as an ordinary transport error, which the
// classifier treated as a sidecar fault and handled fail-OPEN. So the identical
// condition, "the scan did not finish in time", blocked on one deployment and
// forwarded content unscanned on the other, decided by a startup flag.
//
// Five more defects sat around it:
//
//  1. A 200 response with no affirmative verdict ({} , null, a load balancer's
//     JSON error page) was read as CLEAN, with no counter, log or alert.
//  2. The admin hash allowlist was never consulted, and the Result's Hash came
//     from the SIDECAR — the value that then names objects in the operator's
//     allowlist and cache-evict surfaces.
//  3. The fail-open alert fired per request, ungated, with a raw err.Error() in
//     the dedup key (transport errors embed the ephemeral local port, so dedup
//     could not suppress them by construction).
//  4. The log fired per request too, so a sidecar fault degraded the node
//     hardest exactly when it was already degraded.
//  5. Status() decoded an unbounded response body from an operator-configured
//     URL, on an admin endpoint.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// newRemoteAt builds a client pointed at url. Init installs the production
// client, so these gates exercise the real transport and the real deadline.
func newRemoteAt(t *testing.T, url string) *RemoteScanner {
	t.Helper()
	rs := &RemoteScanner{}
	rs.Init(url)
	return rs
}

// sidecar starts a stand-in scan service running h.
func sidecar(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// jsonSidecar replies with resp to every /scan call.
func jsonSidecar(t *testing.T, resp ScanResponse) *httptest.Server {
	t.Helper()
	return sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// countersDelta returns what changed between two snapshots, so gates can assert
// on process-global counters other tests in this binary also move.
type delta struct{ timeout, fail, saturated int64 }

func since(before CounterSnapshot) delta {
	after := Counters()
	return delta{
		timeout:   after.ScanTimeout - before.ScanTimeout,
		fail:      after.RemoteScanFail - before.RemoteScanFail,
		saturated: after.RemoteScanSaturated - before.RemoteScanSaturated,
	}
}

// captureAlerts installs a sink that records scan_svc_down events only, plus a
// subscriber probe that answers yes, restoring no-op versions afterwards.
//
// Event-filtered for the reason clam_error_test.go filters on its detail
// marker: the sink is process-global inside this binary and alerts fire on
// their own goroutine, so a straggler from a neighbouring test must not satisfy
// this one's assertion. Every gate below that ARMS an alert also waits for it,
// so no straggler of this event escapes its own test either.
func captureAlerts(t *testing.T) *remoteAlertRecorder {
	t.Helper()
	rec := &remoteAlertRecorder{fired: make(chan alerts.Payload, 16)}
	alerts.SetSink(func(event string, p alerts.Payload) {
		if event != "scan_svc_down" {
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

type remoteAlertRecorder struct{ fired chan alerts.Payload }

func (a *remoteAlertRecorder) wait(t *testing.T) alerts.Payload {
	t.Helper()
	select {
	case p := <-a.fired:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("expected an alert, none fired")
		return alerts.Payload{}
	}
}

func (a *remoteAlertRecorder) none(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case p := <-a.fired:
		t.Fatalf("expected no alert, got %s/%s", p.Event, p.Detail)
	case <-time.After(within):
	}
}

// resetRemoteLogGates clears the rate-limit slots so a gate that asserts on a
// log-adjacent behaviour is not affected by an earlier test claiming the slot.
func resetRemoteLogGates(t *testing.T) {
	t.Helper()
	lastRemoteFailLog.Store(0)
	lastRemoteRefusalLog.Store(0)
	t.Cleanup(func() {
		lastRemoteFailLog.Store(0)
		lastRemoteRefusalLog.Store(0)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// The posture inversion
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos_SlowSidecarFailsClosedNotOpen is the headline gate.
//
// Pre-fix: the sidecar taking longer than the scan budget produced a transport
// error, classified as a fault, handled fail-OPEN — so the response was
// forwarded UNSCANNED and the only trace was a counter that never reached
// Prometheus. The local path fails CLOSED for the identical condition.
func TestChaos_SlowSidecarFailsClosedNotOpen(t *testing.T) {
	withScanBudget(t, 150*time.Millisecond)
	resetRemoteLogGates(t)
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_ = json.NewEncoder(w).Encode(ScanResponse{Clean: true})
	})
	rs := newRemoteAt(t, srv.URL)

	before := Counters()
	res := rs.ScanBody([]byte("payload"), "")
	d := since(before)

	if res == nil {
		t.Fatal("slow sidecar admitted content unscanned (fail-open) — the local path blocks for the same condition")
	}
	if !res.Blocked || res.Source != "timeout" {
		t.Fatalf("want a fail-closed timeout refusal, got %+v", res)
	}
	if res.Hash != hashcache.SHA256Hex([]byte("payload")) {
		t.Fatalf("refusal must carry the locally computed hash, got %q", res.Hash)
	}
	if d.timeout != 1 {
		t.Fatalf("scan timeout counter moved by %d, want 1 — the sidecar deployment must report the same signal as the local one", d.timeout)
	}
	if d.fail != 0 {
		t.Fatalf("a budget refusal is not a sidecar fault; fail-open counter moved by %d", d.fail)
	}
}

// TestChaos_RemoteScanIsBoundedByTheSharedBudget proves the deadline that fires
// is the process's scan budget, not the client's private one.
//
// Pre-fix the request was bounded by a hardcoded 30 s context inside a client
// with a 60 s timeout: 3x and 6x the budget the local path gives the same
// decision. A slow sidecar therefore held the request goroutine, the connection
// and the whole buffered body for half a minute per response.
func TestChaos_RemoteScanIsBoundedByTheSharedBudget(t *testing.T) {
	withScanBudget(t, 200*time.Millisecond)
	resetRemoteLogGates(t)
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	})
	rs := newRemoteAt(t, srv.URL)

	start := time.Now()
	res := rs.ScanBody([]byte("payload"), "")
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("remote scan took %s against a 200ms budget — it is still using a private deadline", elapsed)
	}
	if res == nil || !res.Blocked {
		t.Fatalf("want a fail-closed refusal at the budget, got %+v", res)
	}
}

// TestChaos_SidecarCapacityRefusalFailsClosed pins the CHAOS-52 saturation rule
// for the remote path: "at capacity" is decided by the outer budget, which
// fails closed, and is counted apart from a fault because the operator action
// differs (add capacity vs. fix the scanner).
func TestChaos_SidecarCapacityRefusalFailsClosed(t *testing.T) {
	resetRemoteLogGates(t)
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusTooManyRequests)
	})
	rs := newRemoteAt(t, srv.URL)

	before := Counters()
	res := rs.ScanBody([]byte("payload"), "")
	d := since(before)

	if res == nil || !res.Blocked || res.Source != "timeout" {
		t.Fatalf("a sidecar at capacity must fail closed, got %+v", res)
	}
	if d.saturated != 1 {
		t.Fatalf("saturation counter moved by %d, want 1", d.saturated)
	}
	if d.fail != 0 {
		t.Fatalf("saturation is not a fault; fail-open counter moved by %d", d.fail)
	}
	if d.timeout != 1 {
		t.Fatalf("a capacity refusal is a budget refusal; scan timeout moved by %d, want 1", d.timeout)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The silent clean
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos_TwoHundredWithoutAVerdictIsAFaultNotClean covers the shape an
// operator cannot discover from any surface the product exposes: something in
// front of the sidecar answers 200 with JSON that is not a verdict, and every
// file is admitted with no counter, no log and no alert.
func TestChaos_TwoHundredWithoutAVerdictIsAFaultNotClean(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"status":"ok"}`, `{"clean":false}`} {
		t.Run(body, func(t *testing.T) {
			resetRemoteLogGates(t)
			srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			rs := newRemoteAt(t, srv.URL)

			before := Counters()
			res := rs.ScanBody([]byte("payload"), "")
			d := since(before)

			if res != nil {
				t.Fatalf("a non-verdict is fail-open (WK-2b), got %+v", res)
			}
			if d.fail != 1 {
				t.Fatalf("a non-verdict must be COUNTED as a fault; counter moved by %d, want 1 — this is the silent case", d.fail)
			}
		})
	}
}

// TestChaos_AffirmativeCleanIsStillClean is the control for the gate above: the
// shipped sidecar sets Clean explicitly, and nothing about a correct deployment
// may change.
func TestChaos_AffirmativeCleanIsStillClean(t *testing.T) {
	resetRemoteLogGates(t)
	srv := jsonSidecar(t, ScanResponse{Clean: true})
	rs := newRemoteAt(t, srv.URL)

	before := Counters()
	if res := rs.ScanBody([]byte("payload"), ""); res != nil {
		t.Fatalf("clean content must be forwarded, got %+v", res)
	}
	if d := since(before); d.fail != 0 || d.timeout != 0 {
		t.Fatalf("a clean verdict moved failure counters: %+v", d)
	}
}

// TestChaos_BlockedVerdictIsHonoured pins the other half.
func TestChaos_BlockedVerdictIsHonoured(t *testing.T) {
	srv := jsonSidecar(t, ScanResponse{Blocked: true, Reason: "Eicar-Test-Signature", Source: "clamav"})
	rs := newRemoteAt(t, srv.URL)

	res := rs.ScanBody([]byte("payload"), "")
	if res == nil || !res.Blocked || res.Reason != "Eicar-Test-Signature" || res.Source != "clamav" {
		t.Fatalf("blocked verdict not honoured: %+v", res)
	}
}

// TestChaos_ResultHashIsComputedLocallyNotTakenFromTheSidecar.
//
// The Hash on a Result feeds the admin allowlist and cache-evict surfaces. Taken
// from the reply, a compromised — or merely buggy — sidecar could name any
// object it liked in the operator's UI, including one it never scanned.
func TestChaos_ResultHashIsComputedLocallyNotTakenFromTheSidecar(t *testing.T) {
	srv := jsonSidecar(t, ScanResponse{Blocked: true, Reason: "x", Source: "clamav", Hash: "deadbeef-attacker-chosen"})
	rs := newRemoteAt(t, srv.URL)

	data := []byte("payload")
	res := rs.ScanBody(data, "")
	if res == nil {
		t.Fatal("expected a block")
	}
	if res.Hash != hashcache.SHA256Hex(data) {
		t.Fatalf("hash came from the sidecar (%q); it must be computed from the bytes actually scanned", res.Hash)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The allowlist
// ─────────────────────────────────────────────────────────────────────────────

type stubExcl struct{ hashes map[string]bool }

func (s stubExcl) IsHashExcluded(h string) bool { return s.hashes[h] }

// TestChaos_HashAllowlistAppliesToTheRemotePath.
//
// Scanner.ScanBody has always consulted the allowlist; the remote client never
// did. An admin clearing a false positive by hash saw the entry accepted,
// persisted and audited — and the object kept being blocked, with nothing
// anywhere reporting that the setting did not apply to this deployment.
func TestChaos_HashAllowlistAppliesToTheRemotePath(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(ScanResponse{Blocked: true, Reason: "false positive", Source: "yara"})
	})
	rs := newRemoteAt(t, srv.URL)

	data := []byte("payload")
	rs.SetExclusions(stubExcl{hashes: map[string]bool{hashcache.SHA256Hex(data): true}})

	if res := rs.ScanBody(data, ""); res != nil {
		t.Fatalf("allowlisted hash was still blocked: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("allowlisted content was still shipped to the sidecar (%d calls)", calls)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The alert and log on the fail-open path
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos_FaultAlertIsGatedOnASubscriber pins the contract package main's
// fireDNSFailureAlert documents, applied to the other producer whose rate is
// set by a fault rather than by an operator: with no webhook subscribed, a
// sidecar outage must not spawn a goroutine and a payload per proxied response.
func TestChaos_FaultAlertIsGatedOnASubscriber(t *testing.T) {
	resetRemoteLogGates(t)
	rec := captureAlerts(t)
	alerts.SetSubscriberProbe(func(string) bool { return false })

	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	rs := newRemoteAt(t, srv.URL)

	before := Counters()
	rs.ScanBody([]byte("payload"), "")
	if d := since(before); d.fail != 1 {
		t.Fatalf("the fault must still be COUNTED when nobody subscribes; counter moved by %d", d.fail)
	}
	rec.none(t, 300*time.Millisecond)
}

// TestChaos_FaultAlertDetailIsBoundedForDedup.
//
// The alert store dedups on "event:detail" for 30 s. Raw transport errors embed
// the ephemeral LOCAL port, so a sidecar resetting connections produced a
// distinct key per request: dedup could not suppress it by construction, and
// the fan-out landed in the 500-entry retry queue, where a scanner fault can
// evict real threat alerts.
func TestChaos_FaultAlertDetailIsBoundedForDedup(t *testing.T) {
	resetRemoteLogGates(t)
	rec := captureAlerts(t)

	// A hijacked connection closed without a reply: the client sees a transport
	// error whose text names the URL and, on a reset, the ephemeral local port.
	// That text used to BE the dedup key.
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	})
	rs := newRemoteAt(t, srv.URL)
	rs.ScanBody([]byte("payload"), "")

	p := rec.wait(t)
	if p.Event != "scan_svc_down" || p.Source != "remote_scan" {
		t.Fatalf("unexpected alert %+v", p)
	}
	if strings.Contains(p.Detail, "://") || strings.Contains(p.Detail, "127.0.0.1") || strings.Contains(p.Detail, srv.Listener.Addr().String()) {
		t.Fatalf("alert detail carries per-request text (%q) — the dedup key is event:detail, so this cannot be suppressed", p.Detail)
	}
	if p.Detail != remoteFaultTransport {
		t.Fatalf("alert detail must be a bounded reason class, got %q", p.Detail)
	}

	// The status-code classes are bounded too — the code is the actionable
	// half and there are only a few dozen of them.
	rec2 := captureAlerts(t)
	resetRemoteLogGates(t)
	bad := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	})
	newRemoteAt(t, bad.URL).ScanBody([]byte("payload"), "")
	if got := rec2.wait(t).Detail; got != fmt.Sprintf("sidecar returned HTTP %d", http.StatusBadGateway) {
		t.Fatalf("status class not bounded: %q", got)
	}
}

// TestChaos_TransportFaultStillFailsOpenAndIsCounted pins the posture that is
// deliberately UNCHANGED: an unreachable sidecar forwards content, counted and
// alerted (register row WK-2b, an owner decision — the sibling of the local
// path's WK-1b). What changed is only that this branch is now reached by an
// actual fault.
func TestChaos_TransportFaultStillFailsOpenAndIsCounted(t *testing.T) {
	resetRemoteLogGates(t)
	rec := captureAlerts(t)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	rs := newRemoteAt(t, url)
	before := Counters()
	res := rs.ScanBody([]byte("payload"), "")
	d := since(before)

	if res != nil {
		t.Fatalf("an unreachable sidecar must stay fail-open (WK-2b), got %+v", res)
	}
	if d.fail != 1 {
		t.Fatalf("fail-open counter moved by %d, want 1", d.fail)
	}
	if d.timeout != 0 {
		t.Fatalf("a dial failure is not a budget refusal; scan timeout moved by %d", d.timeout)
	}
	if p := rec.wait(t); p.Detail != remoteFaultTransport {
		t.Fatalf("want the bounded transport class, got %q", p.Detail)
	}
}

// TestChaos_FaultLogIsRateLimitedWhileTheCounterStaysExact — the sidecar fault
// recurs once per proxied response for as long as it lasts, so the line is
// gated and the counter carries the magnitude. Same discipline as
// storage_health.go and the CHAOS-52 saturation path.
func TestChaos_FaultLogIsRateLimitedWhileTheCounterStaysExact(t *testing.T) {
	resetRemoteLogGates(t)
	alerts.SetSubscriberProbe(func(string) bool { return false })
	t.Cleanup(func() { alerts.SetSubscriberProbe(func(string) bool { return true }) })

	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	rs := newRemoteAt(t, srv.URL)

	const n = 25
	before := Counters()
	for i := 0; i < n; i++ {
		rs.ScanBody([]byte("payload"), "")
	}
	if d := since(before); d.fail != n {
		t.Fatalf("counter must be exact: moved by %d, want %d", d.fail, n)
	}
	// The gate claimed its slot on the first call and must hold it for the
	// whole burst.
	if degradedLogAllowed(&lastRemoteFailLog) {
		t.Fatal("the degradation log is not rate-limited — a sidecar fault would log once per proxied response")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Visibility and the admin probes
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos_RemoteInflightGaugeRisesAndFalls. On a sidecar deployment every
// culvert_scan_* series is structurally zero, so this is the only saturation
// signal an operator has.
func TestChaos_RemoteInflightGaugeRisesAndFalls(t *testing.T) {
	withScanBudget(t, 2*time.Second)
	resetRemoteLogGates(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(ScanResponse{Clean: true})
	})
	rs := newRemoteAt(t, srv.URL)

	base := RemoteScanInflight()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rs.ScanBody([]byte("payload"), "")
	}()

	<-entered
	if got := RemoteScanInflight(); got <= base {
		t.Fatalf("in-flight gauge did not rise (base %d, got %d)", base, got)
	}
	close(release)
	<-done

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if RemoteScanInflight() == base {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("in-flight gauge did not fall back to %d (got %d)", base, RemoteScanInflight())
}

// TestChaos_StatusResponseIsBounded. Status() is reachable from an admin
// endpoint, against a URL an operator can point anywhere — a typo'd port, a
// wedged sidecar, a service that streams. It used to decode without limit into
// the proxy's heap.
//
// The gate is on LATENCY, not on the error: unbounded, the decode runs until
// the 5 s probe deadline stops it, and reports an error too. Bounded, the limit
// fires within a few reads. So "returned an error" cannot distinguish the two;
// "returned promptly, having read a bounded amount" can.
func TestChaos_StatusResponseIsBounded(t *testing.T) {
	srv := sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"junk":"`))
		chunk := strings.Repeat("A", 32<<10)
		for { // never ends — a wedged service, or the wrong endpoint entirely
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
	rs := newRemoteAt(t, srv.URL)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := rs.Status()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an oversized status body must be refused, not decoded")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Status() read for %s — it is bounded only by the probe deadline, not by a byte limit", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Status() did not return — the response body is unbounded")
	}
}

// TestChaos_DisabledScannerDoesNothing pins the default posture: with no
// sidecar configured the client is inert and costs nothing.
func TestChaos_DisabledScannerDoesNothing(t *testing.T) {
	rs := &RemoteScanner{}
	before := Counters()
	if res := rs.ScanBody([]byte("payload"), ""); res != nil {
		t.Fatalf("a disabled remote scanner must return nil, got %+v", res)
	}
	if d := since(before); d != (delta{}) {
		t.Fatalf("a disabled remote scanner moved counters: %+v", d)
	}
	if err := rs.Health(); err == nil {
		t.Fatal("Health on a disabled scanner must report not configured")
	}
}
