package main

// CHAOS-115 — the scan sidecar's admission plane.
//
// The sidecar's /scan handler buffered up to `security.max_scan_mb + 1` bytes
// per request (readScanWindow) with nothing bounding how many handlers could be
// inside that call at once, so its heap exposure was
// `open_connections x (window+1)`. Measured on the pre-fix tree with callers
// that declare Content-Length and stall one byte short:
//
//	slow callers | handlers buffering concurrently | heap delta
//	          64 |                             64 |    75.8 MiB
//	         192 |                            192 |   244.5 MiB
//
// A shared sidecar's concurrency is the SUM over every node pointed at it, and
// when it dies every one of those nodes takes internal/secscan's fail-OPEN
// branch (remoteScanFail, WK-2b). These gates pin the bound, and — the
// load-bearing one — pin that the refusal reaches the caller as the fail-CLOSED
// capacity outcome scanOnce has classified since CHAOS-52, not as a fault.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// resetScanSvcAdmission restores every global this file moves. Conventions:
// setupProxyTest resets at test START only, so a test that moves a shared
// global registers its own restoration.
func resetScanSvcAdmission(t *testing.T, slots int) {
	t.Helper()
	origCap := atomic.LoadInt64(&statScanSvcAtCapacity)
	origLog := lastScanSvcCapacityLog.Load()
	origSlots := scanSvcSlots.Load()
	origOverride := scanSvcSlotsOverride.Load()
	scanSvcSlotsOverride.Store(int64(slots))
	lastScanSvcCapacityLog.Store(0)
	t.Cleanup(func() {
		scanSvcSlotsOverride.Store(origOverride)
		atomic.StoreInt64(&statScanSvcAtCapacity, origCap)
		lastScanSvcCapacityLog.Store(origLog)
		scanSvcSlots.Store(origSlots)
	})
}

// stallPayload builds the body prefix a stalled caller sends, ONCE, so that a
// wave of callers shares it.
//
// Sharing is not a micro-optimisation, it is what makes the benchgate heap
// measurement mean anything: these tests run in the same process as the sidecar
// they measure, so a per-caller `bytes.Repeat(…, 1 MiB)` put 32 MiB of CLIENT
// garbage on the same heap as the 4 MiB of sidecar buffers under test and
// swamped it. One shared, immutable prefix leaves the sidecar's own buffering
// as the only thing that grows with the caller count.
func stallPayload(n int) []byte {
	return bytes.Repeat([]byte("a"), n-1)
}

// stallingScanPost opens a raw connection, declares Content-Length: len(prefix)+1
// and writes only prefix, parking the handler inside readScanWindow with
// whatever it has buffered. That is the "slow caller / lossy network" shape,
// and it holds a handler open without needing an engine seam.
func stallingScanPost(t *testing.T, addr string, prefix []byte) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	hdr := fmt.Sprintf("POST /scan HTTP/1.1\r\nHost: scan\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(prefix)+1)
	if _, err := c.Write([]byte(hdr)); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := c.Write(prefix); err != nil {
		t.Fatalf("write body prefix: %v", err)
	}
	return c
}

// waitForInflight waits for the slot gauge to settle at want, and returns the
// highest value it ever observed. A gauge that overshoots the slot count is the
// defect, so the maximum — not the final reading — is what the gates assert on.
func waitForInflight(want int64, within time.Duration) (peak int64) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cur := scanSvcInflight.Load(); cur > peak {
			peak = cur
		}
		if peak >= want {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Keep sampling briefly past the settle, so an overshoot that arrives late
	// is still seen.
	extra := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(extra) {
		if cur := scanSvcInflight.Load(); cur > peak {
			peak = cur
		}
		time.Sleep(5 * time.Millisecond)
	}
	return peak
}

// ─────────────────────────────────────────────────────────────────────────────
// The bound
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos115_SlowCallersCannotOutrunTheWindow is the fixed form of the
// reproduction. Twice as many stalled callers as there are slots must still
// leave exactly `slots` handlers buffering; the rest wait outside with their
// bodies still in the kernel.
func TestChaos115_SlowCallersCannotOutrunTheWindow(t *testing.T) {
	const window = 1 << 20 // 1 MiB, so an overshoot is visible in the heap too
	const slots = 4
	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	// 8x the slot count, deliberately: a wide ratio makes an overshoot
	// unmistakable, and it is the ratio the benchgate heap measurement uses.
	const callers = 8 * slots
	prefix := stallPayload(window)
	for i := 0; i < callers; i++ {
		stallingScanPost(t, addr, prefix)
	}

	peak := waitForInflight(slots, 10*time.Second)
	t.Logf("CHAOS-115: window=%d slots=%d stalled callers=%d peak inflight=%d goroutines=%d",
		window, slots, callers, peak, runtime.NumGoroutine())

	if peak > slots {
		t.Errorf("peak inflight = %d with %d slots: the admission bound does not hold, so the sidecar's heap exposure is still set by the network", peak, slots)
	}
	if peak < slots {
		t.Errorf("peak inflight = %d with %d slots and %d stalled callers: the gate is refusing work it has room for", peak, slots, callers)
	}

	// THE HEAP ITSELF is measured under the benchgate tag
	// (scan_svc_admission_benchgate_test.go), not here. It was an assertion in
	// this gate first, and the full suite is what retired it: HeapAlloc is a
	// PROCESS-wide number, so in a run with 140 live goroutines from unrelated
	// tests the same bounded sidecar measured 37 MiB against a 16 MiB ceiling
	// while `peak inflight` correctly read 4. The contract held and the oracle
	// did not, which is the definition of a flake.
	//
	// Nothing is lost in coverage: the ordering mutation this gate's heap
	// assertion was aimed at — acquiring AFTER readScanWindow — is caught by
	// the `peak < slots` arm above, because a stalled caller never finishes its
	// read and therefore never reaches a gate placed after it, leaving the
	// gauge at 0. Verified by mutation, which reported both arms.
}

// TestChaos115_AbandonedWaiterLeaksNoSlot covers the abort path: a caller that
// gives up while queued must leave the gate exactly as it found it.
//
// It also records what the wait is NOT bounded by, which this test is how the
// round learned. The first form of this gate asserted that a client aborting at
// 400 ms freed its waiter then, on the reading that
// context.WithTimeout(r.Context(), ...) keeps an earlier deadline. It does —
// but an HTTP request carries no deadline over the wire, so the server's
// r.Context() has none to keep, and net/http did not deliver the cancellation
// either: the waiter stayed parked until the 5 s backstop. The claim was wrong,
// scanSvcQueueWait is the real bound, and acquire's comment now says so. What
// survives as a contract is the part that matters for correctness — a slot is
// never taken by a request that was refused, and the handler does return.
func TestChaos115_AbandonedWaiterLeaksNoSlot(t *testing.T) {
	const window = 64 << 10
	const slots = 2
	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	prefix := stallPayload(window)
	for i := 0; i < slots; i++ {
		stallingScanPost(t, addr, prefix)
	}
	if peak := waitForInflight(slots, 5*time.Second); peak != slots {
		t.Fatalf("could not fill the gate: peak inflight = %d, want %d", peak, slots)
	}

	beforeRefusals := atomic.LoadInt64(&statScanSvcAtCapacity)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+addr+"/scan", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	start := time.Now()
	resp, err := directClient().Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
		}
	}

	// The handler must classify and return. The bound is scanSvcQueueWait plus
	// slack, not the client's 400 ms — see the doc comment.
	deadline := time.Now().Add(scanSvcQueueWait + 5*time.Second)
	var refusals int64
	for time.Now().Before(deadline) {
		refusals = atomic.LoadInt64(&statScanSvcAtCapacity) - beforeRefusals
		if refusals > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if refusals != 1 {
		t.Errorf("at-capacity counter moved by %d after %s, want 1: an abandoned waiter never returned, so the handler is parked past its own backstop",
			refusals, time.Since(start))
	}
	// The load-bearing assertion: the refused request must not have taken a
	// slot, or every abort would permanently narrow the gate until the sidecar
	// refused everything — and a refusal fails CLOSED, so that is a fleet-wide
	// download outage built out of ordinary client timeouts.
	if left := scanSvcInflight.Load(); left != int64(slots) {
		t.Errorf("inflight gauge = %d, want %d: a refused waiter took a slot and did not give it back", left, slots)
	}
}

// TestChaos115_DeadlinelessWaiterIsStillBounded is the other direction. This
// endpoint is reachable by anything that can route to it, including a client
// with no deadline at all, and such a client must not be able to park a
// slot-waiter indefinitely. scanSvcQueueWait is the backstop.
func TestChaos115_DeadlinelessWaiterIsStillBounded(t *testing.T) {
	const window = 64 << 10
	const slots = 2
	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	prefix := stallPayload(window)
	for i := 0; i < slots; i++ {
		stallingScanPost(t, addr, prefix)
	}
	if peak := waitForInflight(slots, 5*time.Second); peak != slots {
		t.Fatalf("could not fill the gate: peak inflight = %d, want %d", peak, slots)
	}

	start := time.Now()
	status, _ := postScan(t, addr, "application/octet-stream", []byte("payload"))
	elapsed := time.Since(start)

	if status != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", status, http.StatusTooManyRequests)
	}
	if elapsed < scanSvcQueueWait {
		t.Errorf("answered after %s, before the %s queue wait: a transient burst must be waited out, not refused on sight", elapsed, scanSvcQueueWait)
	}
	if elapsed > scanSvcQueueWait+5*time.Second {
		t.Errorf("answered after %s: the deadlineless wait is not bounded by scanSvcQueueWait (%s)", elapsed, scanSvcQueueWait)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The posture, measured through the real client
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos115_CapacityRefusalFailsClosedAtTheCaller is the load-bearing gate,
// and the reason this fix needed no caller change: the refusal must arrive at
// internal/secscan as `remoteOutcomeCapacity` — fail CLOSED, counted as
// saturation — and NOT as a fault, which fails OPEN.
//
// It runs the real RemoteScanner against a really saturated sidecar rather than
// asserting on the status code by inspection, because the whole value of
// choosing 429 over 503 lives in a switch in another package.
func TestChaos115_CapacityRefusalFailsClosedAtTheCaller(t *testing.T) {
	const window = 64 << 10
	const slots = 2
	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	prefix := stallPayload(window)
	for i := 0; i < slots; i++ {
		stallingScanPost(t, addr, prefix)
	}
	if peak := waitForInflight(slots, 5*time.Second); peak != slots {
		t.Fatalf("could not fill the gate: peak inflight = %d, want %d", peak, slots)
	}

	rs := &secscan.RemoteScanner{}
	rs.Init("http://" + addr)

	before := secscan.Counters()
	res := rs.ScanBody([]byte("payload"), "application/octet-stream")
	after := secscan.Counters()

	if res == nil || !res.Blocked {
		t.Fatalf("a sidecar at capacity must fail CLOSED, got %+v — content was forwarded UNSCANNED", res)
	}
	if res.Source != "timeout" {
		t.Errorf("Source = %q, want \"timeout\": capacity reuses the local path's budget vocabulary (CHAOS-52)", res.Source)
	}
	if d := after.RemoteScanSaturated - before.RemoteScanSaturated; d != 1 {
		t.Errorf("remote saturation counter moved by %d, want 1", d)
	}
	if d := after.RemoteScanFail - before.RemoteScanFail; d != 0 {
		t.Errorf("fail-OPEN fault counter moved by %d: saturation is not a fault, and treating it as one would forward the body unscanned", d)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Negative controls
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos115_OrdinaryTrafficIsNotRefused is the control that matters most for
// customers: the gate must be invisible below its bound. A refusal fails
// CLOSED, so a gate that is too eager BLOCKS legitimate downloads.
func TestChaos115_OrdinaryTrafficIsNotRefused(t *testing.T) {
	const window = 64 << 10
	const slots = 4
	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	before := atomic.LoadInt64(&statScanSvcAtCapacity)
	for i := 0; i < 50; i++ {
		status, sr := postScan(t, addr, "text/plain", []byte("harmless payload"))
		if status != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, status)
		}
		if !sr.Clean {
			t.Fatalf("request %d: clean = false for a harmless payload", i)
		}
	}
	if got := atomic.LoadInt64(&statScanSvcAtCapacity) - before; got != 0 {
		t.Errorf("at-capacity counter moved by %d on 50 sequential requests through %d slots: the gate is refusing work it has room for", got, slots)
	}
	if left := scanSvcInflight.Load(); left != 0 {
		t.Errorf("inflight gauge = %d after all requests completed: a slot is leaking, which makes the sidecar refuse everything after %d requests", left, slots)
	}
}

// TestChaos115_TruncationContractSurvivesAdmission is the CHAOS-101 regression
// control. Admission was inserted immediately before readScanWindow, which is
// the one place in this handler where ordering is a correctness argument: a
// body the sidecar could not finish must still never be reported clean.
func TestChaos115_TruncationContractSurvivesAdmission(t *testing.T) {
	const window = 4096
	const slots = 4
	withScanWindow(t, window, []string{"CULVERT-CHAOS115-MARKER"})
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	body := append(bytes.Repeat([]byte("a"), window+64), []byte("CULVERT-CHAOS115-MARKER")...)
	status, sr := postScan(t, addr, "text/plain", body)
	if status == http.StatusOK && sr.Clean {
		t.Errorf("sidecar answered 200 clean=true for a body truncated at its %d-byte window: admission must not have displaced the CHAOS-101 refusal", window)
	}
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d (413): the caller distinguishes a size limit from capacity, and they have opposite postures", status, http.StatusRequestEntityTooLarge)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The arithmetic
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos115_SlotArithmetic pins the derivation directly, so no gate above
// has to fill a 32-slot sidecar to cover it.
func TestChaos115_SlotArithmetic(t *testing.T) {
	cases := []struct {
		name   string
		window int64
		want   int
	}{
		// A narrow window is capped by the engines' own concurrency, not by
		// memory: slots far above ClamAV's 4 buy no throughput.
		{"tiny window hits the ceiling", 4096, scanSvcMaxSlots},
		{"shipped 5 MiB default hits the ceiling", 5 << 20, scanSvcMaxSlots},
		// The budget starts binding once the window is wide enough that
		// 32 of them would exceed it.
		{"16 MiB window is budget-bound", 16 << 20, 15},
		{"64 MiB window is budget-bound", 64 << 20, 3},
		// A pathological window must not serialise the sidecar completely.
		{"512 MiB window hits the floor", 512 << 20, scanSvcMinSlots},
		// Defensive: a zero/absent window must not divide by zero or return 0
		// slots, which would refuse every request and fail the fleet CLOSED.
		{"zero window hits the ceiling", 0, scanSvcMaxSlots},
		{"negative window hits the ceiling", -1, scanSvcMaxSlots},
	}
	for _, tc := range cases {
		if got := scanSvcAdmissionSlots(tc.window); got != tc.want {
			t.Errorf("%s: scanSvcAdmissionSlots(%d) = %d, want %d", tc.name, tc.window, got, tc.want)
		}
	}
	for _, tc := range cases {
		if got := scanSvcAdmissionSlots(tc.window); got < scanSvcMinSlots {
			t.Errorf("%s: %d slots is below the floor — a sidecar that admits nothing blocks every download in the fleet", tc.name, got)
		}
	}
}

// TestChaos115_HeapCeilingIsStatedNotImplied pins the budget arithmetic the
// /health and /metrics surfaces publish: slots x (window+1) must stay within
// the stated budget wherever the ceiling is not the binding constraint.
func TestChaos115_HeapCeilingIsStatedNotImplied(t *testing.T) {
	for _, window := range []int64{8 << 20, 16 << 20, 32 << 20, 64 << 20, 128 << 20} {
		slots := int64(scanSvcAdmissionSlots(window))
		if slots == scanSvcMaxSlots || slots == scanSvcMinSlots {
			continue // a clamped count is a stated choice, not the budget
		}
		if ceiling := slots * (window + 1); ceiling > scanSvcHeapBudget {
			t.Errorf("window %d: %d slots x %d bytes = %d, over the %d-byte budget",
				window, slots, window+1, ceiling, int64(scanSvcHeapBudget))
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The surfaces
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos115_SaturationSeriesRideTheConfiguredGuard pins where the three new
// series may appear. A node that never ran a sidecar must not export a
// sidecar's saturation plane at all — `at_capacity_total 0` and
// `inflight 0` on an ordinary proxy are indistinguishable from a healthy
// sidecar host, which is the asymmetry the CHAOS-113 listener gauges already
// carry and the reason the paging rules in the runbook are expressed against
// `slots`.
func TestChaos115_SaturationSeriesRideTheConfiguredGuard(t *testing.T) {
	series := []string{
		"culvert_scan_svc_inflight",
		"culvert_scan_svc_slots",
		"culvert_scan_svc_at_capacity_total",
	}

	scanSvcChaosSetup(t)
	body := renderMetrics(t)
	for _, s := range series {
		if strings.Contains(body, s) {
			t.Errorf("a node that never ran a sidecar exports %s", s)
		}
	}

	noteScanSvcConfigured("127.0.0.1:8484")
	noteScanSvcBound()
	body = renderMetrics(t)
	for _, s := range series {
		if !strings.Contains(body, s) {
			t.Errorf("a configured sidecar host does not export %s", s)
		}
	}
}

// TestChaos115_HealthPublishesTheCeilingArithmetic pins the pair an operator
// has to multiply. `scan_slots` without `scan_window_bytes` is not actionable:
// the buffered-body ceiling is their product, and the runbook tells operators
// to size the container against it, so both must be on the same reply.
func TestChaos115_HealthPublishesTheCeilingArithmetic(t *testing.T) {
	const window = 64 << 10
	const slots = 6
	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/health", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := directClient().Do(req)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	for _, key := range []string{"scan_slots", "scan_inflight", "at_capacity_refused", "scan_window_bytes"} {
		if _, ok := health[key]; !ok {
			t.Errorf("/health omits %q: an operator cannot compute the buffered-body ceiling from this reply", key)
		}
	}
	if got, ok := health["scan_slots"].(float64); !ok || int(got) != slots {
		t.Errorf("scan_slots = %v, want %d", health["scan_slots"], slots)
	}
	if got, ok := health["scan_window_bytes"].(float64); !ok || int64(got) != window {
		t.Errorf("scan_window_bytes = %v, want %d", health["scan_window_bytes"], window)
	}
}
