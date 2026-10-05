package main

// av_unavailable_integration_test.go — the av_unavailable posture driven
// through the REAL proxy path (handleRequest → handleHTTP →
// scanHTTPResponseBody → secscan → the real internal/clamav INSTREAM client)
// against a real TCP listener standing in for clamd. Each outage shape an
// operator actually meets is reproduced on the wire, not faked behind an
// interface:
//
//	stopped  — the daemon's port has no listener (connection refused)
//	crashed  — the daemon accepts and then RESETS the connection mid-stream
//	           (a crash or a restart under load)
//	stalled  — the daemon accepts, reads the body and never answers (the
//	           budget path, already fail-closed in BOTH postures)
//
// and then recovery: the same daemon comes back clean (200) or detecting
// (403 clamav). The CONTROL half proves the default open posture still
// forwards content on stop/crash — the cheapest way to pass every closed gate
// is to block everything, which is not the fix.

import (
	"bufio"
	"encoding/binary"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// clamdMode is how the stand-in answers an INSTREAM.
type clamdMode int32

const (
	clamdClean clamdMode = iota
	clamdFound
	clamdReset
	clamdStall
)

// fakeClamd is a minimal clamd speaking the two commands the client sends
// (zPING, zINSTREAM) on a FIXED loopback address, so it can be stopped and
// restarted on the same port the scanner was configured with.
type fakeClamd struct {
	t    *testing.T
	addr string
	mode atomic.Int32

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

func newFakeClamd(t *testing.T) *fakeClamd {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeClamd{t: t, addr: ln.Addr().String(), conns: map[net.Conn]struct{}{}}
	f.serve(ln)
	t.Cleanup(f.stop)
	return f
}

func (f *fakeClamd) setMode(m clamdMode) { f.mode.Store(int32(m)) }

func (f *fakeClamd) serve(ln net.Listener) {
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns[c] = struct{}{}
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				f.handle(c)
				f.mu.Lock()
				delete(f.conns, c)
				f.mu.Unlock()
			}()
		}
	}()
}

// stop closes the listener AND every live connection: the daemon is gone.
func (f *fakeClamd) stop() {
	f.mu.Lock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
	for c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

// restart re-binds the SAME address (the daemon came back).
func (f *fakeClamd) restart() {
	f.t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = (&net.ListenConfig{}).Listen(f.t.Context(), "tcp", f.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		f.t.Fatalf("re-listen on %s: %v", f.addr, err)
	}
	f.serve(ln)
}

func (f *fakeClamd) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	cmd, err := br.ReadString(0)
	if err != nil {
		return
	}
	switch strings.TrimSuffix(cmd, "\x00") {
	case "zPING":
		_, _ = c.Write([]byte("PONG\x00"))
		return
	case "zINSTREAM":
	default:
		return
	}
	mode := clamdMode(f.mode.Load())
	if mode == clamdReset {
		// A crash mid-stream: abortive close (RST), no verdict.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		return
	}
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 {
			break
		}
		if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
			return
		}
	}
	switch mode {
	case clamdStall:
		// Read everything, answer nothing: the client's budget decides.
		_, _ = io.Copy(io.Discard, br)
	case clamdFound:
		_, _ = c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
	default:
		_, _ = c.Write([]byte("stream: OK\x00"))
	}
}

// avIntegrationSetup wires a real-client scanner at the fake daemon, an
// origin serving per-path content, and an allow-all policy.
func avIntegrationSetup(t *testing.T, posture string) (*fakeClamd, *httptest.Server) {
	t.Helper()
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	policyStore.Add(PolicyRule{Priority: 1, Name: "allow-av-it", DestFQDN: "*", Action: ActionAllow})

	clamd := newFakeClamd(t)
	prevScanner := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{})
	globalSecScanner.Init("tcp:"+clamd.addr, 0, newHashCache(256, time.Hour))
	t.Cleanup(func() { globalSecScanner = prevScanner })

	prevPosture := secscan.AVUnavailablePosture()
	if err := secscan.SetAVUnavailablePosture(posture); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secscan.SetAVUnavailablePosture(prevPosture) })

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		// A distinct body per path (so each fetch is a fresh, uncached scan);
		// escaped because it reflects request input.
		_, _ = w.Write([]byte("payload-for:" + html.EscapeString(r.URL.Path)))
	}))
	t.Cleanup(origin.Close)
	return clamd, origin
}

// proxyGet sends one request through the real proxy pipeline.
func proxyGet(t *testing.T, origin *httptest.Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest(origin.URL+path, nil))
	return w
}

func clamavReadinessStatus(t *testing.T) string {
	t.Helper()
	report, _ := computeReadiness()
	if c := report.Checks["clamav"]; c != nil {
		return c.Status
	}
	return ""
}

func TestAVUnavailableIT_ClosedRefusesStopCrashStallAndRecovers(t *testing.T) {
	clamd, origin := avIntegrationSetup(t, secscan.AVUnavailableClosed)

	// Healthy daemon, clean content: delivered.
	if w := proxyGet(t, origin, "/healthy"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "payload-for:/healthy") {
		t.Fatalf("healthy clean: got %d %q", w.Code, w.Body.String())
	}
	if st := clamavReadinessStatus(t); st != "ok" {
		t.Fatalf("healthy daemon: /ready clamav = %q, want ok", st)
	}

	// STOPPED: nothing listens on the daemon's port.
	clamd.stop()
	refusedBefore := secscan.AVUnavailableRefusedTotal()
	w := proxyGet(t, origin, "/while-stopped")
	if w.Code != http.StatusForbidden {
		t.Fatalf("stopped daemon, closed posture: want 403, got %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "payload-for:") {
		t.Fatal("refused content leaked to the client")
	}
	if !strings.Contains(w.Body.String(), "antivirus scanning is currently unavailable") {
		t.Fatalf("403 body must say the content was refused because AV was unavailable, got %q", w.Body.String())
	}
	if d := secscan.AVUnavailableRefusedTotal() - refusedBefore; d != 1 {
		t.Fatalf("refusal counter moved by %d, want 1", d)
	}
	// Readiness truth: the request path saw the outage, so /ready must not
	// keep serving the "connected" it cached a moment ago.
	if st := clamavReadinessStatus(t); st != "fail" {
		t.Fatalf("/ready clamav = %q after a request-path outage, want fail", st)
	}

	// CRASHED / restarting: the daemon is back on its port but resets.
	clamd.setMode(clamdReset)
	clamd.restart()
	if w := proxyGet(t, origin, "/while-crashing"); w.Code != http.StatusForbidden {
		t.Fatalf("crashing daemon, closed posture: want 403, got %d %q", w.Code, w.Body.String())
	}

	// STALLED past the budget: the timeout refusal (both postures).
	restore := secscan.SetScanBudgetForTest(300 * time.Millisecond)
	clamd.setMode(clamdStall)
	timeoutBefore := secscan.Counters().ScanTimeout
	w = proxyGet(t, origin, "/while-stalled")
	restore()
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "TIMEOUT") {
		t.Fatalf("stalled daemon: want 403 timeout, got %d %q", w.Code, w.Body.String())
	}
	if d := secscan.Counters().ScanTimeout - timeoutBefore; d != 1 {
		t.Fatalf("stall must be the timeout path (scan timeout moved by %d)", d)
	}

	// RECOVERY, clean: the very object refused while stopped is now delivered
	// — the refusal was never cached.
	clamd.setMode(clamdClean)
	if w := proxyGet(t, origin, "/while-stopped"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "payload-for:/while-stopped") {
		t.Fatalf("recovered daemon, clean content: want 200 + body, got %d %q", w.Code, w.Body.String())
	}
	// RECOVERY, detecting: a real verdict, not a reopened gate.
	clamd.setMode(clamdFound)
	w = proxyGet(t, origin, "/while-crashing")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Blocked by CLAMAV scan: Eicar-Test-Signature") {
		t.Fatalf("recovered daemon, infected content: want 403 clamav, got %d %q", w.Code, w.Body.String())
	}
}

// TestAVUnavailableIT_OpenForwardsOnStopAndCrash is the CONTROL: the default
// posture is unchanged — a daemon outage forwards the content (counted and
// alerted elsewhere), and a stall is still refused by the budget.
func TestAVUnavailableIT_OpenForwardsOnStopAndCrash(t *testing.T) {
	clamd, origin := avIntegrationSetup(t, secscan.AVUnavailableOpen)

	clamd.stop()
	refusedBefore := secscan.AVUnavailableRefusedTotal()
	if w := proxyGet(t, origin, "/open-stopped"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "payload-for:/open-stopped") {
		t.Fatalf("stopped daemon, open posture: want 200 + body, got %d %q", w.Code, w.Body.String())
	}
	clamd.setMode(clamdReset)
	clamd.restart()
	if w := proxyGet(t, origin, "/open-crashing"); w.Code != http.StatusOK {
		t.Fatalf("crashing daemon, open posture: want 200, got %d %q", w.Code, w.Body.String())
	}
	if d := secscan.AVUnavailableRefusedTotal() - refusedBefore; d != 0 {
		t.Fatalf("open posture must not refuse (counter moved by %d)", d)
	}

	restore := secscan.SetScanBudgetForTest(300 * time.Millisecond)
	defer restore()
	clamd.setMode(clamdStall)
	if w := proxyGet(t, origin, "/open-stalled"); w.Code != http.StatusForbidden {
		t.Fatalf("stalled daemon, open posture: the budget still refuses (want 403), got %d", w.Code)
	}
}
