package main

// upstream_transport_swap_test.go — P5.3 / S6 Categories B, C, E
// from roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md.
//
// Tests:
//   B1 — TestUpstreamTransport_SwapPreservesMTLSAndOCSP
//   B2 — TestUpstreamTransport_ConcurrentSwapsAreConsistent
//   C1 — TestUpstreamTransport_SwapDoesNotLeakGoroutines
//   C2 — TestUpstreamTransport_OldTransportClosesIdleConns
//   E1 — TestUpstreamTransport_GetterReturnsCurrentInstance
//
// Run under -race in CI to catch swap-implementation regressions.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────
// B1 — Swap preserves mTLS + OCSP
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_SwapPreservesMTLSAndOCSP configures mTLS +
// OCSP, then performs an unrelated swap (Proxy mutation), and asserts
// the post-swap transport STILL carries the mTLS certificate AND the
// OCSP callbacks. Proves that cloneTransport + cloneTLSConfig
// correctly carry TLS state forward across a swap that didn't itself
// touch TLS state — the immutable-after-publish contract in action.
func TestUpstreamTransport_SwapPreservesMTLSAndOCSP(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
		OCSPCheck:      true,
	})

	tlsCfg := getUpstreamTransport().TLSClientConfig
	if tlsCfg == nil || len(tlsCfg.Certificates) != 1 || tlsCfg.VerifyPeerCertificate == nil || tlsCfg.VerifyConnection == nil {
		t.Fatal("baseline mTLS+OCSP state was not installed correctly")
	}

	// Perform an unrelated swap (set Proxy). Under the immutable-
	// after-publish model, this must clone the existing TLS state
	// forward rather than dropping it.
	witnessURL, err := url.Parse("http://swap-witness.invalid:3128")
	if err != nil {
		t.Fatalf("parse witness URL: %v", err)
	}
	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		newT := cloneTransport(old)
		newT.Proxy = http.ProxyURL(witnessURL)
		return newT
	})

	postTLS := getUpstreamTransport().TLSClientConfig
	if postTLS == nil {
		t.Fatal("post-swap TLSClientConfig is nil; clone dropped TLS state")
	}
	if len(postTLS.Certificates) != 1 {
		t.Errorf("post-swap Certificates len = %d; want 1 (mTLS preserved)", len(postTLS.Certificates))
	}
	if postTLS.VerifyPeerCertificate == nil {
		t.Error("post-swap VerifyPeerCertificate is nil; OCSP verifier was lost")
	}
	if postTLS.VerifyConnection == nil {
		t.Error("post-swap VerifyConnection is nil; OCSP session-resumption verifier was lost")
	}
}

// ────────────────────────────────────────────────────────────────────
// B2 — Concurrent swaps are consistent
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_ConcurrentSwapsAreConsistent drives many
// concurrent swaps, each installing a transport with a unique
// witness value (MaxIdleConns). After all swaps complete, asserts
// the final transport's witness matches one of the inputs exactly
// (no torn intermediate state).
func TestUpstreamTransport_ConcurrentSwapsAreConsistent(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	const swaps = 200
	witnesses := make(map[int]struct{}, swaps)
	var witnessMu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < swaps; i++ {
		wg.Add(1)
		go func(witness int) {
			defer wg.Done()
			swapUpstreamTransport(func(old *http.Transport) *http.Transport {
				newT := cloneTransport(old)
				newT.MaxIdleConns = witness
				return newT
			})
			witnessMu.Lock()
			witnesses[witness] = struct{}{}
			witnessMu.Unlock()
		}(1000 + i)
	}
	wg.Wait()

	finalWitness := getUpstreamTransport().MaxIdleConns
	witnessMu.Lock()
	_, ok := witnesses[finalWitness]
	witnessMu.Unlock()
	if !ok {
		t.Errorf("final MaxIdleConns = %d; want one of the input witnesses (1000..%d). A value outside this range proves a torn write.", finalWitness, 1000+swaps-1)
	}
}

// ────────────────────────────────────────────────────────────────────
// C1 — Swap does not leak goroutines
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_SwapDoesNotLeakGoroutines captures the
// goroutine count before/after a bounded sequence of swaps + requests
// and asserts the delta stays within a small threshold. Approximate
// proxy for resource leak; a real long-duration soak still belongs in
// the lab.
func TestUpstreamTransport_SwapDoesNotLeakGoroutines(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(dst.Close)

	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	// 20 swaps × 5 requests = 100 ops.
	for i := 0; i < 20; i++ {
		for j := 0; j < 5; j++ {
			client := &http.Client{
				Transport: getUpstreamTransport(),
				Timeout:   2 * time.Second,
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, dst.URL, nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
		swapUpstreamTransport(func(old *http.Transport) *http.Transport {
			newT := cloneTransport(old)
			newT.MaxIdleConns = 100 + i
			return newT
		})
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	delta := after - baseline

	// Threshold chosen with headroom: even with httptest internals
	// keeping a few goroutines around, a leak of one-per-swap would
	// show up as ~20+. A threshold of 10 catches the leak without
	// false positives from incidental scheduler bookkeeping.
	const allowedDelta = 10
	if delta > allowedDelta {
		t.Errorf("goroutine delta = %d (baseline=%d, after=%d); exceeds allowed delta %d — possible leak from swap path", delta, baseline, after, allowedDelta)
	}
}

// ────────────────────────────────────────────────────────────────────
// C2 — Old transport closes idle conns on swap
// ────────────────────────────────────────────────────────────────────

// swapTrackedConn lets the caller observe completion of the real client-side Close.
type swapTrackedConn struct {
	net.Conn
	swapObserved <-chan struct{}
	pauseClose   atomic.Bool
	closed       atomic.Bool
}

func (c *swapTrackedConn) Close() error {
	// Give an asynchronously returning swap a chance to report back while this
	// socket is still open. A synchronous caller proceeds when the timer fires.
	if c.pauseClose.Load() {
		select {
		case <-c.swapObserved:
		case <-time.After(100 * time.Millisecond):
		}
	}
	err := c.Conn.Close()
	if err == nil {
		c.closed.Store(true)
	}
	return err
}

// TestUpstreamTransport_OldTransportClosesIdleConns verifies the synchronous
// old-transport cleanup contract in UPSTREAM-TRANSPORT-OWNERSHIP-MODEL.md §2.3.
func TestUpstreamTransport_OldTransportClosesIdleConns(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	const timeout = 5 * time.Second
	bodyGate := make(chan struct{})
	releaseBody := sync.OnceFunc(func() { close(bodyGate) })
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Length", "2")
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			select {
			case <-bodyGate:
				_, _ = io.WriteString(w, "b")
			case <-r.Context().Done():
			case <-time.After(timeout):
			}
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(dst.Close)
	t.Cleanup(releaseBody)

	swapObserved := make(chan struct{})
	releaseClose := sync.OnceFunc(func() { close(swapObserved) })
	preSwap := newBaseUpstreamTransport()
	var dialer net.Dialer
	preSwap.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &swapTrackedConn{Conn: conn, swapObserved: swapObserved}, nil
	}
	upstreamTransportPtr.Store(preSwap)
	t.Cleanup(preSwap.CloseIdleConnections)
	t.Cleanup(releaseClose)

	request := func(tr *http.Transport, path string, putIdle func(error)) (*http.Response, *swapTrackedConn) {
		t.Helper()
		var used *swapTrackedConn
		trace := &httptrace.ClientTrace{
			GotConn:     func(info httptrace.GotConnInfo) { used = info.Conn.(*swapTrackedConn) },
			PutIdleConn: putIdle,
		}
		ctx := httptrace.WithClientTrace(t.Context(), trace)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, dst.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: tr, Timeout: timeout}).Do(req)
		if err != nil {
			t.Fatalf("request %s: %v", path, err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		if used == nil {
			t.Fatalf("request %s did not report its connection", path)
		}
		return resp, used
	}
	drain := func(resp *http.Response, want string) {
		t.Helper()
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || string(body) != want {
			t.Fatalf("response body = %q, want %q; read %v, close %v", body, want, readErr, closeErr)
		}
	}

	stream, active := request(preSwap, "/stream", nil)
	var prefix [1]byte
	if _, err := io.ReadFull(stream.Body, prefix[:]); err != nil || prefix[0] != 'a' {
		t.Fatalf("stream prefix = %q, want a: %v", prefix, err)
	}
	putIdle := make(chan error, 1)
	resp, idle := request(preSwap, "/idle", func(err error) { putIdle <- err })
	drain(resp, "ok")
	select {
	case err := <-putIdle:
		if err != nil {
			t.Fatalf("baseline connection did not enter idle pool: %v", err)
		}
	case <-time.After(timeout):
		t.Fatal("timed out waiting for baseline connection to enter idle pool")
	}
	if idle == active || idle.closed.Load() || active.closed.Load() {
		t.Fatal("expected distinct open idle and active connections before swap")
	}
	idle.pauseClose.Store(true)

	type observation struct{ idleClosed, activeClosed bool }
	returned := make(chan observation, 1)
	go func() {
		swapUpstreamTransport(func(old *http.Transport) *http.Transport {
			newT := cloneTransport(old)
			newT.MaxIdleConns = 9876
			return newT
		})
		returned <- observation{idle.closed.Load(), active.closed.Load()}
	}()
	select {
	case atReturn := <-returned:
		if !atReturn.idleClosed {
			t.Error("swap returned before the old idle connection finished closing")
		}
		if atReturn.activeClosed {
			t.Error("swap closed the active connection before its response finished")
		}
	case <-time.After(timeout):
		t.Fatal("timed out waiting for swap to return")
	}
	releaseClose()

	postSwap := getUpstreamTransport()
	if postSwap == preSwap {
		t.Fatal("swap did not produce a new transport pointer")
	}
	t.Cleanup(postSwap.CloseIdleConnections)
	if postSwap.MaxIdleConns != 9876 {
		t.Errorf("post-swap MaxIdleConns = %d; want 9876 (witness)", postSwap.MaxIdleConns)
	}
	fresh, next := request(postSwap, "/new", nil)
	drain(fresh, "ok")
	if next == idle || next == active {
		t.Error("post-swap request reused an old-generation connection")
	}

	releaseBody()
	drain(stream, "b")

	// Verify a second cleanup remains safe after the observations above.
	preSwap.CloseIdleConnections()
}

// ────────────────────────────────────────────────────────────────────
// E1 — Getter returns the current instance
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_GetterReturnsCurrentInstance pins the
// reader-surface migration: getUpstreamTransport() reflects the
// most recent swap, not a stale snapshot.
func TestUpstreamTransport_GetterReturnsCurrentInstance(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	first := getUpstreamTransport()
	again := getUpstreamTransport()
	if first != again {
		t.Error("getUpstreamTransport returned different pointers without an intervening swap")
	}

	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		newT := cloneTransport(old)
		newT.MaxIdleConns = 13579
		return newT
	})

	postSwap := getUpstreamTransport()
	if postSwap == first {
		t.Error("getUpstreamTransport returned the pre-swap pointer; reader is reading stale state")
	}
	if postSwap.MaxIdleConns != 13579 {
		t.Errorf("post-swap MaxIdleConns = %d; want 13579 (witness)", postSwap.MaxIdleConns)
	}

	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		newT := cloneTransport(old)
		newT.MaxIdleConns = 24680
		return newT
	})
	revert := getUpstreamTransport()
	if revert == first || revert == postSwap {
		t.Error("getUpstreamTransport returned a stale pointer after the second swap")
	}
	if revert.MaxIdleConns != 24680 {
		t.Errorf("revert MaxIdleConns = %d; want 24680", revert.MaxIdleConns)
	}
}
