package main

// proxy_http_upstream_breaker_test.go — CHAOS-11 end-to-end pin: real
// request failures through a broken parent proxy trip the pool's circuit
// breaker, and the resulting all-parents-down state falls open to DIRECT
// egress with the fallback recorded (DirectFallback active + counted).
//
// Before the attribution wiring, this test's third request would still have
// been sent to the dead parent (the breaker never moved off "closed" on
// real traffic), and the fallback state did not exist.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// deadTCPAddr returns a 127.0.0.1 address that refuses connections: it
// listens, captures the ephemeral port, and closes the listener.
func deadTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestHandleHTTP_BrokenParentProxyTripsBreakerThenDirectFallback(t *testing.T) {
	// Snapshot/restore the two globals this test mutates.
	snapshotUpstreamPool(t)
	origPtr := upstreamTransportPtr.Load()
	defer upstreamTransportPtr.Store(origPtr)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "direct-ok")
	}))
	defer origin.Close()

	// One dead parent, breaker threshold 2, long open window so the breaker
	// cannot half-open mid-test.
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://" + deadTCPAddr(t)}}, 2, time.Minute)
	applyUpstreamProxy()

	_, fallbackBefore := upstreamPool.DirectFallback()

	// Requests 1–2: routed to the dead parent → 502, each failure attributed
	// to the parent's breaker.
	for i := 1; i <= 2; i++ {
		rr := httptest.NewRecorder()
		handleHTTP(rr, httptest.NewRequest(http.MethodGet, origin.URL, http.NoBody))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("request %d via dead parent: status %d, want 502", i, rr.Code)
		}
	}
	st := upstreamPool.List()
	if len(st) != 1 || st[0].Circuit != "open" {
		t.Fatalf("breaker after 2 real request failures = %+v, want circuit=open", st)
	}

	// Request 3: breaker open → pool exhausted → DIRECT egress reaches the
	// origin, and the fail-open fallback is recorded.
	rr := httptest.NewRecorder()
	handleHTTP(rr, httptest.NewRequest(http.MethodGet, origin.URL, http.NoBody))
	if rr.Code != http.StatusOK || rr.Body.String() != "direct-ok" {
		t.Fatalf("direct-fallback request: status %d body %q, want 200 %q", rr.Code, rr.Body.String(), "direct-ok")
	}
	active, total := upstreamPool.DirectFallback()
	if !active {
		t.Fatal("DirectFallback() not active after pool-exhausted request")
	}
	if total <= fallbackBefore {
		t.Fatalf("DirectFallback total = %d, want > %d", total, fallbackBefore)
	}
}
