package main

// Engine-level pool/circuit-breaker/health-loop tests moved to
// internal/upstream with the ADR-0002 extraction. This file keeps only the
// main-side wiring test: applyUpstreamProxy publishing the pool's ProxyFunc
// onto the shared upstream transport (P5.3 atomic-pointer surface).

import (
	"testing"
	"time"
)

func TestApplyUpstreamProxy_SetsTransportProxy(t *testing.T) {
	// P5.3: snapshot/restore via the new atomic pointer surface
	// rather than direct field assignment on the published transport.
	origPtr := upstreamTransportPtr.Load()
	defer upstreamTransportPtr.Store(origPtr)

	// Configure the global pool directly (avoids copying mutex).
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://test.proxy:8080"}}, 5, time.Minute)
	defer upstreamPool.Configure(nil, 0, 0) // cleanup

	applyUpstreamProxy()

	current := getUpstreamTransport()
	if current.Proxy == nil {
		t.Fatal("expected transport Proxy to be set")
	}

	u, err := current.Proxy(nil)
	if err != nil {
		t.Fatalf("Proxy func error: %v", err)
	}
	if u == nil {
		t.Fatal("expected proxy URL, got nil")
	}
	if u.Host != "test.proxy:8080" {
		t.Fatalf("proxy host = %s, want test.proxy:8080", u.Host)
	}
}
