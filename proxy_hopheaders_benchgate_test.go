//go:build benchgate

package main

import (
	"net/http"
	"testing"
)

// Performance-regression gate for the hop-by-hop header strip (removeHopHeaders,
// proxy_tunnel.go), in the repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Correctness contracts — the differential against the frozen pre-change
// implementation, and the canonical-spelling structural wall — live in
// proxy_hopheaders_test.go and run in the NORMAL suite, where they belong:
// TestHopByHopHeaderNames_AreCanonical is what actually stops the cost being
// reintroduced, and it is deterministic on any hardware.
//
// The gates here are ALLOCATION gates, never timing ratios. An allocation count
// is exact and machine-independent, so these fail deterministically under any
// load, on any runner, with or without -race — unlike a ns/op ratio, which is
// the shape this repository has repeatedly had to abandon because a gate that
// can flake gets muted (see the sanitizeLog, connlimit and histogram notes).

// allocsFor reports allocations per call of strip against a freshly rebuilt
// header, so the map rebuild is charged to neither arm.
func allocsFor(strip func(http.Header), shape map[string][]string) float64 {
	h := make(http.Header, len(shape)+4)
	return testing.AllocsPerRun(200, func() {
		clear(h)
		for k, vs := range shape {
			h[k] = vs
		}
		strip(h)
	})
}

// TestBenchGate_HopHeaderStripIsAllocationFree pins the floor every proxied
// exchange gets regardless of what the peers sent: with no Connection header in
// play the strip must not allocate at all. Before the canonical-spelling fix it
// allocated once per call — four times per exchange — purely to re-derive "Te"
// from "TE".
func TestBenchGate_HopHeaderStripIsAllocationFree(t *testing.T) {
	shape := map[string][]string{
		"Host": {"example.com"}, "User-Agent": {"curl/8.5.0"},
		"Accept": {"*/*"}, "Accept-Encoding": {"gzip"},
	}
	if got := allocsFor(removeHopHeaders, shape); got != 0 {
		t.Errorf("removeHopHeaders allocated %.0f time(s) on a header carrying no "+
			"hop-by-hop field; want 0. A non-canonical name in hopByHopHeaderNames "+
			"puts every Del on textproto's allocating slow path.", got)
	}
}

// TestBenchGate_HopHeaderStripBeatsLegacy is the before/after contract, measured
// in ONE run against the frozen pre-change implementation so it can never become
// a stale number quoted from a commit message. It asserts the SAVING, not an
// absolute figure.
func TestBenchGate_HopHeaderStripBeatsLegacy(t *testing.T) {
	for _, sh := range hopHeaderShapes {
		t.Run(sh.name, func(t *testing.T) {
			now := allocsFor(removeHopHeaders, sh.hdr)
			legacy := allocsFor(legacyRemoveHopHeaders, sh.hdr)
			if now >= legacy {
				t.Errorf("shape %s: current shape allocates %.0f/call, frozen pre-change "+
					"shape allocates %.0f/call — the saving is gone", sh.name, now, legacy)
			}
		})
	}
}

// TestBenchGate_HopHeaderStripConnectionListIsSplitFree pins the second half of
// the change: a Connection header naming further hop-by-hop fields must not cost
// a slice allocation per value. The names themselves are peer-supplied and
// arbitrarily spelled, so their own Del stays on the canonicalising path — this
// bounds the strip's OWN allocations, not theirs.
func TestBenchGate_HopHeaderStripConnectionListIsSplitFree(t *testing.T) {
	// Every listed token is already canonical, so no Del can allocate and any
	// allocation left is the strip's own.
	shape := map[string][]string{
		"Host": {"example.com"}, "Connection": {"Upgrade, Trailer, Keep-Alive"},
		"Upgrade": {"websocket"}, "Trailer": {"Expires"}, "Keep-Alive": {"timeout=5"},
	}
	if got := allocsFor(removeHopHeaders, shape); got != 0 {
		t.Errorf("removeHopHeaders allocated %.0f time(s) walking a 3-token Connection "+
			"header whose every token is canonical; want 0 (strings.Split would cost one "+
			"slice per Connection value)", got)
	}
}

// TestBenchGate_HopHeaderStripStillStrips is the CONTROL. Every gate above is
// satisfied most cheaply by a function that does nothing, which would be a
// request-smuggling and topology-leak defect far worse than the cost it saves.
func TestBenchGate_HopHeaderStripStillStrips(t *testing.T) {
	h := http.Header{
		"Host": {"example.com"}, "Connection": {"keep-alive, X-Custom-Hop"},
		"X-Custom-Hop": {"drop-me"}, "Keep-Alive": {"timeout=5"},
		"Te": {"trailers"}, "Transfer-Encoding": {"chunked"},
		"Proxy-Authorization": {"Basic eA=="}, "Upgrade": {"h2c"},
		"Trailer": {"Expires"}, "Proxy-Authenticate": {"Basic"},
	}
	removeHopHeaders(h)
	for _, gone := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade", "X-Custom-Hop",
	} {
		if v := h.Get(gone); v != "" {
			t.Errorf("hop-by-hop header %q survived the strip as %q", gone, v)
		}
	}
	if h.Get("Host") != "example.com" {
		t.Error("end-to-end header Host was stripped")
	}
}
