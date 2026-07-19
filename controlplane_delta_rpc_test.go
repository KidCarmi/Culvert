package main

// controlplane_delta_rpc_test.go — T3 P1 slice 4: GetConfigDelta CP handler.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// publishBlocklistVersions swaps in a fresh ConfigStore and publishes a sequence
// of blocklists, returning the resolved server + the versions in order.
func setupDeltaStore(t *testing.T, lists ...[]string) *controlPlaneServer {
	t.Helper()
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig; gcMarshalCache.reset(); gcDeltaRemainderCache.reset() })
	globalConfigStore = &ConfigStore{}
	gcMarshalCache.reset()
	gcDeltaRemainderCache.reset()
	for _, l := range lists {
		if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: l}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	return &controlPlaneServer{}
}

func deltaCtx(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000},
	})
}

func callDelta(t *testing.T, svc *controlPlaneServer, ctx context.Context, known int64) getConfigDeltaReply {
	t.Helper()
	req, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: known})
	raw, err := svc.GetConfigDelta(ctx, req)
	if err != nil {
		t.Fatalf("GetConfigDelta(known=%d): %v", known, err)
	}
	var reply getConfigDeltaReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	return reply
}

func TestGetConfigDelta_Unchanged(t *testing.T) {
	ip := "203.0.113.10"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	svc := setupDeltaStore(t, []string{"a.example"}) // version 1
	reply := callDelta(t, svc, deltaCtx(ip), 1)
	if reply.Mode != "unchanged" || reply.TargetVersion != 1 {
		t.Fatalf("got mode=%q target=%d, want unchanged/1", reply.Mode, reply.TargetVersion)
	}
}

func TestGetConfigDelta_DeltaChainConverges(t *testing.T) {
	ip := "203.0.113.11"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	v1 := []string{"a.example", "b.example"}
	v2 := []string{"a.example", "b.example", "c.example"}
	v3 := []string{"a.example", "c.example", "*.d.example"}
	svc := setupDeltaStore(t, v1, v2, v3) // versions 1,2,3

	reply := callDelta(t, svc, deltaCtx(ip), 1) // DP holds v1
	if reply.Mode != "delta" || reply.BaseVersion != 1 || reply.TargetVersion != 3 {
		t.Fatalf("got mode=%q base=%d target=%d, want delta/1/3", reply.Mode, reply.BaseVersion, reply.TargetVersion)
	}
	if len(reply.Remainder) == 0 {
		t.Fatal("delta reply must carry a remainder")
	}
	var rem ConfigSnapshot
	if err := json.Unmarshal(reply.Remainder, &rem); err != nil {
		t.Fatalf("unmarshal remainder: %v", err)
	}
	if rem.BlockedHosts != nil {
		t.Fatal("remainder must omit BlockedHosts (it rides as the delta chain)")
	}
	if reply.TargetFP != blocklist.FeedSetFingerprint(v3) {
		t.Fatal("target FP must equal the fingerprint of the newest blocklist")
	}
	// Apply the chain to a store starting at v1 → converge to v3.
	store := blocklist.New()
	store.ReplaceFeedEntries(v1)
	for _, d := range reply.Deltas {
		store.ApplyDelta(d.Added, d.Removed)
	}
	if store.SyncedFingerprint() != reply.TargetFP {
		t.Fatal("applying the delta chain did not converge to the advertised target FP")
	}
}

func TestGetConfigDelta_GapResync(t *testing.T) {
	ip := "203.0.113.12"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	svc := setupDeltaStore(t, []string{"a"}, []string{"a", "b"}) // versions 1,2
	// A DP claiming a version far ahead of the store (e.g. after talking to a
	// newer CP, then this stale one) cannot be served incrementally → resync.
	reply := callDelta(t, svc, deltaCtx(ip), 999)
	if reply.Mode != "resync" || reply.TargetVersion != 2 {
		t.Fatalf("got mode=%q target=%d, want resync/2", reply.Mode, reply.TargetVersion)
	}
}

func TestGetConfigDelta_FreshDPResyncs(t *testing.T) {
	ip := "203.0.113.13"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	svc := setupDeltaStore(t, []string{"a"}, []string{"a", "b"}, []string{"a", "b", "c"}) // versions 1,2,3
	// A fresh DP (base 0) traverses the FIRST published version, which is recorded
	// as a nil-baseline resync marker (no prior published snapshot to diff against
	// — the Dur-F3 fix), so it correctly gets a resync directive and does a full
	// GetConfig rather than a bogus "add-everything" delta.
	reply := callDelta(t, svc, deltaCtx(ip), 0)
	if reply.Mode != "resync" {
		t.Fatalf("fresh DP crossing the nil-baseline marker: got mode=%q, want resync", reply.Mode)
	}
}

func TestGetConfigDelta_UnservableConfig(t *testing.T) {
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig; gcMarshalCache.reset() })
	globalConfigStore = &ConfigStore{}
	gcMarshalCache.reset()
	// Force a rejected initial publish so nothing valid was ever published.
	over := make([]string, maxSnapBlockedHosts+1)
	for i := range over {
		over[i] = "h"
	}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: over}); err == nil {
		t.Fatal("expected over-cap publish to be rejected")
	}
	svc := &controlPlaneServer{}
	req, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: 0})
	_, err := svc.GetConfigDelta(deltaCtx("203.0.113.14"), req)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable when no servable config", err)
	}
}

func TestGetConfigDelta_RedactsSecretsFromUnenrolled(t *testing.T) {
	ip := "203.0.113.15"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig; gcMarshalCache.reset() })
	globalConfigStore = &ConfigStore{}
	gcMarshalCache.reset()
	// Two versions so the DP (at v1) gets a delta with a remainder.
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a"}, SessionHMAC: "deadbeef"}); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a", "b"}, SessionHMAC: "deadbeef"}); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	svc := &controlPlaneServer{}
	reply := callDelta(t, svc, deltaCtx(ip), 1)
	if reply.Mode != "delta" || len(reply.Remainder) == 0 {
		t.Fatalf("want delta with remainder, got mode=%q", reply.Mode)
	}
	var rem ConfigSnapshot
	if err := json.Unmarshal(reply.Remainder, &rem); err != nil {
		t.Fatalf("unmarshal remainder: %v", err)
	}
	if rem.SessionHMAC != "" {
		t.Fatal("SessionHMAC must be redacted from an unenrolled caller's remainder")
	}
}

// TestCPGRPC_GetConfigDeltaRoundTrip exercises GetConfigDelta over the REAL
// service registration + hand-rolled codec via bufconn (like the GetConfig
// roundtrip tests) — proving the new method is wired into registerConfigService
// and travels the wire, not just the direct-call path.
func TestCPGRPC_GetConfigDeltaRoundTrip(t *testing.T) {
	dial := startBufconnCP(t)
	v1 := []string{"a.example", "b.example"}
	v2 := []string{"a.example", "b.example", "c.example"}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: v1}); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	baseVer := globalConfigStore.Get().Version
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: v2}); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	targetVer := globalConfigStore.Get().Version

	conn := dial(t, clusterClientCallOptions()...)
	body, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: baseVer})
	var resp json.RawMessage
	if err := conn.Invoke(context.Background(), methodGetConfigDelta, body, &resp); err != nil {
		t.Fatalf("GetConfigDelta over wire: %v", err)
	}
	var reply getConfigDeltaReply
	if err := json.Unmarshal(resp, &reply); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if reply.Mode != "delta" || reply.TargetVersion != targetVer {
		t.Fatalf("got mode=%q target=%d, want delta/%d", reply.Mode, reply.TargetVersion, targetVer)
	}
	store := blocklist.New()
	store.ReplaceFeedEntries(v1)
	for _, d := range reply.Deltas {
		store.ApplyDelta(d.Added, d.Removed)
	}
	if store.SyncedFingerprint() != reply.TargetFP || reply.TargetFP != blocklist.FeedSetFingerprint(v2) {
		t.Fatal("wire delta chain did not converge to the target fingerprint")
	}
}

func TestGetConfigDelta_UnenrolledExfilThrottled(t *testing.T) {
	ip := "203.0.113.16"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	svc := setupDeltaStore(t, []string{"a"}, []string{"a", "b"})
	req, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: 1})
	ctx := deltaCtx(ip)
	for i := 0; i < 10; i++ {
		if _, err := svc.GetConfigDelta(ctx, req); err != nil {
			t.Fatalf("unenrolled delta pull %d should succeed: %v", i+1, err)
		}
	}
	if _, err := svc.GetConfigDelta(ctx, req); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("11th unenrolled delta pull: got %v, want ResourceExhausted", err)
	}
}

// TestDeltaRemainderCache_VersionGuard is the Codex-review regression: the
// remainder cache must refuse to marshal/serve a snapshot whose version does not
// match the requested version (a publish raced between reading `cur`/building the
// chain and fetching the remainder), so GetConfigDelta resyncs rather than pairing
// a version-N chain with a version-N+1 remainder.
func TestDeltaRemainderCache_VersionGuard(t *testing.T) {
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig; gcMarshalCache.reset(); gcDeltaRemainderCache.reset() })
	globalConfigStore = &ConfigStore{}
	gcDeltaRemainderCache.reset()
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cur := globalConfigStore.Version()

	// Serving at the current version succeeds.
	if _, err := gcDeltaRemainderCache.serve(cur, "", true); err != nil {
		t.Fatalf("serve at current version %d: %v", cur, err)
	}
	gcDeltaRemainderCache.reset()
	// Serving at a version the store is NOT at (simulating a raced publish) must
	// signal a version move, not silently marshal the wrong version's remainder.
	if _, err := gcDeltaRemainderCache.serve(cur-1, "", true); !errors.Is(err, errRemainderVersionMoved) {
		t.Fatalf("serve at stale version %d: got %v, want errRemainderVersionMoved", cur-1, err)
	}
}
