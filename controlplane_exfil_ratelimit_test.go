package main

// controlplane_exfil_ratelimit_test.go — T2 exfil hardening: unenrolled callers
// may pull the (non-secret but sensitive) full config for bootstrap, but a bulk
// exfiltration loop is rate-limited per peer IP. Enrolled peers are never
// throttled; the version-conditional sentinel path is not a full pull.

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func clearUnenrolledPull(ip string) {
	unenrolledConfigPull.mu.Lock()
	delete(unenrolledConfigPull.attempts, ip)
	unenrolledConfigPull.mu.Unlock()
}

func TestUnenrolledConfigPullAllow_RateLimits(t *testing.T) {
	const ip = "203.0.113.199"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })

	for i := 0; i < 10; i++ {
		if !unenrolledConfigPullAllow(ip) {
			t.Fatalf("pull %d should be allowed within the window", i+1)
		}
	}
	if unenrolledConfigPullAllow(ip) {
		t.Error("11th unenrolled pull in the window should be rate-limited")
	}
	// A different peer is independent.
	if !unenrolledConfigPullAllow("203.0.113.200") {
		t.Error("a different peer IP must not inherit another peer's limit")
	}
	clearUnenrolledPull("203.0.113.200")
}

// TestGetConfig_UnenrolledExfilThrottled drives the limit through the real
// GetConfig handler: an unenrolled peer pulling the full snapshot repeatedly is
// eventually refused with ResourceExhausted, while the redacted config is served
// up to the limit (bootstrap still works).
func TestGetConfig_UnenrolledExfilThrottled(t *testing.T) {
	origStore := globalConfigStore
	t.Cleanup(func() {
		globalConfigStore = origStore
		gcMarshalCache.reset()
		clearUnenrolledPull("198.51.100.7")
	})
	globalConfigStore = &ConfigStore{}
	gcMarshalCache.reset()
	clearUnenrolledPull("198.51.100.7")
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	svc := &controlPlaneServer{}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 55555},
	})
	req := []byte(`{"known_version":0}`) // full-snapshot pull (unenrolled ⇒ redacted)

	for i := 0; i < 10; i++ {
		if _, err := svc.GetConfig(ctx, req); err != nil {
			t.Fatalf("unenrolled bootstrap pull %d should succeed: %v", i+1, err)
		}
	}
	_, err := svc.GetConfig(ctx, req)
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("11th unenrolled pull: got %v (code %s), want ResourceExhausted", err, status.Code(err))
	}
}
