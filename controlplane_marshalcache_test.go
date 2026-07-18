package main

// controlplane_marshalcache_test.go — T2: the CP-side per-version marshal cache
// serves N enrolled DP pollers one shared marshal per config change, and MUST
// invalidate on a version bump or CA-fingerprint change. The unenrolled/redacted
// path is intentionally never cached (covered by the GetConfig security tests).

import (
	"bytes"
	"testing"
)

func TestConfigMarshalCache_ServePerVersion(t *testing.T) {
	origStore := globalConfigStore
	t.Cleanup(func() {
		globalConfigStore = origStore
		gcMarshalCache.reset()
	})
	globalConfigStore = &ConfigStore{}
	gcMarshalCache.reset()

	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}, SessionHMAC: "top-secret-hmac"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	b1, err := gcMarshalCache.serve("")
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	// The enrolled (full) blob carries the secret — this cache is the enrolled
	// variant, so SessionHMAC MUST be present (redaction is the uncached path).
	if !bytes.Contains(b1, []byte("top-secret-hmac")) {
		t.Error("enrolled cache blob must carry SessionHMAC")
	}

	// Second call at the same version is a cache HIT: identical bytes, and the
	// SAME backing array (proving it did not re-marshal).
	b2, _ := gcMarshalCache.serve("")
	if !bytes.Equal(b1, b2) || &b1[0] != &b2[0] {
		t.Error("serve re-marshaled on a cache hit instead of returning the cached bytes")
	}

	// A version bump invalidates the cache.
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"b.example"}}); err != nil {
		t.Fatalf("republish: %v", err)
	}
	b3, _ := gcMarshalCache.serve("")
	if bytes.Equal(b1, b3) {
		t.Error("cache not invalidated on a version bump")
	}

	// A CA-fingerprint change re-marshals (the fingerprint is part of the key and
	// is injected into the snapshot).
	b4, _ := gcMarshalCache.serve("sha256:deadbeef")
	if bytes.Equal(b3, b4) {
		t.Error("cache not invalidated on a CA-fingerprint change")
	}
	if !bytes.Contains(b4, []byte("sha256:deadbeef")) {
		t.Error("CA fingerprint not injected into the served snapshot")
	}
}
