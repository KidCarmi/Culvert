package ssrf

import (
	"net"
	"testing"
	"time"
)

// dummyRawConn satisfies syscall.RawConn so Control can be unit-tested.
type dummyRawConn struct{}

func (dummyRawConn) Control(func(uintptr)) error    { return nil }
func (dummyRawConn) Read(func(uintptr) bool) error  { return nil }
func (dummyRawConn) Write(func(uintptr) bool) error { return nil }

func TestPrivateIP_Table(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.1", "224.0.0.1",
		"::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", // IPv4-mapped loopback
	}
	for _, s := range private {
		if !PrivateIP(net.ParseIP(s)) {
			t.Errorf("PrivateIP(%s) = false, want true", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"}
	for _, s := range public {
		if PrivateIP(net.ParseIP(s)) {
			t.Errorf("PrivateIP(%s) = true, want false", s)
		}
	}
}

func TestPrivateHost_IPLiterals(t *testing.T) {
	if err := PrivateHost("127.0.0.1:8080"); err == nil {
		t.Error("loopback with port must be rejected")
	}
	if err := PrivateHost("10.0.0.5"); err == nil {
		t.Error("RFC1918 literal must be rejected")
	}
	t.Cleanup(func() { CacheDelete("8.8.8.8") })
	if err := PrivateHost("8.8.8.8:53"); err != nil {
		t.Errorf("public literal must pass, got %v", err)
	}
}

func TestPrivateHost_CachedVerdicts(t *testing.T) {
	// Seed both verdicts; no DNS is consulted for cached hosts.
	CacheStore("evil.cached.test", true)
	CacheStore("good.cached.test", false)
	t.Cleanup(func() {
		CacheDelete("evil.cached.test")
		CacheDelete("good.cached.test")
	})
	if err := PrivateHost("evil.cached.test:443"); err == nil {
		t.Error("cached-private host must be rejected")
	}
	if err := PrivateHost("good.cached.test:443"); err != nil {
		t.Errorf("cached-public host must pass, got %v", err)
	}
}

func TestControl(t *testing.T) {
	if err := Control("tcp", "127.0.0.1:80", dummyRawConn{}); err == nil {
		t.Error("Control must reject loopback")
	}
	if err := Control("tcp", "8.8.8.8:53", dummyRawConn{}); err != nil {
		t.Errorf("Control must allow public, got %v", err)
	}
	if err := Control("tcp", "not-an-address", dummyRawConn{}); err == nil {
		t.Error("Control must fail closed on malformed address")
	}
	if err := Control("tcp", "hostname:80", dummyRawConn{}); err == nil {
		t.Error("Control must fail closed on non-IP host")
	}
}

func TestCacheCleanup_EvictsExpired(t *testing.T) {
	dnsCache.mu.Lock()
	dnsCache.entries["stale.test"] = cacheEntry{private: true, expires: time.Now().Add(-time.Minute)}
	dnsCache.entries["fresh.test"] = cacheEntry{private: false, expires: time.Now().Add(time.Hour)}
	dnsCache.mu.Unlock()
	t.Cleanup(func() {
		CacheDelete("stale.test")
		CacheDelete("fresh.test")
	})

	CacheCleanup()

	if _, found := dnsCache.Lookup("stale.test"); found {
		t.Error("expired entry must be evicted")
	}
	if _, found := dnsCache.Lookup("fresh.test"); !found {
		t.Error("fresh entry must survive cleanup")
	}
}
