package geoip

// Focused engine-boundary tests. These exercise the disabled-DB and nil-IP
// behaviour without requiring a real GeoLite2 .mmdb file (none is shipped in
// the tree). Behaviour-based, no artificial coverage.

import (
	"net"
	"testing"
)

func TestEnabled_FalseBeforeInit(t *testing.T) {
	// No database has been opened in this package's process, so the engine must
	// report disabled and never panic.
	if Enabled() {
		t.Fatal("Enabled() must be false when no GeoIP database is loaded")
	}
}

func TestInitGeoDB_MissingFileErrors(t *testing.T) {
	// A non-existent path must return an error and leave the engine disabled
	// (fail-closed: a bad path never silently enables a half-open reader).
	if err := InitGeoDB("/nonexistent/GeoLite2-Country.mmdb"); err == nil {
		t.Fatal("InitGeoDB on a missing file must return an error")
	}
	if Enabled() {
		t.Fatal("Enabled() must stay false after a failed InitGeoDB")
	}
}

func TestLookupByIP_DisabledReturnsEmpty(t *testing.T) {
	// With no DB loaded, a well-formed public IP must yield ("", "").
	code, name := LookupByIP(net.ParseIP("8.8.8.8"))
	if code != "" || name != "" {
		t.Fatalf("LookupByIP on a disabled engine = (%q,%q), want empty", code, name)
	}
}

func TestLookupByIP_NilIP(t *testing.T) {
	// A nil IP must be handled fail-closed, never panic.
	if code, name := LookupByIP(nil); code != "" || name != "" {
		t.Fatalf("LookupByIP(nil) = (%q,%q), want empty", code, name)
	}
}

func TestLookupCachedByIP_MissAndNil(t *testing.T) {
	// Cache-only lookups must report a miss (never a new DB query) for an
	// uncached IP and for a nil IP.
	if code, ok := LookupCachedByIP(net.ParseIP("1.1.1.1")); ok || code != "" {
		t.Fatalf("LookupCachedByIP miss = (%q,%v), want (\"\",false)", code, ok)
	}
	if code, ok := LookupCachedByIP(nil); ok || code != "" {
		t.Fatalf("LookupCachedByIP(nil) = (%q,%v), want (\"\",false)", code, ok)
	}
}

func TestLookupCachedByIP_Hit(t *testing.T) {
	// A populated cache entry must be returned without consulting the database
	// (this is the caching contract the hot policy path relies on). Whitebox:
	// seed the cache directly since no .mmdb fixture is available to populate it.
	const ip = "203.0.113.7" // TEST-NET-3, never resolves to a real country
	geo.mu.Lock()
	geo.cache[ip] = &geoResult{CountryCode: "ZZ", Country: "Testland"}
	geo.mu.Unlock()
	t.Cleanup(func() {
		geo.mu.Lock()
		delete(geo.cache, ip)
		geo.mu.Unlock()
	})
	code, ok := LookupCachedByIP(net.ParseIP(ip))
	if !ok || code != "ZZ" {
		t.Fatalf("LookupCachedByIP hit = (%q,%v), want (\"ZZ\",true)", code, ok)
	}
}
