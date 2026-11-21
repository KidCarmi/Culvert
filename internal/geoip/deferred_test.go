package geoip

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip/geoiptest"
)

// resetForDeferredTest isolates the package-level engine state for one test.
func resetForDeferredTest(t *testing.T) {
	t.Helper()
	ResetForTest()
	t.Cleanup(ResetForTest)
}

func writeTestDB(t *testing.T, path, iso, name string, built time.Time) {
	t.Helper()
	if err := geoiptest.WriteCountryDB(path, iso, name, built); err != nil {
		t.Fatalf("write test database: %v", err)
	}
}

// The fixture itself must be a database the real loader accepts, or every
// test below would be proving something about a file no deployment has.
func TestFixture_LoadsThroughInitGeoDB(t *testing.T) {
	resetForDeferredTest(t)
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	built := time.Unix(1_700_000_000, 0).UTC()
	writeTestDB(t, path, "IL", "Israel", built)
	if err := InitGeoDB(path); err != nil {
		t.Fatalf("InitGeoDB on the fixture: %v", err)
	}
	if code, name := LookupByIP(net.ParseIP(geoiptest.MatchedIP)); code != "IL" || name != "Israel" {
		t.Fatalf("LookupByIP = (%q, %q), want (IL, Israel)", code, name)
	}
	if code, _ := LookupByIP(net.ParseIP(geoiptest.UnmatchedIP)); code != "" {
		t.Fatalf("an address outside the fixture's network resolved to %q", code)
	}
	if got, ok := BuildTime(); !ok || !got.Equal(built) {
		t.Fatalf("BuildTime = (%v, %v), want (%v, true)", got, ok, built)
	}
}

func TestDeferredLoad_CompletesAFailedStartupLoad(t *testing.T) {
	resetForDeferredTest(t)
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")

	// Startup: the file is not there yet.
	if err := InitGeoDB(path); err == nil {
		t.Fatal("InitGeoDB on a missing file must fail")
	}
	if !ArmDeferredLoad(path) {
		t.Fatal("a failed startup load must arm the deferred load")
	}
	if got := DeferredLoadPending(); got != path {
		t.Fatalf("DeferredLoadPending = %q, want %q", got, path)
	}

	// Still missing: the attempt fails, stays armed and keeps the error.
	if _, loaded, err := TryDeferredLoad(); err == nil || loaded {
		t.Fatalf("TryDeferredLoad on a missing file = (loaded=%v, err=%v), want an error", loaded, err)
	}
	if DeferredLoadPending() != path || Enabled() {
		t.Fatal("a failed attempt must leave the intent armed and GeoIP disabled")
	}
	if _, _, ok := LoadError(); !ok {
		t.Fatal("a failed attempt must keep the load error on record")
	}
	// Nothing was resolved while disabled, and nothing may be cached from it.
	if code, _ := LookupByIP(net.ParseIP(geoiptest.MatchedIP)); code != "" {
		t.Fatalf("lookup while disabled returned %q", code)
	}

	// The operator puts the file in place.
	built := time.Unix(1_700_000_000, 0).UTC()
	writeTestDB(t, path, "IL", "Israel", built)
	got, loaded, err := TryDeferredLoad()
	if err != nil || !loaded || got != path {
		t.Fatalf("TryDeferredLoad = (%q, %v, %v), want (%q, true, nil)", got, loaded, err, path)
	}
	if !Enabled() {
		t.Fatal("GeoIP must be enabled after the deferred load")
	}
	if _, _, ok := LoadError(); ok {
		t.Fatal("a successful load must clear the recorded error")
	}
	if DeferredLoadPending() != "" {
		t.Fatal("a successful load must disarm the intent")
	}
	if code, name := LookupByIP(net.ParseIP(geoiptest.MatchedIP)); code != "IL" || name != "Israel" {
		t.Fatalf("LookupByIP after the deferred load = (%q, %q), want (IL, Israel)", code, name)
	}
	if b, ok := BuildTime(); !ok || !b.Equal(built) {
		t.Fatalf("BuildTime = (%v, %v), want (%v, true)", b, ok, built)
	}
	// A further attempt is a no-op.
	if _, loaded, err := TryDeferredLoad(); loaded || err != nil {
		t.Fatalf("TryDeferredLoad after success = (loaded=%v, err=%v), want a no-op", loaded, err)
	}
}

func TestDeferredLoad_CorruptFileStaysArmedAndDisabled(t *testing.T) {
	resetForDeferredTest(t)
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	// A truncated copy: the tree and data of a real database without its
	// metadata, which is what an interrupted in-place copy leaves behind.
	raw, err := geoiptest.CountryDB("IL", "Israel", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:30], 0o600); err != nil {
		t.Fatal(err)
	}
	ArmDeferredLoad(path)
	if _, loaded, err := TryDeferredLoad(); err == nil || loaded {
		t.Fatalf("TryDeferredLoad on a truncated file = (loaded=%v, err=%v), want an error", loaded, err)
	}
	if Enabled() || DeferredLoadPending() != path {
		t.Fatal("a truncated file must not enable GeoIP and must stay armed")
	}
}

func TestDeferredLoad_ArmsNothingWithoutAFailure(t *testing.T) {
	resetForDeferredTest(t)
	if ArmDeferredLoad("") {
		t.Fatal("an empty path must arm nothing")
	}
	if got, loaded, err := TryDeferredLoad(); got != "" || loaded || err != nil {
		t.Fatalf("TryDeferredLoad with nothing armed = (%q, %v, %v), want a no-op", got, loaded, err)
	}
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	writeTestDB(t, path, "IL", "Israel", time.Now())
	if err := InitGeoDB(path); err != nil {
		t.Fatal(err)
	}
	if ArmDeferredLoad(path) {
		t.Fatal("a loaded database must arm nothing")
	}
}

// The GEO-1 boundary: a deferred load must never replace a reader that is
// already published, even when its armed path holds a different, valid file.
func TestDeferredLoad_NeverReplacesALoadedDatabase(t *testing.T) {
	resetForDeferredTest(t)
	dir := t.TempDir()
	armed := filepath.Join(dir, "armed.mmdb")
	live := filepath.Join(dir, "live.mmdb")
	liveBuilt := time.Unix(1_600_000_000, 0).UTC()
	writeTestDB(t, live, "FR", "France", liveBuilt)

	if !ArmDeferredLoad(armed) {
		t.Fatal("arming with nothing loaded must succeed")
	}
	// Something else loads a database before the next attempt.
	if err := InitGeoDB(live); err != nil {
		t.Fatal(err)
	}
	writeTestDB(t, armed, "IL", "Israel", time.Unix(1_700_000_000, 0))

	got, loaded, err := TryDeferredLoad()
	if loaded || err != nil || got != armed {
		t.Fatalf("TryDeferredLoad over a loaded database = (%q, %v, %v), want (%q, false, nil)", got, loaded, err, armed)
	}
	if DeferredLoadPending() != "" {
		t.Fatal("a refused attempt must disarm")
	}
	if code, _ := LookupByIP(net.ParseIP(geoiptest.MatchedIP)); code != "FR" {
		t.Fatalf("the live database was replaced: lookup = %q, want FR", code)
	}
	if b, _ := BuildTime(); !b.Equal(liveBuilt) {
		t.Fatalf("the live database was replaced: BuildTime = %v, want %v", b, liveBuilt)
	}
}

// publishIfUnloaded is the re-check an attempt makes after its open returns,
// i.e. the case where a database was loaded while the open was in flight.
func TestPublishIfUnloaded_RefusesOverALoadedReader(t *testing.T) {
	resetForDeferredTest(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "live.mmdb")
	writeTestDB(t, live, "FR", "France", time.Unix(1_600_000_000, 0))
	if err := InitGeoDB(live); err != nil {
		t.Fatal(err)
	}
	geoDBMu.RLock()
	published := geoDB
	geoDBMu.RUnlock()
	if publishIfUnloaded(published, time.Now()) {
		t.Fatal("publishIfUnloaded must refuse while a reader is loaded")
	}
}

// Concurrent attempts and lookups: exactly one attempt loads, none replaces
// the reader, and lookups racing the publication never fault (run under -race).
func TestDeferredLoad_ConcurrentAttemptsLoadOnce(t *testing.T) {
	resetForDeferredTest(t)
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	writeTestDB(t, path, "IL", "Israel", time.Now())
	ArmDeferredLoad(path)

	const n = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		loadedN int
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if _, loaded, err := TryDeferredLoad(); err != nil {
				t.Errorf("TryDeferredLoad: %v", err)
			} else if loaded {
				mu.Lock()
				loadedN++
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if code, _ := LookupByIP(net.ParseIP(geoiptest.MatchedIP)); code != "" && code != "IL" {
				t.Errorf("lookup during the load returned %q", code)
			}
		}()
	}
	close(start)
	wg.Wait()
	if loadedN != 1 {
		t.Fatalf("%d attempts reported a load, want exactly 1", loadedN)
	}
	if code, _ := LookupByIP(net.ParseIP(geoiptest.MatchedIP)); code != "IL" {
		t.Fatalf("lookup after the load = %q, want IL", code)
	}
}
