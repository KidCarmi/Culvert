package secscan

// ADR-0006: Scanner decision-tree tests with injected fakes. These exercise
// ScanBody / CheckURL / CheckDomain / BodyScanEnabled branch logic without
// ClamAV sockets, YARA fixture files, or global mutation.

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/clamav"
	"github.com/KidCarmi/Culvert/internal/hashcache"
)

type fakeClam struct {
	name    string
	found   bool
	scanErr error
	pingErr error
	calls   int
}

func (f *fakeClam) Ping() error { return f.pingErr }
func (f *fakeClam) Scan([]byte) (name string, found bool, err error) {
	f.calls++
	return f.name, f.found, f.scanErr
}

type fakeYARA struct {
	loaded  bool
	enabled bool
	matches []string
	calls   int
}

func (f *fakeYARA) Loaded() bool  { return f.loaded }
func (f *fakeYARA) Enabled() bool { return f.enabled }
func (f *fakeYARA) Match([]byte) []string {
	f.calls++
	return f.matches
}

type fakeFeed struct {
	enabled bool
	hit     bool
	source  string
}

func (f fakeFeed) Enabled() bool                                { return f.enabled }
func (f fakeFeed) CheckURL(string) (hit bool, source string)    { return f.hit, f.source }
func (f fakeFeed) CheckDomain(string) (hit bool, source string) { return f.hit, f.source }

type fakeExcl struct{ excluded bool }

func (f fakeExcl) IsHashExcluded(string) bool { return f.excluded }

// newEnabledTestScanner builds a scanner from deps and enables it via the
// production Init path (New constructs disabled, mirroring the package-main
// singleton contract).
func newEnabledTestScanner(deps Deps) *Scanner {
	ss := New(deps)
	ss.Init("", 0, nil)
	return ss
}

func TestSecScanDI_ExclusionSkipsAllEngines(t *testing.T) {
	clam := &fakeClam{name: "EICAR", found: true}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Excl: fakeExcl{excluded: true},
		Yara: &fakeYARA{},
		Feed: fakeFeed{},
	})
	if res := ss.ScanBody([]byte("payload")); res != nil {
		t.Fatalf("excluded hash must skip scanning, got %+v", res)
	}
	if clam.calls != 0 {
		t.Fatalf("ClamAV must not run for excluded hash, ran %d times", clam.calls)
	}
	if _, ok := ss.cache.Get(hashcache.SHA256Hex([]byte("payload"))); ok {
		t.Fatal("excluded content must not be cached")
	}
}

func TestSecScanDI_ClamBlockThenCacheHit(t *testing.T) {
	clam := &fakeClam{name: "EICAR-Test", found: true}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Excl: fakeExcl{},
		Yara: &fakeYARA{},
		Feed: fakeFeed{},
	})
	data := []byte("malicious")

	res := ss.ScanBody(data)
	if res == nil || !res.Blocked || res.Source != "clamav" || res.Reason != "EICAR-Test" {
		t.Fatalf("expected clamav block, got %+v", res)
	}
	if res.Hash != hashcache.SHA256Hex(data) {
		t.Fatalf("result hash mismatch: %s", res.Hash)
	}

	// Second scan must come from the cache, not the engine.
	res2 := ss.ScanBody(data)
	if res2 == nil || !res2.Blocked || res2.Source != "clamav" {
		t.Fatalf("expected cached block, got %+v", res2)
	}
	if clam.calls != 1 {
		t.Fatalf("engine must run once (cache hit second time), ran %d times", clam.calls)
	}
}

func TestSecScanDI_ClamErrorFallsThroughToYARA(t *testing.T) {
	// Install a recorder for this test's async scan_clam_error and drain it
	// before returning — a straggler alert goroutine left in flight would land
	// in the next shuffled test's recorder (see clam_error_test.go).
	rec := withAlertRecorder(t)
	clam := &fakeClam{scanErr: errors.New("daemon down")}
	yr := &fakeYARA{loaded: true, enabled: true, matches: []string{"rule_a", "rule_b"}}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: yr,
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	res := ss.ScanBody([]byte("data"))
	if res == nil || res.Source != "yara" || res.Reason != "rule_a, rule_b" {
		t.Fatalf("expected yara block after clam error, got %+v", res)
	}
	// Fail on timeout so a delayed alert goroutine surfaces here instead of
	// leaking into the next shuffled test's recorder.
	if events := rec.waitForEvents(t, 1); len(events) != 1 || events[0] != "scan_clam_error" {
		t.Fatalf("drain: want one scan_clam_error alert, got %v", events)
	}
}

func TestSecScanDI_YARADisabledToggleSkipsMatch(t *testing.T) {
	// Rules loaded but runtime toggle off: body scanning stays active
	// (BodyScanEnabled keys on Loaded), yet Match must not run — the
	// pre-ADR-0006 verbatim contract.
	yr := &fakeYARA{loaded: true, enabled: false, matches: []string{"would_hit"}}
	ss := newEnabledTestScanner(Deps{
		Yara: yr,
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	if !ss.BodyScanEnabled() {
		t.Fatal("BodyScanEnabled must be true when rules are loaded (toggle-independent)")
	}
	if res := ss.ScanBody([]byte("data")); res != nil {
		t.Fatalf("disabled toggle must skip YARA match, got %+v", res)
	}
	if yr.calls != 0 {
		t.Fatalf("Match must not run with toggle off, ran %d times", yr.calls)
	}
	// Clean verdict must be cached.
	if cached, ok := ss.cache.Get(hashcache.SHA256Hex([]byte("data"))); !ok || !cached.Clean {
		t.Fatalf("clean result must be cached, got %+v ok=%v", cached, ok)
	}
}

func TestSecScanDI_CheckURLAndDomain(t *testing.T) {
	hit := newEnabledTestScanner(Deps{Feed: fakeFeed{enabled: true, hit: true, source: "urlhaus"}})
	if res := hit.CheckURL("http://evil.example/x"); res == nil || res.Source != "threatfeed" || res.Reason != "threat intelligence (urlhaus)" {
		t.Fatalf("expected threatfeed block, got %+v", res)
	}
	if res := hit.CheckDomain("evil.example"); res == nil || !res.Blocked {
		t.Fatalf("expected domain block, got %+v", res)
	}

	off := newEnabledTestScanner(Deps{Feed: fakeFeed{enabled: false, hit: true, source: "urlhaus"}})
	if res := off.CheckURL("http://evil.example/x"); res != nil {
		t.Fatalf("disabled feed must not block, got %+v", res)
	}
}

func TestSecScanDI_CacheAccessors(t *testing.T) {
	ss := newEnabledTestScanner(Deps{Excl: fakeExcl{}, Yara: &fakeYARA{loaded: true, enabled: true}, Feed: fakeFeed{}})
	_ = ss.ScanBody([]byte("content")) // clean → cached

	if !ss.CacheReady() {
		t.Fatal("CacheReady must be true after construction")
	}
	if _, _, size := ss.CacheStats(); size != 1 {
		t.Fatalf("expected 1 cached entry, got %d", size)
	}
	hash := hashcache.SHA256Hex([]byte("content"))
	if !ss.CacheEvict(hash) {
		t.Fatal("CacheEvict must report the entry was present")
	}
	if ss.CacheEvict(hash) {
		t.Fatal("CacheEvict must report absence on second evict")
	}
	_ = ss.ScanBody([]byte("content"))
	ss.CacheClear()
	if _, _, size := ss.CacheStats(); size != 0 {
		t.Fatalf("expected empty cache after CacheClear, got %d", size)
	}

	// Nil-tolerance: zero-value scanner has no cache.
	var empty Scanner
	if empty.CacheReady() {
		t.Fatal("zero-value scanner must report cache not ready")
	}
	empty.CacheClear() // must not panic
	if empty.CacheEvict("x") {
		t.Fatal("evict on nil cache must be false")
	}
}

// ── ClamAV VERSION surface ──────────────────────────────────────────────────

// fakeClamVer is a ClamScanner that also implements the optional VERSION
// capability, so ClamAVVersion can exercise the happy + caching paths.
type fakeClamVer struct {
	fakeClam
	ver     clamav.Version
	verErr  error
	verHits int
}

func (f *fakeClamVer) Version() (clamav.Version, error) {
	f.verHits++
	return f.ver, f.verErr
}

func TestClamAVVersion_ReportsAndCaches(t *testing.T) {
	clam := &fakeClamVer{ver: clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27000", DBDate: "Wed Apr 12 2023", Raw: "raw"}}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Feed: fakeFeed{}})

	v, ok := ss.ClamAVVersion()
	if !ok {
		t.Fatal("ClamAVVersion ok=false, want true for a version-capable client")
	}
	if v.Engine != "ClamAV 1.0.0" || v.DBVersion != "27000" {
		t.Errorf("got %+v, want engine ClamAV 1.0.0 / db 27000", v)
	}
	if clam.verHits != 1 {
		t.Fatalf("verHits = %d after first call, want 1", clam.verHits)
	}
	// Second call within TTL must be served from cache (no re-query).
	if _, ok := ss.ClamAVVersion(); !ok {
		t.Fatal("second ClamAVVersion ok=false")
	}
	if clam.verHits != 1 {
		t.Errorf("verHits = %d after cached call, want 1 (result must be cached)", clam.verHits)
	}
}

func TestClamAVVersion_NoVersionCapability(t *testing.T) {
	// A plain fakeClam does not implement Version() → ok=false, no panic.
	ss := newEnabledTestScanner(Deps{Clam: &fakeClam{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})
	if _, ok := ss.ClamAVVersion(); ok {
		t.Error("ClamAVVersion ok=true for a client without VERSION support, want false")
	}
}

func TestClamAVVersion_Disabled(t *testing.T) {
	// No clam injected → disabled → ok=false.
	ss := newEnabledTestScanner(Deps{Yara: &fakeYARA{}, Feed: fakeFeed{}})
	if _, ok := ss.ClamAVVersion(); ok {
		t.Error("ClamAVVersion ok=true with no ClamAV, want false")
	}
}

func TestClamAVVersion_ErrorNotCachedLong(t *testing.T) {
	clam := &fakeClamVer{verErr: errValidation}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Feed: fakeFeed{}})

	if _, ok := ss.ClamAVVersion(); ok {
		t.Fatal("ClamAVVersion ok=true on error, want false")
	}
	// An errored result must not be treated as a successful cache: the next
	// call re-queries (clamVerOK stays false).
	if _, ok := ss.ClamAVVersion(); ok {
		t.Fatal("second call ok=true, want false")
	}
	if clam.verHits != 2 {
		t.Errorf("verHits = %d, want 2 (errors must not be cached as success)", clam.verHits)
	}
}

var errValidation = errClamTest("clamav down")

type errClamTest string

func (e errClamTest) Error() string { return string(e) }
