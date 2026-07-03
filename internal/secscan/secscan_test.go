package secscan

// ADR-0006: Scanner decision-tree tests with injected fakes. These exercise
// ScanBody / CheckURL / CheckDomain / BodyScanEnabled branch logic without
// ClamAV sockets, YARA fixture files, or global mutation.

import (
	"errors"
	"testing"

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
