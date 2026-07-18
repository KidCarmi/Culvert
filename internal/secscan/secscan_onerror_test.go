package secscan

// CHAOS-10 — on-scan-error posture tests. A ClamAV daemon error (or remote
// sidecar failure) must not silently degrade to an unscanned pass, and a
// verdict produced under a failed scanner must never be cached: the old code
// cached "clean" after a daemon error, so content that slipped past a crashed
// daemon stayed unscanned for the cache TTL even after recovery.

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// restorePosture pins the process-global posture back after a test mutates it
// (the PR3d fence-pollution class: package globals must not leak across tests).
func restorePosture(t *testing.T) {
	t.Helper()
	prev := GetOnScanError()
	t.Cleanup(func() { SetOnScanError(prev) })
}

// seqClam fails its first n calls, then reports found/name like fakeClam.
type seqClam struct {
	failFirst int
	name      string
	found     bool
	calls     int
}

func (f *seqClam) Ping() error { return nil }
func (f *seqClam) Scan([]byte) (name string, found bool, err error) {
	f.calls++
	if f.calls <= f.failFirst {
		return "", false, errors.New("daemon down")
	}
	return f.name, f.found, nil
}

func TestScanOnError_DefaultFailClosedBlocksAndNeverCaches(t *testing.T) {
	restorePosture(t)
	SetOnScanError(FailClosed)

	clam := &fakeClam{scanErr: errors.New("write unix @->/run/clamd.sock: broken pipe")}
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})
	data := []byte("unscannable payload")
	before := Counters().ScanError

	res := ss.ScanBody(data)
	if res == nil || !res.Blocked || res.Source != "scan_error" {
		t.Fatalf("default posture must fail closed on scanner error, got %+v", res)
	}
	if res.Hash != hashcache.SHA256Hex(data) {
		t.Fatalf("result hash mismatch: %s", res.Hash)
	}
	if got := Counters().ScanError; got != before+1 {
		t.Fatalf("ScanError counter = %d, want %d", got, before+1)
	}
	// The error verdict must NOT be cached in either direction: a transient
	// daemon failure must not pin the hash as blocked after recovery.
	if _, ok := ss.cache.Get(hashcache.SHA256Hex(data)); ok {
		t.Fatal("error verdict must not be cached")
	}
	if res2 := ss.ScanBody(data); res2 == nil || res2.Source != "scan_error" {
		t.Fatalf("second scan should re-consult the engine, got %+v", res2)
	}
	if clam.calls != 2 {
		t.Fatalf("engine must be re-consulted on every scan while erroring, ran %d times", clam.calls)
	}
}

func TestScanOnError_FailOpenAllowsButNeverCachesClean(t *testing.T) {
	restorePosture(t)
	SetOnScanError(FailOpenWithAlert)

	clam := &fakeClam{scanErr: errors.New("daemon down")}
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})
	data := []byte("payload under fail-open")

	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("fail_open_with_alert must allow on scanner error, got %+v", res)
	}
	// The poisoned-clean-cache fix: the fail-open pass must NOT be recorded as
	// a clean verdict — the next request for the same content re-scans.
	if _, ok := ss.cache.Get(hashcache.SHA256Hex(data)); ok {
		t.Fatal("fail-open pass must not be cached as clean")
	}
	ss.ScanBody(data)
	if clam.calls != 2 {
		t.Fatalf("engine must be re-consulted after a fail-open pass, ran %d times", clam.calls)
	}
}

func TestScanOnError_DaemonRecoveryRestoresRealVerdict(t *testing.T) {
	restorePosture(t)
	SetOnScanError(FailClosed)

	clam := &seqClam{failFirst: 1, name: "EICAR-Test", found: true}
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})
	data := []byte("malicious content behind a flapping daemon")

	if res := ss.ScanBody(data); res == nil || res.Source != "scan_error" {
		t.Fatalf("first scan should be an error block, got %+v", res)
	}
	// Daemon recovers: the real verdict must come through (nothing poisoned).
	res := ss.ScanBody(data)
	if res == nil || res.Source != "clamav" || res.Reason != "EICAR-Test" {
		t.Fatalf("post-recovery scan must return the real verdict, got %+v", res)
	}
	// And the real verdict IS cached.
	cached, ok := ss.cache.Get(hashcache.SHA256Hex(data))
	if !ok || cached.Clean {
		t.Fatalf("real verdict must be cached, got ok=%v %+v", ok, cached)
	}
}

func TestScanOnError_RealYARAVerdictBeatsErrorBlockAndCaches(t *testing.T) {
	restorePosture(t)
	SetOnScanError(FailClosed)

	clam := &fakeClam{scanErr: errors.New("daemon down")}
	yr := &fakeYARA{loaded: true, enabled: true, matches: []string{"rule_a"}}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: yr, Excl: fakeExcl{}, Feed: fakeFeed{}})
	data := []byte("yara-matched content")

	res := ss.ScanBody(data)
	if res == nil || res.Source != "yara" {
		t.Fatalf("a real engine verdict must beat the generic error block, got %+v", res)
	}
	// A true positive from a live engine is valid regardless of the failed
	// engine and stays cacheable.
	if cached, ok := ss.cache.Get(hashcache.SHA256Hex(data)); !ok || cached.Clean {
		t.Fatalf("real yara verdict must be cached, got ok=%v %+v", ok, cached)
	}
}

func TestRemoteScanFail_PostureGoverned(t *testing.T) {
	restorePosture(t)

	rs := &RemoteScanner{}
	rs.Init("http://127.0.0.1:1") // nothing listens: instant connection refused

	SetOnScanError(FailClosed)
	before := Counters().ScanError
	res := rs.ScanBody([]byte("data"), "")
	if res == nil || !res.Blocked || res.Source != "scan_error" {
		t.Fatalf("sidecar failure must fail closed by default, got %+v", res)
	}
	if got := Counters().ScanError; got != before+1 {
		t.Fatalf("ScanError counter = %d, want %d", got, before+1)
	}

	SetOnScanError(FailOpenWithAlert)
	if res := rs.ScanBody([]byte("data"), ""); res != nil {
		t.Fatalf("fail_open_with_alert must allow on sidecar failure, got %+v", res)
	}
}
