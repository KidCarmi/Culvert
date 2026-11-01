package secscan

// CHAOS-107 regression gates: the scan verdict cache is keyed on the content
// hash alone, so it must be reconciled against the signature set that produced
// the verdicts in it. These tests pin BOTH directions — it invalidates when the
// definitions change, and it does NOT invalidate on anything else, because a
// cache that flushes on a daemon blip is a self-inflicted scan storm against an
// already-struggling daemon (CHAOS-52/53).

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/clamav"
	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// sigGenScanner builds an enabled scanner with a version-capable ClamAV fake
// whose signature identity the test can move.
func sigGenScanner(t *testing.T, db string) (*Scanner, *fakeClamVer) {
	t.Helper()
	clam := &fakeClamVer{ver: clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: db}}
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})
	return ss, clam
}

// expireVersionCache forces the next ClamAVVersion call to re-query, standing
// in for the passage of clamVersionTTL.
func expireVersionCache(ss *Scanner) {
	ss.mu.Lock()
	ss.clamVerOK = false
	ss.mu.Unlock()
}

// TestCHAOS107_SignatureUpdateInvalidatesCleanVerdict is the finding itself: a
// "clean" cached under one signature set must not survive the arrival of a set
// that detects the same bytes. Before the fix the second request was served
// from the cache and the engine never ran again, for the rest of CacheTTL —
// operator-configurable with no upper bound, so "the rest of the hour" was only
// the default.
func TestCHAOS107_SignatureUpdateInvalidatesCleanVerdict(t *testing.T) {
	ss, clam := sigGenScanner(t, "27000")

	// Baseline the generation while the cache is empty, as the production
	// poller's opening tick does (startScanSignatureWatch runs its first
	// observation before its first tick, and initScanning precedes
	// initBackgroundServices).
	//
	// The counter is process-global and other tests in this package advance
	// it, so the assertion is a delta against a baseline taken here, never an
	// absolute value: under -shuffle an absolute zero is order-dependent.
	baseline := SigDBInvalidations()
	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if n := SigDBInvalidations() - baseline; n != 0 {
		t.Fatalf("baseline observation on an empty cache must not flush; invalidations delta = %d", n)
	}

	payload := []byte("a-dropper-no-signature-covers-yet")
	if res := ss.ScanBody(payload); res != nil {
		t.Fatalf("db 27000 must report clean, got %+v", res)
	}
	if _, _, size := ss.CacheStats(); size != 1 {
		t.Fatalf("clean verdict must be cached, size = %d", size)
	}

	before := SigDBInvalidations()

	// freshclam lands: new definitions, and the daemon now detects the sample.
	clam.ver = clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27001"}
	clam.name, clam.found = "Win.Trojan.Dropper", true
	expireVersionCache(ss)
	if !ss.RefreshSignatures() {
		t.Fatal("observation after the signature update failed")
	}

	if got := SigDBInvalidations() - before; got != 1 {
		t.Errorf("signature change must flush the verdict cache exactly once, invalidations delta = %d", got)
	}
	res := ss.ScanBody(payload)
	if res == nil || !res.Blocked {
		t.Fatalf("after the signature update the content must be re-scanned and blocked, got %+v", res)
	}
	if res.Source != "clamav" || res.Reason != "Win.Trojan.Dropper" {
		t.Errorf("expected the new clamav detection, got %+v", res)
	}
	if clam.calls != 2 {
		t.Errorf("engine must run again after invalidation; clam scans = %d, want 2", clam.calls)
	}
	if gen, known := ss.SignatureGeneration(); !known || gen != "ClamAV 1.0.0/27001/" {
		t.Errorf("recorded generation = %q known=%v, want the new set", gen, known)
	}
}

// TestCHAOS107_UnchangedSignatureKeepsCache pins the efficiency half. The cache
// exists to keep the same object off the engines; an observer that flushed on
// every poll would destroy that and hand the node a re-scan of its entire
// working set every interval.
func TestCHAOS107_UnchangedSignatureKeepsCache(t *testing.T) {
	ss, clam := sigGenScanner(t, "27000")
	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if res := ss.ScanBody([]byte("ordinary-content")); res != nil {
		t.Fatalf("expected clean, got %+v", res)
	}
	before := SigDBInvalidations()

	for i := 0; i < 5; i++ {
		expireVersionCache(ss)
		if !ss.RefreshSignatures() {
			t.Fatalf("observation %d failed", i)
		}
	}
	if got := SigDBInvalidations() - before; got != 0 {
		t.Errorf("repeated polls of an UNCHANGED signature set must not flush; delta = %d", got)
	}
	if _, _, size := ss.CacheStats(); size != 1 {
		t.Errorf("cache must survive unchanged-signature polls, size = %d", size)
	}
	if res := ss.ScanBody([]byte("ordinary-content")); res != nil {
		t.Fatalf("expected cached clean, got %+v", res)
	}
	if clam.calls != 1 {
		t.Errorf("engine must still run only once; clam scans = %d", clam.calls)
	}
}

// TestCHAOS107_VersionQueryFailureKeepsCache pins the fail direction, and it is
// the deliberate one. A failed VERSION query is a fault in the OBSERVER, not
// evidence that the definitions moved. Flushing on it would let any daemon blip
// wipe the cache node-wide and send every subsequent body to the very daemon
// that just failed to answer — the self-sustaining saturation that scan
// cancellation exists to prevent. The dark window cannot accumulate new false
// cleans either: the clamDark branch already refuses to cache a "clean"
// computed while ClamAV was unreachable.
func TestCHAOS107_VersionQueryFailureKeepsCache(t *testing.T) {
	ss, clam := sigGenScanner(t, "27000")
	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if res := ss.ScanBody([]byte("ordinary-content")); res != nil {
		t.Fatalf("expected clean, got %+v", res)
	}
	before := SigDBInvalidations()

	clam.verErr = errValidation
	expireVersionCache(ss)
	if ss.RefreshSignatures() {
		t.Fatal("RefreshSignatures must report failure when VERSION errors")
	}
	if got := SigDBInvalidations() - before; got != 0 {
		t.Errorf("a failed VERSION query must not flush the cache; delta = %d", got)
	}
	if _, _, size := ss.CacheStats(); size != 1 {
		t.Errorf("cache must survive an observer fault, size = %d", size)
	}
	// And the recorded generation must be unchanged, so recovery does not look
	// like a change and flush for nothing.
	if gen, known := ss.SignatureGeneration(); !known || gen != "ClamAV 1.0.0/27000/" {
		t.Errorf("generation = %q known=%v, want the pre-fault set retained", gen, known)
	}
	clam.verErr = nil
	expireVersionCache(ss)
	if !ss.RefreshSignatures() {
		t.Fatal("observation after recovery failed")
	}
	if got := SigDBInvalidations() - before; got != 0 {
		t.Errorf("recovery to the SAME signature set must not flush; delta = %d", got)
	}
}

// TestCHAOS107_BaselineOntoNonEmptyCacheFlushes covers the race the fix must not
// depend on winning. The poller's opening observation normally precedes any
// traffic, but if traffic got there first those verdicts have no recorded
// provenance — they may predate any signature set the node can name — so the
// first observation must flush rather than silently adopt them as current.
func TestCHAOS107_BaselineOntoNonEmptyCacheFlushes(t *testing.T) {
	ss, _ := sigGenScanner(t, "27000")

	// Traffic before any observation.
	if res := ss.ScanBody([]byte("unprovenanced")); res != nil {
		t.Fatalf("expected clean, got %+v", res)
	}
	if _, _, size := ss.CacheStats(); size != 1 {
		t.Fatalf("precondition: one cached verdict, size = %d", size)
	}
	if gen, known := ss.SignatureGeneration(); known || gen != "" {
		t.Fatalf("precondition: no generation observed yet, got %q known=%v", gen, known)
	}
	before := SigDBInvalidations()

	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if got := SigDBInvalidations() - before; got != 1 {
		t.Errorf("baselining onto a non-empty cache must flush the unprovenanced entries; delta = %d", got)
	}
	if _, _, size := ss.CacheStats(); size != 0 {
		t.Errorf("unprovenanced verdicts must be gone, size = %d", size)
	}
}

// TestCHAOS107_EngineUpgradeInvalidates: an engine upgrade changes what the
// daemon can detect even when the signature counter does not move, so it counts
// as a new generation.
func TestCHAOS107_EngineUpgradeInvalidates(t *testing.T) {
	ss, clam := sigGenScanner(t, "27000")
	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if res := ss.ScanBody([]byte("content")); res != nil {
		t.Fatalf("expected clean, got %+v", res)
	}
	before := SigDBInvalidations()

	clam.ver = clamav.Version{Engine: "ClamAV 1.5.0", DBVersion: "27000"}
	expireVersionCache(ss)
	if !ss.RefreshSignatures() {
		t.Fatal("observation after the engine upgrade failed")
	}
	if got := SigDBInvalidations() - before; got != 1 {
		t.Errorf("an engine upgrade must invalidate; delta = %d", got)
	}
}

// TestCHAOS107_UnidentifiableReplyIsNotAnObservation: a VERSION reply Culvert
// cannot parse into any identity must not be recorded. Recording "" would make
// the NEXT real reply look like a change and flush a warm cache for nothing.
func TestCHAOS107_UnidentifiableReplyIsNotAnObservation(t *testing.T) {
	clam := &fakeClamVer{ver: clamav.Version{}} // all fields empty, including Raw
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})

	if !ss.RefreshSignatures() {
		t.Fatal("an empty-but-successful VERSION reply is still ok=true")
	}
	if gen, known := ss.SignatureGeneration(); known || gen != "" {
		t.Fatalf("an unidentifiable reply must not be recorded, got %q known=%v", gen, known)
	}
	if res := ss.ScanBody([]byte("content")); res != nil {
		t.Fatalf("expected clean, got %+v", res)
	}
	before := SigDBInvalidations()

	// A later identifiable reply baselines. The cache is non-empty and
	// unprovenanced, so exactly one flush is correct here — what must NOT
	// happen is a flush attributed to a "change" from the empty reply.
	clam.ver = clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27000"}
	expireVersionCache(ss)
	if !ss.RefreshSignatures() {
		t.Fatal("second observation failed")
	}
	if got := SigDBInvalidations() - before; got != 1 {
		t.Errorf("delta = %d, want 1 (baseline onto unprovenanced entries)", got)
	}
	if gen, known := ss.SignatureGeneration(); !known || gen != "ClamAV 1.0.0/27000/" {
		t.Errorf("generation = %q known=%v", gen, known)
	}
}

// TestCHAOS107_InitRebaselines: Init may point the scanner at a different
// daemon, so the old daemon's counter must not be compared against the new
// one's — that comparison is meaningless and would flush (or, worse, NOT flush)
// on an unrelated difference.
func TestCHAOS107_InitRebaselines(t *testing.T) {
	ss, _ := sigGenScanner(t, "27000")
	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if gen, known := ss.SignatureGeneration(); !known || gen == "" {
		t.Fatalf("precondition: a generation is recorded, got %q known=%v", gen, known)
	}

	ss.Init("", 0, hashcache.New(10, 0))
	if gen, known := ss.SignatureGeneration(); known || gen != "" {
		t.Errorf("Init must drop the recorded generation, got %q known=%v", gen, known)
	}
}

// TestCHAOS107_NoClamIsNotAnObservation: the poller runs unconditionally, so it
// must be a clean no-op where there is nothing to observe (remote/sidecar mode,
// or ClamAV simply not configured) rather than flushing or panicking.
func TestCHAOS107_NoClamIsNotAnObservation(t *testing.T) {
	ss := newEnabledTestScanner(Deps{Excl: fakeExcl{}, Yara: &fakeYARA{loaded: true, enabled: true}, Feed: fakeFeed{}})
	before := SigDBInvalidations()
	if ss.RefreshSignatures() {
		t.Error("RefreshSignatures must report not-ok with no ClamAV")
	}
	if got := SigDBInvalidations() - before; got != 0 {
		t.Errorf("no-ClamAV polls must not flush; delta = %d", got)
	}
	if gen, known := ss.SignatureGeneration(); known || gen != "" {
		t.Errorf("nothing observable must record nothing, got %q known=%v", gen, known)
	}

	// And a scanner with no cache at all must not panic on a would-be flush.
	var zero Scanner
	if zero.RefreshSignatures() {
		t.Error("zero-value scanner must report not-ok")
	}
}

// TestCHAOS107_ConcurrentObservationsFlushOnce: the dashboard metrics payload
// and the background poller both drive the observation, so two callers can race
// on the same change. The flush must be accounted exactly once per change, or
// the counter stops being readable as "how many times did this node adopt new
// definitions".
func TestCHAOS107_ConcurrentObservationsFlushOnce(t *testing.T) {
	clam := &syncClamVer{ver: clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27000"}}
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: &fakeYARA{}, Feed: fakeFeed{}})
	if !ss.RefreshSignatures() {
		t.Fatal("opening observation failed")
	}
	if res := ss.ScanBody([]byte("content")); res != nil {
		t.Fatalf("expected clean, got %+v", res)
	}
	before := SigDBInvalidations()

	clam.setVersion(clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27001"})
	expireVersionCache(ss)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ss.RefreshSignatures()
		}()
	}
	wg.Wait()

	if got := SigDBInvalidations() - before; got != 1 {
		t.Errorf("one signature change must be counted once across concurrent observers; delta = %d", got)
	}
}

// guard: the counter accessor and the snapshot must agree, so the Prometheus
// series and the admin JSON cannot drift apart.
func TestCHAOS107_CounterSnapshotAgrees(t *testing.T) {
	if got, want := Counters().SigDBInvalidations, atomic.LoadInt64(&statScanSigDBInvalidations); got != want {
		t.Errorf("snapshot = %d, accessor = %d", got, want)
	}
	if got, want := SigDBInvalidations(), Counters().SigDBInvalidations; got != want {
		t.Errorf("SigDBInvalidations() = %d, snapshot = %d", got, want)
	}
}

// syncClamVer is a race-safe version-capable ClamAV fake. The shared
// fakeClamVer counts its own calls with a bare int, which is fine for the
// sequential tests that own it and not fine under -race with sixteen concurrent
// observers; this one exists so the concurrency gate tests the SCANNER's
// synchronization rather than the fake's.
type syncClamVer struct {
	mu    sync.Mutex
	ver   clamav.Version
	err   error
	name  string
	found bool
	calls int
}

func (f *syncClamVer) Ping() error { return nil }

func (f *syncClamVer) Scan([]byte) (name string, found bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.name, f.found, nil
}

// detect makes the fake report name for every subsequent scan, standing in for
// the daemon loading a signature that covers the test payload.
func (f *syncClamVer) detect(name string) {
	f.mu.Lock()
	f.name, f.found = name, true
	f.mu.Unlock()
}

func (f *syncClamVer) scans() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *syncClamVer) Version() (clamav.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ver, f.err
}

func (f *syncClamVer) setVersion(v clamav.Version) {
	f.mu.Lock()
	f.ver = v
	f.mu.Unlock()
}

// answerVersion makes VERSION succeed again, reporting v.
func (f *syncClamVer) answerVersion(v clamav.Version) {
	f.mu.Lock()
	f.ver, f.err = v, nil
	f.mu.Unlock()
}

// pausingYARA holds the FIRST Match call until released, so a test can park a
// scan after its ClamAV leg has returned and before it publishes a verdict.
// Later calls return immediately. The injected YARAMatcher is the package's
// existing seam between the two legs (ADR-0006); no production hook is needed.
type pausingYARA struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newPausingYARA() *pausingYARA {
	return &pausingYARA{entered: make(chan struct{}), release: make(chan struct{})}
}

func (y *pausingYARA) Loaded() bool  { return true }
func (y *pausingYARA) Enabled() bool { return true }

func (y *pausingYARA) Match([]byte) []string {
	first := false
	y.once.Do(func() { first = true })
	if first {
		close(y.entered)
		<-y.release
	}
	return nil
}

// TestCHAOS107_InFlightScanAcrossFlushIsNotCached is the race the flush alone
// does not close. A scan whose ClamAV leg ran under the OLD definitions but
// which is still in its YARA leg when the cache is flushed would otherwise
// publish its old "clean" into the freshly emptied cache — and since later
// observations of the same new generation do not flush again, that content
// would bypass the new definitions for the full CacheTTL. The scan must carry
// the cache generation it started under and lose the publication if the cache
// was invalidated meanwhile.
//
// Both invalidation sources are pinned: the observed signature-set change, and
// a direct cache flush (the operator flush and the YARA rule CRUD paths in
// package main), which distrusts in-flight verdicts for the same reason.
func TestCHAOS107_InFlightScanAcrossFlushIsNotCached(t *testing.T) {
	cases := []struct {
		name       string
		invalidate func(t *testing.T, ss *Scanner, clam *syncClamVer)
	}{
		{"signature set change", func(t *testing.T, ss *Scanner, clam *syncClamVer) {
			before := SigDBInvalidations()
			clam.setVersion(clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27001"})
			expireVersionCache(ss)
			if !ss.RefreshSignatures() {
				t.Fatal("observation after the signature update failed")
			}
			if got := SigDBInvalidations() - before; got != 1 {
				t.Fatalf("signature change must flush once mid-scan; delta = %d", got)
			}
		}},
		{"operator cache flush", func(_ *testing.T, ss *Scanner, _ *syncClamVer) {
			ss.CacheClear()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clam := &syncClamVer{ver: clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27000"}}
			yara := newPausingYARA()
			ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: yara, Feed: fakeFeed{}})
			if !ss.RefreshSignatures() {
				t.Fatal("opening observation failed")
			}

			payload := []byte("dropper-cleared-by-the-old-definitions")
			hash := hashcache.SHA256Hex(payload)
			done := make(chan *Result, 1)
			go func() { done <- ss.ScanBody(payload) }()

			// Park the scan between its legs: ClamAV has already called the
			// payload clean under the old definitions.
			select {
			case <-yara.entered:
			case res := <-done:
				t.Fatalf("scan finished before reaching YARA: %+v", res)
			}
			if got := clam.scans(); got != 1 {
				t.Fatalf("precondition: ClamAV leg ran once before the pause, got %d", got)
			}

			// The new definitions now detect the payload, and the cache is
			// invalidated while the old scan is still in flight.
			clam.detect("Win.Trojan.Dropper")
			tc.invalidate(t, ss, clam)

			close(yara.release)
			if res := <-done; res != nil {
				t.Fatalf("the in-flight request itself completes clean (its verdict was computed before the change), got %+v", res)
			}

			if cached, ok := ss.CacheGet(hash); ok {
				t.Fatalf("a verdict begun before the invalidation must not be published after it, cached %+v", cached)
			}
			res := ss.ScanBody(payload)
			if res == nil || !res.Blocked || res.Source != "clamav" || res.Reason != "Win.Trojan.Dropper" {
				t.Fatalf("the next request must be re-scanned under the new definitions and blocked, got %+v", res)
			}
			if got := clam.scans(); got != 2 {
				t.Errorf("ClamAV must run again for the next request; scans = %d, want 2", got)
			}
		})
	}
}

// TestCHAOS107_FirstObservationMidScanRefusesPublication: an empty cache at the
// FIRST identifiable observation does not mean there is nothing to invalidate.
// After an opening VERSION failure the node has no recorded signature set, and
// a request can finish its ClamAV leg under the old definitions and still be in
// YARA when a later poll first identifies the (already updated) set. Nothing
// has been cached yet, so there are no entries to drop — but the in-flight
// verdict has no provenance either, and if the observation leaves the cache
// epoch where it was, that old "clean" is published into the cache and served
// for the full CacheTTL. The first observation must therefore advance the epoch
// regardless of entry count, while the invalidation counter still reports only
// first-observation flushes that actually dropped verdicts.
func TestCHAOS107_FirstObservationMidScanRefusesPublication(t *testing.T) {
	clam := &syncClamVer{err: errValidation}
	yara := newPausingYARA()
	ss := newEnabledTestScanner(Deps{Clam: clam, Excl: fakeExcl{}, Yara: yara, Feed: fakeFeed{}})

	// The opening observation fails, so nothing is recorded.
	if ss.RefreshSignatures() {
		t.Fatal("RefreshSignatures must report failure when VERSION errors")
	}
	if gen, known := ss.SignatureGeneration(); known || gen != "" {
		t.Fatalf("precondition: no generation recorded after a failed VERSION, got %q known=%v", gen, known)
	}

	payload := []byte("dropper-cleared-before-the-first-observation")
	hash := hashcache.SHA256Hex(payload)
	done := make(chan *Result, 1)
	go func() { done <- ss.ScanBody(payload) }()

	// Park the scan between its legs: ClamAV has already called the payload
	// clean, under definitions the node never identified.
	select {
	case <-yara.entered:
	case res := <-done:
		t.Fatalf("scan finished before reaching YARA: %+v", res)
	}
	if got := clam.scans(); got != 1 {
		t.Fatalf("precondition: ClamAV leg ran once before the pause, got %d", got)
	}
	if _, _, size := ss.CacheStats(); size != 0 {
		t.Fatalf("precondition: nothing cached while the scan is in flight, size = %d", size)
	}

	// The daemon now answers VERSION, with definitions that detect the payload.
	clam.answerVersion(clamav.Version{Engine: "ClamAV 1.0.0", DBVersion: "27001"})
	clam.detect("Win.Trojan.Dropper")
	expireVersionCache(ss)

	before := SigDBInvalidations()
	if !ss.RefreshSignatures() {
		t.Fatal("first successful observation failed")
	}
	if got := SigDBInvalidations() - before; got != 0 {
		t.Errorf("a first observation on an EMPTY cache dropped nothing and must not count as a flush; delta = %d", got)
	}

	close(yara.release)
	if res := <-done; res != nil {
		t.Fatalf("the in-flight request itself completes clean (its verdict was computed before the observation), got %+v", res)
	}
	if cached, ok := ss.CacheGet(hash); ok {
		t.Fatalf("a verdict begun before the first observation must not be published after it, cached %+v", cached)
	}
	res := ss.ScanBody(payload)
	if res == nil || !res.Blocked || res.Source != "clamav" || res.Reason != "Win.Trojan.Dropper" {
		t.Fatalf("the next request must be re-scanned under the observed definitions and blocked, got %+v", res)
	}
	if got := clam.scans(); got != 2 {
		t.Errorf("ClamAV must run again for the next request; scans = %d, want 2", got)
	}
}
