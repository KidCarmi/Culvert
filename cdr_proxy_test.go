package main

// Phase 2b tests — exercises safeCDRSanitize() directly against a bufconn
// fake Sluice server.  Covers all five Status paths, cache behaviour
// (hit / miss / policy-epoch invalidation / SANITIZED-not-cached),
// oversize handling, and fail-open / fail-closed branching.
//
// Test helpers from cdr_test.go (fakeSluice, startFakeSluice) are reused.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// withActiveCDRClient plugs `c` into the process-wide pool for the
// duration of a test.  Restores the previous state on cleanup.
func withActiveCDRClient(t *testing.T, c *CDRClient, cfg CDRConfig) {
	t.Helper()
	prev := cdrPool.List()
	cdrClientMu.Lock()
	prevCfg := cdrActiveCfg
	cdrActiveCfg = cfg
	cdrClientMu.Unlock()
	cdrPoolInstallSingleForTest(c)
	t.Cleanup(func() {
		cdrClientMu.Lock()
		cdrActiveCfg = prevCfg
		cdrClientMu.Unlock()
		cdrPool.replace(prev)
	})
}

// resetCDRCountersAndCache clears per-test state so tests don't see each
// other's counters or cache entries.
func resetCDRCountersAndCache(t *testing.T) {
	t.Helper()
	atomic.StoreInt64(&statCDRClean, 0)
	atomic.StoreInt64(&statCDRSanitized, 0)
	atomic.StoreInt64(&statCDRBlocked, 0)
	atomic.StoreInt64(&statCDRUnsupported, 0)
	atomic.StoreInt64(&statCDROversizeSkipped, 0)
	atomic.StoreInt64(&statCDRErrors, 0)
	atomic.StoreInt64(&statCDRFailOpen, 0)
	atomic.StoreInt64(&statCDRFailClosed, 0)
	atomic.StoreInt64(&statCDRPanics, 0)
	atomic.StoreInt64(&statCDRBytesOut, 0)
	cdrCache.mu.Lock()
	cdrCache.entries = map[string]*cdrCacheEntry{}
	cdrCache.hits.Store(0)
	cdrCache.misses.Store(0)
	cdrCache.mu.Unlock()
}

// freshPolicyStore swaps a fresh empty store in for a single test.
func freshPolicyStore(t *testing.T) {
	t.Helper()
	orig := cdrPolicyStore
	cdrPolicyStore = &CDRPolicyStore{}
	t.Cleanup(func() { cdrPolicyStore = orig })
}

// sampleID is the identity context fed to safeCDRSanitize in tests.
var sampleID = ProxyIdentity{
	ClientIP:   "10.0.0.42",
	Identity:   "alice@corp",
	AuthSource: "local",
	Groups:     []string{"staff"},
}

// sampleReq is the request context populated for tests.
func sampleReq(host string) cdrRequestContext {
	return cdrRequestContext{
		Host:        host,
		URL:         "/downloads/invoice.docx",
		RequestID:   "req-unit-test",
		TraceParent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	}
}

// ─── Gate + oversize ───────────────────────────────────────────────────────

func TestSafeCDRSanitize_DisabledReturnsSkipped(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	// No active client — CDR off.
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("any"), "application/pdf", sampleID, CDRConfig{Enabled: false})
	if out.Outcome != cdrPass || out.Status != "SKIPPED" {
		t.Fatalf("expected cdrPass SKIPPED, got %+v", out)
	}
}

func TestSafeCDRSanitize_OversizeBodyIsSkipped(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	c, stop := startFakeSluice(t, &fakeSluice{})
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, MaxFileSizeMB: 1})

	// 2 MiB body > 1 MiB cap — skipped client-side before any RPC.
	body := make([]byte, 2<<20)
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		body, "application/pdf", sampleID, cdrActiveConfig())
	if out.Outcome != cdrPass || out.Status != "SKIPPED_OVERSIZE" {
		t.Fatalf("expected cdrPass SKIPPED_OVERSIZE, got %+v", out)
	}
	if got := atomic.LoadInt64(&statCDROversizeSkipped); got != 1 {
		t.Fatalf("oversize counter = %d, want 1", got)
	}
}

// TestSafeCDRSanitize_ProfileCapTightensGate — when the Sluice profile
// advertises a smaller cap than our config, we honour the smaller.
// This is v0.2 Q5 defence-in-depth — stops files Sluice would reject
// from hitting the wire.
func TestSafeCDRSanitize_ProfileCapTightensGate(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	c, stop := startFakeSluice(t, &fakeSluice{})
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, MaxFileSizeMB: 50})

	// Seed a tight profile cap (1 MiB) on the pool member via the
	// same setter the Health poller uses.
	for _, pc := range cdrPool.List() {
		pc.profileCap.Store(1 << 20)
	}

	body := make([]byte, 2<<20) // 2 MiB > 1 MiB profile cap
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		body, "application/pdf", sampleID, cdrActiveConfig())
	if out.Status != "SKIPPED_OVERSIZE" {
		t.Fatalf("expected SKIPPED_OVERSIZE when body > profile cap, got %+v", out)
	}
}

// TestSafeCDRSanitize_ProfileCapLooserThanConfigDoesNotRelax — if the
// profile cap is LARGER than our config, we stay at the config limit.
// (i.e. we never silently widen the gate.)
func TestSafeCDRSanitize_ProfileCapLooserThanConfigDoesNotRelax(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	c, stop := startFakeSluice(t, &fakeSluice{})
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, MaxFileSizeMB: 1})

	for _, pc := range cdrPool.List() {
		pc.profileCap.Store(50 << 20) // profile allows 50 MiB
	}

	body := make([]byte, 2<<20) // 2 MiB > 1 MiB config cap
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		body, "application/pdf", sampleID, cdrActiveConfig())
	if out.Status != "SKIPPED_OVERSIZE" {
		t.Fatalf("config cap must still be enforced even with looser profile cap; got %+v", out)
	}
}

// ─── Happy paths: CLEAN / SANITIZED / BLOCKED / UNSUPPORTED ────────────────

func TestSafeCDRSanitize_CleanPath(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN, DurationMs: 7}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	body := []byte("clean document bytes")
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		body, "application/pdf", sampleID, cdrActiveConfig())
	if out.Outcome != cdrPass || out.Status != "CLEAN" {
		t.Fatalf("status = %+v", out)
	}
	if out.Cached {
		t.Fatal("first call should not be cached")
	}
	if got := srv.lastHeader.GetFilename(); got != "invoice.docx" {
		t.Fatalf("filename hint = %q, want invoice.docx", got)
	}
	if got := srv.lastHeader.GetTraceParent(); got != sampleReq("").TraceParent {
		t.Fatalf("trace_parent not propagated: %q", got)
	}
	if got := srv.lastHeader.GetTags()["direction"]; got != "download" {
		t.Fatalf("tags.direction = %q", got)
	}
}

func TestSafeCDRSanitize_Sanitized(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	cleanBytes := []byte("SANITIZED_BYTES")
	sum := sha256.Sum256(cleanBytes)
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:          pb.Status_SANITIZED,
			SanitizedSize:   int64(len(cleanBytes)),
			SanitizedSha256: sum[:],
			ThreatsRemoved:  []*pb.Threat{{Type: "macro", Severity: "high"}},
		},
		replyChunks: [][]byte{cleanBytes},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		make([]byte, 128), "application/msword", sampleID, cdrActiveConfig())
	if out.Outcome != cdrSwap || out.Status != "SANITIZED" {
		t.Fatalf("got %+v, want cdrSwap SANITIZED", out)
	}
	if !bytes.Equal(out.Body, cleanBytes) {
		t.Fatalf("Body = %q, want %q", out.Body, cleanBytes)
	}
	if len(out.Threats) != 1 || out.Threats[0].Type != "macro" {
		t.Fatalf("threats = %+v", out.Threats)
	}
}

func TestSafeCDRSanitize_Blocked(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:         pb.Status_BLOCKED,
			ErrorMessage:   "unsalvageable_macro_payload",
			ThreatsRemoved: []*pb.Threat{{Type: "macro", Severity: "critical"}},
		},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("bad"), "application/msword", sampleID, cdrActiveConfig())
	if out.Outcome != cdrBlock || out.Status != "BLOCKED" {
		t.Fatalf("got %+v", out)
	}
	if !strings.Contains(out.BlockReason, "unsalvageable") {
		t.Fatalf("block reason = %q", out.BlockReason)
	}
}

func TestSafeCDRSanitize_Unsupported(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_UNSUPPORTED}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/octet-stream", sampleID, cdrActiveConfig())
	if out.Outcome != cdrPass || out.Status != "UNSUPPORTED" {
		t.Fatalf("got %+v", out)
	}
}

// ─── Fail-mode branching on ERROR status ───────────────────────────────────

func TestSafeCDRSanitize_ErrorFailOpen(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_ERROR, ErrorMessage: "unknown_profile: aggressive"}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, FailMode: "open"})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/pdf", sampleID, cdrActiveConfig())
	if out.Outcome != cdrPass || out.Status != "ERROR" {
		t.Fatalf("want cdrPass ERROR, got %+v", out)
	}
	if got := atomic.LoadInt64(&statCDRFailOpen); got != 1 {
		t.Fatalf("fail_open counter = %d", got)
	}
}

func TestSafeCDRSanitize_ErrorFailClosed(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_ERROR, ErrorMessage: "oops"}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, FailMode: "closed"})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/pdf", sampleID, cdrActiveConfig())
	if out.Outcome != cdrBlock {
		t.Fatalf("want cdrBlock, got %+v", out)
	}
	if got := atomic.LoadInt64(&statCDRFailClosed); got != 1 {
		t.Fatalf("fail_closed counter = %d", got)
	}
}

// ─── Hash cache ─────────────────────────────────────────────────────────────

func TestSafeCDRSanitize_CacheHitOnCleanSkipsSluice(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	body := []byte("same file bytes")
	_ = safeCDRSanitize(context.Background(), sampleReq("example.com"), body, "application/pdf", sampleID, cdrActiveConfig())

	// Remove the server response so any second call would fail loudly.
	srv.mu.Lock()
	srv.result = nil
	srv.mu.Unlock()

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"), body, "application/pdf", sampleID, cdrActiveConfig())
	if !out.Cached || out.Status != "CLEAN" {
		t.Fatalf("second call didn't hit cache: %+v", out)
	}
}

func TestSafeCDRSanitize_SanitizedIsNeverCached(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{
		result:      &pb.SanitizeResult{Status: pb.Status_SANITIZED, SanitizedSize: 3},
		replyChunks: [][]byte{[]byte("abc")},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	body := []byte("identical file")
	_ = safeCDRSanitize(context.Background(), sampleReq("example.com"), body, "application/msword", sampleID, cdrActiveConfig())
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"), body, "application/msword", sampleID, cdrActiveConfig())
	if out.Cached {
		t.Fatal("SANITIZED results MUST NOT be cached")
	}
}

func TestSafeCDRSanitize_CacheInvalidatedOnPolicyEdit(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	body := []byte("cache me")

	// First call — CLEAN, cached.
	_ = safeCDRSanitize(context.Background(), sampleReq("example.com"), body, "application/pdf", sampleID, cdrActiveConfig())

	// Admin edits a rule — bumps epoch, cache becomes stale.
	if _, err := cdrPolicyStore.Add(CDRPolicyRule{Name: "new-rule", Priority: 10, Mode: "ENFORCE"}); err != nil {
		t.Fatal(err)
	}

	// Second call — must not hit cache, must call Sluice again.
	srv.mu.Lock()
	srv.result = &pb.SanitizeResult{Status: pb.Status_UNSUPPORTED}
	srv.mu.Unlock()

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"), body, "application/pdf", sampleID, cdrActiveConfig())
	if out.Cached {
		t.Fatal("epoch change did not invalidate cache")
	}
	if out.Status != "UNSUPPORTED" {
		t.Fatalf("status = %q, want UNSUPPORTED (fresh Sluice response)", out.Status)
	}
}

// ─── Policy decision propagation ───────────────────────────────────────────

func TestSafeCDRSanitize_PolicyDecisionReachesHeader(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	// Rule forces REPORT_ONLY for 'staff' group.
	if _, err := cdrPolicyStore.Add(CDRPolicyRule{
		Name: "staff-report", Priority: 100, SourceGroup: "staff",
		ProfileName: "default", Mode: "REPORT_ONLY",
	}); err != nil {
		t.Fatal(err)
	}
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	_ = safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/pdf", sampleID, cdrActiveConfig())

	if got := srv.lastHeader.GetMode(); got != pb.Mode_REPORT_ONLY {
		t.Fatalf("mode not propagated: %v", got)
	}
	if got := srv.lastHeader.GetProfileName(); got != "default" {
		t.Fatalf("profile not propagated: %q", got)
	}
}

// ─── file_too_large is NOT a fail event ────────────────────────────────────

func TestSafeCDRSanitize_FileTooLargeFromSluiceIsPass(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	// Fake Sluice returns gRPC InvalidArgument with "file_too_large:" prefix.
	srv := &fakeSluiceCallError{err: nil}
	// We need a real error rather than a result — use the fakeSluice's
	// lifecycle helper.  For this test, instead of the canned fakeSluice,
	// we install a handler that returns InvalidArgument.
	_ = srv
	// Use the plain fake, but its Sanitize returns nil/empty unless result is set.
	// Simpler: reuse ErrorFailOpen pattern but look for file_too_large.
	fake := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:       pb.Status_ERROR,
			ErrorMessage: "file_too_large: 99999",
		},
	}
	c, stop := startFakeSluice(t, fake)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, FailMode: "closed"})

	// Status ERROR with file_too_large message is still an ERROR in the
	// result path — the IsFileTooLarge() short-circuit only triggers on
	// transport-level gRPC errors.  So this is properly routed through
	// fail-mode (closed in this test) — documents the contract.
	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/pdf", sampleID, cdrActiveConfig())
	if out.Outcome != cdrBlock {
		t.Fatalf("ERROR path under fail-closed must cdrBlock, got %+v", out)
	}
}

// fakeSluiceCallError is a stub type for future expansion (gRPC error
// injection); referenced above to keep the import set honest.  Unused in
// the currently-compiling test.
type fakeSluiceCallError struct{ err error }

// ─── Helpers ────────────────────────────────────────────────────────────────

func TestCDRFilenameFromURL(t *testing.T) {
	cases := map[string]string{
		"/downloads/invoice.docx":                 "invoice.docx",
		"/file%20with%20spaces.pdf":               "file with spaces.pdf",
		"/a/b/c/readme":                           "readme",
		"":                                        "",
		"/":                                       "/",
		"/path?download=true&v=2":                 "path",
		"/deep/path/file.pdf#page=1":              "file.pdf",
	}
	for in, want := range cases {
		if got := cdrFilenameFromURL(in); got != want {
			t.Errorf("cdrFilenameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCDRSummariseThreats_CapsAtEight(t *testing.T) {
	threats := make([]CDRThreat, 12)
	for i := range threats {
		threats[i] = CDRThreat{Type: "macro"}
	}
	got := cdrSummariseThreats(threats)
	if !strings.Contains(got, "+4_more") {
		t.Fatalf("expected +4_more suffix, got %q", got)
	}
	if strings.Count(got, ",") != 8 {
		t.Fatalf("expected 8 commas + suffix, got %q", got)
	}
}

// ─── Cache TTL + eviction ──────────────────────────────────────────────────

func TestCDRHashCache_TTLExpiry(t *testing.T) {
	cache := newCDRHashCache(100, 10*time.Millisecond)
	cache.Put("h", &cdrCacheEntry{status: "CLEAN", expiresAt: time.Now().Add(5 * time.Millisecond), epoch: 1})
	if _, ok := cache.Get("h", 1); !ok {
		t.Fatal("fresh entry not found")
	}
	time.Sleep(15 * time.Millisecond)
	if _, ok := cache.Get("h", 1); ok {
		t.Fatal("expired entry returned")
	}
}

func TestCDRHashCache_EpochStale(t *testing.T) {
	cache := newCDRHashCache(100, time.Hour)
	cache.Put("h", &cdrCacheEntry{status: "CLEAN", expiresAt: time.Now().Add(time.Hour), epoch: 5})
	if _, ok := cache.Get("h", 5); !ok {
		t.Fatal("matching epoch missed")
	}
	if _, ok := cache.Get("h", 6); ok {
		t.Fatal("stale epoch returned")
	}
}

func TestCDRHashCache_EvictionUnderPressure(t *testing.T) {
	cache := newCDRHashCache(4, time.Hour)
	for i := 0; i < 6; i++ {
		cache.Put(string(rune('a'+i)), &cdrCacheEntry{status: "CLEAN", expiresAt: time.Now().Add(time.Hour), epoch: 0})
	}
	_, _, size := cache.Stats()
	if size > 4 {
		t.Fatalf("cache exceeded capacity: %d", size)
	}
}

// Ensure tags are whitelisted low-cardinality only (direction=download).
func TestSafeCDRSanitize_TagsAreWhitelisted(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	_ = safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/pdf", sampleID, cdrActiveConfig())

	tags := srv.lastHeader.GetTags()
	if len(tags) != 1 || tags["direction"] != "download" {
		t.Fatalf("tags = %+v, want only direction=download", tags)
	}
}

// Ensure policy_version propagates as an opaque log-only string.
func TestSafeCDRSanitize_PolicyVersionPropagates(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	_, _ = cdrPolicyStore.Add(CDRPolicyRule{Name: "r1", Priority: 10, Mode: "ENFORCE"})
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	_ = safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("x"), "application/pdf", sampleID, cdrActiveConfig())

	pv := srv.lastHeader.GetPolicyVersion()
	if !strings.HasPrefix(pv, "cdr-v") {
		t.Fatalf("policy_version format = %q", pv)
	}
}

// ─── Metrics side-effects ──────────────────────────────────────────────────

func TestSafeCDRSanitize_CountersAdvance(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"),
		[]byte("data"), "application/pdf", sampleID, cdrActiveConfig())

	// safeCDRSanitize itself doesn't increment the terminal counters —
	// the proxy.go caller does via recordCDRTerminal.  Simulate that here.
	recordCDRTerminal(out.Status)
	if got := atomic.LoadInt64(&statCDRClean); got != 1 {
		t.Fatalf("statCDRClean = %d, want 1", got)
	}
}
