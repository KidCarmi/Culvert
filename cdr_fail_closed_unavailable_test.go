package main

// cdr_fail_closed_unavailable_test.go — the CDR unavailable fail-mode gate.
//
// THE REGRESSION PINNED HERE. cdr.fail_mode: closed is the operator's
// instruction that a document CDR could not scan must not reach the endpoint.
// cdrErrorOutcome has always honoured it for a Sluice that ANSWERS with an
// error, but the "no instance available" path — every instance's breaker open,
// or none enrolled — returned an unconditional cdrPassSkipped("SKIPPED"), which
// runCDRStage forwards. So the one situation the setting exists for, Sluice
// unreachable rather than one bad RPC, was exactly the situation that fell
// open: with the default breaker threshold (5 consecutive failures, 30 s open)
// anything able to make Sluice fail that often opened a window in which every
// document was forwarded unsanitized, while /api/cdr/* still reported CDR
// enabled and fail-closed.
//
// Both halves are asserted here: the fail-CLOSED deployment now refuses, and
// the fail-OPEN deployment (the default) is byte-for-byte unchanged — including
// that a DISABLED CDR never blocks, whatever fail_mode says, since an empty
// pool is also what "off" looks like from the picker.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// withActiveCDRConfig publishes cfg as the active CDR config for one test.
func withActiveCDRConfig(t *testing.T, cfg CDRConfig) {
	t.Helper()
	cdrClientMu.Lock()
	prev := cdrActiveCfg
	cdrActiveCfg = cfg
	cdrClientMu.Unlock()
	t.Cleanup(func() {
		cdrClientMu.Lock()
		cdrActiveCfg = prev
		cdrClientMu.Unlock()
	})
}

// openBreakerPool installs a single-instance pool whose breaker is already
// open and stays open (ResetTimeout far beyond the test), so every Reserve is
// denied and the picker returns nil — the production "Sluice is down" shape.
func openBreakerPool(t *testing.T) *cdrPooledClient {
	t.Helper()
	pc, stop := newPooledFake(t, "all_open", &fakeSluice{})
	t.Cleanup(stop)
	pc.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Hour})
	pc.Breaker.OnFailure(cdrReserveForTest(pc.Breaker))
	if pc.Breaker.State() != cbStateOpen {
		t.Fatalf("breaker state = %s, want open", breakerStateName(pc.Breaker.State()))
	}
	withTempPool(t, pc)
	return pc
}

// ─── The outcome helper: every fail_mode spelling, both enablement states ───

func TestCDRUnavailableOutcome_AppliesFailMode(t *testing.T) {
	cases := []struct {
		name      string
		cfg       CDRConfig
		wantBlock bool
	}{
		// Fail-closed: the whole point of the fix.
		{"ExplicitClosed", CDRConfig{Enabled: true, FailMode: "closed"}, true},
		// Boundary: CDRFailOpen folds case and trims space, so these are the
		// SAME instruction and must not silently fall open.
		{"ClosedUppercase", CDRConfig{Enabled: true, FailMode: "CLOSED"}, true},
		{"ClosedMixedCase", CDRConfig{Enabled: true, FailMode: "Closed"}, true},
		{"ClosedPadded", CDRConfig{Enabled: true, FailMode: "  closed  "}, true},

		// Fail-open: unchanged, including the unset default.
		{"Unset", CDRConfig{Enabled: true}, false},
		{"ExplicitOpen", CDRConfig{Enabled: true, FailMode: "open"}, false},

		// NEGATIVE CONTROL. A disabled CDR must never refuse traffic: an empty
		// pool is also what "off" looks like, and fail_mode says nothing about
		// a feature that is not running. Blocking here would deny every
		// inspected document on a deployment that never asked for CDR.
		{"DisabledWithClosedFailMode", CDRConfig{Enabled: false, FailMode: "closed"}, false},
		{"DisabledWithOpenFailMode", CDRConfig{Enabled: false, FailMode: "open"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCDRCountersAndCache(t)
			before := atomic.LoadInt64(&statCDRFailClosed)
			got := cdrUnavailableOutcome(tc.cfg)
			delta := atomic.LoadInt64(&statCDRFailClosed) - before

			if tc.wantBlock {
				if got.Outcome != cdrBlock {
					t.Fatalf("outcome = %v (status %q), want cdrBlock", got.Outcome, got.Status)
				}
				if got.Status != "BLOCKED" {
					t.Errorf("status = %q, want BLOCKED", got.Status)
				}
				if got.BlockReason != cdrUnavailableBlockReason {
					t.Errorf("reason = %q, want %q", got.BlockReason, cdrUnavailableBlockReason)
				}
				if delta != 1 {
					t.Errorf("statCDRFailClosed delta = %d, want 1", delta)
				}
				return
			}
			if got.Outcome != cdrPass || got.Status != "SKIPPED" {
				t.Fatalf("outcome = %v status = %q, want cdrPass/SKIPPED", got.Outcome, got.Status)
			}
			// The fail-open path touched no counter before the fix and must
			// still touch none: the metric means "a document was refused".
			if delta != 0 {
				t.Errorf("statCDRFailClosed delta = %d on a fail-open pass, want 0", delta)
			}
		})
	}
}

// ─── safeCDRSanitize: the RPC path's own pick ──────────────────────────────

func TestSafeCDRSanitize_AllBreakersOpenFailClosedBlocks(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	openBreakerPool(t)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "closed"})

	out := safeCDRSanitize(t.Context(), sampleReq("example.com"), []byte("payload.docx"),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		sampleID, cdrActiveConfig())

	if out.Outcome != cdrBlock {
		t.Fatalf("fail-closed with every breaker open must BLOCK, got %+v", out)
	}
	if out.BlockReason != cdrUnavailableBlockReason {
		t.Errorf("reason = %q, want %q", out.BlockReason, cdrUnavailableBlockReason)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 1 {
		t.Errorf("statCDRFailClosed = %d, want 1", n)
	}
}

// Negative control for the above: the default fail-OPEN deployment keeps the
// documented SKIPPED pass (this is TestSafeCDRSanitize_BreakerOpenReturnsSkipped's
// contract, restated here so the pair cannot drift apart).
func TestSafeCDRSanitize_AllBreakersOpenFailOpenStillSkips(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	openBreakerPool(t)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "open"})

	out := safeCDRSanitize(t.Context(), sampleReq("example.com"), []byte("payload.docx"),
		"application/pdf", sampleID, cdrActiveConfig())

	if out.Outcome != cdrPass || out.Status != "SKIPPED" {
		t.Fatalf("fail-open with every breaker open must SKIP, got %+v", out)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 0 {
		t.Errorf("statCDRFailClosed = %d on the fail-open path, want 0", n)
	}
}

// POSITIVE control: the fix must not refuse a document CDR CAN scan. A healthy
// instance under fail_mode: closed still returns the engine's verdict.
func TestSafeCDRSanitize_FailClosedWithHealthyInstanceStillScans(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	pc, stop := newPooledFake(t, "healthy", &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}})
	defer stop()
	withTempPool(t, pc)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "closed"})

	out := safeCDRSanitize(t.Context(), sampleReq("example.com"), []byte("clean.pdf"),
		"application/pdf", sampleID, cdrActiveConfig())

	if out.Outcome != cdrPass || out.Status != "CLEAN" {
		t.Fatalf("healthy instance under fail-closed must return the verdict, got %+v", out)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 0 {
		t.Errorf("statCDRFailClosed = %d, want 0 — nothing was refused", n)
	}
}

// ─── runCDRStage: the proxy-side liveness gate ─────────────────────────────

// stageResponder records the block emission runCDRStage writes onto the tunnel.
type stageResponder struct {
	mu    sync.Mutex
	calls int
	ct    string
	body  string
}

func (s *stageResponder) blockBeforeResponse(contentType, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.ct, s.body = contentType, body
}

func (s *stageResponder) snapshot() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.body
}

func runStageForTest(t *testing.T, br blockResponder, body []byte) cdrStageDecision {
	t.Helper()
	r := httptest.NewRequest(http.MethodConnect, "https://files.example.com:443", nil)
	req := httptest.NewRequest(http.MethodGet, "https://files.example.com/downloads/invoice.docx", nil)
	return runCDRStage(r, req, body, body, "application/pdf", "", br,
		"files.example.com", sampleID.ClientIP, sampleID)
}

// The gate is the path a real proxied response takes: it runs BEFORE
// safeCDRSanitize and used to return an unconditional pass of its own, so
// fixing only the picker inside safeCDRSanitize would have left the hot path
// forwarding the document anyway.
func TestRunCDRStage_UnavailableFailClosedRefusesTheTunnel(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	openBreakerPool(t)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "closed"})

	br := &stageResponder{}
	dec := runStageForTest(t, br, []byte("payload.docx"))

	if !dec.blocked {
		t.Fatalf("fail-closed with CDR unavailable must block the tunnel, got %+v", dec)
	}
	if dec.body != nil || dec.scanBody != nil {
		t.Errorf("a blocked decision must carry no body, got body=%d scanBody=%d", len(dec.body), len(dec.scanBody))
	}
	calls, page := br.snapshot()
	if calls != 1 {
		t.Fatalf("blockBeforeResponse calls = %d, want 1", calls)
	}
	if page == "" {
		t.Error("block page body is empty")
	}
	if n := atomic.LoadInt64(&statCDRBlocked); n != 1 {
		t.Errorf("statCDRBlocked = %d, want 1 — the refusal must be visible as a CDR block", n)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 1 {
		t.Errorf("statCDRFailClosed = %d, want 1", n)
	}
}

// Negative control: the default deployment is untouched — no block, no block
// page, the original bytes forwarded, and none of the counters moved.
func TestRunCDRStage_UnavailableFailOpenForwardsUnchanged(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	openBreakerPool(t)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "open"})

	br := &stageResponder{}
	body := []byte("payload.docx")
	dec := runStageForTest(t, br, body)

	if dec.blocked {
		t.Fatal("fail-open must not block when CDR is unavailable")
	}
	if !bytes.Equal(dec.body, body) || !bytes.Equal(dec.scanBody, body) {
		t.Errorf("body = %q / scanBody = %q, want the original %q passed through", dec.body, dec.scanBody, body)
	}
	if calls, _ := br.snapshot(); calls != 0 {
		t.Errorf("blockBeforeResponse calls = %d, want 0", calls)
	}
	if n := atomic.LoadInt64(&statCDRBlocked); n != 0 {
		t.Errorf("statCDRBlocked = %d, want 0", n)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 0 {
		t.Errorf("statCDRFailClosed = %d, want 0", n)
	}
}

// A DISABLED CDR must not block even with fail_mode: closed left in the config
// — the empty pool is indistinguishable from "off" at the picker.
func TestRunCDRStage_DisabledCDRNeverBlocks(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	withTempPool(t) // no instances enrolled at all
	withActiveCDRConfig(t, CDRConfig{Enabled: false, FailMode: "closed"})

	br := &stageResponder{}
	body := []byte("payload.docx")
	dec := runStageForTest(t, br, body)

	if dec.blocked {
		t.Fatal("a disabled CDR must never refuse a document")
	}
	if !bytes.Equal(dec.body, body) {
		t.Errorf("body = %q, want the original %q", dec.body, body)
	}
	if calls, _ := br.snapshot(); calls != 0 {
		t.Errorf("blockBeforeResponse calls = %d, want 0", calls)
	}
}

// ─── Concurrency ───────────────────────────────────────────────────────────

// Every concurrent request must reach the same refusal, and the refusal path
// must not disturb the breaker: it takes no reservation (the picker denied it),
// so the instance stays open and no half-open probe is consumed or stranded.
// Run under -race.
func TestCDRUnavailable_FailClosedIsRaceFreeAndLeavesTheBreakerAlone(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	pc := openBreakerPool(t)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "closed"})
	beforeStats := pc.Breaker.Stats()

	const workers = 24
	var wg sync.WaitGroup
	blocked := make([]bool, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out := safeCDRSanitize(t.Context(), sampleReq("example.com"), []byte("payload.docx"),
				"application/pdf", sampleID, cdrActiveConfig())
			blocked[i] = out.Outcome == cdrBlock && out.BlockReason == cdrUnavailableBlockReason
		}(i)
	}
	wg.Wait()

	for i, ok := range blocked {
		if !ok {
			t.Fatalf("worker %d was not refused — a fail-closed bypass under concurrency", i)
		}
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != workers {
		t.Errorf("statCDRFailClosed = %d, want %d (one per refused document)", n, workers)
	}
	if got := pc.Breaker.State(); got != cbStateOpen {
		t.Errorf("breaker state = %s, want open — the refusal must not transition it", breakerStateName(got))
	}
	after := pc.Breaker.Stats()
	if after.StaleProbes != beforeStats.StaleProbes {
		t.Errorf("staleProbes %d -> %d: the refusal path stranded a reservation",
			beforeStats.StaleProbes, after.StaleProbes)
	}
}

// ─── Cold start: the configured posture must survive a failed pool init ────

// TestCDRUnavailable_FailClosedSurvivesPoolInitFailure is the Codex #1668 P1.
//
// initCDRClient returned its "every instance failed to dial / none enrolled"
// error BEFORE publishing the config it was asked to apply, so cdrActiveCfg
// stayed at its zero value — Enabled false. An appliance configured enabled +
// fail_mode: closed that boots while Sluice is unreachable therefore read
// ITSELF as disabled: cdrUnavailableFailsClosed saw Enabled false, the
// unavailable path returned SKIPPED, and every inspected document was
// forwarded unsanitized — the exact state this whole change exists to refuse,
// reached by the most ordinary route to it. initCDRInfrastructure logs the
// init error and carries on by design (cdr_startup.go), so nothing else
// stopped it.
//
// The scenario is the one TestInitCDRClient_NoInstanceNoEndpointFails already
// builds: enabled, empty registry, no endpoint ⇒ error with an empty pool.
func TestCDRUnavailable_FailClosedSurvivesPoolInitFailure(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	resetCDRClient(t)
	withActiveCDRConfig(t, CDRConfig{}) // the zero value a cold boot starts from

	origInstances := cdrInstances
	cdrInstances = &CDRInstanceRegistry{}
	t.Cleanup(func() { cdrInstances = origInstances })
	withTempPool(t)

	want := CDRConfig{Enabled: true, FailMode: "closed"}
	if err := initCDRClient(want); err == nil {
		t.Fatal("initCDRClient must fail with no enrolled instance and no endpoint")
	}

	// The error is expected. What must NOT happen is losing the posture.
	got := cdrActiveConfig()
	if !got.Enabled {
		t.Error("cdrActiveConfig().Enabled = false after a failed init — the appliance reads itself as disabled")
	}
	if got.FailMode != "closed" {
		t.Errorf("cdrActiveConfig().FailMode = %q, want \"closed\"", got.FailMode)
	}
	if !cdrUnavailableFailsClosed(got) {
		t.Fatal("a failed pool init must not downgrade a fail-closed appliance to fail-open")
	}

	// And the decision that depends on it must refuse, through the real path.
	br := &stageResponder{}
	dec := runStageForTest(t, br, []byte("payload.docx"))
	if !dec.blocked {
		t.Fatalf("fail-closed with a failed pool init must block, got %+v", dec)
	}
	if calls, _ := br.snapshot(); calls != 1 {
		t.Errorf("blockBeforeResponse calls = %d, want 1", calls)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 1 {
		t.Errorf("statCDRFailClosed = %d, want 1", n)
	}
}

// Negative control for the above: a failed init under fail-OPEN still passes,
// so publishing the config on the failure path cannot turn the default
// deployment into a blocking one.
func TestCDRUnavailable_FailOpenSurvivesPoolInitFailureWithoutBlocking(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	resetCDRClient(t)
	withActiveCDRConfig(t, CDRConfig{})

	origInstances := cdrInstances
	cdrInstances = &CDRInstanceRegistry{}
	t.Cleanup(func() { cdrInstances = origInstances })
	withTempPool(t)

	if err := initCDRClient(CDRConfig{Enabled: true, FailMode: "open"}); err == nil {
		t.Fatal("initCDRClient must fail with no enrolled instance and no endpoint")
	}
	if got := cdrActiveConfig(); !got.Enabled || got.FailMode != "open" {
		t.Fatalf("cdrActiveConfig() = %+v, want enabled fail-open", got)
	}

	br := &stageResponder{}
	body := []byte("payload.docx")
	dec := runStageForTest(t, br, body)
	if dec.blocked {
		t.Fatal("fail-open must not block after a failed pool init")
	}
	if !bytes.Equal(dec.body, body) {
		t.Errorf("body = %q, want the original %q", dec.body, body)
	}
	if calls, _ := br.snapshot(); calls != 0 {
		t.Errorf("blockBeforeResponse calls = %d, want 0", calls)
	}
	if n := atomic.LoadInt64(&statCDRFailClosed); n != 0 {
		t.Errorf("statCDRFailClosed = %d, want 0", n)
	}
}
