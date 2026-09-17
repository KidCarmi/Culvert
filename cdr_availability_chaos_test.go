package main

// CHAOS-66 — the CDR plane when the Sluice backend goes away.
//
// Three defects, each reproduced against the pre-fix tree:
//
//   D1  Pick() RESERVES a half-open probe slot that only a reported call
//       outcome gives back, and 8 of its 9 call sites never report one.
//       On a single-instance pool the reservation leaked on the FIRST
//       request after the reset timeout, wedging the breaker in half-open
//       permanently: CDR never ran again until a process restart.
//   D2  A pool that can serve nothing passed the file through regardless
//       of `fail_mode: closed`, with no counter, no log and no alert.
//   D3  The `cdr_unavailable` alert was ungated and carried a raw
//       err.Error() as its Dispatch dedup key.
//
// The CONTROLS matter as much as the gates: the cheapest way to pass every
// defect gate is to delete the half-open budget outright (a thundering
// herd onto a recovering Sluice) or to make PeekAvailable always true (a
// status surface that never reports an outage).

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// openBreakerPastReset builds a pooled instance whose breaker has opened
// and whose reset timeout has already elapsed — i.e. the exact moment the
// breaker is willing to issue one recovery probe.
func openBreakerPastReset(t *testing.T, name string) (*cdrPooledClient, func(time.Duration)) {
	t.Helper()
	pc := &cdrPooledClient{
		Name:    name,
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 10 * time.Second}),
	}
	current := time.Unix(0, 0)
	pc.Breaker.setNowFn(func() time.Time { return current })
	pc.Breaker.OnFailure()
	advance := func(d time.Duration) { current = current.Add(d) }
	advance(11 * time.Second)
	return pc, advance
}

// ─── D1: the leaked half-open reservation ──────────────────────────────────

func TestChaos66_ObserverDoesNotConsumeHalfOpenProbe(t *testing.T) {
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)

	// Eight admin/status reads — each one called Pick() before the fix.
	for i := 0; i < 8; i++ {
		_ = cdrActiveClient()
		_ = cdrBackendAvailable()
	}
	if got := pc.Breaker.halfOpenTried.Load(); got != 0 {
		t.Fatalf("observer reads consumed %d probe slot(s); want 0 — "+
			"an observation must never change the control it observes", got)
	}
	// The request path must still be able to take its probe.
	picked, release := cdrPickForCall()
	defer release()
	if picked == nil {
		t.Fatal("request path denied its recovery probe after status reads — breaker wedged")
	}
}

func TestChaos66_BreakerRecoversAfterTheRequestPathDeclinesToCall(t *testing.T) {
	// The pre-fix request path picked twice per request (runCDRStage's
	// nil-check, then safeCDRSanitize) and threw the first away.
	pc, advance := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)

	_ = cdrActiveClient() // the nil-check, now non-reserving
	picked, release := cdrPickForCall()
	if picked == nil {
		t.Fatal("real pick denied — the nil-check stole the probe")
	}
	// The call never reaches the wire (cache hit / oversize skip): release
	// runs from safeCDRSanitize's defer without any reported outcome.
	release()

	advance(time.Hour)
	again, release2 := cdrPickForCall()
	defer release2()
	if again == nil {
		t.Fatalf("breaker never issued another probe (state=%d halfOpenTried=%d) — "+
			"an unreported pick leaked its reservation permanently",
			pc.Breaker.State(), pc.Breaker.halfOpenTried.Load())
	}
}

func TestChaos66_ReleaseIsIdempotentAndNeverGoesNegative(t *testing.T) {
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)

	picked, release := cdrPickForCall()
	if picked == nil {
		t.Fatal("expected a probe to be permitted")
	}
	// A reported outcome already zeroed the counter; the deferred release
	// then runs anyway. Over-releasing would hand out more concurrent
	// probes than the configured budget.
	pc.Breaker.OnSuccess()
	release()
	release()
	pc.Breaker.ReleaseProbe()
	if got := pc.Breaker.halfOpenTried.Load(); got != 0 {
		t.Fatalf("halfOpenTried = %d after over-release; want 0 (never negative)", got)
	}
}

func TestChaos66_PermitsChangesNoBreakerState(t *testing.T) {
	pc, _ := openBreakerPastReset(t, "sluice-1")
	before := pc.Breaker.Stats()
	for i := 0; i < 50; i++ {
		_ = pc.Breaker.Permits()
	}
	after := pc.Breaker.Stats()
	if after.State != before.State {
		t.Fatalf("Permits advanced the state machine: %s -> %s", before.State, after.State)
	}
	if after.TotalTrips != before.TotalTrips {
		t.Fatalf("Permits charged totalTrips %d -> %d — status reads must not "+
			"inflate culvert_cdr_pool_breaker_trips_total", before.TotalTrips, after.TotalTrips)
	}
	if got := pc.Breaker.halfOpenTried.Load(); got != 0 {
		t.Fatalf("Permits reserved %d probe slot(s); want 0", got)
	}
}

func TestChaos66_ReleaseOnlyGivesBackASlotThisCallTook(t *testing.T) {
	// A pick admitted in the CLOSED state reserves nothing.  Releasing on
	// its behalf would decrement a slot another goroutine is holding,
	// handing out more concurrent probes than the budget allows -- the
	// inverse of the defect the budget exists to prevent.
	pc := &cdrPooledClient{
		Name:    "sluice-1",
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 10 * time.Second}),
	}
	current := time.Unix(0, 0)
	pc.Breaker.setNowFn(func() time.Time { return current })
	withTempPool(t, pc)

	// Picked while CLOSED: no reservation taken.
	_, releaseClosed := cdrPickForCall()

	// The breaker now opens and reaches half-open; a concurrent request
	// takes the one real slot.
	pc.Breaker.OnFailure()
	current = current.Add(11 * time.Second)
	holder, holderRelease := cdrPickForCall()
	if holder == nil {
		t.Fatal("setup: expected the half-open probe to be granted")
	}

	// The closed-state pick's deferred release must NOT free the holder's slot.
	releaseClosed()
	if extra, _ := cdrPickForCall(); extra != nil {
		t.Fatal("a release from a pick that reserved nothing freed another " +
			"goroutine's probe slot — the budget was over-released")
	}
	holderRelease()
}

func TestChaos66_ReleaseDoesNotCrossAnOpenGeneration(t *testing.T) {
	// A release that arrives after the breaker has completed a further
	// open cycle belongs to a generation that no longer owns the counter.
	pc := &cdrPooledClient{
		Name:    "sluice-1",
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 10 * time.Second}),
	}
	current := time.Unix(0, 0)
	pc.Breaker.setNowFn(func() time.Time { return current })
	pc.Breaker.OnFailure()
	current = current.Add(11 * time.Second)
	withTempPool(t, pc)

	_, staleRelease := cdrPickForCall() // generation N
	pc.Breaker.OnSuccess()              // closes
	pc.Breaker.OnFailure()              // generation N+1: open
	current = current.Add(11 * time.Second)
	holder, holderRelease := cdrPickForCall() // takes N+1's slot
	if holder == nil {
		t.Fatal("setup: expected a probe in the new generation")
	}

	staleRelease() // must be inert
	if extra, _ := cdrPickForCall(); extra != nil {
		t.Fatal("a stale release freed a newer generation's probe slot")
	}
	holderRelease()
}

// ─── D2: an unavailable backend must obey fail_mode ────────────────────────

func TestChaos66_AllInstancesUnavailableAppliesFailModeClosed(t *testing.T) {
	resetCDRAvailabilityForTest()
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)
	// Burn the probe so nothing is pickable — a sustained outage.
	if picked, _ := cdrPickForCall(); picked == nil {
		t.Fatal("setup: expected one probe")
	}

	res := cdrUnavailableOutcome(CDRConfig{Enabled: true, FailMode: "closed"})
	if res.Outcome != cdrBlock {
		t.Fatalf("fail_mode=closed with every instance down produced outcome=%d (%s); "+
			"want cdrBlock — the operator explicitly asked for fail-closed and the "+
			"breaker tripping is exactly the condition that setting governs",
			res.Outcome, res.Status)
	}
}

func TestChaos66_AllInstancesUnavailableAppliesFailModeOpen(t *testing.T) {
	resetCDRAvailabilityForTest()
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)
	if p, _ := cdrPickForCall(); p == nil {
		t.Fatal("setup: expected one probe")
	}

	res := cdrUnavailableOutcome(CDRConfig{Enabled: true, FailMode: "open"})
	if res.Outcome != cdrPass {
		t.Fatalf("fail_mode=open produced outcome=%d; want cdrPass", res.Outcome)
	}
	if res.Status != "ERROR" {
		t.Fatalf("status = %q; want ERROR so the bypass is visible in the request log", res.Status)
	}
}

func TestChaos66_UnavailableBypassIsCounted(t *testing.T) {
	resetCDRAvailabilityForTest()
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)
	if p, _ := cdrPickForCall(); p == nil {
		t.Fatal("setup: expected one probe")
	}

	before := loadCDRStat(&statCDRUnavailable)
	_ = cdrUnavailableOutcome(CDRConfig{Enabled: true, FailMode: "open"})
	if got := loadCDRStat(&statCDRUnavailable); got != before+1 {
		t.Fatalf("culvert_cdr_unavailable_total did not move (%d -> %d); the bypass "+
			"was silent on every surface before CHAOS-66", before, got)
	}
}

func TestChaos66_EmptyPoolIsNotDeployedRatherThanAnOutage(t *testing.T) {
	resetCDRAvailabilityForTest()
	withTempPool(t) // nothing enrolled

	// fail_mode=closed must NOT block here: CDR was never deployed on this
	// node, and blocking every download over a provisioning gap would be a
	// self-inflicted outage. The `cdr` diagnostics row already FAILs on it.
	res := cdrUnavailableOutcome(CDRConfig{Enabled: true, FailMode: "closed"})
	if res.Outcome != cdrPass {
		t.Fatalf("empty pool produced outcome=%d; want cdrPass", res.Outcome)
	}
	if res.Status != "SKIPPED_NOT_DEPLOYED" {
		t.Fatalf("status = %q; want SKIPPED_NOT_DEPLOYED — a provisioning gap and a "+
			"backend outage need different operator actions", res.Status)
	}
	if loadCDRStat(&statCDRNotDeployed) == 0 {
		t.Fatal("culvert_cdr_not_deployed_total did not move")
	}
	if loadCDRStat(&statCDRUnavailable) != 0 {
		t.Fatal("an undeployed CDR was charged as a backend outage")
	}
}

// ─── D3: the alert's gate and its bounded dedup key ────────────────────────

func TestChaos66_ErrorReasonClassIsBoundedAndNeverEchoesTheError(t *testing.T) {
	allowed := map[string]bool{
		"none": true, "file_too_large": true, "timeout": true, "unavailable": true,
		"resource_exhausted": true, "unauthenticated": true, "permission_denied": true,
		"unimplemented": true, "backend_internal": true, "tls_error": true,
		"call_failed": true,
	}
	// A transport error embeds the peer address AND the ephemeral local
	// port — the value that made every failure a distinct Dispatch dedup key.
	noisy := errors.New(`rpc error: code = Unavailable desc = connection error: ` +
		`dial tcp 10.0.0.7:8443->10.0.0.9:51234: connect: connection refused`)
	cases := []error{
		nil,
		noisy,
		status.Error(codes.DeadlineExceeded, "deadline"),
		status.Error(codes.ResourceExhausted, "queue full"),
		status.Error(codes.Internal, "boom"),
		errors.New("x509: certificate has expired"),
		errors.New("something nobody classified"),
	}
	for _, err := range cases {
		got := cdrErrorReasonClass(err)
		if !allowed[got] {
			t.Fatalf("cdrErrorReasonClass(%v) = %q — outside the bounded vocabulary; "+
				"an unbounded class gives Dispatch one dedup key per request", err, got)
		}
	}
	if got := cdrErrorReasonClass(noisy); strings.Contains(got, "51234") ||
		strings.Contains(got, "10.0.0.") {
		t.Fatalf("reason class %q leaked the transport error's addresses/ports", got)
	}
}

func TestChaos66_CallFailureLogIsRateLimited(t *testing.T) {
	resetCDRAvailabilityForTest()
	now := time.Unix(0, 0)
	if !noteCDRCallFailure("unavailable", now) {
		t.Fatal("onset must log immediately")
	}
	logged := 0
	for i := 0; i < 500; i++ {
		now = now.Add(time.Second)
		if noteCDRCallFailure("unavailable", now) {
			logged++
		}
	}
	// 500s at one line per minute.
	if logged > 9 {
		t.Fatalf("%d lines in 500s; want <= 9 — a mitigation for write "+
			"amplification must not be one itself", logged)
	}
	if logged == 0 {
		t.Fatal("rate limit suppressed everything — the outage must stay visible")
	}
	// A change of reason class is news and logs immediately.
	if !noteCDRCallFailure("timeout", now) {
		t.Fatal("a new reason class must log immediately")
	}
}

func TestChaos66_AlertIsGatedOnSubscriber(t *testing.T) {
	// No webhook subscribes to cdr_unavailable — the default posture. The
	// producer must not spawn a goroutine or build a payload.
	prev := globalAlertStore
	globalAlertStore = &AlertStore{}
	t.Cleanup(func() { globalAlertStore = prev })

	if globalAlertStore.HasSubscriber("cdr_unavailable") {
		t.Skip("unexpected subscriber in a fresh store")
	}
	// The gate is about COST, so cost is what the gate asserts: ungated,
	// this producer pays a goroutine spawn, a payload build and a round
	// trip through the process-wide dedup mutex on every file during an
	// outage. Allocation-free is the observable that distinguishes the two
	// shapes deterministically, on any hardware, under any load.
	avg := testing.AllocsPerRun(200, func() {
		fireCDRUnavailableAlert("unavailable")
	})
	if avg != 0 {
		t.Fatalf("fireCDRUnavailableAlert allocated %.1f objects/call with no "+
			"subscriber; want 0 — the HasSubscriber gate must short-circuit "+
			"BEFORE the goroutine spawn and payload build", avg)
	}
}

// ─── Contract row ──────────────────────────────────────────────────────────

func TestChaos66_DiagnosticsRowReportsADarkBackend(t *testing.T) {
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc) // enrolled, but nothing pickable
	if p, _ := cdrPickForCall(); p == nil {
		t.Fatal("setup: expected one probe")
	}

	prevCfg := cdrActiveConfig()
	setCDRConfigForTest(t, CDRConfig{Enabled: true, FailMode: "closed", DefaultProfile: "default"})
	t.Cleanup(func() { setCDRConfigForTest(t, prevCfg) })

	row := checkCDR()
	if row.Status == diagOK {
		t.Fatalf("cdr row = OK (%q) while no instance can serve a request — "+
			"the row keyed on pool LENGTH, so a dark backend read as enabled-healthy",
			row.Message)
	}
	if !strings.Contains(row.Message, "enabled-dark") {
		t.Fatalf("row message = %q; want the enabled-dark classification", row.Message)
	}
}

// ─── CONTROLS ──────────────────────────────────────────────────────────────

func TestChaos66_Control_HealthyBackendIsUntouched(t *testing.T) {
	pc := &cdrPooledClient{Name: "sluice-1", Breaker: newCDRCircuitBreaker(cdrBreakerConfig{})}
	withTempPool(t, pc)

	for i := 0; i < 100; i++ {
		picked, release := cdrPickForCall()
		if picked == nil {
			t.Fatalf("closed breaker denied request %d", i)
		}
		release()
	}
	if !cdrBackendAvailable() {
		t.Fatal("a healthy pool reported unavailable")
	}
	if checkCDRStatusFor(t, CDRConfig{Enabled: true, FailMode: "closed", DefaultProfile: "default"}) != diagOK {
		t.Fatal("a healthy CDR did not report OK")
	}
}

func TestChaos66_Control_ObserverStillReportsAnOpenBreaker(t *testing.T) {
	// The cheapest way to pass the observer gates is to make PeekAvailable
	// always true, which would delete the outage signal entirely.
	pc := &cdrPooledClient{
		Name:    "sluice-1",
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Hour}),
	}
	current := time.Unix(0, 0)
	pc.Breaker.setNowFn(func() time.Time { return current })
	pc.Breaker.OnFailure() // open, reset timeout NOT elapsed
	withTempPool(t, pc)

	if cdrBackendAvailable() {
		t.Fatal("an open breaker inside its reset window reported available")
	}
	if cdrActiveClient() != nil {
		t.Fatal("cdrActiveClient returned a client from an open breaker")
	}
}

func TestChaos66_Control_HalfOpenBudgetStillBoundsConcurrentProbes(t *testing.T) {
	// The cheapest way to pass every leak gate is to delete the budget,
	// which would aim the full request rate at a recovering Sluice.
	pc, _ := openBreakerPastReset(t, "sluice-1")
	withTempPool(t, pc)

	granted := 0
	releases := []func(){}
	for i := 0; i < 20; i++ {
		picked, release := cdrPickForCall()
		if picked != nil {
			granted++
			releases = append(releases, release) // held, as an in-flight call would
		}
	}
	for _, r := range releases {
		r()
	}
	if granted != 1 {
		t.Fatalf("half-open granted %d concurrent probes; want exactly 1 (HalfOpenProbes default) — "+
			"the budget must still bound the herd onto a recovering backend", granted)
	}
}

// ─── Local test helpers ────────────────────────────────────────────────────

func loadCDRStat(p *int64) int64 { return atomic.LoadInt64(p) }

func setCDRConfigForTest(t *testing.T, cfg CDRConfig) {
	t.Helper()
	cdrClientMu.Lock()
	cdrActiveCfg = cfg
	cdrClientMu.Unlock()
}

func checkCDRStatusFor(t *testing.T, cfg CDRConfig) string {
	t.Helper()
	prev := cdrActiveConfig()
	setCDRConfigForTest(t, cfg)
	t.Cleanup(func() { setCDRConfigForTest(t, prev) })
	return checkCDR().Status
}
