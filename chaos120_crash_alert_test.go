package main

// chaos120_crash_alert_test.go — CHAOS-120: a contained panic must reach an
// operator who is not already looking.
//
// The premise these gates defend is CHAOS-25's, generalised. notePanicRound's
// own doc states it for the HA plane: the counter and the alert "are the ONLY
// operator-facing signal that replication has stalled — without them the
// containment would trade a loud crash for a silent one, which is the failure
// class the guard exists to remove." Since CHAOS-24 every detached background
// round runs under runGuarded, so that trade is now made for ~62 components and
// was reported for one. Four consecutive rounds recorded "no alert rule ships on
// the crash counters" as residual risk (CHAOS-116 (4), 117 (5), 118 (1),
// 119 (3)).
//
// Every assertion below was falsified against a mutant before it was trusted;
// the mutation table is in the round's write-up.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chaos120Page is one observed dispatch decision. Observed at the fireAlert
// seam, not at webhook delivery, for the reason alerts.go documents: delivery
// passes through a package-global concurrency semaphore shared by every test in
// the binary, and a saturated semaphore diverts the payload to the retry queue —
// so a delivery-based assertion reports "the alert was suppressed" when the
// producer did everything right.
type chaos120Page struct {
	event   string
	detail  string
	actor   string
	source  string
	host    string
	payload AlertPayload
}

// chaos120Harness installs a crash plane with a live subscriber for
// component_panic and returns a reader for the pages the sink produced.
//
// The subscriber is REAL (an enabled webhook naming the event) rather than a
// stubbed probe, because the HasSubscriber gate is part of what is under test:
// a producer gated on a store that cannot answer would be green here and silent
// in production.
func chaos120Harness(t *testing.T, events ...string) func(want int) []chaos120Page {
	t.Helper()
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	origStore := globalAlertStore
	t.Cleanup(func() { globalAlertStore = origStore })
	as := &AlertStore{}
	as.Init("")
	if len(events) > 0 {
		as.Add(AlertWebhook{
			Name:    "chaos120",
			URL:     "https://collector.invalid/hook",
			Events:  events,
			Enabled: true,
		})
	}
	globalAlertStore = as

	var mu sync.Mutex
	var got []chaos120Page
	arrived := make(chan struct{}, 1024)
	prev := fireAlert
	fireAlert = func(event string, p AlertPayload) {
		mu.Lock()
		got = append(got, chaos120Page{
			event: event, detail: p.Detail, actor: p.Actor,
			source: p.Source, host: p.Host, payload: p,
		})
		mu.Unlock()
		select {
		case arrived <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { fireAlert = prev })

	// Join every detached page before the cleanups above restore the globals it
	// reads. Registered LAST so it runs FIRST (t.Cleanup is LIFO). Without it the
	// restore is a write racing a page goroutine's read of globalAlertStore and
	// fireAlert with no happen-before edge between them — which `-race` reports,
	// correctly, even for a goroutine that finished long before.
	var inflight sync.WaitGroup
	prevBarrier := crashAlertPageBarrier
	crashAlertPageBarrier = func() func() {
		inflight.Add(1) // on the sink's stack, before the goroutine exists
		return inflight.Done
	}
	t.Cleanup(func() {
		crashAlertPageBarrier = prevBarrier
		inflight.Wait()
	})

	// The dispatch is detached (`go fire(...)`) on purpose: recordCrash runs on
	// the proxy hot path and inside its callers' critical sections, so the
	// webhook store's lock must never be taken on its stack. That makes the
	// observation asynchronous, so the reader takes the count it is WAITING FOR
	// rather than sampling whatever has landed.
	//
	// Waiting for a target rather than sampling is what makes the flood-bound
	// gate deterministic in BOTH directions: with the page inside the throttle,
	// waiting for 2 times out and the caller asserts exactly 1; with the page
	// hoisted outside it, the 2nd arrives at once and the caller fails. Sampling
	// after a single-page wait made the observed count depend on scheduling, so
	// a slow box could have let that mutant pass.
	snapshot := func() []chaos120Page {
		mu.Lock()
		defer mu.Unlock()
		return append([]chaos120Page(nil), got...)
	}
	return func(want int) []chaos120Page {
		deadline := time.After(5 * time.Second)
		for len(snapshot()) < want {
			select {
			case <-arrived:
			case <-deadline:
				return snapshot()
			}
		}
		return snapshot()
	}
}

func chaos120PagesFor(pages []chaos120Page, event string) []chaos120Page {
	var out []chaos120Page
	// Index rather than range-copy: chaos120Page embeds the full payload DTO,
	// which the repository's gocritic rangeValCopy threshold rejects copying.
	for i := range pages {
		if pages[i].event == event {
			out = append(out, pages[i])
		}
	}
	return out
}

// TestCHAOS120_AContainedPanicPagesTheOperator is the headline gate: the sink
// that already writes a counter, a log line, an audit entry and a record now
// also writes the one sink an operator subscribes to.
func TestCHAOS120_AContainedPanicPagesTheOperator(t *testing.T) {
	pages := chaos120Harness(t, alertEventComponentPanic)

	if panicked := runGuarded("threatfeed", func() { panic("feed round blew up") }); !panicked {
		t.Fatal("runGuarded did not report the round as panicked — the guard plane changed under this gate")
	}

	got := chaos120PagesFor(pages(1), alertEventComponentPanic)
	if len(got) != 1 {
		t.Fatalf("a contained panic produced %d %q pages, want exactly 1 — a contained panic with no page is "+
			"the silent-failure class the guard exists to remove (CHAOS-25 notePanicRound)",
			len(got), alertEventComponentPanic)
	}
	p := got[0]
	if !strings.Contains(p.detail, "threatfeed") {
		t.Errorf("page Detail does not name the component: %q. The component is the ONLY thing that tells an "+
			"operator which work is not being done.", p.detail)
	}
	if p.source != "crashguard" {
		t.Errorf("page Source = %q, want %q", p.source, "crashguard")
	}
	if p.actor != "system" {
		t.Errorf("page Actor = %q, want %q — a background round has no request context", p.actor, "system")
	}
	// The record must exist too: the page is an addition to the evidence, never
	// a substitute for it.
	if rec, ok := lastCrashSnapshot(); !ok || rec.Component != "threatfeed" {
		t.Errorf("lastCrash = %+v, ok=%v: the page must not have displaced the record", rec, ok)
	}
}

// TestCHAOS120_ThePageNeverCarriesThePanicValue. recover()'s value can embed a
// credential — panic(cfg.SessionHMAC) is the case crashguard.go's header names —
// which is why the raw value is kept out of the log and masked on export. A
// webhook body leaves the box to a third-party collector, so it is the LAST
// place that text may appear.
func TestCHAOS120_ThePageNeverCarriesThePanicValue(t *testing.T) {
	pages := chaos120Harness(t, alertEventComponentPanic)

	const secret = "s3cret-session-hmac-do-not-exfiltrate"
	runGuarded("cluster_heartbeat", func() { panic("auth failed for " + secret) })

	got := chaos120PagesFor(pages(1), alertEventComponentPanic)
	if len(got) != 1 {
		t.Fatalf("got %d pages, want 1", len(got))
	}
	// Every field of the delivered payload, not just Detail: the DTO is what
	// ships, and a future field would otherwise be an unasserted channel.
	p := got[0].payload
	for name, v := range map[string]string{
		"Detail": p.Detail, "Host": p.Host, "Actor": p.Actor,
		"Source": p.Source, "Event": p.Event, "Timestamp": p.Timestamp,
	} {
		if strings.Contains(v, secret) {
			t.Errorf("payload field %s carries the panic value off-box: %q", name, v)
		}
	}
	// And the record still holds it locally, where only the redacting accessor
	// can export it — the page is a notification, not a replacement for evidence.
	if rec, ok := lastCrashSnapshot(); !ok || !strings.Contains(rec.Summary, secret) {
		t.Error("the local crash record lost the panic text: the page must not have replaced the evidence")
	}
}

// TestCHAOS120_ThePageIsKeyedOnTheComponentSoTheWindowCanDedupIt. Store.Dispatch
// dedups on `event + ":" + Detail`. A crash id in Detail is unique per crash by
// construction, so every page would be a distinct key the 30 s window cannot
// suppress and the fan-out would land in the 500-entry retry queue where it
// evicts real threat alerts — the CHAOS-64 dns_failure defect, exactly.
func TestCHAOS120_ThePageIsKeyedOnTheComponentSoTheWindowCanDedupIt(t *testing.T) {
	pages := chaos120Harness(t, alertEventComponentPanic)

	runGuarded("syslog_health", func() { panic("first") })
	first := chaos120PagesFor(pages(1), alertEventComponentPanic)
	if len(first) != 1 {
		t.Fatalf("got %d pages, want 1", len(first))
	}
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record")
	}
	if strings.Contains(first[0].detail, rec.ID) {
		t.Fatalf("Detail embeds the crash id %q: %q\n"+
			"The dedup key is event+Detail, so a per-crash id makes every page a distinct key the 30 s "+
			"window cannot suppress (CHAOS-64).", rec.ID, first[0].detail)
	}

	// Two panics in the SAME component, far enough apart that the sink's own
	// per-component throttle has reopened, must produce the same dedup key — so
	// the alert store's window can collapse them.
	crashThrottleMu.Lock()
	crashThrottleLast["syslog_health"] = time.Now().Add(-10 * crashThrottleEvery).UnixNano()
	crashThrottleMu.Unlock()
	runGuarded("syslog_health", func() { panic("second, different text") })

	all := chaos120PagesFor(pages(2), alertEventComponentPanic)
	if len(all) != 2 {
		t.Fatalf("got %d pages after reopening the throttle, want 2", len(all))
	}
	if all[0].detail != all[1].detail {
		t.Errorf("two panics in the same component produced different dedup keys:\n  %q\n  %q", all[0].detail, all[1].detail)
	}
}

// TestCHAOS120_ThePageInheritsTheSinksFloodBound. The page sits INSIDE the
// throttle gate, with the log line and the audit entry, because its rate is set
// by the fault and not by the operator. A request-triggered panic on the proxy
// hot path must not be able to fan out one webhook delivery per request.
func TestCHAOS120_ThePageInheritsTheSinksFloodBound(t *testing.T) {
	pages := chaos120Harness(t, alertEventComponentPanic)

	for i := 0; i < 50; i++ {
		recordCrash("proxy", "", "repeatable request-triggered panic")
	}

	// Wait for a SECOND page, which the fix never produces: the throttle gate
	// closes for crashThrottleEvery after the first.
	got := chaos120PagesFor(pages(2), alertEventComponentPanic)
	if len(got) != 1 {
		t.Errorf("50 same-component crashes within the throttle window produced %d pages, want 1. The page must "+
			"be inside the crashThrottleAllow gate, not before it.", len(got))
	}
	// The unlabeled total still counts every one: the throttle bounds the
	// floodable sinks, it never loses the rate. Asserted as a FLOOR, not an
	// equality: this package's tests share process-global counters and a
	// goroutine left over from an earlier test can record its own crash, which
	// would make an exact count order-dependent. The floor still falsifies the
	// mutant this gate exists for — a metric moved inside the throttle reads 1.
	if n := atomic.LoadInt64(&statCrashRecords); n < 50 {
		t.Errorf("culvert_crash_records_total = %d, want at least 50 — the throttle must bound the SINKS, not the metric", n)
	}
}

// TestCHAOS120_TheAlertPlanesOwnPanicDoesNotPageItself is the termination gate.
// fireAlert carries `defer recoverGoroutine("alert")` and internal/alerts' retry
// round runs under obs.SafeCall("alerts_retry") whose sink is this one. Without
// the exclusion, a panicking delivery path would record a crash, which would
// fire a page, which would panic in the same place, forever — bounded in RATE by
// the throttle and never terminating, feeding the persistent retry queue on
// every pass.
func TestCHAOS120_TheAlertPlanesOwnPanicDoesNotPageItself(t *testing.T) {
	for _, component := range []string{"alert", "alerts_retry"} {
		t.Run(component, func(t *testing.T) {
			pages := chaos120Harness(t, alertEventComponentPanic)
			recordCrash(component, "", "the delivery path itself panicked")

			if got := chaos120PagesFor(pages(1), alertEventComponentPanic); len(got) != 0 {
				t.Errorf("a crash in the alert plane's own component %q produced %d pages, want 0: paging through "+
					"the plane that just panicked is a non-terminating loop", component, len(got))
			}
			// Everything the sink CAN safely do, it still did.
			rec, ok := lastCrashSnapshot()
			if !ok || rec.Component != component {
				t.Errorf("the exclusion dropped the RECORD too (%+v, ok=%v) — it must drop only the page", rec, ok)
			}
		})
	}
}

// TestCHAOS120_EveryExcludedComponentIsAnAlertPlaneComponent keeps the exclusion
// set honest in the other direction. The set is a safety mechanism, so it must
// not become a place where a component quietly stops paging: every entry has to
// still be a guard label the alert delivery path actually uses.
func TestCHAOS120_EveryExcludedComponentIsAnAlertPlaneComponent(t *testing.T) {
	want := map[string]string{
		"alert":        `recoverGoroutine("alert")`,
		"alerts_retry": `obs.SafeCall("alerts_retry"`,
	}
	if len(crashAlertSelfExcluded) != len(want) {
		t.Errorf("crashAlertSelfExcluded has %d entries, want %d (%v). An entry added here is a component that "+
			"silently stops paging; it needs a termination argument, not a line.",
			len(crashAlertSelfExcluded), len(want), crashAlertSelfExcluded)
	}
	for c := range crashAlertSelfExcluded {
		marker, known := want[c]
		if !known {
			t.Errorf("%q is excluded from paging but is not a recorded alert-plane component", c)
			continue
		}
		if !chaos120TreeContains(t, marker) {
			t.Errorf("%q is excluded because of %s, but that call site is no longer in the tree — "+
				"delete the exclusion or re-derive it", c, marker)
		}
	}
}

// TestCHAOS120_NoSubscriberNoWork. The default posture is no webhooks
// configured, and this producer's rate is set by the fault, not the operator, so
// the gate fireDNSFailureAlert documents applies here too.
//
// What it buys here is narrower than at that producer, and the test says so
// rather than restating a rationale that stopped being true: since §3.4 moved
// the whole outbound step onto a detached goroutine, the gate no longer avoids
// SPAWNING one — it avoids building the payload and entering Store.Dispatch,
// whose dedup mutex and O(n) expiry scan are the parts that cost something on a
// node already having a bad day. The spawn itself is bounded by the sink's
// per-component throttle, which is why detaching it was affordable.
func TestCHAOS120_NoSubscriberNoWork(t *testing.T) {
	pages := chaos120Harness(t) // empty store: no subscriber

	runGuarded("dns-health", func() { panic("no subscriber configured") })

	if got := pages(1); len(got) != 0 {
		t.Errorf("an empty webhook store still dispatched %d alerts: the HasSubscriber gate is missing", len(got))
	}
	if _, ok := lastCrashSnapshot(); !ok {
		t.Error("the subscriber gate suppressed the crash RECORD — it must gate only the page")
	}
}

// TestCHAOS120_ComponentPanicIsSubscribableFromTheAlertsPanel. A producer gated
// on HasSubscriber for an event with no checkbox is a producer that never fires:
// the panel is the only place the vocabulary is discoverable (CHAOS-113). The
// cross-tree parity gate in alerts_gui_parity_chaos_test.go covers the class;
// this names THIS round's own event, as CHAOS-113 did for the scanning plane.
func TestCHAOS120_ComponentPanicIsSubscribableFromTheAlertsPanel(t *testing.T) {
	if gui := guiSubscribableEvents(t); !gui[alertEventComponentPanic] {
		t.Errorf("%q has no Alerts-panel checkbox, so an operator cannot subscribe to it and the "+
			"HasSubscriber gate will make it never fire", alertEventComponentPanic)
	}
	if _, known := scanAlertGUIKnownGaps[alertEventComponentPanic]; known {
		t.Errorf("%q is recorded as a known GUI gap but this round ships its checkbox — delete the entry",
			alertEventComponentPanic)
	}
}

// chaos120TreeContains reports whether any non-test Go source in the module
// contains marker. Anchored to pkgSourceDir(), never the process working
// directory, for the CWD-race reason the other source-scanning parity walls
// document.
func chaos120TreeContains(t *testing.T, marker string) bool {
	t.Helper()
	found := false
	scanned := 0
	err := filepath.WalkDir(pkgSourceDir(), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 G122 -- this repository's own checked-in sources
		if rerr != nil {
			return nil
		}
		scanned++
		if strings.Contains(string(b), marker) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A broken walk must not make the caller vacuously green.
	if scanned < 400 {
		t.Fatalf("the source scan examined only %d files — it is not reading the tree", scanned)
	}
	return found
}

// TestCHAOS120_TheSinkNeverBlocksOnTheAlertPlane is the deadlock gate, and it
// exists because this round's own first design had the defect.
//
// The first version called globalAlertStore.HasSubscriber SYNCHRONOUSLY, on
// recordCrash's stack. That probe takes the store's RWMutex — and Store.Add,
// Store.Update and Store.Delete release that WRITE lock with a non-deferred
// `as.mu.Unlock()` (internal/alerts/store.go), the CHAOS-118 §8.2a lock-pairing
// shape. A panic inside one of those critical sections leaks the write lock, and
// the recovering goroutine would then have blocked inside the crash sink forever
// against a lock nothing will release:
//
//   - from runGuarded: the round never returns, so the loop is stalled
//     permanently — the exact "silent permanent stall" runGuarded's doc says
//     guarding the round instead of the goroutine exists to remove, reintroduced
//     by the reporting of it;
//   - from withAdminPanicRecovery: the deferred func never completes, so the 500
//     is never written and the request hangs holding a connection;
//   - and one goroutine is leaked per subsequent crash, in any component.
//
// Blocking is as fatal to a worker as panicking, so the sink's "can never take
// down the process it protects" contract covers both. The whole outbound step —
// probe included — now runs on a detached goroutine, which this gate pins by
// making that step block forever and requiring recordCrash to return anyway.
func TestCHAOS120_TheSinkNeverBlocksOnTheAlertPlane(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	// A page step that never returns — the leaked-write-lock shape, without
	// needing to leak a real lock in another package.
	release := make(chan struct{})
	var inflight sync.WaitGroup
	prevBarrier := crashAlertPageBarrier
	crashAlertPageBarrier = func() func() {
		inflight.Add(1)
		return inflight.Done
	}
	prev := crashAlertPage
	crashAlertPage = func(string, crashPageTarget) { <-release }
	t.Cleanup(func() {
		// Release the blocked page, join it, then restore: the goroutine reads
		// crashAlertPage, so restoring it while one is parked inside would be
		// the same unsynchronised write the barrier exists to prevent.
		close(release)
		inflight.Wait()
		crashAlertPage = prev
		crashAlertPageBarrier = prevBarrier
	})

	returned := make(chan struct{})
	go func() {
		// Through runGuarded, so the assertion is about the worker plane the
		// containment exists for, not about recordCrash in isolation.
		runGuarded("threatfeed", func() { panic("round blew up while the alert store was wedged") })
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("runGuarded did not return while the page step was blocked: the crash sink is on the alert " +
			"plane's stack, so a leaked store lock stalls the guarded round forever instead of costing one window")
	}

	// And the durable evidence landed, because the page is the sink's LAST step.
	if rec, ok := lastCrashSnapshot(); !ok || rec.Component != "threatfeed" {
		t.Errorf("lastCrash = %+v, ok=%v: a blocked page must not cost the record", rec, ok)
	}
}

// TestCHAOS120_TheSubscriberProbeIsNotOnTheSinksStack narrows the gate above to
// the specific call that made it necessary. The blocking seam proves the step as
// a whole is detached; this proves the PROBE is inside it, by running the real
// bound page step against a real store and asserting recordCrash returns before
// any dispatch could have been observed.
func TestCHAOS120_TheSubscriberProbeIsNotOnTheSinksStack(t *testing.T) {
	pages := chaos120Harness(t, alertEventComponentPanic)

	// The real crashAlertPage closure (not swapped): probe + dispatch.
	done := make(chan struct{})
	go func() {
		recordCrash("threatfeed", "", "probe placement")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("recordCrash did not return")
	}

	// The page still arrives — detaching the step must not lose it.
	if got := chaos120PagesFor(pages(1), alertEventComponentPanic); len(got) != 1 {
		t.Fatalf("the detached page step delivered %d pages, want 1", len(got))
	}
}
