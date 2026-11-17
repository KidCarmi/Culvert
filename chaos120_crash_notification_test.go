package main

// chaos120_crash_notification_test.go — CHAOS-120: the panic-containment
// plane's NOTIFICATION boundary.
//
// CHAOS-119 asked what an operator can SEE after a contained panic and built
// the answer: a labelled counter, a crash record, a log line, an audit entry.
// This round asks the next question — who TELLS them — and the answer at the
// base revision was "nobody", for 62 of the 63 components that funnel into the
// sink. The 63rd, ha-standby-sync, alerts itself from HAState.notePanicRound,
// whose doc comment states the rule the other 62 were missing:
//
//	without them the containment would trade a loud crash for a silent one,
//	which is the failure class the guard exists to remove
//
// Four consecutive rounds recorded this as residual risk and none closed it
// (CHAOS-116 `4`, CHAOS-117 `5`, CHAOS-118 `1`, CHAOS-119 `3`). It is closed
// here, in the sink, so it covers every component rather than one plane.
//
// The second half of the boundary is the alert plane's own vocabulary: an
// event an operator cannot subscribe to from the product's UI is an event they
// never receive, and for the four that gate on a subscriber it is an event that
// never fires at all. CHAOS-113 found ten and recorded them in
// scanAlertGUIKnownGaps because a scan-sidecar round was the wrong owner. This
// round's scope IS the notification boundary, so it is the right one.

import (
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── test seam plumbing ──────────────────────────────────────────────────────

// panicAlertLog records the dispatch DECISION, which is what every assertion
// here is about. Delivery is deliberately not asserted: internal/alerts routes
// it through a package-global concurrency semaphore shared by every test in the
// binary, and a saturated semaphore diverts to the retry queue — which reports
// as "the alert was suppressed" even though the producer did everything right.
// Same rationale fireAlert's own doc comment gives for being a var.
type panicAlertLog struct {
	mu    sync.Mutex
	calls []panicAlertCall
}

type panicAlertCall struct {
	component string
	crashID   string
}

func (l *panicAlertLog) record(component, crashID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, panicAlertCall{component: component, crashID: crashID})
}

func (l *panicAlertLog) snapshot() []panicAlertCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]panicAlertCall(nil), l.calls...)
}

// capturePanicAlerts installs the log and restores the production dispatcher,
// so a later test in the same binary is never left with a stubbed notifier.
func capturePanicAlerts(t *testing.T) *panicAlertLog {
	t.Helper()
	resetCrashGuardStateForTest()
	log := &panicAlertLog{}
	prev := firePanicContainedAlert
	firePanicContainedAlert = log.record
	t.Cleanup(func() {
		firePanicContainedAlert = prev
		resetCrashGuardStateForTest()
	})
	return log
}

// ── 1. a contained panic now reaches an operator ────────────────────────────

// The headline assertion. Before this round recordCrash wrote the counter, the
// record, the log line and the audit entry and then returned, so a background
// round could fail forever behind a green dashboard — CHAOS-119 residual `4`
// states exactly that for five such rounds.
//
// Reverting the notePanicContained call in recordCrash fails this.
func TestCHAOS120_ContainedPanicRaisesAnOperatorAlert(t *testing.T) {
	log := capturePanicAlerts(t)

	recordCrash(crashComponentHALeadershipResume, "", "leadership resume exploded")

	calls := log.snapshot()
	if len(calls) != 1 {
		t.Fatalf("panic_contained dispatches = %d, want 1 — a contained panic that nothing reports is a "+
			"silent failure, which is the class the guard exists to remove", len(calls))
	}
	if calls[0].component != crashComponentHALeadershipResume {
		t.Errorf("alert component = %q, want %q", calls[0].component, crashComponentHALeadershipResume)
	}
	// The crash id is the join key between the alert and the local evidence
	// (the record, the ERROR log line, the audit entry). An alert without it
	// tells an operator that something panicked and gives them no way to find
	// which occurrence.
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record stored")
	}
	if calls[0].crashID == "" || calls[0].crashID != rec.ID {
		t.Errorf("alert crash_id = %q, want the stored record's id %q", calls[0].crashID, rec.ID)
	}
	// The durable evidence is unchanged by the notification.
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1", got)
	}
}

// The notification must never be able to carry the recovered panic VALUE. The
// ERROR log line documents why: a panic value can embed a credential
// (panic(cfg.SessionHMAC)), and sanitizeLog scrubs control characters rather
// than masking secrets. A webhook is an egress to a third party, so this is a
// stricter boundary than the local log, not a looser one.
//
// Asserted at the seam rather than on the payload, because the seam is what a
// future round would have to widen to leak it.
func TestCHAOS120_TheNotificationCannotCarryThePanicValue(t *testing.T) {
	log := capturePanicAlerts(t)

	const secret = "SUPERSECRET-SESSION-HMAC-c120"
	recordCrash(crashComponentSyslogHealth, "corr-c120", "boom: "+secret)

	calls := log.snapshot()
	if len(calls) != 1 {
		t.Fatalf("panic_contained dispatches = %d, want 1", len(calls))
	}
	for _, field := range []string{calls[0].component, calls[0].crashID} {
		if strings.Contains(field, secret) {
			t.Errorf("the panic value reached the notification seam in %q — a webhook is an egress and a "+
				"recovered panic value can embed a credential", field)
		}
	}
	// The local record still has it: this is a boundary, not a loss of evidence.
	rec, ok := lastCrashSnapshot()
	if !ok || !strings.Contains(rec.Summary, secret) {
		t.Error("the local crash record lost the panic text — the egress boundary must not weaken local evidence")
	}
}

// ── 2. the latch ────────────────────────────────────────────────────────────

// The sink's own throttle is ONE SECOND, which is right for a log line and
// wrong for a webhook: a deterministically crash-looping round (the shape
// CHAOS-109 found in the feed plane, where RunNow re-syncs immediately at every
// boot) would deliver 86,400 alerts a day, and an operator would mute the
// event — the same outcome as never shipping it.
//
// Deleting the crashAlertAllow call fails this with 2 dispatches.
func TestCHAOS120_AlertIsLatchedPerComponentThenRearms(t *testing.T) {
	log := capturePanicAlerts(t)

	// Two crashes of the same component, far enough apart to clear the SINK's
	// one-second throttle, so what is being measured is the alert latch and not
	// crashThrottleAllow.
	recordCrash(crashComponentSyslogHealth, "", "first")
	crashThrottleMu.Lock()
	delete(crashThrottleLast, crashComponentSyslogHealth)
	crashThrottleMu.Unlock()
	recordCrash(crashComponentSyslogHealth, "", "second")

	if n := len(log.snapshot()); n != 1 {
		t.Fatalf("dispatches for one component = %d, want 1 — the latch is what keeps a crash loop from "+
			"becoming 86,400 webhooks a day", n)
	}

	// A DIFFERENT component is a different latch: one noisy component must not
	// mask another. This is the inversion CHAOS-119 found in the label cap,
	// asked of the alert path.
	recordCrash(crashComponentSupportUpload, "", "other component")
	calls := log.snapshot()
	if len(calls) != 2 {
		t.Fatalf("dispatches after a second component = %d, want 2 — the latch must be per component", len(calls))
	}
	if calls[1].component != crashComponentSupportUpload {
		t.Errorf("second dispatch component = %q, want %q", calls[1].component, crashComponentSupportUpload)
	}

	// And it re-arms, so a recurrence after a quiet period is new information
	// rather than a swallowed repeat. The latch is aged by rewriting its
	// timestamp, which is the only way to test an hour-long window without
	// faking the clock process-wide.
	crashAlertMu.Lock()
	crashAlertLast[crashComponentSyslogHealth] = time.Now().Add(-2 * crashAlertRearm).UnixNano()
	crashAlertMu.Unlock()
	crashThrottleMu.Lock()
	delete(crashThrottleLast, crashComponentSyslogHealth)
	crashThrottleMu.Unlock()

	recordCrash(crashComponentSyslogHealth, "", "recurrence an hour later")
	if n := len(log.snapshot()); n != 3 {
		t.Errorf("dispatches after the re-arm window = %d, want 3 — a latch that never re-arms loses every "+
			"later episode for the life of the process", n)
	}
}

// CHAOS-84's finding, asked of the new latch: the comparison must be on
// MAGNITUDE. A backward wall-clock step (NTP correction, a VM restored from a
// snapshot) makes now-last negative, and a sign-based test would then latch the
// component out until the clock caught up — losing every alert in between.
//
// Replacing the Abs() with a plain `<` fails this.
func TestCHAOS120_AlertLatchSurvivesABackwardClockStep(t *testing.T) {
	capturePanicAlerts(t)

	// A latch stamped in the FUTURE is what a backward step leaves behind: the
	// timestamp was written before the correction, so now is earlier than last.
	//
	// Within one window either way, suppression is correct and intended.
	crashAlertMu.Lock()
	crashAlertLast[crashComponentSyslogHealth] = time.Now().Add(crashAlertRearm / 2).UnixNano()
	crashAlertMu.Unlock()
	if crashAlertAllow(crashComponentSyslogHealth) {
		t.Error("a latch half a window into the future must suppress — the bound is one window in either direction")
	}

	// PAST that window it must pass again. This is the assertion that
	// discriminates: with a sign-based `now-last < rearm` the difference is
	// negative for the whole size of the step, so the component stays latched
	// out until the clock catches up — hours or days of lost alerts after one
	// NTP correction or a VM restored from a snapshot. Abs() bounds the loss to
	// a single window.
	crashAlertMu.Lock()
	crashAlertLast[crashComponentSyslogHealth] = time.Now().Add(48 * time.Hour).UnixNano()
	crashAlertMu.Unlock()
	if !crashAlertAllow(crashComponentSyslogHealth) {
		t.Error("a 48-hour forward stamp still suppresses: the comparison is sign-based, so a backward clock " +
			"step latches the component out until the clock catches up (CHAOS-84)")
	}
}

// ── 3. the plane that must not alert about itself ───────────────────────────

// fireAlert's own recover is recoverGoroutine("alert"), so a dispatch that
// panics re-enters this sink as component "alert". Alerting from there would
// spawn another dispatch, which panics again, which re-enters the sink: a
// self-sustaining loop clocked by crashThrottleEvery at one iteration per
// second, forever, each iteration a fresh goroutine and a fresh webhook
// attempt. And it could not work even if it were safe — the alert saying "the
// thing that delivers alerts just panicked" is dispatched by the thing that
// just panicked.
//
// Removing either name from crashAlertExcluded fails this.
func TestCHAOS120_AlertPlaneDoesNotAlertAboutItself(t *testing.T) {
	log := capturePanicAlerts(t)

	for _, component := range []string{crashComponentAlert, crashComponentAlertsRetry} {
		recordCrash(component, "", "the pager is on fire")
	}

	if n := len(log.snapshot()); n != 0 {
		t.Errorf("dispatches for the alert-delivery plane = %d, want 0 — firing from there re-enters the sink "+
			"through fireAlert's own recover and the loop never terminates", n)
	}

	// The loss is accepted and it is NOT silent: the counter, the log line and
	// the audit entry all still carry it. A broken alert plane is discoverable,
	// just not via the alert plane.
	if got := atomic.LoadInt64(&statCrashRecords); got != 2 {
		t.Errorf("crash records = %d, want 2 — the exclusion must suppress the ALERT, never the evidence", got)
	}
	if rec, ok := lastCrashSnapshot(); !ok || rec.Component != crashComponentAlertsRetry {
		t.Error("the excluded component lost its crash record")
	}
}

// A notifier that panics must not be able to break the sink. The sink's
// contract is that it never re-panics, and the notification is the newest thing
// on its path — so the newest thing is the one most likely to violate it.
func TestCHAOS120_APanickingNotifierCannotBreakTheSink(t *testing.T) {
	resetCrashGuardStateForTest()
	prev := firePanicContainedAlert
	firePanicContainedAlert = func(string, string) { panic("the notifier itself exploded") }
	t.Cleanup(func() {
		firePanicContainedAlert = prev
		resetCrashGuardStateForTest()
	})

	// Must not propagate: a re-panic here lands in whatever plane was already
	// unwinding from a panic, which is the one place it cannot be handled.
	recordCrash(crashComponentSyslogHealth, "", "boom")

	if got := atomic.LoadInt64(&statCrashSinkPanics); got != 1 {
		t.Errorf("crash sink panics = %d, want 1 — a panicking notifier must be swallowed AND counted", got)
	}
	// The evidence committed before the notification survives, which is why the
	// notification is last.
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1", got)
	}
	if rec, ok := lastCrashSnapshot(); !ok || rec.Component != crashComponentSyslogHealth {
		t.Error("the crash record was lost to the notifier's panic — ordering regression")
	}
}

// A nil seam must fail toward DELIVERY, not toward silence, and must not
// nil-deref the sink. Same contract alerts.HasSubscriber documents for a
// missing probe: a wiring gap can never silence a real alert.
func TestCHAOS120_ANilNotifierFailsTowardDelivery(t *testing.T) {
	resetCrashGuardStateForTest()
	prev := firePanicContainedAlert
	firePanicContainedAlert = nil
	t.Cleanup(func() {
		firePanicContainedAlert = prev
		resetCrashGuardStateForTest()
	})

	// Reaches the production dispatcher, which spawns a goroutine, finds no
	// subscriber in the default posture and returns. The assertion is that the
	// sink survives and still records.
	recordCrash(crashComponentSyslogHealth, "", "boom")

	if got := atomic.LoadInt64(&statCrashSinkPanics); got != 0 {
		t.Errorf("crash sink panics = %d, want 0 — a nil seam must not be dereferenced", got)
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1", got)
	}
}

// ── 4. the sink acquires no foreign lock ────────────────────────────────────

// This gate exists because this round's own first design failed it.
//
// Every other fault-driven alert producer gates on alerts.HasSubscriber BEFORE
// the `go`, to keep a degraded node from spawning a goroutine per request in
// the default posture, and the obvious thing to do here was the same. That
// would put alertStore()'s mutex on the crash-sink path — and the alert
// store releases that mutex with a BARE trailing Unlock in Add, Update and
// Delete (deliberately, so the fsync lands outside the lock). That is the
// CHAOS-118 §7.4 lock-pairing shape, and unlike §7.4's examples it IS reachable
// from a guard: a panic inside one of those critical sections strands as.mu
// held, unwinds to withAdminPanicRecovery, and re-enters recordCrash. A gate on
// the sink path would then block the sink forever on a mutex the panic itself
// stranded — hanging the admin request and destroying the one crash record that
// explains it. The sink would have become the thing that hangs.
//
// So the gate moved inside the goroutine, and this test holds the invariant
// that made that necessary: no function on the sink's SYNCHRONOUS path may
// touch a lock owned by another plane. It is asserted structurally because the
// deadlock it prevents cannot be provoked from outside internal/alerts (as.mu
// is unexported), and a test that cannot fail is not a gate.
func TestCHAOS120_CrashSinkTakesNoForeignLock(t *testing.T) {
	decls := chaos120TopLevelFuncs(t)

	// The synchronous path: recordCrash and everything it calls before it
	// returns. dispatchPanicContainedAlert is NOT on it — its whole body is a
	// `go` statement, which this gate verifies separately.
	syncPath := []string{
		"recordCrash",
		"notePanicContained",
		"crashAlertAllow",
		"crashAlertExcluded",
		"crashThrottleAllow",
		"recoverGoroutine",
		"runGuarded",
		"proxyCrashGuard",
	}

	var resolved int
	for _, name := range syncPath {
		fn := decls[name]
		if fn == nil {
			continue
		}
		resolved++
		for _, foreign := range chaos120ForeignLocksOutsideGo(fn) {
			t.Errorf("%s references %s on the crash sink's SYNCHRONOUS path. A panic raised inside that "+
				"store's critical section strands its mutex (bare trailing Unlock in Add/Update/Delete) and "+
				"then re-enters this sink, so the sink would block forever on a lock the panic itself "+
				"stranded. Move the access inside the goroutine.", name, foreign)
		}
	}

	// Negative control: a gate that enumerated nothing would pass silently,
	// which is the failure mode CHAOS-118 §7.2 found in its own first draft.
	if resolved < 5 {
		t.Fatalf("the gate resolved only %d of the %d synchronous-path functions — it is matching nothing, "+
			"not proving anything", resolved, len(syncPath))
	}

	dispatch := decls["dispatchPanicContainedAlert"]
	if dispatch == nil {
		t.Fatal("dispatchPanicContainedAlert not found — the gate has lost its subject")
	}
	for _, foreign := range chaos120ForeignLocksOutsideGo(dispatch) {
		t.Errorf("dispatchPanicContainedAlert touches %s OUTSIDE its goroutine — the subscriber gate must "+
			"stay inside the `go` for the reason this test documents", foreign)
	}
}

// chaos120TopLevelFuncs indexes the module's non-test, non-method function
// declarations by name.
func chaos120TopLevelFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	files := chaos119ParseModule(t, pkgSourceDir())
	if len(files) < 400 {
		t.Fatalf("the scan only parsed %d files — it is not reading the tree", len(files))
	}
	out := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil || fn.Recv != nil {
				continue
			}
			out[fn.Name.Name] = fn
		}
	}
	return out
}

// chaos120ForeignLocksOutsideGo reports which process-wide stores fn touches
// outside a `go` statement. Selector bases count
// (alertStore().HasSubscriber reports "alertStore"), because it is
// the lock acquisition that matters rather than which method takes it.
func chaos120ForeignLocksOutsideGo(fn *ast.FuncDecl) []string {
	// Locks owned by another plane. alertStore() is the one this round
	// nearly added; the others are process-wide stores whose critical sections
	// a panicking caller could equally strand.
	foreign := map[string]bool{
		"alertStore":     true,
		"configVersions": true,
	}
	var hits []string
	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, isGo := n.(*ast.GoStmt); isGo {
			return false // everything under `go` is off the synchronous path
		}
		id, ok := n.(*ast.Ident)
		if ok && foreign[id.Name] && !seen[id.Name] {
			seen[id.Name] = true
			hits = append(hits, id.Name)
		}
		return true
	})
	return hits
}

// ── 5. the vocabulary an operator can actually subscribe to ─────────────────

// An alert nobody can subscribe to is an alert nobody receives, and for a
// producer that GATES on a subscriber it is an alert that never fires at all.
// CHAOS-113 built the differential oracle that proves every fired event has a
// panel row; it also recorded ten events it deliberately left out, because a
// scan-sidecar round was the wrong owner for ten operator-facing panels.
//
// This round's scope IS the notification boundary, so it closes them. This test
// holds the result: the known-gap list is empty, and it names the four that
// were live defects rather than discoverability gaps.
func TestCHAOS120_NoFiredAlertShipsUnsubscribable(t *testing.T) {
	if len(scanAlertGUIKnownGaps) != 0 {
		var names []string
		for ev := range scanAlertGUIKnownGaps {
			names = append(names, ev)
		}
		t.Errorf("scanAlertGUIKnownGaps still holds %d entries (%s). CHAOS-120 emptied it; an entry added "+
			"back is a new event shipping unsubscribable and needs its reason written down.",
			len(scanAlertGUIKnownGaps), strings.Join(names, ", "))
	}

	gui := guiSubscribableEvents(t)

	// The four that gate on a subscriber: with no checkbox these could never be
	// delivered to an operator who configures Culvert through its own UI.
	for _, ev := range []string{"admin_ui_unavailable", "cdr_unavailable", "dns_failure", "yara_degraded"} {
		if !gui[ev] {
			t.Errorf("%q gates on alerts.HasSubscriber and has no Alerts-panel checkbox, so it can never fire "+
				"for a UI-configured operator", ev)
		}
	}
	// The six that were deliverable only by hand-POSTing the event name.
	for _, ev := range []string{
		"disk_critical", "pac_profile_degraded",
		"ha_self_fenced", "ha_lease_reacquired", "ha_resume_unfenced", "ha_manual_failover_required",
	} {
		if !gui[ev] {
			t.Errorf("%q has no Alerts-panel checkbox", ev)
		}
	}
	// And this round's own event, asserted directly rather than through
	// CHAOS-113's regex: that oracle resolves no constants, so an event named
	// by a constant at its gate would satisfy it vacuously.
	if !gui["panic_contained"] {
		t.Error("panic_contained has no Alerts-panel checkbox — the crash sink would alert into a vocabulary " +
			"no operator can subscribe to")
	}
}

// The event must also be documented where the other 20-odd are, because that
// catalog is what tells an operator what a row MEANS — subscribable but
// undocumented is half a contract.
func TestCHAOS120_PanicContainedIsDocumentedInTheAlertCatalog(t *testing.T) {
	path := filepath.Join(pkgSourceDir(), "internal", "alerts", "store.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)
	if !strings.Contains(src, `"panic_contained"`) {
		t.Error("panic_contained is missing from internal/alerts/store.go's event catalog")
	}
	// The catalog must state the egress boundary, since that is the property a
	// future round is most likely to weaken.
	if !strings.Contains(src, "crash id and NOTHING else") {
		t.Error("the catalog entry no longer records that the payload excludes the panic value")
	}
}
