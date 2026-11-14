package main

// chaos119_crash_reporting_test.go — CHAOS-119: the panic-containment plane's
// REPORTING boundary.
//
// The CHAOS-24/105/116/117/118 family established that every detached
// background round runs under a guard, because Go terminates the process on an
// unrecovered panic in ANY goroutine. That work is about CONTAINMENT. This
// round is about what an operator can SEE afterwards, and it found three
// different ways the answer was "nothing":
//
//  1. §1 — a detached goroutine with no guard at all, in the one place where a
//     panic is strictly worse than anywhere else: inside a graceful shutdown,
//     from a hook that runs before every durability flush.
//  2. §2 — five background rounds that WERE contained, by a bespoke
//     `recover()` that logs, and so moved no counter, stored no crash record
//     and wrote no audit entry. Containment without reporting is a silent
//     failure with extra steps.
//  3. §3 — the sink's own label cap was half the size of its fixed label set,
//     so even a correctly reported component could be suppressed outright.
//
// The three are one defect class: the signal the family keeps telling operators
// to watch (culvert_crash_records_total{component}) did not cover the rounds the
// family itself was adding.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── 1. the shutdown drain: contained, reported, and still bounded ───────────

// The pre-fix defect cannot be driven to its conclusion in-process: an
// unrecovered panic in a detached goroutine terminates the TEST BINARY, so
// there is no "before" assertion to make here. What is asserted instead is
// every property the fix has to deliver, each of which fails on a revert:
// the panic is contained, it is attributed to its own component, Close still
// RETURNS (rather than letting the hook wait out the whole shutdown budget),
// and it reports the failure rather than a clean shutdown.
//
// The fault is injected by clearing the cursor store, which makes
// drainPartition's first statement (t.cursors.get) a nil-receiver dereference
// — a panic raised inside the drain itself, on the production code path, with
// no test-only seam in the guarded region.
func TestCHAOS119_ShutdownDrainPanicIsContainedReportedAndBounded(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	rt := buildReadyTelemetry(t)
	// Restore the store before the fixture's own Close cleanup runs (cleanups
	// are LIFO, so this one lands first): a shared-global test must not leave
	// a poisoned runtime behind for the fixture to trip over.
	origCursors := rt.cursors
	t.Cleanup(func() { rt.cursors = origCursors })
	rt.cursors = nil // drainPartition will dereference a nil cursor store

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	err := rt.Close(ctx)
	elapsed := time.Since(start)

	// Reaching this line at all is the headline: pre-fix the panic was
	// unrecovered in a `go func()`, which is process-fatal.
	if err == nil {
		t.Error("Close reported a clean shutdown for a drain that panicked — the caller logs this error, " +
			"and a graceful-shutdown line that claims success hides unexported evidence")
	}

	// Bounded: the hook must not spend the shutdown budget. A stage that
	// panicked without answering `done` would park here until ctx expired,
	// starving orders 67..140.
	if elapsed > 5*time.Second {
		t.Errorf("Close took %v — a panicking stage must still answer done so the hook returns promptly", elapsed)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Errorf("the shutdown context expired (%v): the drain consumed the budget it exists to honour", ctxErr)
	}

	// Reported, under its own component: an operator reading
	// culvert_crash_records_total{component} must be able to tell a shutdown
	// drain fault from a periodic flush or export fault, because only the
	// first one leaves pending evidence unexported.
	if got := atomic.LoadInt64(&statCrashRecords); got < 1 {
		t.Fatalf("crash records = %d, want >= 1 — a contained panic that moves no counter is a silent failure", got)
	}
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record stored for the contained drain panic")
	}
	if rec.Component != crashComponentMCPTelemetryDrain {
		t.Errorf("component = %q, want %q", rec.Component, crashComponentMCPTelemetryDrain)
	}
	if rec.Category != "crash" {
		t.Errorf("category = %q, want %q", rec.Category, "crash")
	}
}

// The drain is staged, so one partition's fault costs that partition and the
// durability-critical step still runs. mgr.Close() does its own final
// per-domain flush and closes the encrypted spool; a single guard around the
// whole sequence would have skipped it on exactly the fault §1 injects.
//
// The two halves are pinned by different means, and the difference is worth
// stating because the first draft of this test got it wrong:
//
//   - Per-partition staging is BEHAVIOURAL. Three crash records for three
//     partitions can only be produced by a guard inside the loop; a guard
//     around the loop unwinds on the first partition and records once.
//     (Verified by mutation: hoisting the guard out of the loop fails this.)
//   - "mgr.Close() still runs" is STRUCTURAL. There is no observable of a
//     closed events.Manager from outside internal/mcp/events — `closed` is
//     written and never read, and the final denial flush has nothing left to
//     commit once stage 1 has force-flushed the open window. The first draft
//     claimed the returned error's identity proved it; a mutation that skipped
//     mgr.Close() and returned the same sentinel passed, so that claim was
//     false and is withdrawn. The source gate below is what actually holds it:
//     the manager-close stage must be its own guarded, UNCONDITIONAL stage.
//     Same honest framing as CHAOS-118 residual 3.
func TestCHAOS119_DrainIsStagedSoManagerCloseStillRuns(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	rt := buildReadyTelemetry(t)
	origCursors := rt.cursors
	t.Cleanup(func() { rt.cursors = origCursors })
	rt.cursors = nil

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := rt.Close(ctx)
	if err == nil {
		t.Fatal("expected the drain failure to be reported")
	}
	if !strings.Contains(err.Error(), "drain panicked") {
		t.Errorf("error = %v, want the drain sentinel so the caller's shutdown log names what failed", err)
	}
	if got := atomic.LoadInt64(&statCrashRecords); got < int64(len(gatewayPartitions)) {
		t.Errorf("crash records = %d, want >= %d (one per partition). Fewer means the guard is around "+
			"the partition LOOP rather than inside it, so one partition's fault costs the others' drains",
			got, len(gatewayPartitions))
	}
}

// The structural half of the staging contract: the manager-close stage is its
// own guard and nothing short-circuits past it. Pinned at the source because
// §1's fault cannot distinguish "stage 3 ran" from "stage 3 was skipped" —
// see TestCHAOS119_DrainIsStagedSoManagerCloseStillRuns for why.
func TestCHAOS119_ManagerCloseStageIsGuardedAndUnconditional(t *testing.T) {
	body := funcSource(t, "mcp_telemetry.go", "Close")

	if n := strings.Count(body, "runGuarded("); n < 3 {
		t.Errorf("Close has %d guarded stages, want >= 3 (the force-flush, the per-partition drain and "+
			"the manager close). One guard around the whole sequence lets an early fault skip the step "+
			"that flushes and releases the encrypted spool.", n)
	}
	closeStage := "runGuarded(crashComponentMCPTelemetryDrain, func() { closeErr = t.mgr.Close() })"
	if !strings.Contains(body, closeStage) {
		t.Errorf("Close no longer runs t.mgr.Close() as its own guarded stage (%q)", closeStage)
	}
	// Nothing may return from the goroutine between the drain and the manager
	// close: a `return` there is the shape mutation B2 used to skip stage 3
	// while still reporting the drain sentinel.
	drainIdx := strings.Index(body, "t.drainPartition(ctx, part)")
	closeIdx := strings.Index(body, closeStage)
	if drainIdx < 0 || closeIdx < 0 || drainIdx > closeIdx {
		t.Fatalf("Close's stages are not in the expected order (drain at %d, close at %d)", drainIdx, closeIdx)
	}
	if between := body[drainIdx:closeIdx]; strings.Contains(between, "return") {
		t.Errorf("Close can return between the partition drain and the manager close: %q. A panicking "+
			"drain must still reach mgr.Close(), which is the step that flushes and releases the spool.",
			strings.TrimSpace(between))
	}
	// And every exit answers `done`, so a panicking stage cannot make the hook
	// wait out the shutdown budget it exists to honour.
	if !strings.Contains(body, "done <- closeErr") {
		t.Error("Close's goroutine no longer answers done unconditionally: a stage that panicked without " +
			"sending would park the hook until the shutdown context expired, starving every later hook")
	}
}

// ── 2. the rounds that were contained but unreported ────────────────────────

// chaos119ContainedRounds are the background rounds whose own `recover()` now
// reports into the crash plane. Each row names the file, the function that owns
// the recover, and the component the record must carry.
//
// Pinned at the source level for the reason CHAOS-105's registry is: a revert
// to a log-only recover is invisible behaviourally without a fault injected
// into each round's production dependencies (a BadgerDB, a signed catalog
// origin, a live HA intent, a CP address source), and the property under test
// is "the panic reaches the sink", which is a property of the recover block.
var chaos119ContainedRounds = []struct {
	file      string
	fn        string
	component string
}{
	// The SOLE runtime driver of catalog refresh AND, through runRefresh, the
	// freshness watchdog: a loop that panicked every tick froze both while
	// every operator surface stayed quiet.
	{"release_refresh.go", "refreshLoopTick", "crashComponentReleaseCatalogRefresh"},
	// The SOLE runtime driver of stale-alerting on a disabled-fetch
	// (air-gapped) or break-glass appliance — the CHAOS-23 defect, reachable
	// again through a fault nothing counted.
	{"release_refresh.go", "staleWatchdogTick", "crashComponentReleaseCatalogStale"},
	// Charged as a failed round (so it backs off), but never counted: a feed
	// whose parse panics every round was indistinguishable from an origin
	// that is merely unreachable.
	{"saas_feed_scheduler.go", "runTick", "crashComponentSaaSFeedRefresh"},
	// A WORKER-level recover: one panic ends republication for the whole
	// episode. Deliberate (it clears `retrying` so a later failure starts a
	// fresh loop), but it left no evidence that the retry died rather than
	// succeeded.
	{"cp_addr_publish.go", "retryCPAddrPublish", "crashComponentCPAddrPublishRetry"},
	// The sharpest of the five, and its own log line says why: the panic
	// permanently ends the only retry of the persisted HA intent, so the node
	// serves with no write authority until an operator restarts it.
	{"cluster_startup.go", "retryLeadershipResume", "crashComponentHALeadershipResume"},
}

func TestCHAOS119_EveryContainedRoundReportsIntoTheCrashPlane(t *testing.T) {
	for _, r := range chaos119ContainedRounds {
		t.Run(r.fn, func(t *testing.T) {
			body := funcSource(t, r.file, r.fn)
			if !strings.Contains(body, "recover()") {
				t.Fatalf("%s/%s no longer contains a recover() — the inventory is stale", r.file, r.fn)
			}
			if !strings.Contains(body, "recordCrash(") {
				t.Errorf("%s/%s contains its panic without reporting it: a recovered panic that moves no "+
					"culvert_crash_records_total{component} series, stores no record and writes no audit "+
					"entry is a silent failure. Route it through recordCrash (or runGuarded).", r.file, r.fn)
			}
			if !strings.Contains(body, r.component) {
				t.Errorf("%s/%s does not report under %s — the record must name the round so an operator "+
					"can tell which one died", r.file, r.fn, r.component)
			}
		})
	}
}

// recordCrash's contract on this path, driven end to end once: the sink is
// re-panic-proof, it counts before it throttles, and it attributes. A round
// that calls it from inside a recover therefore cannot make things worse, which
// is the precondition for adding it to five live loops.
func TestCHAOS119_ContainedRoundReportingIsAttributedAndSafe(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	recordCrash(crashComponentHALeadershipResume, "", "leadership resume exploded")

	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1", got)
	}
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record stored")
	}
	if rec.Component != crashComponentHALeadershipResume {
		t.Errorf("component = %q, want %q", rec.Component, crashComponentHALeadershipResume)
	}
	if !strings.Contains(rec.Summary, "leadership resume exploded") {
		t.Errorf("summary = %q, want the panic text", rec.Summary)
	}
}

// ── 3. the cap that was smaller than the label set ──────────────────────────

// maxCrashLabels is a cap on DYNAMIC labels. Culvert has none: every sink call
// site passes a compile-time constant or literal, which is why
// crashRecord.Component calls itself a "fixed enum". The cap was 32 and a
// source enumeration counted 62 fixed labels, so on a long-lived node the
// 33rd distinct component to crash lost its record, its log line and its audit
// entry for the rest of the process lifetime — and the slots are
// first-crash-wins and never pruned, so they went to the frequent request-path
// components rather than the rare, high-severity background rounds.
//
// This gate holds the invariant the fix restored. It is the one that matters
// for future rounds: every chaos round in this family adds components, so
// without it the cap is crossed again silently.
func TestCHAOS119_FixedCrashLabelSetFitsTheCardinalityCap(t *testing.T) {
	labels := chaos119FixedCrashLabels(t)
	if len(labels) == 0 {
		t.Fatal("enumerated no crash components — the enumerator is broken, not the tree")
	}
	t.Logf("fixed crash-component labels: %d (cap %d): %s", len(labels), maxCrashLabels, strings.Join(labels, " "))
	if len(labels) > maxCrashLabels {
		t.Errorf("the tree declares %d fixed crash-component labels but maxCrashLabels is %d. Past the cap, "+
			"crashThrottleAllow SUPPRESSES a new component outright — no record, no log line, no audit entry, "+
			"only the unlabeled total — and the counter folds it to component=\"other\". Raise the cap; do not "+
			"let a round add a component the sink cannot report.", len(labels), maxCrashLabels)
	}
}

// The overflow behaviour itself, pinned so the reasoning above stays true: past
// the cap the counter FOLDS (attribution lost, series intact) while the
// throttle SUPPRESSES (record, log and audit lost). They are not equivalent,
// and the second is why the cap was a reporting defect.
func TestCHAOS119_PastTheCapTheRecordIsLostNotJustTheLabel(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	// Fill every throttle slot. Seeded directly rather than through
	// maxCrashLabels recordCrash calls: the map IS the state the cap is
	// enforced against, and driving it through the sink would emit 128 crash
	// log lines for no additional coverage.
	crashThrottleMu.Lock()
	for i := 0; i < maxCrashLabels; i++ {
		crashThrottleLast["chaos119-filler-"+strconv.Itoa(i)] = 0
	}
	filled := len(crashThrottleLast)
	crashThrottleMu.Unlock()
	if filled < maxCrashLabels {
		t.Fatalf("seeded %d throttle slots, want %d", filled, maxCrashLabels)
	}
	before := atomic.LoadInt64(&statCrashSuppressed)
	recordCrash("chaos119-overflow-component", "", "the 129th component")

	if got := atomic.LoadInt64(&statCrashSuppressed); got <= before {
		t.Fatalf("suppressed = %d (was %d): the overflow path is not the throttle any more — "+
			"re-derive what a component past the cap actually loses before trusting the cap's comment",
			got, before)
	}
	rec, ok := lastCrashSnapshot()
	if ok && strings.Contains(rec.Summary, "the 129th component") {
		t.Error("a component past the cap stored a record: the cap's documented fail-closed behaviour changed")
	}
}

// chaos119FixedCrashLabels enumerates the distinct component labels reaching a
// panic sink across the whole module, resolving same-file string constants. It
// is deliberately a source enumeration rather than a hand-written list: a
// hand-written list is the thing CHAOS-118 §7.2 asked this family to stop
// relying on.
func chaos119FixedCrashLabels(t *testing.T) []string {
	t.Helper()
	// package main IS the module root in this repository, so walking the
	// package directory covers internal/* too — the sink is shared across the
	// module through obs.SetPanicSink, so the cap applies to every label in it.
	files := chaos119ParseModule(t, pkgSourceDir())
	consts := chaos119StringConsts(files)
	seen := map[string]bool{}
	for _, f := range files {
		chaos119CollectSinkLabels(f, consts, seen)
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// chaos119ParseModule parses every non-test Go file under root.
func chaos119ParseModule(t *testing.T, root string) []*ast.File {
	t.Helper()
	var out []*ast.File
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subtree is not this gate's business
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if f, perr := parser.ParseFile(fset, path, nil, 0); perr == nil {
			out = append(out, f)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// chaos119StringConsts maps every string-literal constant name to its value, so
// a sink call passing crashComponentX resolves to the label X carries.
func chaos119StringConsts(files []*ast.File) map[string]string {
	consts := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, nm := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						consts[nm.Name] = strings.Trim(bl.Value, `"`)
					}
				}
			}
		}
	}
	return consts
}

// chaos119SinkFuncs are the calls that put a component label into the crash
// plane: main's sink and guards, and the internal/obs seam they share.
var chaos119SinkFuncs = map[string]bool{
	"recordCrash": true, "runGuarded": true, "recoverGoroutine": true,
	"SafeCall": true, "Guard": true, "ReportPanic": true,
}

// chaos119CollectSinkLabels adds every FIXED label this file hands a sink.
//
// An unresolved identifier is a variable component; it is not a fixed label, so
// it is deliberately not counted. The cap exists for exactly that case and
// still fails closed on it.
func chaos119CollectSinkLabels(f *ast.File, consts map[string]string, seen map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if !chaos119SinkFuncs[name] {
			return true
		}
		switch a := call.Args[0].(type) {
		case *ast.BasicLit:
			if a.Kind == token.STRING {
				seen[strings.Trim(a.Value, `"`)] = true
			}
		case *ast.Ident:
			if v, ok := consts[a.Name]; ok {
				seen[v] = true
			}
		}
		return true
	})
}
