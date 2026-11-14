package main

// chaos119_round_loop_registry_test.go — CHAOS-119: the MECHANICAL discovery
// gate CHAOS-116 §8.2 called for and CHAOS-118 §7.2 handed forward.
//
// The problem it solves is stated most plainly in CHAOS-118's own residual risk
// 4: "this family of defects is still found by reading, not by CI. Eleven
// workers are registered because eleven were noticed. The honest statement is
// that the KNOWN set is guarded and audited, not that the package contains no
// twelfth detached loop."
//
// chaos105Workers is a hand-written list, so every gate built on it inherits
// that limit: a background loop added tomorrow is invisible to all of them
// until someone remembers to add a row. This gate inverts the direction. It
// DISCOVERS background round loops from the AST and fails on one it does not
// recognise, so the registry can no longer be silently incomplete.
//
// Scope, stated precisely because an over-broad gate is a gate people delete:
// it covers BACKGROUND ROUND LOOPS, the CHAOS-105 family's subject — a `for`
// whose `select` waits on both a cancellation channel and a timer/ticker. That
// is the shape whose fault repeats forever and whose containment decision is
// therefore load-bearing. It is deliberately NOT "every detached goroutine":
// the package has 93 `go` statements, most of them request-scoped relays and
// alert fan-outs with their own planes (proxyCrashGuard, recoverGoroutine, the
// relay defer), and a registry of those would be churn rather than a gate.
//
// It found two things on the tree it was written against. First, it is the
// reason Refresher.RunTicker is now guarded: a round loop driving a
// verify/persist/publish cycle over third-party catalog bytes, with no
// containment and no production caller — a trap armed for whoever wires it.
// Second, it is what forced every row below to NAME its guard mechanism, which
// is how the two bespoke-recover loops in §2 of the reporting gate were found.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// chaos119RoundLoop is one discovered background round loop and the containment
// contract its body must satisfy.
type chaos119RoundLoop struct {
	file string
	fn   string
	// guard is the token the loop body must contain. A loop whose round is
	// guarded directly names runGuarded/obs.SafeCall; one that delegates to a
	// guarding helper names that helper, so the chain is written down rather
	// than inferred.
	guard string
	// detached records whether the loop is started by a `go` statement in this
	// package. A loop that is NOT detached runs on a caller's goroutine — for
	// the rows below, a shutdown hook, whose own registry recovers — so its
	// containment contract is the caller's, not this gate's.
	detached bool
	// why explains a row that is exempt from the guard requirement.
	why string
}

// chaos119KnownRoundLoops is the expected inventory. A loop the discovery pass
// finds that is absent here fails the gate; a row here the pass no longer finds
// fails it too, so a renamed or deleted loop cannot leave a stale row behind.
var chaos119KnownRoundLoops = []chaos119RoundLoop{
	// ── detached background rounds, guarded directly ──
	{file: "cdr_health.go", fn: "startCDRHealthPoller", guard: "runGuarded(", detached: false,
		why: "started by loadCDRHealthPoller through a closure the discovery pass sees as inline"},
	{file: "connlimit_startup.go", fn: "rateLimitCleanupLoop", guard: "runGuarded(", detached: true},
	{file: "controlplane_client.go", fn: "metricsLoop", guard: "runGuarded(", detached: true},
	{file: "controlplane_client.go", fn: "rateLimitGossipLoop", guard: "runGuarded(", detached: true},
	{file: "controlplane_client.go", fn: "revocationSyncLoop", guard: "runGuarded(", detached: true},
	{file: "controlplane_client.go", fn: "auditPushLoop", guard: "runGuarded(", detached: true},
	{file: "dp_enrollment.go", fn: "dpCertRenewalLoop", guard: "runGuarded(", detached: true},
	{file: "events.go", fn: "run", guard: "runGuarded(", detached: true},
	{file: "idp_metadata_health.go", fn: "runIdPMetadataDegradationWatchdog", guard: "runGuarded(", detached: true},
	{file: "logstore.go", fn: "startLogStoreRetention", guard: "runGuarded(", detached: false,
		why: "the loop is inline in the go func() this function detaches"},
	{file: "mcp_health_plane.go", fn: "startMCPHealthAlertPoller", guard: "runGuarded(", detached: false,
		why: "the loop is inline in the go func() this function detaches"},
	{file: "mcp_telemetry.go", fn: "flushLoop", guard: "runGuarded(", detached: true},
	{file: "mcp_telemetry.go", fn: "exportLoop", guard: "runGuarded(", detached: true},
	{file: "mcp_tooltrust.go", fn: "startToolTrustReconcileLoop", guard: "runGuarded(", detached: false,
		why: "the loop is inline in the go func() this function detaches"},
	{file: "metrics.go", fn: "startHitCounterPersistence", guard: "runGuarded(", detached: false,
		why: "the loop is inline in the go func() this function detaches"},
	{file: "rootca_recovery.go", fn: "runInspectionCARecoveryLoop", guard: "runGuarded(", detached: true},
	{file: "support_debug_level.go", fn: "startDebugLevelWatchdog", guard: "runGuarded(", detached: true},
	{file: "support_upload_worker.go", fn: "startSupportUploadWorker", guard: "runGuarded(", detached: true},
	// Discovered by the structural pass, and already guarded — these three are
	// the reason the pass matches a select ARM rather than the loop's text.
	// The first draft searched for "ticker.C" and missed every loop that names
	// its ticker `t`, which was thirteen of them.
	{file: "decryption_trend.go", fn: "startDecCoverageSampler", guard: "runGuarded(", detached: true},
	{file: "enrollment.go", fn: "StartHeartbeatMonitor", guard: "runGuarded(", detached: false,
		why: "the loop is inline in the go func() this function detaches"},
	{file: "scan_signature_watch.go", fn: "startScanSignatureWatch", guard: "runGuarded(", detached: true},
	{file: "syslog_health.go", fn: "startSyslogHealthWatchdog", guard: "runGuarded(", detached: true},
	{file: "ui_support.go", fn: "startSupportRetentionJanitor", guard: "runGuarded(", detached: true},
	{file: "release_catalog_refresher.go", fn: "RunTicker", guard: "runGuarded(", detached: false,
		why: "no production caller yet; guarded by CHAOS-119 before it acquires one"},

	// ── detached background rounds that delegate to a guarding helper ──
	{file: "ca.go", fn: "StartCAAutoRotation", guard: "runGuarded(", detached: false,
		why: "the loop is inline in the go func() this function detaches"},
	{file: "controlplane_client.go", fn: "pollLoop", guard: "guardedConfigRound(", detached: true},
	{file: "ha.go", fn: "standbyLoop", guard: "guardedTick(", detached: false,
		why: "detached by StartAsStandbyWithUndo through a closure, which the pass sees as inline"},
	{file: "ha_lease.go", fn: "leaseKeepaliveLoop", guard: "leaseRenewRound(", detached: false,
		why: "detached by startLeaseKeepalive through a closure, which the pass sees as inline"},
	{file: "release_refresh.go", fn: "runCatalogRefreshLoop", guard: "refreshLoopTick(", detached: true},
	{file: "release_refresh.go", fn: "runCatalogStaleWatchdogLoop", guard: "staleWatchdogTick(", detached: true},
	{file: "saas_feed_scheduler.go", fn: "run", guard: "s.runTick(", detached: true},

	// ── loops that are NOT detached: the caller owns containment ──
	{file: "main_shutdown.go", fn: "drainActiveTunnels", detached: false,
		why: "a shutdown hook, run synchronously by internal/shutdown's registry, which recovers per hook"},
	{file: "proxy_tunnel_drain.go", fn: "settleAfterForceClose", detached: false,
		why: "called from drainActiveTunnels inside the same recovered shutdown hook"},
	{file: "mcp_telemetry.go", fn: "exportWithRetry", detached: false,
		why: "the inner retry of one export step; every caller is already inside a runGuarded round"},
	{file: "release_catalog_http.go", fn: "doGet", detached: false,
		why: "request-scoped HTTP retry on the caller's goroutine, not a background round"},
	{file: "release_dispatch_exec.go", fn: "WaitOp", detached: false,
		why: "a synchronous wait on the dispatch caller's goroutine; the dispatch worker it serves is guarded under crashComponentReleaseDispatch"},
}

// TestCHAOS119_EveryBackgroundRoundLoopIsRegistered is the discovery gate. It
// is the half CHAOS-118 §7.2 asked for: the inventory is now checked against
// the tree, not the tree against the inventory.
func TestCHAOS119_EveryBackgroundRoundLoopIsRegistered(t *testing.T) {
	found := chaos119DiscoverRoundLoops(t)
	if len(found) == 0 {
		t.Fatal("discovered no background round loops — the discovery pass is broken, not the tree. " +
			"A gate that finds nothing passes everything.")
	}

	known := map[string]chaos119RoundLoop{}
	for _, l := range chaos119KnownRoundLoops {
		known[l.file+"/"+l.fn] = l
	}

	for key := range found {
		if _, ok := known[key]; !ok {
			t.Errorf("unregistered background round loop %s. Go terminates the process on an unrecovered "+
				"panic in ANY goroutine, so a detached round loop must run its round under runGuarded (or a "+
				"helper that does) and be registered in chaos119KnownRoundLoops with the guard it uses. "+
				"If the loop is NOT detached, register it with a `why` naming the caller that owns "+
				"containment.", key)
		}
	}
	for key := range known {
		if !found[key] {
			t.Errorf("registered round loop %s is no longer discovered: the row is stale. Remove it, or "+
				"fix the loop if its select lost its cancellation or timer arm.", key)
		}
	}
}

// TestCHAOS119_EveryRegisteredRoundLoopHonoursItsGuard holds the second half:
// a registered loop must still contain the guard its row names. This is what
// catches a `b.tick()` put back in place of the guarded call — the mutation
// CHAOS-105 recorded as behaviourally invisible without per-worker fault
// injection.
func TestCHAOS119_EveryRegisteredRoundLoopHonoursItsGuard(t *testing.T) {
	for _, l := range chaos119KnownRoundLoops {
		t.Run(l.file+"/"+l.fn, func(t *testing.T) {
			if l.guard == "" {
				if l.why == "" {
					t.Fatalf("%s/%s is registered with neither a guard nor a reason", l.file, l.fn)
				}
				return // containment is the caller's, per the row's reason
			}
			body := funcSource(t, l.file, l.fn)
			if !strings.Contains(body, l.guard) {
				t.Errorf("%s/%s no longer contains %q. Its round must stay guarded: a panic in a "+
					"background round is otherwise a total outage of an in-line security gateway, "+
					"the proxy data plane included.", l.file, l.fn, l.guard)
			}
		})
	}
}

// TestCHAOS119_DiscoveryPassRejectsAnUnguardedLoop is the gate's own negative
// control. A discovery gate that cannot be shown to FAIL is decoration, and
// §7.2's complaint was precisely about assertions nobody had falsified.
func TestCHAOS119_DiscoveryPassRejectsAnUnguardedLoop(t *testing.T) {
	const synthetic = `package main

import (
	"context"
	"time"
)

func syntheticUnregisteredWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doSomethingDangerous()
		}
	}
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.go")
	if err := os.WriteFile(path, []byte(synthetic), 0o600); err != nil {
		t.Fatalf("write synthetic: %v", err)
	}
	loops := chaos119RoundLoopsIn(t, dir)
	if !loops["synthetic.go/syntheticUnregisteredWorker"] {
		t.Fatal("the discovery pass did not find a ticker+ctx.Done round loop. It would therefore not " +
			"find a real one either, and every other assertion in this file is vacuous.")
	}
}

// chaos119DiscoverRoundLoops runs the discovery pass over package main.
func chaos119DiscoverRoundLoops(t *testing.T) map[string]bool {
	t.Helper()
	return chaos119RoundLoopsIn(t, pkgSourceDir())
}

// chaos119RoundLoopsIn returns "<file>/<func>" for every background round loop
// in dir's non-test Go files.
//
// The shape it matches: a `for` statement containing a `select` with at least
// two communication clauses, where the loop's source mentions BOTH a
// cancellation channel (ctx.Done, a stop channel) and a timer/ticker channel.
// Both arms are required on purpose. A select on a cancellation channel alone
// is a wait, not a round loop; a ticker alone is a loop nothing can stop, which
// is a different defect with its own gates (shutdown ownership).
func chaos119RoundLoopsIn(t *testing.T, dir string) map[string]bool {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	sort.Strings(paths)
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") {
			continue
		}
		parsedFile, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", base, err)
		}
		for _, decl := range parsedFile.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				loop, ok := n.(*ast.ForStmt)
				if !ok || !chaos119IsRoundLoop(loop) {
					return true
				}
				out[base+"/"+fn.Name.Name] = true
				return true
			})
		}
	}
	return out
}

func chaos119IsRoundLoop(loop *ast.ForStmt) bool {
	found := false
	ast.Inspect(loop, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectStmt)
		if !ok || len(sel.Body.List) < 2 {
			return true
		}
		cancellable, timed := false, false
		for _, arm := range sel.Body.List {
			clause, ok := arm.(*ast.CommClause)
			if !ok || clause.Comm == nil {
				continue // default: neither
			}
			if chaos119ArmIsCancellation(clause.Comm) {
				cancellable = true
			}
			if chaos119ArmIsTimer(clause.Comm) {
				timed = true
			}
		}
		if cancellable && timed {
			found = true
		}
		return !found
	})
	return found
}

// chaos119ArmIsCancellation matches the two cancellation shapes in this tree:
// a receive on ctx.Done() and a receive on a stop/quit channel. Matched
// structurally (a call to a method named Done, or a receive from an identifier
// whose name is a stop channel) rather than by searching the loop's text, so a
// loop does not escape the gate by naming its ticker something unexpected —
// which is exactly how the first draft of this gate missed thirteen loops that
// call their ticker `t` instead of `ticker`.
func chaos119ArmIsCancellation(comm ast.Stmt) bool {
	found := false
	ast.Inspect(comm, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Done" {
				found = true
			}
		case *ast.UnaryExpr:
			if e.Op != token.ARROW {
				return true
			}
			if id, ok := e.X.(*ast.Ident); ok {
				switch id.Name {
				case "stop", "stopCh", "quit", "done", "doneCh", "shutdown":
					found = true
				}
			}
		}
		return true
	})
	return found
}

// chaos119ArmIsTimer matches a receive from a timer/ticker channel: the stdlib
// `.C` field, a clock seam's `.C()` accessor, or time.After. The `C` name is
// the convention every timer type in this tree follows, including the injected
// clock in saas_feed_scheduler.go.
func chaos119ArmIsTimer(comm ast.Stmt) bool {
	found := false
	ast.Inspect(comm, func(n ast.Node) bool {
		u, ok := n.(*ast.UnaryExpr)
		if !ok || u.Op != token.ARROW {
			return true
		}
		switch x := u.X.(type) {
		case *ast.SelectorExpr: // ticker.C / t.C / timer.C
			if x.Sel.Name == "C" {
				found = true
			}
		case *ast.CallExpr:
			// timer.C() (clock seam) / time.After(d) / time.Tick(d)
			if f, ok := x.Fun.(*ast.SelectorExpr); ok {
				switch f.Sel.Name {
				case "C", "After", "Tick":
					found = true
				}
			}
		}
		return true
	})
	return found
}
