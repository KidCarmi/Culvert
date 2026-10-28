package main

// socks5_posture_gate_chaos_test.go — CHAOS-102 regression coverage for the
// pre-posture accept window.
//
// main binds the optional SOCKS5 listener at initSOCKS5 and restores the
// operator's GUI-persisted admission posture on the NEXT line, at
// initPersistentAdminState. startSOCKS5 returns only once the accept loop is
// serving, so for the whole of that next line the gateway relayed arbitrary
// TCP from ANY source IP: with no -ip-filter-mode and no YAML ip_filter_mode
// (the normal case when the allowlist was built in the GUI) applyAdminSecurity
// is the only writer of ipf/rl/connLimiter, and an unconfigured IPFilter
// admits everything.
//
// Three gates, in the order the evidence has to be read:
//
//  1. the DIFFERENTIAL ORACLE — the same listener, the same unconfigured
//     admission owners, with and without the gate. Without it the connection
//     negotiates (that is the pre-fix behaviour, measured, not asserted from
//     prose); with it the connection is refused.
//  2. the OBSERVABILITY gates — the refusal is counted, the first one is
//     logged, the count reaches /metrics, and the release reports the total.
//  3. the BOOT-ORDER WALL — an AST gate over main() and
//     loadPersistentAdminState. It is what survives a future reorder: it
//     accepts EITHER remedy (arm the gate before the bind, or move initSOCKS5
//     after initPersistentAdminState) and fails only if a boot ends up with
//     the listener serving and nothing closing the window.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

// armPostureGateForTest arms the pre-posture gate and guarantees the global is
// restored, per the conventions' global-test-cleanup rule. setupProxyTest
// resets state at test START only, so the restore has to be registered here.
func armPostureGateForTest(t *testing.T) {
	t.Helper()
	resetSOCKS5PostureGateForTest()
	t.Cleanup(resetSOCKS5PostureGateForTest)
	armSOCKS5PostureGate()
}

// socks5GreetAnswered dials addr, sends the no-auth greeting and reports
// whether the server answered it ([05 00]). A refused connection is closed by
// the handler before any negotiation, so the read fails.
func socks5GreetAnswered(t *testing.T, addr string) bool {
	t.Helper()
	conn, ok := socks5Greet(t, addr)
	t.Cleanup(func() { _ = conn.Close() })
	return ok
}

// ── 1. The differential oracle ──────────────────────────────────────────────

// TestCHAOS102_PrePostureWindow_RefusedWhenHeld_AdmittedWhenReleased is the
// measurement. Both halves run against the SAME listener with the SAME
// admission owners in their pre-posture state — an IPFilter whose mode was
// never set, a rate limiter that was never configured and a disabled
// connection limiter, which is exactly what main has on the line between
// initSOCKS5 and applyAdminSecurity. The only variable is the gate.
//
// The unfiltered half is deliberately asserted rather than assumed: it is the
// pre-fix behaviour of the shipped binary, and if a future change to the
// admission engine made an unconfigured filter DENY by default, this sweep's
// premise would be gone and the test should say so loudly rather than pass.
func TestCHAOS102_PrePostureWindow_RefusedWhenHeld_AdmittedWhenReleased(t *testing.T) {
	setupProxyTest(t)
	resetSOCKS5PostureGateForTest()
	t.Cleanup(resetSOCKS5PostureGateForTest)

	// The window's admission state, stated as a fact about the owners.
	const anySource = "192.0.2.77" // on no allowlist anywhere
	if !ipf.Allowed(anySource) {
		t.Fatal("premise gone: an unconfigured IPFilter no longer admits every address — " +
			"CHAOS-102's window depends on it, re-derive the finding before relaxing this gate")
	}
	if !rl.AllowAuto(anySource) {
		t.Fatal("premise gone: an unconfigured rate limiter no longer admits — re-derive CHAOS-102")
	}

	ln := startSOCKS5Listener(t)
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	// PRE-FIX: gate not armed. The handler consults the three uninstalled
	// globals, every one of them admits, and the session negotiates.
	if !socks5GreetAnswered(t, addr) {
		t.Fatal("control failed: with the gate released a SOCKS5 session must negotiate; " +
			"the refusal half below would prove nothing")
	}

	// POST-FIX: the same connection inside the window.
	armSOCKS5PostureGate()
	if socks5GreetAnswered(t, addr) {
		t.Fatal("CHAOS-102: a SOCKS5 session negotiated while the persisted admission posture " +
			"was still pending — the gateway is relaying unfiltered in the boot window")
	}

	// And the window is not sticky: once the posture restore has run the
	// listener serves normally again, without a rebind.
	releaseSOCKS5PostureGate()
	if !socks5GreetAnswered(t, addr) {
		t.Fatal("CHAOS-102: the listener did not resume after the posture was installed — " +
			"the gate must close a boot window, not disable SOCKS5")
	}
}

// ── 2. Observability ────────────────────────────────────────────────────────

// TestCHAOS102_RefusalsAreCountedAndTheFirstIsLogged pins the shape CHAOS-54
// established for this listener and scan_svc.go states outright: the counter
// carries the magnitude, the line carries the news. The window can cover a
// mass-reconnect storm, and this is the accept loop that was measured flooding
// 40 MB/s into a 50 MB rotating log and destroying the evidence of its own
// fault, so one line per boot is the budget.
func TestCHAOS102_RefusalsAreCountedAndTheFirstIsLogged(t *testing.T) {
	setupProxyTest(t)
	// LIFO cleanup: the logger must be captured BEFORE the listener is started
	// so the listener's drain-every-handler cleanup runs first and no handler
	// is still writing when the logger global is restored (socks5_log_injection
	// records this as a real -race failure otherwise).
	sink := captureLoggerForTest(t)
	armPostureGateForTest(t)

	ln := startSOCKS5Listener(t)
	t.Cleanup(func() { _ = ln.Close() })

	const attempts = 4
	for i := 0; i < attempts; i++ {
		if socks5GreetAnswered(t, ln.Addr().String()) {
			t.Fatalf("attempt %d negotiated inside the pre-posture window", i)
		}
	}
	// The handler counts from its own goroutine; wait for the count rather
	// than racing it.
	deadline := time.Now().Add(5 * time.Second)
	for socks5PostureRefusedTotal() < attempts && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := socks5PostureRefusedTotal(); got != attempts {
		t.Fatalf("refusal counter = %d, want %d — a refused connection that is not counted is a silent failure", got, attempts)
	}

	out := sink.String()
	if n := strings.Count(out, "SOCKS5 NOT_READY"); n != 1 {
		t.Fatalf("pre-posture refusal logged %d times across %d refusals, want exactly 1:\n%s", n, attempts, out)
	}
	// The one line has to be actionable on its own: it must name the gates
	// that are missing, not just that something was refused.
	for _, want := range []string{"admission posture", "culvert_socks5_posture_refused_total"} {
		if !strings.Contains(out, want) {
			t.Fatalf("refusal line does not mention %q — an operator cannot act on it:\n%s", want, out)
		}
	}
	// CWE-117: the client-controlled address is quoted, as sanitizeLog+%q
	// requires everywhere else on this path.
	if !strings.Contains(out, `"127.0.0.1"`) {
		t.Fatalf("client address not %%q-quoted in the refusal line:\n%s", out)
	}

	// The release reports the total exactly once, and only because there was
	// something to report.
	releaseSOCKS5PostureGate()
	if n := strings.Count(sink.String(), "admission posture installed"); n != 1 {
		t.Fatalf("release summary emitted %d times, want 1:\n%s", n, sink.String())
	}
}

// TestCHAOS102_ReleaseOnAQuietBootSaysNothing — "the window closed with no
// connections in it" is the expected outcome of every healthy boot. Logging it
// would train operators to read past the line that matters.
func TestCHAOS102_ReleaseOnAQuietBootSaysNothing(t *testing.T) {
	sink := captureLoggerForTest(t)
	armPostureGateForTest(t)
	releaseSOCKS5PostureGate()
	if out := sink.String(); strings.Contains(out, "admission posture installed") {
		t.Fatalf("a boot that refused nothing logged a summary:\n%s", out)
	}
}

// TestCHAOS102_GateLifecycleIsIdempotent covers the orderings a restart,
// a double release or a socks5_port: 0 appliance can produce. An unarmed
// release must be a no-op — and must NOT log a summary, which is the trap in
// reading the counter instead of the armed flag.
func TestCHAOS102_GateLifecycleIsIdempotent(t *testing.T) {
	sink := captureLoggerForTest(t)
	resetSOCKS5PostureGateForTest()
	t.Cleanup(resetSOCKS5PostureGateForTest)

	// The socks5_port: 0 appliance: never armed, so nothing is ever held.
	if socks5PostureHeld() {
		t.Fatal("the gate is held before any boot armed it — the zero value must be open")
	}
	releaseSOCKS5PostureGate() // no-op
	if socks5PostureHeld() {
		t.Fatal("an unarmed release left the gate held")
	}

	armSOCKS5PostureGate()
	armSOCKS5PostureGate() // idempotent
	if !socks5PostureHeld() {
		t.Fatal("the gate is not held after arming")
	}
	noteSOCKS5PostureRefusal("198.51.100.5")
	releaseSOCKS5PostureGate()
	releaseSOCKS5PostureGate() // idempotent
	if socks5PostureHeld() {
		t.Fatal("the gate is still held after release")
	}
	// The count survives the release — it is boot evidence an operator reads
	// afterwards, not a live gauge that resets with the window.
	if got := socks5PostureRefusedTotal(); got != 1 {
		t.Fatalf("refusal count = %d after release, want 1 (the counter is cumulative evidence)", got)
	}
	// ...and the summary is reported once, by the release that actually held
	// the gate, not again by the second one.
	if n := strings.Count(sink.String(), "admission posture installed"); n != 1 {
		t.Fatalf("release summary emitted %d times across two releases, want 1:\n%s", n, sink.String())
	}
}

// TestCHAOS102_MetricsExposeTheWindow — the log rotates; the window is
// milliseconds on a healthy volume. /metrics is where the evidence has to be
// durable, and the gauge is what a scrape taken DURING a slow boot shows.
func TestCHAOS102_MetricsExposeTheWindow(t *testing.T) {
	resetSOCKS5HealthForTest()
	t.Cleanup(resetSOCKS5HealthForTest)
	armPostureGateForTest(t)

	// The series are emitted only on a node where SOCKS5 is configured, the
	// documented socks5/cluster_ca gauge precedent.
	noteSOCKS5Configured(1080)
	noteSOCKS5PostureRefusal("203.0.113.9")
	noteSOCKS5PostureRefusal("203.0.113.9")

	body := renderMetricsForTest(t)
	for _, want := range []string{
		"culvert_socks5_posture_pending 1",
		"culvert_socks5_posture_refused_total 2",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics is missing %q:\n%s", want, socks5MetricLinesForTest(body))
		}
	}

	releaseSOCKS5PostureGate()
	body = renderMetricsForTest(t)
	if !strings.Contains(body, "culvert_socks5_posture_pending 0") {
		t.Fatalf("posture_pending did not clear after the release:\n%s", socks5MetricLinesForTest(body))
	}
	if !strings.Contains(body, "culvert_socks5_posture_refused_total 2") {
		t.Fatalf("the refusal total did not survive the release:\n%s", socks5MetricLinesForTest(body))
	}
}

// socks5MetricLinesForTest trims a scrape to the socks5 series so a failure
// message is readable.
func socks5MetricLinesForTest(body string) string {
	var keep []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "socks5") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

// ── 3. The boot-order wall ──────────────────────────────────────────────────

// TestCHAOS102_Wall_NoListenerServesBeforeThePostureIsClosed is the regression
// gate, and it is written to accept EITHER remedy.
//
// The invariant is not "initSOCKS5 arms the gate" and not "initSOCKS5 runs
// late" — it is that no boot leaves the SOCKS5 accept loop serving with
// nothing closing the pre-posture window. So the wall passes when
// initPersistentAdminState precedes initSOCKS5 in main() (the reorder remedy,
// which makes the gate unnecessary) OR when initSOCKS5 arms the gate (the
// shipped remedy). It fails when neither holds, which is precisely the state
// the 2026-10-18 sweep found and the state a future refactor would silently
// restore by deleting one line.
func TestCHAOS102_Wall_NoListenerServesBeforeThePostureIsClosed(t *testing.T) {
	file := parseMainPkgFileForTest(t, "main.go")

	mainFn := funcDeclForTest(t, file, "main")
	socksAt := callStatementIndexForTest(mainFn, "initSOCKS5")
	postureAt := callStatementIndexForTest(mainFn, "initPersistentAdminState")
	if socksAt < 0 || postureAt < 0 {
		t.Fatalf("main() no longer calls initSOCKS5 (%d) / initPersistentAdminState (%d) directly — "+
			"re-derive CHAOS-102's window against the new boot shape before editing this wall", socksAt, postureAt)
	}

	initSocks := funcDeclForTest(t, file, "initSOCKS5")
	arms := calleeNames(initSocks)["armSOCKS5PostureGate"]

	switch {
	case postureAt < socksAt:
		// The reorder remedy: the posture is installed before the bind, so
		// there is no window to gate.
		return
	case arms:
		// The shipped remedy. Guard the half an AST cannot see by position
		// alone: the arm has to be reachable from initSOCKS5 itself, which is
		// what being in its callee set means.
		return
	default:
		t.Fatalf("CHAOS-102 regression: main() calls initSOCKS5 (stmt %d) BEFORE "+
			"initPersistentAdminState (stmt %d) and initSOCKS5 no longer arms the pre-posture gate. "+
			"startSOCKS5 returns with the accept loop serving, so SOCKS5 relays from any source IP, "+
			"unrate-limited and uncapped, until applyAdminSecurity runs. Either arm the gate again or "+
			"move initSOCKS5 after initPersistentAdminState", socksAt, postureAt)
	}
}

// TestCHAOS102_Wall_ThePostureRestoreReleasesTheGate pins the other end. A
// gate that is armed and never released is a permanently dead listener, so
// this is the gate on the gate: loadPersistentAdminState must release it, and
// must do so AFTER the LoadAdminSettings call that installs the posture —
// releasing first would reopen the window it exists to close.
func TestCHAOS102_Wall_ThePostureRestoreReleasesTheGate(t *testing.T) {
	file := parseMainPkgFileForTest(t, "persistent_admin_state_startup.go")
	fn := funcDeclForTest(t, file, "loadPersistentAdminState")

	loadAt := callStatementIndexForTest(fn, "LoadAdminSettings")
	releaseAt := callStatementIndexForTest(fn, "releaseSOCKS5PostureGate")
	if loadAt < 0 {
		t.Fatal("loadPersistentAdminState no longer calls LoadAdminSettings — re-derive CHAOS-102")
	}
	if releaseAt < 0 {
		t.Fatal("CHAOS-102 regression: loadPersistentAdminState does not release the SOCKS5 pre-posture " +
			"gate. initSOCKS5 arms it before binding, so without this call the listener refuses every " +
			"connection for the life of the process")
	}
	if releaseAt < loadAt {
		t.Fatalf("CHAOS-102 regression: the pre-posture gate is released at stmt %d, BEFORE "+
			"LoadAdminSettings at stmt %d — that reopens the window the gate exists to close", releaseAt, loadAt)
	}
}

// parseMainPkgFileForTest parses one non-test file of package main.
func parseMainPkgFileForTest(t *testing.T, name string) *ast.File {
	t.Helper()
	src, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return file
}

func funcDeclForTest(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

// callStatementIndexForTest returns the index of the top-level statement in
// fn's body that contains a call to name (anywhere inside it, including nested
// in an if/for), or -1. The INDEX is what the ordering assertions compare, so
// a call moved inside a conditional still reports the position of the
// statement that guards it — which is the position that runs.
func callStatementIndexForTest(fn *ast.FuncDecl, name string) int {
	if fn == nil || fn.Body == nil {
		return -1
	}
	for i, stmt := range fn.Body.List {
		found := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
				found = true
			}
			return !found
		})
		if found {
			return i
		}
	}
	return -1
}

// ── Negative controls for the wall's own logic ──────────────────────────────

// TestCHAOS102_Wall_NegativeControls proves the wall can fail. Each control is
// a synthetic boot shape; the helpers must classify all four correctly, or an
// always-passing wall would report the defect fixed forever.
func TestCHAOS102_Wall_NegativeControls(t *testing.T) {
	controls := map[string]struct {
		src                    string
		wantSocks, wantRelease int
	}{
		"the pre-fix shape — bind first, no arm": {`package main
func main() {
	initSOCKS5(s)
	initPersistentAdminState(s)
}
func initSOCKS5(s *startupState) { s.socks5Srv = startSOCKS5(1) }`, 0, -1},
		"the shipped shape — bind first, armed": {`package main
func main() {
	initSOCKS5(s)
	initPersistentAdminState(s)
}
func initSOCKS5(s *startupState) { armSOCKS5PostureGate(); s.socks5Srv = startSOCKS5(1) }`, 0, -1},
		"the reorder remedy": {`package main
func main() {
	initPersistentAdminState(s)
	initSOCKS5(s)
}
func initSOCKS5(s *startupState) { s.socks5Srv = startSOCKS5(1) }`, 1, -1},
		"a call nested in a conditional still reports its statement": {`package main
func main() {
	a()
	if cond {
		initSOCKS5(s)
	}
}
func initSOCKS5(s *startupState) {}`, 1, -1},
	}
	for name, tc := range controls {
		file, err := parser.ParseFile(token.NewFileSet(), "control.go", tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		mainFn := funcDeclForTest(t, file, "main")
		if got := callStatementIndexForTest(mainFn, "initSOCKS5"); got != tc.wantSocks {
			t.Errorf("%s: initSOCKS5 statement index = %d, want %d", name, got, tc.wantSocks)
		}
		if got := callStatementIndexForTest(mainFn, "releaseSOCKS5PostureGate"); got != tc.wantRelease {
			t.Errorf("%s: release index = %d, want %d", name, got, tc.wantRelease)
		}
	}

	// And the arm detection: present in one shape, absent in the other.
	armed, _ := parser.ParseFile(token.NewFileSet(), "c.go", `package main
func initSOCKS5(s *startupState) { armSOCKS5PostureGate(); startSOCKS5(1) }`, parser.SkipObjectResolution)
	bare, _ := parser.ParseFile(token.NewFileSet(), "c.go", `package main
func initSOCKS5(s *startupState) { startSOCKS5(1) }`, parser.SkipObjectResolution)
	if !calleeNames(funcDeclForTest(t, armed, "initSOCKS5"))["armSOCKS5PostureGate"] {
		t.Error("the wall cannot see an arm that is present")
	}
	if calleeNames(funcDeclForTest(t, bare, "initSOCKS5"))["armSOCKS5PostureGate"] {
		t.Error("the wall sees an arm that is absent — it would pass on the pre-fix shape")
	}
}

// ── The negative half of the sweep: the listeners with no window ────────────

// TestCHAOS102_Wall_PrimaryDataPathHasNoPrePostureWindow pins the asymmetry
// that makes CHAOS-102 a defect rather than a posture. The HTTP/HTTPS plane —
// the primary data path — is the thing SOCKS5 was measured against: its
// listener is opened by runProxyUntilShutdown, the LAST statement of main,
// long after every posture is installed. buildAndStartProxyServer must only
// CONSTRUCT the server. If a future change makes it listen, the primary plane
// acquires the same window on a far larger blast radius and this wall is where
// that gets caught.
func TestCHAOS102_Wall_PrimaryDataPathHasNoPrePostureWindow(t *testing.T) {
	file := parseMainPkgFileForTest(t, "main.go")
	build := funcDeclForTest(t, file, "buildAndStartProxyServer")
	callees := calleeNames(build)
	for _, listen := range []string{"ListenAndServe", "ListenAndServeTLS", "Listen", "Serve"} {
		if callees[listen] {
			t.Fatalf("buildAndStartProxyServer now calls %s: the primary HTTP/HTTPS plane has acquired a "+
				"pre-posture accept window (CHAOS-102). It is constructed at main.go's init block but must "+
				"not START serving until after initPersistentAdminState", listen)
		}
	}

	mainFn := funcDeclForTest(t, file, "main")
	postureAt := callStatementIndexForTest(mainFn, "initPersistentAdminState")
	for _, late := range []string{"buildAndStartProxyServer", "startAdminUI", "runProxyUntilShutdown"} {
		at := callStatementIndexForTest(mainFn, late)
		if at < 0 {
			t.Fatalf("main() no longer calls %s — re-derive CHAOS-102's negative half", late)
		}
		if at < postureAt {
			t.Fatalf("%s now runs at stmt %d, BEFORE initPersistentAdminState at stmt %d: it has acquired "+
				"the pre-posture accept window CHAOS-102 closed on SOCKS5", late, at, postureAt)
		}
	}
}

// ── Sanity: the gate costs the request path nothing measurable ──────────────

// TestCHAOS102_ReleasedGateIsOneAtomicLoad documents the steady-state cost of
// the check that now sits first in handleSOCKS5: an atomic.Bool load, on a
// word that is written at most twice in the life of the process and therefore
// stays in every core's cache. Asserting a latency number here would be a
// flake, so this asserts only the property that makes the cost reasoning
// valid — the released gate never allocates and never blocks.
func TestCHAOS102_ReleasedGateIsOneAtomicLoad(t *testing.T) {
	resetSOCKS5PostureGateForTest()
	t.Cleanup(resetSOCKS5PostureGateForTest)
	if allocs := testing.AllocsPerRun(200, func() { _ = socks5PostureHeld() }); allocs != 0 {
		t.Fatalf("socks5PostureHeld allocates %v per call — it is the first statement of every SOCKS5 connection", allocs)
	}
}
