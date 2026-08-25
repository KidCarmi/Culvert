package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// withMCPStatus installs an activation status for the duration of a test and
// restores the previous one.
func withMCPStatus(t *testing.T, act mcpObserveActivation) {
	t.Helper()
	prev := getMCPObserveStatus()
	setMCPObserveStatus(act)
	resetMCPHealthAlertForTest()
	t.Cleanup(func() {
		setMCPObserveStatus(prev)
		resetMCPHealthAlertForTest()
	})
}

// RISK-027. MCP must be REPORT-ONLY for SWG readiness. MCP is disabled by
// default, optional when enabled, and shares no state with the Secure Web Gateway
// data path — so an MCP fault must never pull a healthy proxy out of rotation.
// Making it gating would turn an optional capability into an availability SPOF for
// the primary product.
func TestMCPHealth_FaultIsReportOnlyForSWGReadiness(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "tls_material_invalid"})

	report, code := computeReadiness()
	row, ok := report.Checks["mcp_gateway"]
	if !ok {
		t.Fatal("a requested-but-failed MCP capability must appear on /readyz")
	}
	if row.Status != "fail" {
		t.Fatalf("mcp_gateway row = %q, want fail", row.Status)
	}
	if code != 200 || report.Status != "ready" {
		t.Fatalf("an MCP fault must NOT gate SWG readiness: status=%q code=%d", report.Status, code)
	}
}

// A node that never requested MCP emits no row at all. An always-present row
// would make every node look like it has the capability, and a failing row on a
// node that never wanted MCP is pure noise.
func TestMCPHealth_AbsentWhenNeverRequested(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveDisabled})

	report, code := computeReadiness()
	if _, ok := report.Checks["mcp_gateway"]; ok {
		t.Fatal("a node that never requested MCP must emit no mcp_gateway row")
	}
	if code != 200 {
		t.Fatalf("readiness code = %d, want 200", code)
	}
	if got := computeHealth().MCP; got != "" {
		t.Fatalf("/healthz mcp = %q, want empty on a node without MCP", got)
	}
}

// The /readyz detail must be a FIXED string. The endpoint is unauthenticated on
// the proxy port, and the activation reason can name a configuration fault (a
// certificate path, a policy file) that fingerprints the node's setup.
func TestMCPHealth_ReadinessDetailNeverLeaksTheReason(t *testing.T) {
	// Named for what it IS — a reason that would fingerprint the node — rather than
	// anything matching gosec's G101 credential-name patterns. The value deliberately
	// looks like a real activation fault, because a synthetic reason that looked
	// harmless would not test the leak this row exists to prevent.
	const fingerprintingReason = "tls_key_file_unreadable_/etc/culvert/private/mcp.key"
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: fingerprintingReason})

	report, _ := computeReadiness()
	row := report.Checks["mcp_gateway"]
	if row == nil {
		t.Fatal("missing mcp_gateway row")
	}
	if strings.Contains(row.Detail, fingerprintingReason) || strings.Contains(row.Detail, "/etc/") {
		t.Fatalf("the unauthenticated readiness detail leaked the activation reason: %q", row.Detail)
	}
}

// /healthz reports the bounded capability state, and it must be the LIVE state,
// not a stored configuration claim.
func TestMCPHealth_HealthzReportsTheCapabilityState(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "x"})
	if got := computeHealth().MCP; got != string(mcpCapInvalid) {
		t.Fatalf("/healthz mcp = %q, want %q", got, mcpCapInvalid)
	}
}

// Metrics must be emitted only for a node that requested MCP: `up 0` on a node
// that never had MCP is indistinguishable from a dead listener, and the paging
// rule is `== 0`.
func TestMCPHealth_MetricsAbsentWhenNeverRequested(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveDisabled})
	body := renderMetricsForTest(t)
	// The capability-health series must be absent. (The pre-existing
	// culvert_mcp_telemetry_ready{capability=...} export series is emitted by the
	// telemetry plane and is out of scope for this row.)
	for _, absent := range []string{
		"culvert_mcp_gateway_up", "culvert_mcp_gateway_faulted",
		"culvert_mcp_requests_total", "culvert_mcp_auth_failures_total",
		"culvert_mcp_admission_rejected_total", "culvert_mcp_telemetry_composed",
	} {
		if strings.Contains(body, absent) {
			t.Fatalf("a node without MCP must emit no %s series", absent)
		}
	}
}

// ...and present, with a faulted gauge, once it was requested and failed.
func TestMCPHealth_MetricsReportAFaultedCapability(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "x"})
	body := renderMetricsForTest(t)
	for _, want := range []string{
		"culvert_mcp_gateway_up 0",
		"culvert_mcp_gateway_faulted 1",
		"culvert_mcp_requests_total",
		"culvert_mcp_auth_failures_total",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q", want)
		}
	}
}

// The alert fires ONCE per episode and re-arms only on OBSERVED recovery — never
// on elapsed time. A per-evaluation alert would page continuously for one fault.
func TestMCPHealth_AlertFiresOncePerEpisode(t *testing.T) {
	var fired []string
	prev := fireMCPGatewayAlert
	fireMCPGatewayAlert = func(d string) { fired = append(fired, d) }
	t.Cleanup(func() { fireMCPGatewayAlert = prev })

	faulted := mcpHealthSnapshot{Configured: true, State: mcpCapDegraded}
	serving := mcpHealthSnapshot{Configured: true, State: mcpCapReady, ListenerReady: true}

	resetMCPHealthAlertForTest()
	evaluateMCPHealthAlert(faulted)
	evaluateMCPHealthAlert(faulted)
	evaluateMCPHealthAlert(faulted)
	if len(fired) != 1 {
		t.Fatalf("alert fired %d times for one episode, want 1", len(fired))
	}
	// Observed recovery re-arms; a NEW episode alerts again.
	evaluateMCPHealthAlert(serving)
	evaluateMCPHealthAlert(faulted)
	if len(fired) != 2 {
		t.Fatalf("a second episode after observed recovery must alert again (got %d)", len(fired))
	}
	// The detail is a bounded state label, never the activation reason: Dispatch
	// dedups on event+detail, so an unbounded detail defeats deduplication.
	for _, d := range fired {
		if len(d) > 80 || strings.Contains(d, "/") {
			t.Fatalf("alert detail is not bounded/safe: %q", d)
		}
	}
}

// Draining is an orderly shutdown, not a fault: it must not page.
func TestMCPHealth_DrainingIsNotAFault(t *testing.T) {
	for _, st := range []mcpCapabilityState{mcpCapDraining, mcpCapReady, mcpCapStarting} {
		if (mcpHealthSnapshot{Configured: true, State: st}).Faulted() {
			t.Fatalf("state %q must not be a fault", st)
		}
	}
	for _, st := range []mcpCapabilityState{mcpCapInvalid, mcpCapDegraded, mcpCapStopped} {
		if !(mcpHealthSnapshot{Configured: true, State: st}).Faulted() {
			t.Fatalf("state %q must be a fault", st)
		}
	}
	// A capability nobody requested is never a fault, whatever its state field says.
	if (mcpHealthSnapshot{Configured: false, State: mcpCapDegraded}).Faulted() {
		t.Fatal("an unrequested capability must never be a fault")
	}
}

// renderMetricsForTest renders the Prometheus exposition body.
func renderMetricsForTest(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	return w.Body.String()
}

// Prometheus forbids one metric NAME carrying two different label sets. The MCP
// namespace already had culvert_mcp_telemetry_ready{capability=...} from the
// telemetry plane, so the capability-health gauges must not collide with any
// existing series.
func TestMCPHealth_MetricNamesDoNotCollide(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "x"})
	body := renderMetricsForTest(t)

	seen := map[string]string{} // metric name -> first rendered sample line
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "culvert_mcp_") {
			continue
		}
		name, labels := line, ""
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
			if line[i] == '{' {
				labels = "labelled"
			}
		}
		if prev, ok := seen[name]; ok && prev != labels {
			t.Fatalf("metric %s is rendered with two different label shapes (%q vs %q): "+
				"a single name must have one label set", name, prev, labels)
		}
		seen[name] = labels
	}
	if len(seen) == 0 {
		t.Fatal("no culvert_mcp_* samples rendered; the fixture proves nothing")
	}
}

// RISK-027. The alert must not depend on being scraped.
//
// evaluateMCPHealthAlert also runs from mcpHealthFieldValue, i.e. whenever
// something reads /healthz. On its own that inverts the relationship an alert has
// with monitoring: the alert exists to tell an operator to look, so making it fire
// only when someone is already looking means a node whose MCP listener dies — on a
// deployment that scrapes /metrics but not /healthz, or while the scraper itself is
// down — never says so.
//
// The poller fires an evaluation WITHOUT any probe read.
func TestMCPHealth_AlertFiresWithoutAnyHealthzRead(t *testing.T) {
	var mu sync.Mutex
	fired := make(chan string, 4)
	prev := fireMCPGatewayAlert
	fireMCPGatewayAlert = func(d string) {
		mu.Lock()
		defer mu.Unlock()
		select {
		case fired <- d:
		default:
		}
	}
	t.Cleanup(func() { fireMCPGatewayAlert = prev })

	// A configured capability that did not start: faulted, and nothing reads /healthz.
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "tls_material_invalid"})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startMCPHealthAlertPoller(ctx)

	select {
	case d := <-fired:
		if !strings.Contains(d, "not serving") {
			t.Fatalf("unexpected alert detail %q", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a faulted MCP capability produced no alert without a /healthz read: " +
			"the alert depends on being scraped, which is the wrong way round")
	}
}

// A node that never requested MCP must not even start the goroutine — the alert
// plane follows the same disabled-by-default posture as the rest of MCP.
func TestMCPHealth_PollerDoesNotRunWhenMCPWasNeverRequested(t *testing.T) {
	prev := fireMCPGatewayAlert
	fired := make(chan string, 1)
	fireMCPGatewayAlert = func(d string) {
		select {
		case fired <- d:
		default:
		}
	}
	t.Cleanup(func() { fireMCPGatewayAlert = prev })

	withMCPStatus(t, mcpObserveActivation{State: mcpObserveDisabled})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if started := startMCPHealthAlertPoller(ctx); started {
		t.Error("the health-alert poller started on a node that never requested MCP")
	}

	select {
	case d := <-fired:
		t.Fatalf("a node that never requested MCP produced an alert: %q", d)
	case <-time.After(200 * time.Millisecond):
	}
}

// initMCPRuntime has two early-return startup-failure branches (NewRuntime and
// Start). Both mark the capability invalid — "configured but not serving", the
// fault most worth paging on, an MCP port already in use being the obvious case.
//
// The poller was originally called at the END of initMCPRuntime, so neither branch
// reached it and exactly those faults stayed silent until something scraped
// /healthz — the dependency the poller exists to remove. It is now deferred, which
// covers every return path including ones a later edit introduces.
//
// This test pins the structure, because the behaviour it protects is an ABSENCE (no
// alert on a path not taken) that no unit test of the poller itself can observe.
func TestMCPHealth_PollerIsDeferredSoStartupFailuresStillAlert(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mcp_runtime.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp_runtime.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "initMCPRuntime" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("initMCPRuntime not found; this wall is not reading the startup path")
	}

	deferred, called := false, false
	ast.Inspect(fn, func(n ast.Node) bool {
		if _, ok := n.(*ast.DeferStmt); ok {
			ast.Inspect(n, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok && id.Name == "startMCPHealthAlertPoller" {
					deferred = true
				}
				return true
			})
			return true
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == "startMCPHealthAlertPoller" {
			called = true
		}
		return true
	})
	if !called {
		t.Fatal("initMCPRuntime no longer starts the health-alert poller at all")
	}
	if !deferred {
		t.Fatal("startMCPHealthAlertPoller is called but not DEFERRED in initMCPRuntime: " +
			"the startup-failure branches return early, so a capability that failed to bind " +
			"would never start the poller and its fault would stay silent until something " +
			"read /healthz")
	}
}

// The invalid-startup state must actually be one the poller acts on: configured,
// faulted, and therefore alertable. If Faulted() ever stopped covering it, the
// deferred call above would start a poller that reports nothing.
func TestMCPHealth_InvalidStartupIsAFaultThePollerAlertsOn(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "runtime_start_failed"})
	snap := mcpHealthState()
	if !snap.Configured {
		t.Fatal("a requested-but-failed MCP capability must count as configured")
	}
	if !snap.Faulted() {
		t.Fatalf("state %q after a startup failure is not Faulted(); no alert would fire", snap.State)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if !startMCPHealthAlertPoller(ctx) {
		t.Fatal("the poller refused to start for a failed-startup capability")
	}
}
