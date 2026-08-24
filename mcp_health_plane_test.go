package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	const secretish = "tls_key_file_unreadable_/etc/culvert/private/mcp.key"
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: secretish})

	report, _ := computeReadiness()
	row := report.Checks["mcp_gateway"]
	if row == nil {
		t.Fatal("missing mcp_gateway row")
	}
	if strings.Contains(row.Detail, secretish) || strings.Contains(row.Detail, "/etc/") {
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
