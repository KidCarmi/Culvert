package main

// CONTROLLED SHADOW SOAK & EXIT EVIDENCE — sustained-runtime experiment harness.
//
// The first controlled run (shadow_controlled_run_test.go) proved Shadow can work
// ONCE. This harness proves Shadow stays truthful, side-effect-free, bounded and
// durable while the system changes around it: sustained + concurrent traffic across
// several principals/tools/policy-classes, policy churn, catalog rediscovery, a real
// F1->F2 fingerprint rug-pull, tool-trust churn (approve/revoke/reapprove/expire),
// the kill switch under load, restart recovery, durable-evidence stress, and a
// fail-closed failure-injection + security-mutation campaign.
//
// It drives the SAME real production code paths as the controlled run (real listener,
// TLS+OAuth, policy engine, registry, catalog, tool-trust, rollout, the non-executing
// *execution.ShadowEvaluator, durable schema-v2 evidence spool, metrics, recovery). It
// composes NO LiveExecutor, NO UpstreamCaller, NO credential broker; it never arms
// Canary/Production. A real controlled upstream independently counts invocations, which
// must remain 0 for the whole soak.
//
// Profiles (deterministic request COUNTS, not wall-clock — §6):
//   - default (CI): a small deterministic workload, fast under -race/-shuffle.
//   - heavy (opt-in): set CULVERT_MCP_SOAK to a request count (5000-20000) for a deep
//     manual/nightly soak. Never a permanently 30-minute default.
//
// Run: go test -run TestShadowSoak -count=1 -v .

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// ---- soak topology (richer than the single controlled server) ------------------

const (
	soakP1       = "soak-principal-1" // in-scope
	soakP2       = "soak-principal-2" // in-scope
	soakP3       = "soak-principal-3" // in-scope
	toolApprove  = "approvetool"      // REQUIRE_APPROVAL      -> would_require_approval
	toolConfirm  = "confirmtool"      // REQUIRE_CONFIRMATION  -> would_require_confirmation
	rugServer    = "rugpull-server"   // dedicated to the F1->F2 rediscovery drill
	rugTool      = "rug"              // ALLOW                 -> would_execute
	rugIdentity  = "spiffe://qual/rugpull-server"
	ctrlIdentity = "spiffe://qual/controlled-test-server"
)

// soakPrincipals are the in-scope synthetic identities the workload rotates through.
var soakPrincipals = []string{soakP1, soakP2, soakP3, ctrlPrincip}

// soakInventoryJSON seeds TWO controlled servers under one tenant, both pointed at the
// auxiliary witness endpoint. The main server carries the four outcome-bearing tools; the
// rugpull server carries one tool re-ingested in isolation so a rediscovery never
// withdraws the main server's tools.
func soakInventoryJSON(mainEndpoint, rugEndpoint string) string {
	tool := func(name, prop string) string {
		return `{"name":"` + name + `","input_schema":{"type":"object","properties":{"` + prop +
			`":{"type":"string"}}},"description":"` + name + `","destination_class":"none"}`
	}
	main := `{"server_id":"` + ctrlServer + `","endpoint":"` + mainEndpoint + `",` +
		`"pinned_identity":"` + ctrlIdentity + `","credential_profile":"profile:ro","enabled":true,"tools":[` +
		tool(toolEcho, "text") + `,` + tool(toolDanger, "x") + `,` +
		tool(toolApprove, "a") + `,` + tool(toolConfirm, "c") + `]}`
	rug := `{"server_id":"` + rugServer + `","endpoint":"` + rugEndpoint + `",` +
		`"pinned_identity":"` + rugIdentity + `","credential_profile":"profile:ro","enabled":true,"tools":[` +
		tool(rugTool, "r") + `]}`
	return `{"schema_version":1,"tenant":"` + ctrlTenant + `","servers":[` + main + `,` + rug + `]}`
}

// Policy rules driving each outcome. A tool is Usable (approved) in every case, so the
// outcome is decided purely by the policy action (a non-Usable tool would hard-override
// to would_fail_hard_control regardless of policy — that is the revoke drill's lever).
const (
	soakAllowEcho = `{"id":"ALLOW_ECHO","priority":20,"action":"ALLOW",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"echo"}],"obligations":{"logging":"standard"}}`
	soakAllowRug = `{"id":"ALLOW_RUG","priority":21,"action":"ALLOW",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"rug"}],"obligations":{"logging":"standard"}}`
	soakRequireApproval = `{"id":"REQ_APPROVAL","priority":22,"action":"REQUIRE_APPROVAL",` +
		`"reason":"MCP.POLICY.APPROVAL_REQUIRED","remediation":"request_approval",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"approvetool"}],"obligations":{"approval":true}}`
	soakRequireConfirm = `{"id":"REQ_CONFIRM","priority":23,"action":"REQUIRE_CONFIRMATION",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_confirmation",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"confirmtool"}],"obligations":{"confirmation":true}}`
	// danger has no rule -> default DENY -> would_block.
)

// soakBaseRules is the revision-1 rule set (discovery + the four outcome rules).
func soakBaseRules() string {
	return allowDiscoveryRule + "," + soakAllowEcho + "," + soakAllowRug + "," +
		soakRequireApproval + "," + soakRequireConfirm
}

// soakOutcomeForTool maps a Usable in-scope tool to the Shadow outcome its rev-1 rule
// produces. This is the deterministic oracle the exact-accounting workload asserts against.
func soakOutcomeForTool(tool string) string {
	switch tool {
	case toolEcho, rugTool:
		return "would_execute"
	case toolDanger:
		return "would_block"
	case toolApprove:
		return "would_require_approval"
	case toolConfirm:
		return "would_require_confirmation"
	default:
		return ""
	}
}

// ---- soak run context ----------------------------------------------------------

type soakRun struct {
	t            *testing.T
	pki          *mcpTestPKI
	cli          *http.Client
	base         string
	audience     string
	cat          *catalog.Catalog
	reg          *registry.Registry
	signer       cpdp.Signer
	upstreamHits *int64
	cfgRev       uint64
	approvals    map[string]string // tool -> current approval id
	ev           func(string, ...any)
}

// heavy soak request count from the environment (0 -> use the fast CI default).
func soakHeavyCount() int {
	v := os.Getenv("CULVERT_MCP_SOAK")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// soakScope is the bounded, enumerable Shadow scope: two servers, the in-scope
// principals, write-class, high-risk. The outsider principal is deliberately absent.
func soakScope() rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{ctrlServer, rugServer},
		Principals: soakPrincipals,
		Operations: []rollout.RiskClass{rollout.RiskWrite},
		HighRisk:   true,
	}
}

// newSoakRun composes the real Shadow node with the soak topology, promotes every tool to
// Usable, verifies scope containment + the genuine activation preflight, and activates
// Observe->Shadow. It mirrors newControlledShadowRun but for the richer topology.
func newSoakRun(t *testing.T, hits *int64) *soakRun {
	t.Helper()
	ev := func(format string, a ...any) { t.Logf("SOAK | "+format, a...) }

	signer, _ := mcpProdSetup(t)
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeDisabled, "baseline mode must be Disabled, got %s", getMCPRollout().gateway.CurrentMode())
	req(t, !liveExecDepsConfigured(false), "baseline: live-execution deps must be UNconfigured")

	pki := newMCPTestPKI(t)
	_, mainEndpoint := witnessEndpoint(t, hits)
	_, rugEndpoint := witnessEndpoint(t, hits)
	invPath := writeInv(t, soakInventoryJSON(mainEndpoint, rugEndpoint))
	polPath := writeMCPPolicyFile(t, gwPolicyDoc(1, soakBaseRules()))
	rt, cat, act := composeShadowNode(t, pki, invPath, polPath, telemetryConfigAt(t))
	tel := sharedTelemetry()
	req(t, tel != nil, "durable telemetry must be composed for Shadow")
	t.Cleanup(func() {
		_ = rt.Shutdown(ctxWithTimeout(t))
		_ = tel.Close(context.Background())
		publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	})
	req(t, globalMCPShadow.composed.Load() && shadowDepsConfigured(false), "ShadowEvaluator must be composed and shadow tier armed")
	req(t, !liveExecDepsConfigured(false), "SECURITY: live-execution tier must remain UNarmed after Shadow composition")
	reg, _ := mcpInventory.sharedInventory()
	base := "https://" + rt.Addr(false)

	initMCPToolTrust(nil)
	approvals := map[string]string{}
	for _, tt := range []struct{ server, tool string }{
		{ctrlServer, toolEcho}, {ctrlServer, toolDanger}, {ctrlServer, toolApprove},
		{ctrlServer, toolConfirm}, {rugServer, rugTool},
	} {
		approvals[tt.tool] = approveToUsableOn(t, cat, tt.server, tt.tool)
	}
	for _, tt := range []struct{ server, tool string }{
		{ctrlServer, toolEcho}, {rugServer, rugTool},
	} {
		_, _, elig := catRec(t, cat, tt.server, tt.tool)
		req(t, elig == catalog.Usable, "%s/%s must be Usable after approval, got %v", tt.server, tt.tool, elig)
	}

	scope := soakScope()
	sc1, cerr := rollout.Compile(scope, 1, rollout.DefaultLimits())
	req(t, cerr == nil, "scope compile: %v", cerr)
	for _, p := range soakPrincipals {
		in := rollout.Subject{Capability: rollout.CapabilityGateway, ServerID: ctrlServer, PrincipalID: p, Operation: rollout.RiskWrite}
		req(t, sc1.Contains(in), "in-scope principal %s must be contained", p)
	}
	out := rollout.Subject{Capability: rollout.CapabilityGateway, ServerID: ctrlServer, PrincipalID: outsiderSub, Operation: rollout.RiskWrite}
	req(t, !sc1.Contains(out), "outsider principal must NOT be contained")
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway, scope, 1)
	req(t, pf.Ready, "activation preflight must be ready; reasons=%v", pf.Reasons)

	r := &soakRun{
		t: t, pki: pki, cli: pki.mtlsClient(t, false), base: base, audience: act.CanonicalURL,
		cat: cat, reg: reg, signer: signer, upstreamHits: hits, cfgRev: 1, approvals: approvals, ev: ev,
	}
	r.activate()
	ev("SOAK NODE UP: mode=shadow servers=[%s,%s] tools=[echo,danger,approvetool,confirmtool,rug] principals=%d live_exec_ready=%v",
		ctrlServer, rugServer, len(soakPrincipals), liveExecDepsConfigured(false))
	return r
}

// approveToUsableOn is approveToUsable for an arbitrary (server, tool).
func approveToUsableOn(t *testing.T, cat *catalog.Catalog, server, tool string) string {
	t.Helper()
	return approveToUsable(t, cat, server, tool)
}

// applyGateway signs+applies a Gateway rollout config at a monotonically-increasing rev.
func (r *soakRun) applyGateway(rc *rollout.SignedConfig) {
	r.cfgRev++
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(r.t, r.signer, r.cfgRev, rc)})
}

// activate performs the signed Observe->Shadow transition for the soak scope.
func (r *soakRun) activate() {
	t := r.t
	r.applyGateway(&rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: soakScope(),
	})
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "activation failed: mode=%s", getMCPRollout().gateway.CurrentMode())
	req(t, getMCPRollout().gateway.Evidence().ShadowStartUnix != 0, "Shadow window must be stamped")
}

// session mints an in-scope bearer for a principal and runs the MCP handshake against a
// server, returning the token + session id.
func (r *soakRun) session(principal, server string) (token, sid string) {
	t := r.t
	token = mintBearerSub(t, r.pki, r.audience, ctrlTenant, principal)
	sid = handshake(t, r.cli, r.base, server, token)
	return token, sid
}

// callOn posts a tools/call to an arbitrary server and returns status + result object.
func (r *soakRun) callOn(server, token, sid, id, tool, arg string) (status int, result map[string]any) {
	t := r.t
	st, _, body := gwPost(t, r.cli, r.base, server, token, sid, `{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+arg+`}}`)
	return st, resultOf(t, body)
}

// committedShadowEvents returns every committed schema-v2 shadow-evaluated event across the
// gateway partitions (the durable archive the soak audits for parity/revision/no-loss).
func committedShadowEvents(t *testing.T) []evmodel.Event {
	t.Helper()
	er := mcpAdminEventReader()
	if er == nil {
		return nil
	}
	// Fully paginate the cursor reader (afterSeq -> next) across both partitions so the
	// audit sees EVERY committed shadow event, not just the first page — the soak's
	// high-volume mode commits far more than one page per partition.
	const batch = 512
	var out []evmodel.Event
	for _, part := range []string{"P-CRIT", "P-ORD"} {
		afterSeq := uint64(0)
		for {
			evs, _, next, err := er.CommittedEvents("gateway", part, afterSeq, batch)
			if err != nil {
				break
			}
			for i := range evs {
				e := evs[i]
				if e.SchemaVersion == evmodel.SchemaVersionV2 && e.Decision.ExecutionState == "shadow_evaluated" && e.Shadow != nil {
					out = append(out, e)
				}
			}
			if len(evs) < batch {
				break
			}
			afterSeq = next
		}
	}
	return out
}

// assertOutcome drives ONE sequential in-scope request and proves the full contract for
// the resulting Shadow evaluation: response says shadow_evaluated/executed=false with the
// wanted outcome; the durable schema-v2 event matches (parity), its digest verifies and it
// validates; materialization/response inspection are not_evaluated; the governing policy
// revision is stamped; exactly the named metric bucket moved; and the upstream saw nothing.
func (r *soakRun) assertOutcome(principal, server, tool, arg, wantOutcome string, wantRev uint64, deltas shadowMetricsView) {
	t := r.t
	before := shadowSnap()
	hitsBefore := atomic.LoadInt64(r.upstreamHits)
	token, sid := r.session(principal, server)
	preIDs := committedShadowEventIDs(t)
	st, res := r.callOn(server, token, sid, "1", tool, arg)
	req(t, st == 200, "%s: status=%d", tool, st)
	req(t, res["execution_state"] == "shadow_evaluated" && res["executed"] == false && res["shadow_outcome"] == wantOutcome,
		"%s: want shadow_evaluated/%s executed=false, got %v", tool, wantOutcome, res)
	de, ok := newShadowEvidence(t, preIDs)
	req(t, ok, "%s: no committed schema-v2 evidence", tool)
	req(t, de.Shadow.Outcome == wantOutcome, "%s: durable outcome=%q want %q", tool, de.Shadow.Outcome, wantOutcome)
	req(t, de.VerifyDigest(), "%s: durable digest must verify", tool)
	req(t, de.Validate() == nil, "%s: durable event must validate: %v", tool, de.Validate())
	req(t, de.Shadow.MaterializationReadiness == "not_evaluated" && de.Shadow.ResponseInspection == "not_evaluated",
		"%s: mat/resp must be not_evaluated: %+v", tool, de.Shadow)
	req(t, de.Shadow.Outcome == res["shadow_outcome"] &&
		de.Shadow.MaterializationReadiness == res["materialization_ready"] &&
		de.Shadow.ResponseInspection == res["response_inspection"],
		"%s: response<->durable parity mismatch: durable=%+v response=%v", tool, de.Shadow, res)
	req(t, de.Decision.PolicyRevision == wantRev, "%s: durable policy_revision=%d want %d", tool, de.Decision.PolicyRevision, wantRev)
	after := shadowSnap()
	assertShadowDelta(t, before, after, deltas)
	req(t, atomic.LoadInt64(r.upstreamHits) == hitsBefore, "%s: SECURITY upstream invoked (delta=%d)", tool, atomic.LoadInt64(r.upstreamHits)-hitsBefore)
}

// coverReachableOutcomes drives every Shadow outcome reachable through the real Gateway
// (5 of 8) once, with full parity/digest/revision/side-effect assertions. The 3 remaining
// outcomes are structurally unreachable from the real request path and are documented
// (never fabricated) — see the soak report §5.
func (r *soakRun) coverReachableOutcomes() {
	// 1..4 — the policy-class outcomes on Usable in-scope tools at revision 1.
	r.assertOutcome(soakP1, ctrlServer, toolEcho, `{"text":"h"}`, "would_execute", 1, shadowMetricsView{Evaluations: 1, WouldExecute: 1})
	r.assertOutcome(soakP1, ctrlServer, toolDanger, `{"x":"y"}`, "would_block", 1, shadowMetricsView{Evaluations: 1, WouldBlock: 1})
	r.assertOutcome(soakP1, ctrlServer, toolApprove, `{"a":"b"}`, "would_require_approval", 1, shadowMetricsView{Evaluations: 1, WouldRequireApproval: 1})
	r.assertOutcome(soakP1, ctrlServer, toolConfirm, `{"c":"d"}`, "would_require_confirmation", 1, shadowMetricsView{Evaluations: 1, WouldRequireConfirmation: 1})
	// 5 — would_fail_hard_control: revoke echo's approval so it loses Usable (policy hard
	// override), then reapprove so the workload's echo->would_execute holds again.
	r.revokeTool(ctrlServer, toolEcho)
	r.assertOutcome(soakP1, ctrlServer, toolEcho, `{"text":"h"}`, "would_fail_hard_control", 1, shadowMetricsView{Evaluations: 1, WouldFailHardControl: 1})
	r.reapproveTool(ctrlServer, toolEcho)
	r.assertOutcome(soakP1, ctrlServer, toolEcho, `{"text":"h"}`, "would_execute", 1, shadowMetricsView{Evaluations: 1, WouldExecute: 1})
	r.ev("OUTCOME COVERAGE: 5/8 driven through the real Gateway (would_execute, would_block, would_require_approval, would_require_confirmation, would_fail_hard_control); 3/8 structurally unreachable and documented (would_fail_credential_readiness: no planner composed; would_fail_inspection: runtime blocks HardFail pre-executor; would_fail_stale_decision: initial drift refused upstream, boundary drift is race-only)")
}

// revokeTool revokes a tool's current shadow approval (immediate demotion below Usable).
func (r *soakRun) revokeTool(server, tool string) {
	t := r.t
	id := r.approvals[tool]
	req(t, id != "", "no approval recorded for %s", tool)
	_, err := mcpToolTrust.Revoke(id, "admin@corp", ctrlTenant, "soak revoke drill")
	req(t, err == nil, "Revoke(%s): %v", tool, err)
	mcpToolTrustReconcile()
	_, _, elig := catRec(t, r.cat, server, tool)
	req(t, elig != catalog.Usable, "%s must lose Usable after revoke, got %v", tool, elig)
}

// reapproveTool creates a FRESH approval for the tool's CURRENT fingerprint and approves it
// (terminal approvals never re-activate — reapproval is a new durable trust decision).
func (r *soakRun) reapproveTool(server, tool string) {
	t := r.t
	id := approveToUsable(t, r.cat, server, tool)
	r.approvals[tool] = id
	_, _, elig := catRec(t, r.cat, server, tool)
	req(t, elig == catalog.Usable, "%s must be Usable after reapproval, got %v", tool, elig)
}

// soakSpec is one worker's assignment: a principal calling a tool on a server; outScope
// marks the out-of-scope (containment) workers.
type soakSpec struct {
	principal, server, tool, arg string
	outScope                     bool
}

// soakStableSpecs builds the in-scope (principal x tool) worker set plus two out-of-scope
// workers, and the expected metric distribution over the in-scope set.
func soakStableSpecs(perPair int) (specs []soakSpec, expected shadowMetricsView) {
	for _, p := range soakPrincipals {
		specs = append(specs,
			soakSpec{p, ctrlServer, toolEcho, `{"text":"x"}`, false},
			soakSpec{p, ctrlServer, toolDanger, `{"x":"y"}`, false},
			soakSpec{p, ctrlServer, toolApprove, `{"a":"b"}`, false},
			soakSpec{p, ctrlServer, toolConfirm, `{"c":"d"}`, false},
			soakSpec{p, rugServer, rugTool, `{"r":"s"}`, false},
		)
	}
	specs = append(specs,
		soakSpec{outsiderSub, ctrlServer, toolEcho, `{"text":"x"}`, true},
		soakSpec{outsiderSub, ctrlServer, toolDanger, `{"x":"y"}`, true},
	)
	for _, s := range specs {
		if s.outScope {
			continue
		}
		expected.Evaluations += int64(perPair)
		bumpOutcome(&expected, soakOutcomeForTool(s.tool), int64(perPair))
	}
	return specs, expected
}

// bumpOutcome adds n to the metric bucket for the given outcome string.
func bumpOutcome(v *shadowMetricsView, outcome string, n int64) {
	switch outcome {
	case "would_execute":
		v.WouldExecute += n
	case "would_block":
		v.WouldBlock += n
	case "would_require_approval":
		v.WouldRequireApproval += n
	case "would_require_confirmation":
		v.WouldRequireConfirmation += n
	}
}

// checkStableResponse validates one worker response: in-scope must be the expected
// shadow_outcome with executed=false; out-of-scope must never be shadow-evaluated.
func (r *soakRun) checkStableResponse(s soakSpec, k, st int, res map[string]any, want string) bool {
	t := r.t
	if st != 200 {
		t.Errorf("worker %s/%s req %d: status=%d", s.principal, s.tool, k, st)
		return false
	}
	if s.outScope {
		if res["execution_state"] == "shadow_evaluated" || res["shadow_outcome"] != nil {
			t.Errorf("SECURITY worker out-of-scope %s/%s req %d entered Shadow: %v", s.principal, s.tool, k, res)
			return false
		}
		return true
	}
	if res["shadow_outcome"] != want || res["executed"] != false {
		t.Errorf("worker %s/%s req %d: want %s executed=false, got %v", s.principal, s.tool, k, want, res)
		return false
	}
	return true
}

// runStableWorker sends perPair sequential requests on one session and returns per-request
// latencies (stopping early on the first failure, which is recorded via t.Errorf).
func (r *soakRun) runStableWorker(s soakSpec, perPair int) []time.Duration {
	token, sid := r.session(s.principal, s.server)
	want := soakOutcomeForTool(s.tool)
	out := make([]time.Duration, 0, perPair)
	for k := 0; k < perPair; k++ {
		start := time.Now()
		st, res := r.callOn(s.server, token, sid, strconv.Itoa(k+2), s.tool, s.arg)
		out = append(out, time.Since(start))
		if !r.checkStableResponse(s, k, st, res, want) {
			return out
		}
	}
	return out
}

// runConcurrentStable runs the deterministic concurrent workload under a STABLE policy/trust
// state, so every request's outcome is a pure function of (tool) and the exact metric
// distribution is knowable in advance. One worker per (principal x tool) reuses a single
// session and the shared http.Client (HTTP/2 reuse/multiplexing across workers).
func (r *soakRun) runConcurrentStable(perPair int) (expected shadowMetricsView, latencies []time.Duration) {
	specs, expected := soakStableSpecs(perPair)
	lat := make([][]time.Duration, len(specs))
	var wg sync.WaitGroup
	for i := range specs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lat[i] = r.runStableWorker(specs[i], perPair)
		}(i)
	}
	wg.Wait()
	for _, l := range lat {
		latencies = append(latencies, l...)
	}
	return expected, latencies
}

// auditAllEvents proves every committed shadow event is truthful and complete: exactly one
// durable schema-v2 event per shadow evaluation (no loss, no duplicate), each with a valid
// digest, structural validity, and not_evaluated materialization/response inspection.
func (r *soakRun) auditAllEvents(evaluations int64) {
	t := r.t
	evs := committedShadowEvents(t)
	req(t, int64(len(evs)) == evaluations, "durable evidence count=%d must equal shadow evaluations=%d (no loss, no duplicate)", len(evs), evaluations)
	seen := map[string]bool{}
	for i := range evs {
		e := evs[i]
		req(t, !seen[e.EventID], "duplicate durable event id %s", e.EventID)
		seen[e.EventID] = true
		req(t, e.VerifyDigest(), "event %s digest must verify", e.EventID)
		req(t, e.Validate() == nil, "event %s must validate: %v", e.EventID, e.Validate())
		req(t, e.Shadow.MaterializationReadiness == "not_evaluated" && e.Shadow.ResponseInspection == "not_evaluated",
			"event %s mat/resp must be not_evaluated: %+v", e.EventID, e.Shadow)
	}
	r.ev("EVIDENCE AUDIT: %d committed schema-v2 events == %d evaluations; all digests verify, all validate, mat/resp=not_evaluated", len(evs), evaluations)
}

// reportLatency logs informational Shadow-evaluation latency percentiles (no SLA is
// asserted — the repo defines no MCP-shadow performance threshold).
func (r *soakRun) reportLatency(lat []time.Duration) {
	if len(lat) == 0 {
		return
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration {
		idx := int(p * float64(len(lat)-1))
		return lat[idx]
	}
	r.ev("LATENCY (informational, n=%d): p50=%s p95=%s p99=%s max=%s", len(lat), pct(0.50), pct(0.95), pct(0.99), lat[len(lat)-1])
}

// reportDistribution logs the outcome distribution so every bucket is explainable.
func (r *soakRun) reportDistribution(v shadowMetricsView) {
	total := v.Evaluations
	pctOf := func(n int64) string {
		if total == 0 {
			return "0%"
		}
		return strconv.FormatInt(n*100/total, 10) + "%"
	}
	r.ev("DISTRIBUTION total=%d would_execute=%d(%s) would_block=%d(%s) would_require_approval=%d(%s) would_require_confirmation=%d(%s) would_fail_hard_control=%d(%s) other=%d evaluation_errors=%d",
		total, v.WouldExecute, pctOf(v.WouldExecute), v.WouldBlock, pctOf(v.WouldBlock),
		v.WouldRequireApproval, pctOf(v.WouldRequireApproval), v.WouldRequireConfirmation, pctOf(v.WouldRequireConfirmation),
		v.WouldFailHardControl, pctOf(v.WouldFailHardControl), v.WouldOther, v.EvaluationErrors)
}

// TestShadowSoak is the sustained/concurrent Shadow soak (fast deterministic CI profile;
// set CULVERT_MCP_SOAK=<count> for the heavy opt-in profile).
func TestShadowSoak(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	r := newSoakRun(t, &hits)
	// The shadow metric singleton is a PROCESS-GLOBAL accumulator (never reset between
	// tests); the durable spool is this run's fresh tempdir. So this-run evaluations are the
	// singleton DELTA over the run, and that delta must equal the committed-event count.
	runBase := shadowSnap()

	r.coverReachableOutcomes()

	per := 8
	if h := soakHeavyCount(); h > 0 {
		per = (h + 19) / 20 // 20 in-scope workers
	}
	before := shadowSnap()
	exp, lat := r.runConcurrentStable(per)
	stable := shadowSnap()
	assertShadowDelta(t, before, stable, exp)
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during concurrent soak: %d", atomic.LoadInt64(&hits))
	r.reportLatency(lat)

	// §8 policy churn (sequential + concurrent-under-traffic).
	r.policyChurn()

	// §9/§10 catalog rediscovery + real F1->F2 fingerprint rug-pull.
	r.catalogRediscoveryAndRugPull()

	// §11 tool-trust expiry (revoke/reapprove already exercised in coverage).
	r.toolTrustExpire()

	// §12 kill switch under concurrent load.
	r.killUnderLoad()

	// Final invariants across the whole soak (every phase kept them true). Audit the durable
	// evidence against THIS run's evaluation delta, not the global accumulator.
	final := shadowSnap()
	delta := shadowMetricsDelta(runBase, final)
	r.auditAllEvents(delta.Evaluations)
	r.reportDistribution(delta)
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during the soak: %d", atomic.LoadInt64(&hits))
	req(t, !liveExecDepsConfigured(false), "SECURITY: live-execution tier must remain UNarmed through the soak")
	r.ev("SOAK PASS: evaluations=%d evaluation_errors=%d upstream=0 materializations=0 live_executions=0", delta.Evaluations, delta.EvaluationErrors)
}

// publishEchoPolicy publishes a new policy revision into the LIVE holder (immediate pickup,
// no recompose) in which echo is ALLOW or DENY (default-deny) and everything else is stable.
func (r *soakRun) publishEchoPolicy(rev uint64, echoAllow bool) {
	t := r.t
	rules := allowDiscoveryRule + "," + soakAllowRug + "," + soakRequireApproval + "," + soakRequireConfirm
	if echoAllow {
		rules += "," + soakAllowEcho
	}
	//nolint:gosec // G115: rev is a small positive test revision; gwPolicyDoc takes int.
	snap, err := policy.Compile([]byte(gwPolicyDoc(int(rev), rules)), policy.CreatedMeta{}, policy.DefaultLimits())
	req(t, err == nil, "compile policy rev %d: %v", rev, err)
	req(t, mcpPolicy.publish(mcpPolLoaded, "", snap) == nil, "publish policy rev %d", rev)
	req(t, mcpPolicy.status().Revision == rev, "live policy revision must be %d after publish, got %d", rev, mcpPolicy.status().Revision)
}

// policyChurn proves policy revisions are applied atomically with correct evidence stamping
// (§8): a sequential ALLOW->DENY->ALLOW on echo (each request lands on the correct revision
// and a restrictive policy is never laundered into would_execute), followed by a concurrent
// churn under traffic where every committed echo event's (revision, outcome) is
// self-consistent — no request uses a partially-updated policy, no revisions mix.
func (r *soakRun) policyChurn() {
	t := r.t
	// Sequential: rev 2 flips echo ALLOW->DENY, rev 3 flips DENY->ALLOW. Each request's
	// durable event must carry the governing revision and the matching outcome.
	r.publishEchoPolicy(2, false)
	r.assertOutcome(soakP2, ctrlServer, toolEcho, `{"text":"h"}`, "would_block", 2, shadowMetricsView{Evaluations: 1, WouldBlock: 1})
	r.publishEchoPolicy(3, true)
	r.assertOutcome(soakP2, ctrlServer, toolEcho, `{"text":"h"}`, "would_execute", 3, shadowMetricsView{Evaluations: 1, WouldExecute: 1})
	r.ev("POLICY CHURN sequential: ALLOW(rev1)->DENY(rev2, would_block)->ALLOW(rev3, would_execute); each event stamped with its governing revision, restrictive never would_execute")

	// Concurrent churn under traffic: flip echo's rule across revisions while many echo
	// requests run, then audit EVERY new committed echo event for (revision, outcome)
	// consistency — no request uses a partially-updated policy, no revisions mix.
	c := &echoChurn{r: r, allowAtRev: map[uint64]bool{3: true}}
	before := shadowSnap()
	preIDs := eventIDSet(committedShadowEvents(t))
	const churnWorkers = 6
	churnPer := 12
	if h := soakHeavyCount(); h > 0 {
		churnPer = max((h+churnWorkers-1)/churnWorkers/4, 1)
	}
	stop := make(chan struct{})
	var churnerWG sync.WaitGroup
	churnerWG.Add(1)
	go func() { defer churnerWG.Done(); c.run(stop) }()
	var wg sync.WaitGroup
	for w := 0; w < churnWorkers; w++ {
		wg.Add(1)
		go func(w int) { defer wg.Done(); r.echoChurnWorker(w, churnPer) }(w)
	}
	wg.Wait()
	close(stop)
	churnerWG.Wait()

	after := shadowSnap()
	newEvts := r.auditChurnEvents(c, preIDs)
	req(t, int64(newEvts) == after.Evaluations-before.Evaluations, "churn: new event count %d must equal new evaluations %d", newEvts, after.Evaluations-before.Evaluations)
	r.ev("POLICY CHURN concurrent: %d echo evaluations across %d flipped revisions; every event's (revision,outcome) self-consistent, no mixing, restrictive never would_execute", newEvts, len(c.allowAtRev))

	// Restore echo to ALLOW at a fresh revision so later phases see would_execute. The
	// concurrent churner advanced the live revision by a VOLUME-DEPENDENT amount (many
	// thousands under heavy soak), and the policy holder rejects a publish at or below the
	// live revision, so the restore revision must be read from the now-stopped holder rather
	// than hardcoded.
	r.publishEchoPolicy(mcpPolicy.status().Revision+1, true)
}

// echoChurn coordinates the concurrent policy churner: which revisions had echo ALLOW,
// guarded so the auditing reader and the publishing churner never race.
type echoChurn struct {
	r          *soakRun
	mu         sync.Mutex
	allowAtRev map[uint64]bool
}

// run flips echo's rule across alternating revisions until stop is closed.
func (c *echoChurn) run(stop <-chan struct{}) {
	rev := uint64(4)
	for {
		select {
		case <-stop:
			return
		default:
		}
		allow := rev%2 == 0
		// publishEchoPolicy can t.Fatalf on a compile/publish/status regression, which
		// runtime.Goexit()s THIS churner goroutine. Do it OUTSIDE c.mu so a failure never
		// abandons the lock held — otherwise the post-churn auditChurnEvents -> allowedAt would
		// block forever on the leaked mutex, turning an intended failure into a CI timeout
		// (Codex). The lock guards only the allowAtRev map write; allowedAt is called only after
		// the churner has stopped (churnerWG.Wait()), so recording after publish is race-free.
		c.r.publishEchoPolicy(rev, allow)
		c.mu.Lock()
		c.allowAtRev[rev] = allow
		c.mu.Unlock()
		rev++
		time.Sleep(time.Millisecond)
	}
}

// allowedAt reports whether echo was ALLOW at the given revision (and whether it is known).
func (c *echoChurn) allowedAt(rev uint64) (allow, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	allow, known = c.allowAtRev[rev]
	return allow, known
}

// echoChurnWorker sends churnPer echo requests; every outcome must be a legitimate echo
// verdict (would_execute or would_block) for whatever revision it landed on.
func (r *soakRun) echoChurnWorker(w, churnPer int) {
	t := r.t
	token, sid := r.session(soakPrincipals[w%len(soakPrincipals)], ctrlServer)
	for k := 0; k < churnPer; k++ {
		st, res := r.callOn(ctrlServer, token, sid, strconv.Itoa(k+2), toolEcho, `{"text":"x"}`)
		if st != 200 {
			t.Errorf("churn worker %d req %d: status=%d", w, k, st)
			return
		}
		oc, _ := res["shadow_outcome"].(string)
		if oc != "would_execute" && oc != "would_block" {
			t.Errorf("churn worker %d req %d: unexpected outcome %v", w, k, res)
			return
		}
	}
}

// auditChurnEvents checks every NEW committed echo event: its outcome must match echo's rule
// at its exact governing revision, and a restrictive revision is never would_execute.
func (r *soakRun) auditChurnEvents(c *echoChurn, preIDs map[string]bool) int {
	t := r.t
	var newEvts int
	evs := committedShadowEvents(t)
	for i := range evs {
		e := &evs[i]
		if preIDs[e.EventID] {
			continue
		}
		newEvts++
		req(t, e.VerifyDigest() && e.Validate() == nil, "churn event %s must verify+validate", e.EventID)
		allow, known := c.allowedAt(e.Decision.PolicyRevision)
		req(t, known, "churn event %s carries an unknown policy revision %d", e.EventID, e.Decision.PolicyRevision)
		wantOutcome := "would_block"
		if allow {
			wantOutcome = "would_execute"
		}
		req(t, e.Shadow.Outcome == wantOutcome,
			"POLICY MIXING: event %s at revision %d (echo allow=%v) has outcome %q, want %q",
			e.EventID, e.Decision.PolicyRevision, allow, e.Shadow.Outcome, wantOutcome)
	}
	return newEvts
}

// eventIDSet returns the set of event ids in a slice of events.
func eventIDSet(evs []evmodel.Event) map[string]bool {
	m := make(map[string]bool, len(evs))
	for i := range evs {
		m[evs[i].EventID] = true
	}
	return m
}

// rugDiscoveryRaw builds a raw MCP tools/list discovery document for the single rug tool
// with the given inputSchema properties (the fingerprint-bearing surface).
func rugDiscoveryRaw(props string) []byte {
	return []byte(`{"tools":[{"name":"` + rugTool + `","inputSchema":{"type":"object","properties":` + props + `}}]}`)
}

// reingestRug re-discovers the rug tool through the REAL catalog ingest path (what the
// production Discovery wraps) and reconciles tool-trust. Identity matches the server pin, so
// this is a per-tool fingerprint rediscovery, never a server-identity change. The
// destination class is the fingerprint dimension the drill mutates for a PROVEN privilege
// expansion (an ordered broadening is quarantine-required by the drift classifier).
func (r *soakRun) reingestRug(props string, dest catalog.DestinationClass) {
	t := r.t
	_, _, err := r.cat.Ingest(r.reg, catalog.DiscoveryInput{
		ServerID:     registry.ServerID(rugServer),
		Identity:     registry.Identity(rugIdentity),
		Raw:          rugDiscoveryRaw(props),
		Destinations: map[string]catalog.DestinationClass{rugTool: dest},
	})
	req(t, err == nil, "reingest rug: %v", err)
	mcpToolTrustReconcile()
}

// catalogRediscoveryAndRugPull proves catalog rediscovery + a REAL runtime F1->F2
// fingerprint rug-pull (§9/§10): identical rediscovery preserves trust and Shadow continues;
// a changed fingerprint drops Usable and the F1 approval does NOT govern F2 (a fresh Shadow
// request cannot return would_execute under the stale trust); reconcile never auto-reapproves;
// then an explicit F2 approval restores usability.
func (r *soakRun) catalogRediscoveryAndRugPull() {
	t := r.t
	const props = `{"r":{"type":"string"}}`

	// Establish the rug fingerprint through the ingest path (destination=None) and (re)approve
	// it at F1 so the drill's baseline is a Usable tool bound to a known digest.
	r.reingestRug(props, catalog.DestNone)
	f1Hex, _, _ := catRec(t, r.cat, rugServer, rugTool)
	r.reapproveTool(rugServer, rugTool)
	f1ApprovedHex, _, elig := catRec(t, r.cat, rugServer, rugTool)
	req(t, elig == catalog.Usable && f1ApprovedHex == f1Hex, "rug must be Usable at F1 (%s), got elig=%v fp=%s", f1Hex, elig, f1ApprovedHex)

	// Identical rediscovery: fingerprint unchanged, Usable preserved, Shadow continues.
	r.reingestRug(props, catalog.DestNone)
	idHex, _, idElig := catRec(t, r.cat, rugServer, rugTool)
	req(t, idHex == f1Hex && idElig == catalog.Usable, "identical rediscovery must preserve fingerprint+Usable, got fp=%s elig=%v", idHex, idElig)
	tok, sid := r.session(soakP3, rugServer)
	st, res := r.callOn(rugServer, tok, sid, "1", rugTool, `{"r":"x"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_execute", "identical rediscovery: rug must still be would_execute, got %v", res)
	r.ev("CATALOG REDISCOVERY identical: fingerprint unchanged (%s), Usable preserved, Shadow continues (would_execute)", f1Hex[:12])

	// Real F1->F2 rug-pull: broaden the destination class (None->Arbitrary) — a PROVEN
	// privilege expansion. The fingerprint changes, the ingest fold quarantines the tool
	// (sticky), reconcile must NOT re-promote (the approval binds F1), and a fresh Shadow
	// request now predicts would_fail_hard_control — never would_execute under stale trust.
	r.reingestRug(props, catalog.DestArbitrary)
	f2Hex, _, f2Elig := catRec(t, r.cat, rugServer, rugTool)
	req(t, f2Hex != f1Hex, "rug-pull: fingerprint must change F1(%s)->F2(%s)", f1Hex[:12], f2Hex[:12])
	req(t, f2Elig == catalog.Quarantined, "rug-pull: privilege-expansion drift must Quarantine, got %v", f2Elig)
	tok, sid = r.session(soakP3, rugServer)
	preIDs := committedShadowEventIDs(t)
	st, res = r.callOn(rugServer, tok, sid, "2", rugTool, `{"r":"x"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_fail_hard_control",
		"rug-pull: a fresh Shadow request under stale F1 trust must be would_fail_hard_control, never would_execute, got %v", res)
	de, ok := newShadowEvidence(t, preIDs)
	req(t, ok && de.Shadow.Outcome == "would_fail_hard_control" && de.VerifyDigest(), "rug-pull: durable would_fail_hard_control evidence must be committed")
	r.ev("RUG-PULL F1->F2 (privilege expansion, destination None->Arbitrary): fingerprint %s->%s, Quarantined, F1 approval does NOT govern F2, reconcile did NOT auto-reapprove, fresh request=would_fail_hard_control", f1Hex[:12], f2Hex[:12])

	// Explicit F2 approval (never automatic) restores usability.
	r.reapproveTool(rugServer, rugTool)
	f2ApprovedHex, _, elig := catRec(t, r.cat, rugServer, rugTool)
	req(t, elig == catalog.Usable && f2ApprovedHex == f2Hex, "rug must be Usable at F2 after explicit reapproval, got elig=%v fp=%s", elig, f2ApprovedHex)
	tok, sid = r.session(soakP3, rugServer)
	st, res = r.callOn(rugServer, tok, sid, "3", rugTool, `{"r":"x"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_execute", "after explicit F2 approval rug must be would_execute, got %v", res)
	r.ev("RUG-PULL recover: explicit F2 approval restores Usable, would_execute resumes")
}

// approveWithExpiry creates+approves a fresh shadow approval for a tool's CURRENT
// fingerprint with an explicit expiry instant.
func (r *soakRun) approveWithExpiry(server, tool string, expiresAt time.Time) string {
	t := r.t
	fpHex, rev, _ := catRec(t, r.cat, server, tool)
	rq, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant: ctrlTenant, ServerID: server, ToolName: tool,
		ExpectedFingerprint: fpHex, ExpectedCatalogRev: rev,
		Purpose: tooltrust.PurposeShadowEvaluation, RequestedBy: "operator@corp",
		Reason: "soak expiry drill", ExpiresAt: &expiresAt,
	})
	req(t, err == nil, "RequestApproval(expiry): %v", err)
	_, err = mcpToolTrust.ApproveShadow(rq.ApprovalID, "admin@corp", ctrlTenant)
	req(t, err == nil, "ApproveShadow(expiry): %v", err)
	return rq.ApprovalID
}

// toolTrustExpire proves an EXPIRED approval cannot govern (§11). Using an injected clock, a
// short-lived approval on confirmtool is minted (Usable -> would_require_confirmation); the
// clock is advanced past expiry and reconcile demotes it; a fresh Shadow request then
// predicts would_fail_hard_control (never would_require_confirmation under the dead grant);
// a new approval restores usability. The revoked/expired grant never resurrects.
func (r *soakRun) toolTrustExpire() {
	t := r.t
	base := time.Now()
	var nowNanos atomic.Int64
	nowNanos.Store(base.UnixNano())
	// Swap UNDER mcpToolTrust.mu: a reconcile loop leaked by an earlier test still reads
	// nowFn through now()'s RLock, so a bare assignment here races it (see
	// swapToolTrustNowFnForTest).
	prev := swapToolTrustNowFnForTest(func() time.Time { return time.Unix(0, nowNanos.Load()) })
	defer func() { swapToolTrustNowFnForTest(prev) }()

	// Replace confirmtool's standing approval with a short-lived one.
	r.revokeTool(ctrlServer, toolConfirm)
	r.approvals[toolConfirm] = r.approveWithExpiry(ctrlServer, toolConfirm, base.Add(10*time.Second))
	_, _, elig := catRec(t, r.cat, ctrlServer, toolConfirm)
	req(t, elig == catalog.Usable, "confirmtool must be Usable before expiry, got %v", elig)
	tok, sid := r.session(soakP2, ctrlServer)
	st, res := r.callOn(ctrlServer, tok, sid, "1", toolConfirm, `{"c":"d"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_require_confirmation", "pre-expiry confirmtool must be would_require_confirmation, got %v", res)

	// Advance the clock past expiry; reconcile sweeps it to Expired and demotes.
	nowNanos.Store(base.Add(time.Hour).UnixNano())
	mcpToolTrustReconcile()
	_, _, elig = catRec(t, r.cat, ctrlServer, toolConfirm)
	req(t, elig != catalog.Usable, "expired approval must demote confirmtool below Usable, got %v", elig)
	tok, sid = r.session(soakP2, ctrlServer)
	st, res = r.callOn(ctrlServer, tok, sid, "2", toolConfirm, `{"c":"d"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_fail_hard_control",
		"expired approval must NOT govern: fresh request must be would_fail_hard_control, got %v", res)

	// Restore the clock and reapprove (no expiry) — a NEW durable trust decision.
	nowNanos.Store(time.Now().UnixNano())
	r.reapproveTool(ctrlServer, toolConfirm)
	tok, sid = r.session(soakP2, ctrlServer)
	st, res = r.callOn(ctrlServer, tok, sid, "3", toolConfirm, `{"c":"d"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_require_confirmation", "reapproved confirmtool must be would_require_confirmation, got %v", res)
	r.ev("TOOL-TRUST EXPIRE: short-lived approval -> Usable -> (clock+1h, reconcile) Expired+demoted -> fresh request=would_fail_hard_control -> reapproved (new decision) -> would_require_confirmation")
}

// killUnderLoad proves the emergency kill switch is honored per-request under concurrency
// (§12): with the kill engaged, a burst of concurrent in-scope requests are ALL emergency-
// blocked (rollout_emergency_active), none report would_execute, no upstream call occurs, and
// exactly one evaluation_error is counted per blocked request (no would_* bucket moves);
// clearing the kill deterministically restores would_execute.
func (r *soakRun) killUnderLoad() {
	t := r.t
	// Baseline: kill off, echo is would_execute.
	tok, sid := r.session(soakP1, ctrlServer)
	st, res := r.callOn(ctrlServer, tok, sid, "1", toolEcho, `{"text":"x"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_execute", "pre-kill echo must be would_execute, got %v", res)

	// Engage kill, then blast concurrent traffic — every request must be emergency-blocked.
	req(t, getMCPRollout().emergencyDisable(rollout.CapabilityGateway, "soak-kill") == nil, "emergencyDisable failed")
	req(t, getMCPRollout().stateFor(rollout.CapabilityGateway).Killed(), "kill must be engaged")

	const killWorkers = 8
	killPer := 6
	if h := soakHeavyCount(); h > 0 {
		killPer = (h / 10 / killWorkers) + 1
	}
	before := shadowSnap()
	hitsBefore := atomic.LoadInt64(r.upstreamHits)
	var wg sync.WaitGroup
	for w := 0; w < killWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			tk, sd := r.session(soakPrincipals[w%len(soakPrincipals)], ctrlServer)
			for k := 0; k < killPer; k++ {
				stt, rr := r.callOn(ctrlServer, tk, sd, strconv.Itoa(k+2), toolEcho, `{"text":"x"}`)
				if stt != 200 {
					t.Errorf("kill worker %d req %d: status=%d", w, k, stt)
					return
				}
				if rr["shadow_outcome"] == "would_execute" || rr["execution_state"] == "shadow_evaluated" {
					t.Errorf("SECURITY kill worker %d req %d NOT blocked under kill: %v", w, k, rr)
					return
				}
				eo, _ := rr["error"].(map[string]any)
				if eo == nil || eo["message"] != "rollout_emergency_active" {
					t.Errorf("kill worker %d req %d: expected rollout_emergency_active, got %v", w, k, rr)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	after := shadowSnap()
	blocked := int64(killWorkers * killPer)
	assertShadowDelta(t, before, after, shadowMetricsView{EvaluationErrors: blocked})
	req(t, atomic.LoadInt64(r.upstreamHits) == hitsBefore, "SECURITY: upstream invoked during kill: %d", atomic.LoadInt64(r.upstreamHits)-hitsBefore)

	// Clear the kill; recovery is deterministic.
	req(t, getMCPRollout().clearEmergency(rollout.CapabilityGateway) == nil, "clearEmergency failed")
	req(t, !getMCPRollout().stateFor(rollout.CapabilityGateway).Killed(), "kill must be cleared")
	tok, sid = r.session(soakP1, ctrlServer)
	st, res = r.callOn(ctrlServer, tok, sid, "99", toolEcho, `{"text":"x"}`)
	req(t, st == 200 && res["shadow_outcome"] == "would_execute", "post-clear echo must recover to would_execute, got %v", res)
	r.ev("KILL UNDER LOAD: %d concurrent requests during kill, ALL emergency-blocked (rollout_emergency_active), 0 would_execute, +%d evaluation_errors, upstream=0; cleared -> would_execute recovered", blocked, blocked)
}

// soakToolTools drives a handful of in-scope requests across the four main-server tools for
// one principal (used to build durable state before a restart).
func soakTrafficRound(t *testing.T, cli *http.Client, base, aud string, pki *mcpTestPKI, principal string) {
	t.Helper()
	tok := mintBearerSub(t, pki, aud, ctrlTenant, principal)
	sid := handshake(t, cli, base, ctrlServer, tok)
	for i, tl := range []string{toolEcho, toolDanger, toolApprove, toolConfirm} {
		st, _, _ := gwPost(t, cli, base, ctrlServer, tok, sid, `{"jsonrpc":"2.0","id":`+strconv.Itoa(i+2)+`,"method":"tools/call","params":{"name":"`+tl+`","arguments":{}}}`)
		req(t, st == 200, "traffic %s: status=%d", tl, st)
	}
}

// TestShadowSoakRestart proves restart recovery mid-soak (§13): after a clean restart against
// the same durable data directory, the rollout mode, active Shadow scope, tool-trust store,
// catalog usability, and the durable evidence spool (exact count + a specific id + a valid
// digest chain) all recover; the LiveExecutor stays absent; the upstream count stays 0; and
// resumed traffic is still shadow_evaluated with zero side effects.
func TestShadowSoakRestart(t *testing.T) {
	ev := func(f string, a ...any) { t.Logf("SOAK-RESTART | "+f, a...) }
	var hits int64
	resetShadowGlobalsForRun(t)
	signer, dir := mcpProdSetup(t)
	pki := newMCPTestPKI(t)
	cli := pki.mtlsClient(t, false)
	_, mainEP := witnessEndpoint(t, &hits)
	_, rugEP := witnessEndpoint(t, &hits)
	invPath := writeInv(t, soakInventoryJSON(mainEP, rugEP))
	polPath := writeMCPPolicyFile(t, gwPolicyDoc(1, soakBaseRules()))
	telCfg := stableTelemetry(dir)
	mainTools := []struct{ s, tl string }{{ctrlServer, toolEcho}, {ctrlServer, toolDanger}, {ctrlServer, toolApprove}, {ctrlServer, toolConfirm}}

	// Boot 1: compose, promote, activate, drive traffic that commits durable evidence, shut down.
	rt1, cat1, act1 := composeShadowNode(t, pki, invPath, polPath, telCfg)
	tel1 := sharedTelemetry()
	initMCPToolTrust(nil)
	for _, tt := range mainTools {
		approveToUsable(t, cat1, tt.s, tt.tl)
	}
	rc := &rollout.SignedConfig{SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow, ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: soakScope()}
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, signer, 2, rc)})
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "boot1: activation failed")
	for _, p := range soakPrincipals {
		soakTrafficRound(t, cli, "https://"+rt1.Addr(false), act1.CanonicalURL, pki, p)
	}
	preEvents := committedShadowEvents(t)
	preCount := len(preEvents)
	req(t, preCount > 0, "boot1 must commit durable evidence")
	anID := preEvents[0].EventID
	req(t, rt1.Shutdown(ctxWithTimeout(t)) == nil, "shutdown boot1 failed")
	_ = tel1.Close(context.Background())
	ev("boot#1: Shadow active, %d durable events committed (sample id=%s), clean shutdown", preCount, anID)

	// Restart: drop in-memory singletons; durable on-disk state under the same dir survives.
	simulateProcessRestart(t)

	// Boot 2: recompose against the SAME dir, mirror production restore order, verify recovery.
	rt2, cat2, act2 := composeShadowNode(t, pki, invPath, polPath, telCfg)
	tel2 := sharedTelemetry()
	t.Cleanup(func() {
		_ = rt2.Shutdown(ctxWithTimeout(t))
		_ = tel2.Close(context.Background())
		publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	})
	initMCPToolTrust(nil)
	for _, tt := range mainTools {
		_, _, elig := catRec(t, cat2, tt.s, tt.tl)
		req(t, elig == catalog.Usable, "boot2: %s must re-derive Usable, got %v", tt.tl, elig)
	}
	getMCPRollout().restore()
	initMCPDistribution(nil)
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "SECURITY: Shadow must survive restart, mode=%s", getMCPRollout().gateway.CurrentMode())
	postEvents := committedShadowEvents(t)
	req(t, len(postEvents) == preCount, "durable evidence count must recover exactly: got %d want %d (no loss, no duplicate)", len(postEvents), preCount)
	req(t, shadowEventByIDPresent(t, anID), "the specific pre-restart event id=%s must recover", anID)
	for i := range postEvents {
		req(t, postEvents[i].VerifyDigest() && postEvents[i].Validate() == nil, "recovered event %s digest/chain must remain valid", postEvents[i].EventID)
	}
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must remain absent across restart")
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during restart/reconciliation: %d", atomic.LoadInt64(&hits))

	// Resume traffic: still shadow-evaluated, zero side effects.
	tok := mintBearerSub(t, pki, act2.CanonicalURL, ctrlTenant, soakP1)
	sid := handshake(t, cli, "https://"+rt2.Addr(false), ctrlServer, tok)
	st, _, body := gwPost(t, cli, "https://"+rt2.Addr(false), ctrlServer, tok, sid, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"text":"post"}}}`)
	res := resultOf(t, body)
	req(t, st == 200 && res["execution_state"] == "shadow_evaluated" && res["shadow_outcome"] == "would_execute", "resumed traffic must be shadow_evaluated/would_execute, got %v", res)
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked by resumed traffic: %d", atomic.LoadInt64(&hits))
	ev("boot#2: Shadow RESTORED (mode=shadow), tools re-derived Usable, %d durable events recovered (id=%s present), digest chain valid, live_executor=absent, upstream=0, traffic resumed", len(postEvents), anID)
}

// soakSmallEvents returns a VALID event-limits set whose SEGMENT size is tiny (32 KiB) so a
// bounded commit loop deterministically crosses many segment-rotation boundaries, while the
// SPOOL/recovery byte budgets are sized to hold n such events losslessly. The tiny segment
// size — not a tiny total spool — is what this test needs; a fixed tiny reserve would make
// the product CORRECTLY fail closed (event_durability_degraded) once n exceeds the reserve,
// which is a different property than the lossless-across-rotation one under test here.
func soakSmallEvents(t *testing.T, n int) limits.EventLimits {
	t.Helper()
	// Conservative durable+framing upper bound per soakShadowFacts event (segment/encryption
	// overhead makes the on-plate cost ~2x the ~480 B canonical body).
	const perEvent = 1400
	crit := 512<<10 + n*perEvent // reserve holds every committed critical event
	// SpoolMaxBytes at 2x the critical reserve keeps n events near ~50% utilization — well
	// under HighWatermarkPct (85%), so the total-spool watermark never triggers a reclaim
	// that cannot free retained critical events (the event_durability_degraded path).
	spoolMax := 2*crit + 256<<10
	segMax := 32 << 10
	segments := spoolMax/segMax + 64
	// The crash-consistent checkpoint records per-segment state, so its size scales with the
	// live segment count. With 32 KiB segments the count grows into the hundreds at volume,
	// so MaxMetadataBytes (which bounds the checkpoint) must scale with the segment cap or a
	// large-n run fails with "checkpoint exceeds metadata bound" — a config-sizing artifact,
	// not a durability property. ~512 B/segment with a 64 KiB floor.
	metaBound := 64<<10 + segments*512
	lim, err := limits.NewEvent(limits.EventConfig{
		SpoolMaxBytes: spoolMax, CriticalReserveBytes: crit,
		OrdinaryQuotaBytes: 128 << 10, DenialQuotaBytes: 64 << 10,
		SegmentMaxBytes: segMax, MaxEventBytes: 16 << 10, MaxMetadataBytes: metaBound,
		MaxSafeResultBytes: 64 << 10, MaxSegments: segments, MaxQueuePerPartition: 4096,
		MaxInFlightCommits: 64, CommitBatchSize: 64, MaxSyncOps: 16, MaxDenialBuckets: 4096,
		MaxBucketsPerSource: 128, MaxCoalescePerAggregate: 1 << 20, MaxRecoveryScanBytes: spoolMax + 1<<20,
		MaxRecoverySegments: segments, MaxRecoveryRecords: n + 65536, MaxReclaimPerPass: 256,
		ExporterWorkers: 2, ExportBatchRecords: 256, ExportBatchBytes: 1 << 20, ExportMaxRetries: 4,
		ReplayWindowEntries: n + 65536, TenantExportMaxRecords: 4096, TenantExportMaxBytes: 4 << 20,
		HighWatermarkPct: 85, LowWatermarkPct: 60, ReserveRecoveryPct: 50,
		AggregationWindow: time.Second, RetentionWindow: time.Hour, ProbeInterval: time.Second,
		CommitBatchDelay: time.Millisecond, ShutdownDrain: time.Second,
	})
	req(t, err == nil, "small event limits: %v", err)
	return lim
}

// soakShadowFacts builds a valid schema-v2 shadow DecisionFacts (a would_execute record).
func soakShadowFacts() events.DecisionFacts {
	return events.DecisionFacts{
		Capability: evmodel.CapGateway, Criticality: evmodel.CritCritical, ActionClass: evmodel.ActionClassWrite,
		Identity: evmodel.IdentityEvidence{Tenant: ctrlTenant, PrincipalID: "p", PrincipalType: "service"},
		Decision: evmodel.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.RESOURCE_SCOPE", PolicyRevision: 1, CatalogRevision: 1, ExecutionState: "shadow_evaluated"},
		Shadow: &evmodel.ShadowEvidence{
			Outcome: "would_execute", Override: false, CredentialPlan: "no_credential_profile",
			MaterializationReadiness: "not_evaluated", RequestInspection: "not_evaluated", ResponseInspection: "not_evaluated",
		},
	}
}

// TestShadowSoakEvidenceStress proves the durable schema-v2 evidence spool is lossless and
// tamper-evident under stress (§14/§20): enough v2 events to cross segment-rotation
// boundaries commit, read back exactly (no loss, no duplicate), survive a recover with an
// identical count and a clean recover report (no corruption repair), re-read identically;
// and the no-hidden-auto-repair invariants hold — an unknown schema version fails closed and
// a tampered event fails its digest verification (never silently repaired).
func TestShadowSoakEvidenceStress(t *testing.T) {
	ev := func(f string, a ...any) { t.Logf("SOAK-EVIDENCE | "+f, a...) }
	dir := t.TempDir()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	var clk atomic.Int64
	clock := func() time.Time { return time.Unix(0, clk.Add(1)) }
	// Honor the documented heavy band [5000, 20000] INCLUSIVELY; CLAMP above it rather than
	// silently falling back to the CI size (the evidence-stress spool/recovery cost is bounded
	// here — the full request-count soak still scales with h in TestShadowSoak). A strict
	// `h < 20000` would make CULVERT_MCP_SOAK=20000, the documented upper endpoint, run the
	// 150-record CI workload instead (Codex).
	n := 150
	if h := soakHeavyCount(); h > 0 {
		n = h
		if n > 20000 {
			n = 20000
		}
	}
	mkMgr := func() *events.Manager {
		m, err := events.NewManager(events.ManagerConfig{
			NodeID: "qual-node-1", DataDir: dir, KEK: secret.MemoryProvider(k),
			GatewayLimits: soakSmallEvents(t, n), ManagementLimits: limits.DefaultManagementEvent(), Clock: clock,
		})
		req(t, err == nil, "NewManager: %v", err)
		return m
	}

	m1 := mkMgr()
	for i := 0; i < n; i++ {
		_, err := m1.CommitDecision(soakShadowFacts())
		req(t, err == nil, "commit %d: %v", i, err)
	}
	sp1 := m1.Spool(evmodel.CapGateway)
	evs, _, _, err := sp1.CommittedForExport(evmodel.PartCrit, 0, n+10)
	req(t, err == nil, "read-back: %v", err)
	req(t, len(evs) == n, "read-back count=%d must equal committed=%d (no loss, no duplicate)", len(evs), n)
	var bytesOnPlate int
	ids := map[string]bool{}
	for i := range evs {
		e := evs[i]
		req(t, !ids[e.EventID], "duplicate event id %s", e.EventID)
		ids[e.EventID] = true
		req(t, e.SchemaVersion == evmodel.SchemaVersionV2 && e.Shadow != nil, "event %s must be schema-v2 shadow", e.EventID)
		req(t, e.VerifyDigest() && e.Validate() == nil, "event %s digest/validity", e.EventID)
		cb, cerr := e.CanonicalBytes()
		req(t, cerr == nil, "canonical bytes: %v", cerr)
		bytesOnPlate += len(cb)
	}
	req(t, bytesOnPlate > (32<<10), "must cross a segment boundary: plaintext bytes=%d <= SegmentMaxBytes=%d", bytesOnPlate, 32<<10)
	req(t, m1.Close() == nil, "close m1")
	ev("committed %d schema-v2 shadow events (~%d KiB plaintext > 32 KiB SegmentMaxBytes => rotation crossed); read back exactly, no loss/duplicate, all digests+validity ok", n, bytesOnPlate>>10)

	// Recover on the same directory: identical count, clean recover report (no repair).
	m2 := mkMgr()
	rep, err := m2.Spool(evmodel.CapGateway).Recover()
	req(t, err == nil, "recover: %v", err)
	req(t, !rep.Corrupt, "recover must report NO corruption (no hidden repair): %s/%s", rep.CorruptPartition, rep.CorruptReason)
	req(t, rep.Records[evmodel.PartCrit] == n, "recover must replay exactly %d P-CRIT records, got %d", n, rep.Records[evmodel.PartCrit])
	evs2, _, _, err := m2.Spool(evmodel.CapGateway).CommittedForExport(evmodel.PartCrit, 0, n+10)
	req(t, err == nil && len(evs2) == n, "post-recover read-back count=%d must equal %d (no loss)", len(evs2), n)
	// Re-read (idempotent export) is identical.
	evs3, _, _, err := m2.Spool(evmodel.CapGateway).CommittedForExport(evmodel.PartCrit, 0, n+10)
	req(t, err == nil && len(evs3) == n, "re-read count=%d must equal %d", len(evs3), n)
	req(t, m2.Close() == nil, "close m2")
	ev("recover: %d records replayed across rotated segments, Corrupt=false, read/re-read == %d (events_written == events_recovered == events_reread)", rep.Records[evmodel.PartCrit], n)

	// §20 no hidden auto-repair: an unknown schema version fails closed; a tampered event
	// fails its digest verification rather than being silently repaired.
	req(t, !evmodel.SupportedSchemaVersion(3), "schema v3 must be unsupported (fail closed)")
	bad := evs[0]
	bad.SchemaVersion = 3
	req(t, bad.Validate() != nil, "an unknown schema version must fail validation (fail closed)")
	tampered := evs[0]
	tampered.Shadow = &evmodel.ShadowEvidence{Outcome: "would_block", Override: true, CredentialPlan: "no_credential_profile", MaterializationReadiness: "not_evaluated", RequestInspection: "not_evaluated", ResponseInspection: "not_evaluated"}
	req(t, !tampered.VerifyDigest(), "a tampered event must FAIL digest verification (corruption detected, never repaired)")
	req(t, evs[0].VerifyDigest(), "the original untampered event still verifies")
	ev("no-hidden-repair (in-memory digest primitive): schema v3 fails closed; tampered event fails VerifyDigest; original still verifies. The DURABLE recovery path is proven separately by TestShadowSoakEvidencePersistedCorruptionFailsClosed")
}

// TestShadowSoakEvidencePersistedCorruptionFailsClosed proves the no-hidden-auto-repair
// invariant at the REAL durable seam (§20): a byte flipped INSIDE a committed, persisted
// P-CRIT segment on disk is detected by Spool.Recover as corruption (Corrupt=true), never
// silently repaired, discarded, or accepted. The in-memory VerifyDigest check in
// TestShadowSoakEvidenceStress proves the detection primitive; this proves the recovery path
// actually invokes it against on-disk corruption. A CLEAN reopen of the same directory is the
// control (Corrupt=false, exact record count) so the gate cannot pass vacuously.
func TestShadowSoakEvidencePersistedCorruptionFailsClosed(t *testing.T) {
	ev := func(f string, a ...any) { t.Logf("SOAK-EVIDENCE-CORRUPT | "+f, a...) }
	dir := t.TempDir()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 11)
	}
	var clk atomic.Int64
	clock := func() time.Time { return time.Unix(0, clk.Add(1)) }
	const n = 64
	mk := func() *events.Manager {
		m, err := events.NewManager(events.ManagerConfig{
			NodeID: "qual-node-1", DataDir: dir, KEK: secret.MemoryProvider(k),
			GatewayLimits: soakSmallEvents(t, n), ManagementLimits: limits.DefaultManagementEvent(), Clock: clock,
		})
		req(t, err == nil, "NewManager: %v", err)
		return m
	}

	// Commit enough critical shadow events to fill and seal at least one P-CRIT segment.
	m1 := mk()
	for i := 0; i < n; i++ {
		_, err := m1.CommitDecision(soakShadowFacts())
		req(t, err == nil, "commit %d: %v", i, err)
	}
	req(t, m1.Close() == nil, "close m1")

	// CONTROL: a clean reopen recovers exactly n P-CRIT records with NO corruption.
	mc := mk()
	repClean, err := mc.Spool(evmodel.CapGateway).Recover()
	req(t, err == nil && !repClean.Corrupt && repClean.Records[evmodel.PartCrit] == n,
		"control: a clean reopen must recover %d P-CRIT records with Corrupt=false, got %+v err=%v", n, repClean, err)
	req(t, mc.Close() == nil, "close mc")
	ev("control: clean reopen recovered %d P-CRIT records, Corrupt=false", n)

	// Corrupt an INTERIOR run of the FIRST persisted P-CRIT segment — past the segment header
	// and well before the (uncommitted) tail, so recovery must classify it as genuine
	// corruption rather than a truncatable torn tail. A run (not one byte) guarantees a
	// record ciphertext is hit, forcing an AEAD/chain failure regardless of frame alignment.
	segs, gerr := filepath.Glob(filepath.Join(dir, "gateway", evmodel.PartCrit.String(), "seg-*.dat"))
	req(t, gerr == nil && len(segs) > 0, "must find a persisted P-CRIT segment, got %v (err=%v)", segs, gerr)
	sort.Strings(segs)
	seg := segs[0]
	b, rerr := os.ReadFile(seg)
	req(t, rerr == nil && len(b) > 512, "read segment %s: err=%v len=%d", seg, rerr, len(b))
	start := len(b) / 4
	for i := start; i < start+128 && i < len(b); i++ {
		b[i] ^= 0xFF
	}
	req(t, os.WriteFile(seg, b, 0o600) == nil, "write corrupted segment")

	// Recovery MUST detect the persisted corruption and fail closed.
	m2 := mk()
	rep, rerr2 := m2.Spool(evmodel.CapGateway).Recover()
	req(t, rerr2 == nil, "Recover must surface corruption via the report, not a hard error: %v", rerr2)
	req(t, rep.Corrupt && rep.CorruptPartition == evmodel.PartCrit,
		"GATE no-hidden-repair: persisted P-CRIT corruption must be detected on recovery (Corrupt, never silently repaired/accepted), got %+v", rep)
	req(t, m2.Close() == nil, "close m2")
	ev("persisted corruption: flipped a 128-byte interior run in %s -> Recover reported Corrupt=true partition=%s reason=%q (no silent repair/discard/accept)",
		filepath.Base(seg), rep.CorruptPartition, rep.CorruptReason)
}

// failAppendBackend wraps the real OS backend but fails every durable segment append (the
// event-commit write). State-file replacement is left intact so the Manager still composes;
// only the durable evidence write fails — the exact fault §19 must fail closed on.
type failAppendBackend struct{ spool.Backend }

func (failAppendBackend) AppendSync(string, []byte, os.FileMode) error {
	return errors.New("soak: injected durable-write failure")
}

// TestShadowSoakEvidenceCommitFailsClosed proves the durable-evidence-commit chokepoint the
// ShadowEvaluator sits on fails CLOSED (§19): with an injected durable-write fault, the real
// Manager.CommitThenAct (the exact seam the evaluator calls at shadow_evaluator.go before it
// would proceed) returns an error, the "act" continuation is NEVER run, and no shadow event
// is committed — a shadow evaluation cannot be reported successful without durable evidence.
// The fault is injected at the real spool.Backend boundary, not a mock that bypasses it.
func TestShadowSoakEvidenceCommitFailsClosed(t *testing.T) {
	ev := func(f string, a ...any) { t.Logf("SOAK-FAILCLOSED | "+f, a...) }
	dir := t.TempDir()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 11)
	}
	var clk atomic.Int64
	m, err := events.NewManager(events.ManagerConfig{
		NodeID: "qual-node-1", DataDir: dir, KEK: secret.MemoryProvider(k),
		GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
		Backend: failAppendBackend{spool.NewOSBackend()}, Clock: func() time.Time { return time.Unix(0, clk.Add(1)) },
	})
	req(t, err == nil, "NewManager (fault backend): %v", err)
	t.Cleanup(func() { _ = m.Close() })

	acted := false
	cerr := m.CommitThenAct(soakShadowFacts(), func(spool.CommitReceipt) error { acted = true; return nil })
	req(t, cerr != nil, "durable-commit failure must FAIL CLOSED: CommitThenAct must return an error")
	req(t, !acted, "SECURITY: the act continuation must NOT run when the durable commit failed (no proceed without evidence)")
	evs, _, _, _ := m.Spool(evmodel.CapGateway).CommittedForExport(evmodel.PartCrit, 0, 10)
	req(t, len(evs) == 0, "no shadow event may be committed when the durable write fails, got %d", len(evs))
	ev("FAIL-CLOSED: injected durable-write fault -> CommitThenAct errored (%v), act continuation NOT run, 0 events committed", cerr != nil)
}

// TestShadowSoakMutationCampaign is the §21 adversarial campaign: for each of the twelve
// hostile mutations, it demonstrates that the corresponding NAMED gate fails/blocks. It
// reuses one real Shadow node for the behavioral mutations and unit checks for the
// structural/durable ones. Each sub-test attempts the mutation and asserts the gate holds.
func TestShadowSoakMutationCampaign(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	r := newSoakRun(t, &hits)
	tok, sid := r.session(soakP1, ctrlServer)

	// M1 — allow one upstream invocation from Shadow. Gate: structural (no UpstreamCaller;
	// the auxiliary witness must observe 0) + live-exec tier never armed.
	t.Run("M1_no_upstream_from_shadow", func(t *testing.T) {
		st, res := r.callOn(ctrlServer, tok, sid, "1", toolEcho, `{"text":"x"}`)
		req(t, st == 200 && res["shadow_outcome"] == "would_execute", "echo must be would_execute")
		req(t, atomic.LoadInt64(&hits) == 0, "GATE upstream-witness: Shadow must cause 0 upstream invocations, got %d", atomic.LoadInt64(&hits))
		req(t, !liveExecDepsConfigured(false), "GATE exec-posture: live-execution tier must never arm")
	})

	// M2 — allow one Materialize call. Gate: MaterializationReadiness is always not_evaluated —
	// asserted over EVERY committed shadow event (no broker composed ⇒ readiness is never
	// derived), not merely one "latest" event.
	t.Run("M2_no_materialization", func(t *testing.T) {
		evs := committedShadowEvents(t)
		req(t, len(evs) > 0, "GATE materialization: expected committed shadow events")
		for i := range evs {
			req(t, evs[i].Shadow.MaterializationReadiness == "not_evaluated",
				"GATE materialization: event %s readiness must be not_evaluated, got %q", evs[i].EventID, evs[i].Shadow.MaterializationReadiness)
		}
	})

	// M3 — let an out-of-scope principal enter Shadow. Gate: scope containment.
	t.Run("M3_out_of_scope_containment", func(t *testing.T) {
		otok, osid := r.session(outsiderSub, ctrlServer)
		st, res := r.callOn(ctrlServer, otok, osid, "1", toolEcho, `{"text":"x"}`)
		req(t, st == 200 && res["execution_state"] != "shadow_evaluated" && res["shadow_outcome"] == nil,
			"GATE scope-containment: out-of-scope principal must NOT be shadow-evaluated, got %v", res)
	})

	// M4 — drop durable evidence for one response. Gate: durable-commit fail-closed (proven at
	// the real seam by TestShadowSoakEvidenceCommitFailsClosed; re-assert the contract).
	t.Run("M4_evidence_commit_fail_closed", func(t *testing.T) {
		dir := t.TempDir()
		k := make([]byte, 32)
		var clk atomic.Int64
		m, err := events.NewManager(events.ManagerConfig{
			NodeID: "n", DataDir: dir, KEK: secret.MemoryProvider(k),
			GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
			Backend: failAppendBackend{spool.NewOSBackend()}, Clock: func() time.Time { return time.Unix(0, clk.Add(1)) },
		})
		req(t, err == nil, "manager: %v", err)
		defer m.Close() //nolint:errcheck // best-effort close in a test
		acted := false
		cerr := m.CommitThenAct(soakShadowFacts(), func(spool.CommitReceipt) error { acted = true; return nil })
		req(t, cerr != nil && !acted, "GATE fail-closed: a dropped durable evidence commit must block, act must not run")
	})

	// M5 — mismatch response and durable outcome. Gate: response<->durable parity (single
	// shadowEvidence source). A would_block request's response and durable event must agree.
	t.Run("M5_response_durable_parity", func(t *testing.T) {
		preIDs := committedShadowEventIDs(t)
		st, res := r.callOn(ctrlServer, tok, sid, "5", toolDanger, `{"x":"y"}`)
		req(t, st == 200, "danger status")
		de, ok := newShadowEvidence(t, preIDs)
		req(t, ok && de.Shadow.Outcome == res["shadow_outcome"] &&
			de.Shadow.MaterializationReadiness == res["materialization_ready"] &&
			de.Shadow.ResponseInspection == res["response_inspection"],
			"GATE parity: response and durable evidence must match, durable=%+v response=%v", de.Shadow, res)
	})

	// M6 — preserve F1 approval after an F2 fingerprint change. Gate: rug-pull (privilege
	// expansion quarantines; the stale approval does not govern; reconcile does not re-promote).
	t.Run("M6_fingerprint_rugpull", func(t *testing.T) {
		r.reingestRug(`{"r":{"type":"string"}}`, catalog.DestNone)
		r.reapproveTool(rugServer, rugTool)
		r.reingestRug(`{"r":{"type":"string"}}`, catalog.DestArbitrary)
		_, _, elig := catRec(t, r.cat, rugServer, rugTool)
		req(t, elig == catalog.Quarantined, "GATE rug-pull: privilege-expansion must Quarantine, got %v", elig)
		rt, rs := r.session(soakP3, rugServer)
		st, res := r.callOn(rugServer, rt, rs, "6", rugTool, `{"r":"x"}`)
		req(t, st == 200 && res["shadow_outcome"] == "would_fail_hard_control",
			"GATE rug-pull: stale F1 approval must NOT govern F2, got %v", res)
		r.reapproveTool(rugServer, rugTool)
	})

	// M7 — ignore a revoke. Gate: revoke is honored immediately.
	t.Run("M7_revoke_honored", func(t *testing.T) {
		r.revokeTool(ctrlServer, toolApprove)
		at, as := r.session(soakP2, ctrlServer)
		st, res := r.callOn(ctrlServer, at, as, "7", toolApprove, `{"a":"b"}`)
		req(t, st == 200 && res["shadow_outcome"] == "would_fail_hard_control",
			"GATE revoke: a revoked tool must be would_fail_hard_control, got %v", res)
		r.reapproveTool(ctrlServer, toolApprove)
	})

	// M8 — ignore the kill switch. Gate: an engaged kill emergency-blocks every request.
	t.Run("M8_kill_honored", func(t *testing.T) {
		req(t, getMCPRollout().emergencyDisable(rollout.CapabilityGateway, "mut") == nil, "kill")
		kt, ks := r.session(soakP1, ctrlServer)
		st, res := r.callOn(ctrlServer, kt, ks, "8", toolEcho, `{"text":"x"}`)
		eo, _ := res["error"].(map[string]any)
		req(t, st == 200 && res["execution_state"] != "shadow_evaluated" && eo != nil && eo["message"] == "rollout_emergency_active",
			"GATE kill: a killed node must emergency-block, got %v", res)
		req(t, getMCPRollout().clearEmergency(rollout.CapabilityGateway) == nil, "clear")
	})

	// M9 — restore live-exec readiness during restart. Gate: live-exec tier stays unarmed
	// (markGatewayExecDepsReady has no production caller — execution-posture wall).
	t.Run("M9_live_exec_never_armed", func(t *testing.T) {
		req(t, !liveExecDepsConfigured(false), "GATE exec-posture: live-execution readiness must stay false")
	})

	// M10 — mix policy revision N and N+1. Gate: each event carries exactly its governing
	// revision (atomic snapshot), a restrictive revision is never would_execute.
	t.Run("M10_no_policy_mixing", func(t *testing.T) {
		r.publishEchoPolicy(5000, false) // echo DENY at rev 5000
		preIDs := committedShadowEventIDs(t)
		st, res := r.callOn(ctrlServer, tok, sid, "10", toolEcho, `{"text":"x"}`)
		req(t, st == 200 && res["shadow_outcome"] == "would_block", "echo must be would_block at the deny revision")
		de, ok := newShadowEvidence(t, preIDs)
		req(t, ok && de.Decision.PolicyRevision == 5000 && de.Shadow.Outcome == "would_block",
			"GATE no-mixing: event must carry revision 5000 with would_block, got rev=%d outcome=%s", de.Decision.PolicyRevision, de.Shadow.Outcome)
		r.publishEchoPolicy(5001, true) // restore echo ALLOW
	})

	// M11 — recover a malformed v2 event permissively. Gate: unknown schema fails closed; a
	// tampered event fails its digest.
	t.Run("M11_no_permissive_recovery", func(t *testing.T) {
		evs := committedShadowEvents(t)
		req(t, len(evs) > 0, "need a committed event")
		de := evs[0] // any committed shadow event serves as the tamper sample
		bad := de
		bad.SchemaVersion = 3
		req(t, !evmodel.SupportedSchemaVersion(3) && bad.Validate() != nil, "GATE schema: an unknown v3 event must fail closed")
		tampered := de
		tampered.Decision.PolicyRevision = de.Decision.PolicyRevision + 999
		req(t, !tampered.VerifyDigest(), "GATE digest: a tampered event must fail VerifyDigest")
	})

	// M12 — let an expired approval remain governing. Gate: an expired approval demotes and a
	// fresh request is would_fail_hard_control.
	t.Run("M12_expired_cannot_govern", func(t *testing.T) {
		base := time.Now()
		var nn atomic.Int64
		nn.Store(base.UnixNano())
		// Swap UNDER mcpToolTrust.mu — same leaked-reconcile-loop race as toolTrustExpire.
		prev := swapToolTrustNowFnForTest(func() time.Time { return time.Unix(0, nn.Load()) })
		defer func() { swapToolTrustNowFnForTest(prev) }()
		r.revokeTool(ctrlServer, toolConfirm)
		r.approvals[toolConfirm] = r.approveWithExpiry(ctrlServer, toolConfirm, base.Add(5*time.Second))
		nn.Store(base.Add(time.Hour).UnixNano())
		mcpToolTrustReconcile()
		ct, cs := r.session(soakP2, ctrlServer)
		st, res := r.callOn(ctrlServer, ct, cs, "12", toolConfirm, `{"c":"d"}`)
		req(t, st == 200 && res["shadow_outcome"] == "would_fail_hard_control",
			"GATE expiry: an expired approval must NOT govern, got %v", res)
		nn.Store(time.Now().UnixNano())
		r.reapproveTool(ctrlServer, toolConfirm)
	})

	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during the mutation campaign: %d", atomic.LoadInt64(&hits))
	r.ev("MUTATION CAMPAIGN: 12/12 hostile mutations each blocked by a named gate; upstream=0")
}

// shadowMetricsDelta returns after-minus-before for every bucket (this-run contribution to
// the process-global accumulator).
func shadowMetricsDelta(before, after shadowMetricsView) shadowMetricsView {
	return shadowMetricsView{
		Evaluations:              after.Evaluations - before.Evaluations,
		WouldExecute:             after.WouldExecute - before.WouldExecute,
		WouldBlock:               after.WouldBlock - before.WouldBlock,
		WouldRequireApproval:     after.WouldRequireApproval - before.WouldRequireApproval,
		WouldRequireConfirmation: after.WouldRequireConfirmation - before.WouldRequireConfirmation,
		WouldFailCredential:      after.WouldFailCredential - before.WouldFailCredential,
		WouldFailInspection:      after.WouldFailInspection - before.WouldFailInspection,
		WouldFailStale:           after.WouldFailStale - before.WouldFailStale,
		WouldFailHardControl:     after.WouldFailHardControl - before.WouldFailHardControl,
		WouldOther:               after.WouldOther - before.WouldOther,
		EvaluationErrors:         after.EvaluationErrors - before.EvaluationErrors,
	}
}
