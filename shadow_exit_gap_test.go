package main

// Shadow Exit Gap Closure — end-to-end runtime proofs (Phase A).
//
// These drive the REAL Culvert MCP production paths end to end on a controlled
// in-process node (real Gateway listener, real TLS+OAuth, the REAL non-executing
// *execution.ShadowEvaluator composed via composeGatewayShadowIntoConfig, the REAL
// signed CP→DP activation, the REAL durable schema-v2 evidence spool) to close the
// Shadow-side Exit criteria that the soak could not establish in a Planner-less build:
//
//   C4  — a REAL post-entry / pre-boundary tool drift, injected mid-pipeline through the
//         credential-planner callback (one of the named real blocking windows), reaching
//         the production ToolStillCurrent boundary re-check and yielding would_fail_stale.
//   C8  — a REAL metadata-only credential-planning path composed through the production
//         Shadow seam (shadowCredentialPlannerSeam); Plan is exercised, Materialize/upstream
//         never are.
//   C9  — the kill switch honored fail-closed BEFORE Shadow evaluation (Invariant A): a
//         killed request commits NO shadow-evaluated event.
//   C6  — same-traffic Observe-vs-Shadow denial parity.
//   C12 — the operator runbook driven through the real admin API surfaces.
//
// BOUNDARIES (verbatim from the phase brief, honored exactly): NO Canary, NO Production,
// NO LiveExecutor, NO upstream execution, NO credential Materialize, NO live_execution
// approval, and Shadow's no-side-effect property is never weakened. Every test reasserts
// upstream=0 and that the live executor stays unarmed. Criterion 13 / PREREQ-MCP-KILL-1 is
// deliberately untouched — it remains a separate follow-up product-security PR.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ── shared gap harness ───────────────────────────────────────────────────────

// ctrlServerIdentity is the controlled server's pinned SPIFFE id — the Identity a
// re-ingest MUST carry so it is a per-tool rediscovery, never a server-identity change.
const ctrlServerIdentity = "spiffe://qual/controlled-test-server"

// allowEchoCredRule is the echo ALLOW rule carrying a credential-profile obligation, so a
// matched echo decision engages decide()'s step-5 credential-readiness path (the planner).
// A credential profile is only valid on an ALLOW-class Gateway rule (obligation.go).
const allowEchoCredRule = `{"id":"ALLOW_ECHO_CRED","priority":20,"action":"ALLOW",` +
	`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
	`"conditions":[{"field":"tool.name","op":"exact","value":"echo"}],` +
	`"obligations":{"logging":"standard","credential_profile":"profile:ro"}}`

// gapEnv carries the handles a gap experiment drives against ONE controlled Shadow node.
type gapEnv struct {
	t        *testing.T
	pki      *mcpTestPKI
	cli      *http.Client
	base     string
	audience string
	rt       *mcpruntime.Runtime
	cat      *catalog.Catalog
	reg      *registry.Registry
	signer   cpdp.Signer
	hits     *int64
	cfgRev   uint64
	ev       func(string, ...any)
}

// newGapEnv runs the REAL production observe+shadow composition against a controlled
// inventory + policy, optionally installing a metadata-only credential planner through the
// production Shadow seam (shadowCredentialPlannerSeam) BEFORE composition so the evaluator
// binds it exactly as a real deployment would. The node is left composed, listening, and in
// Disabled mode (no activation yet); tool-trust is initialized. Callers approve tools and
// activate as each criterion needs.
func newGapEnv(t *testing.T, hits *int64, invFactory func(endpoint string) string, polDoc string, planner execution.CredentialPlanner) *gapEnv {
	t.Helper()
	ev := func(format string, a ...any) { t.Logf("EVIDENCE | "+format, a...) }
	signer, dir := mcpProdSetup(t)
	ev("baseline dataDir=%s; gateway_mode=%s live_exec_ready=%v", dir, getMCPRollout().gateway.CurrentMode(), liveExecDepsConfigured(false))
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeDisabled, "baseline gateway mode must be Disabled, got %s", getMCPRollout().gateway.CurrentMode())

	if planner != nil {
		prev := shadowCredentialPlannerSeam
		shadowCredentialPlannerSeam = planner
		t.Cleanup(func() { shadowCredentialPlannerSeam = prev })
	}

	pki := newMCPTestPKI(t)
	_, endpoint := witnessEndpoint(t, hits)
	invPath := writeInv(t, invFactory(endpoint))
	polPath := writeMCPPolicyFile(t, polDoc)
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
	initMCPToolTrust(nil)
	// The admin-API singleton (getMCPAdmin) snapshots the inventory exactly ONCE (sync.Once) and
	// is a process global that no other reset touches. Reset it AFTER this node's inventory is
	// published so the operator admin endpoints (C12) bind to THIS inventory regardless of test
	// order, and restore a fresh disabled default on cleanup so a bound singleton never leaks
	// into another test — otherwise a prior test that bound it against an empty holder makes
	// GET /api/mcp/tools report 0 tools here (order-dependent flake under -shuffle/-count).
	resetMCPAdminSingleton()
	t.Cleanup(resetMCPAdminSingleton)
	reg, _ := mcpInventory.sharedInventory()
	e := &gapEnv{
		t: t, pki: pki, cli: pki.mtlsClient(t, false), base: "https://" + rt.Addr(false),
		audience: act.CanonicalURL, rt: rt, cat: cat, reg: reg, signer: signer, hits: hits, cfgRev: 1, ev: ev,
	}
	ev("gateway listener LIVE at %s (real TLS+OAuth); shadow_evaluator_composed=YES live_executor_composed=NO", e.base)
	return e
}

// applyGateway signs and applies a Gateway rollout config at a monotonically-increasing rev.
func (e *gapEnv) applyGateway(rc *rollout.SignedConfig) {
	e.cfgRev++
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(e.t, e.signer, e.cfgRev, rc)})
}

// activateShadow performs the signed Observe→Shadow transition for a scope after asserting
// the genuine activation preflight is ready.
func (e *gapEnv) activateShadow(scope rollout.ScopeSpec) {
	t := e.t
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway, scope, 1)
	req(t, pf.Ready, "activation preflight must be ready, reasons=%v", pf.Reasons)
	e.applyGateway(&rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: scope,
	})
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "activation failed: mode=%s", getMCPRollout().gateway.CurrentMode())
	req(t, globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway).Active() != nil, "distribution must be active after Shadow activation")
	e.ev("ACTIVATED Observe->Shadow: mode=shadow distribution_active=true canary=off production=off live_exec_ready=%v", liveExecDepsConfigured(false))
}

// token mints an ES256 gateway bearer for a subject (principal).
func (e *gapEnv) token(sub string) string {
	return mintBearerSub(e.t, e.pki, e.audience, ctrlTenant, sub)
}

// newShadowEventCount returns how many committed schema-v2 shadow events have an id NOT in
// preIDs — the durable shadow events produced since preIDs was captured. Zero proves a
// request produced NO shadow evaluation (the C9 Invariant-A proof).
func newShadowEventCount(t *testing.T, preIDs map[string]bool) int {
	t.Helper()
	n := 0
	evs := committedShadowEvents(t)
	for i := range evs { // index-based: Event is a wide struct (rangeValCopy)
		if !preIDs[evs[i].EventID] {
			n++
		}
	}
	return n
}

// ── Criterion 4 — driven boundary-drift stale (post-entry, pre-boundary) ─────

// driftOnPlanPlanner is a metadata-only CredentialPlanner whose Plan, on its FIRST call,
// re-ingests the controlled server through the REAL catalog ingest path with a changed echo
// input-schema — publishing a new echo fingerprint into the LIVE catalog snapshot. This
// deterministically places a genuine tool drift in the post-entry / pre-boundary window
// (credential planning is one of the real blocking stages the OVN-09 comment names), so the
// production step-6 ToolStillCurrent re-check observes it. Plan returns a VALID plan (nil
// error) so decide() proceeds from the credential step to the boundary drift check. It holds
// NO Materialize, performs no provider call, no secret retrieval, no upstream dial.
type driftOnPlanPlanner struct {
	drifted atomic.Bool
	raw     []byte
	ingests int32
}

func (p *driftOnPlanPlanner) Plan(broker.PlanInput) (broker.CredentialPlan, error) {
	if p.drifted.CompareAndSwap(false, true) {
		reg, cat := mcpInventory.sharedInventory()
		if reg != nil && cat != nil {
			if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
				ServerID:     registry.ServerID(ctrlServer),
				Identity:     registry.Identity(ctrlServerIdentity),
				Raw:          p.raw,
				Destinations: map[string]catalog.DestinationClass{toolEcho: catalog.DestNone, toolDanger: catalog.DestNone},
			}); err == nil {
				atomic.AddInt32(&p.ingests, 1)
			}
		}
	}
	return broker.CredentialPlan{}, nil
}

// driftedEchoDangerRaw is the drifted rediscovery: echo gains a new input-schema property
// ("drift"), changing its InputSchemaHash and therefore its fingerprint; danger is carried
// unchanged so the re-ingest does not incidentally drop it.
const driftedEchoDangerRaw = `{"tools":[` +
	`{"name":"echo","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"drift":{"type":"string"}}},"description":"echo"},` +
	`{"name":"danger","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}},"description":"danger"}` +
	`]}`

// TestShadowExitC4_BoundaryDriftYieldsStale proves criterion 4 end to end: an in-scope echo
// call passes dispatch eligibility (the entry OVN-09 refuseOnToolDrift), the catalog then
// changes AFTER entry (the credential planner re-ingests a drifted echo fingerprint), the
// production boundary re-check (ToolStillCurrent) detects it, and the Shadow evaluator
// predicts would_fail_stale_decision — with a durable schema-v2 event matching the response
// and zero upstream side effects. The would_fail_stale_decision arrives as a SHADOW-EVALUATED
// event (not the entry refuseOnToolDrift rejection, which produces a decision_snapshot_stale
// reject and NO shadow event), which is exactly what proves the drift was caught at the
// boundary, inside the evaluator, not at entry.
func TestShadowExitC4_BoundaryDriftYieldsStale(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	planner := &driftOnPlanPlanner{raw: []byte(driftedEchoDangerRaw)}
	env := newGapEnv(t, &hits, controlledInventoryJSON,
		gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoCredRule), planner)

	// Approve echo -> Usable at its ORIGINAL fingerprint (FP1); danger too (preflight needs a
	// usable in-scope tool). The decision the request is evaluated against binds FP1.
	echoFP1, _, _ := catRec(t, env.cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
	_, _, elig := catRec(t, env.cat, ctrlServer, toolEcho)
	req(t, elig == catalog.Usable, "echo must be Usable before the run, got %v", elig)
	env.activateShadow(controlledScope())

	tok := env.token(ctrlPrincip)
	sid := handshake(t, env.cli, env.base, ctrlServer, tok)
	before := shadowSnap()
	preIDs := committedShadowEventIDs(t)

	st, ra := toolsCall(t, env.cli, env.base, tok, sid, "3", toolEcho, `{"text":"boundary-drift"}`)
	req(t, st == 200, "C4: status=%d", st)
	// The evaluator ran (entry eligibility passed) AND predicted stale at the boundary.
	req(t, ra["execution_state"] == "shadow_evaluated",
		"C4: the request must be shadow-evaluated (entry eligibility passed), got %v", ra)
	req(t, ra["shadow_outcome"] == "would_fail_stale_decision",
		"C4: boundary drift must predict would_fail_stale_decision, got %v", ra)
	req(t, atomic.LoadInt32(&planner.ingests) == 1, "C4: the planner must have driven exactly one boundary re-ingest, got %d", atomic.LoadInt32(&planner.ingests))

	// The catalog genuinely drifted after entry: echo's live fingerprint changed from FP1.
	echoFP2, _, _ := catRec(t, env.cat, ctrlServer, toolEcho)
	req(t, echoFP2 != echoFP1, "C4: echo fingerprint must have drifted (FP1=%s FP2=%s)", echoFP1, echoFP2)

	after := shadowSnap()
	assertShadowDelta(t, before, after, shadowMetricsView{Evaluations: 1, WouldFailStale: 1})

	// Durable v2 evidence for THIS evaluation, matching the response, and the credential planned
	// cleanly (credential_plan_valid) — the failure is the boundary drift, not the credential.
	de, ok := newShadowEvidence(t, preIDs)
	req(t, ok, "C4: a durable schema-v2 shadow event must be committed")
	req(t, de.Shadow.Outcome == "would_fail_stale_decision" && de.VerifyDigest() && de.Validate() == nil,
		"C4: durable event must be would_fail_stale_decision and valid, got %+v", de.Shadow)
	req(t, de.Shadow.Outcome == ra["shadow_outcome"], "C4: response<->durable parity mismatch: durable=%q response=%v", de.Shadow.Outcome, ra["shadow_outcome"])

	// Zero side effects; live executor never armed.
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during C4: %d", atomic.LoadInt64(&hits))
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must stay unarmed through C4")
	env.ev("C4 boundary drift: entry_eligibility=passed post_entry_reingest=1 boundary_detected=yes shadow_outcome=would_fail_stale_decision credential_plan=%s FP1=%s->FP2=%s would_fail_stale %d->%d upstream=0",
		de.Shadow.CredentialPlan, echoFP1, echoFP2, before.WouldFailStale, after.WouldFailStale)
}

// ── Criterion 8 — real metadata-only credential-planning path ────────────────

// gapCountingPlanner counts Plan calls and returns a chosen error; it exposes NO Materialize.
type gapCountingPlanner struct {
	plans int32
	err   error
}

func (p *gapCountingPlanner) Plan(broker.PlanInput) (broker.CredentialPlan, error) {
	atomic.AddInt32(&p.plans, 1)
	return broker.CredentialPlan{}, p.err
}

func (p *gapCountingPlanner) count() int32 { return atomic.LoadInt32(&p.plans) }

// TestShadowExitC8_CredentialPlanningPath proves criterion 8 end to end through the production
// Shadow composition path: a metadata-only CredentialPlanner is installed via
// shadowCredentialPlannerSeam and the three readiness cases are driven as real authenticated
// tools/call requests. It proves Planner.Plan is exercised (calls>0), that an invalid plan
// truthfully yields would_fail_credential_readiness, and that Materialize / secret retrieval /
// upstream calls are all 0 (structurally — the Shadow type graph holds no such capability).
func TestShadowExitC8_CredentialPlanningPath(t *testing.T) {
	// Case (2): a profile named + a VALID plan -> would_execute, Plan called.
	t.Run("valid_plan_would_execute", func(t *testing.T) {
		var hits int64
		resetShadowGlobalsForRun(t)
		planner := &gapCountingPlanner{err: nil}
		env := newGapEnv(t, &hits, controlledInventoryJSON,
			gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoCredRule), planner)
		_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
		_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
		env.activateShadow(controlledScope())
		tok := env.token(ctrlPrincip)
		sid := handshake(t, env.cli, env.base, ctrlServer, tok)

		st, ra := toolsCall(t, env.cli, env.base, tok, sid, "3", toolEcho, `{"text":"cred"}`)
		req(t, st == 200 && ra["shadow_outcome"] == "would_execute" && ra["credential_plan"] == "credential_plan_valid",
			"C8 valid: want would_execute/credential_plan_valid, got %v", ra)
		req(t, planner.count() >= 1, "C8 valid: Planner.Plan must be called (>0), got %d", planner.count())
		req(t, ra["materialization_ready"] == "not_evaluated", "C8 valid: materialization must be not_evaluated, got %v", ra["materialization_ready"])
		req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked (C8 valid): %d", atomic.LoadInt64(&hits))
		env.ev("C8 valid-plan: shadow_outcome=would_execute credential_plan=credential_plan_valid plan_calls=%d materialize=0 upstream=0", planner.count())
	})

	// Case (3): a profile named + an INVALID plan -> would_fail_credential_readiness, Plan called.
	t.Run("invalid_plan_would_fail_credential", func(t *testing.T) {
		var hits int64
		resetShadowGlobalsForRun(t)
		planner := &gapCountingPlanner{err: errCredentialPlanUnready}
		env := newGapEnv(t, &hits, controlledInventoryJSON,
			gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoCredRule), planner)
		_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
		_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
		env.activateShadow(controlledScope())
		tok := env.token(ctrlPrincip)
		sid := handshake(t, env.cli, env.base, ctrlServer, tok)
		before := shadowSnap()
		preIDs := committedShadowEventIDs(t)

		st, ra := toolsCall(t, env.cli, env.base, tok, sid, "3", toolEcho, `{"text":"cred"}`)
		req(t, st == 200 && ra["shadow_outcome"] == "would_fail_credential_readiness" && ra["credential_plan"] == "credential_plan_invalid",
			"C8 invalid: want would_fail_credential_readiness/credential_plan_invalid, got %v", ra)
		req(t, planner.count() >= 1, "C8 invalid: Planner.Plan must be called (>0), got %d", planner.count())
		after := shadowSnap()
		assertShadowDelta(t, before, after, shadowMetricsView{Evaluations: 1, WouldFailCredential: 1})
		de, ok := newShadowEvidence(t, preIDs)
		req(t, ok && de.Shadow.Outcome == "would_fail_credential_readiness" && de.Shadow.MaterializationReadiness == "not_evaluated",
			"C8 invalid: durable event must be would_fail_credential_readiness / not_evaluated, got %+v", de.Shadow)
		req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked (C8 invalid): %d", atomic.LoadInt64(&hits))
		env.ev("C8 invalid-plan: shadow_outcome=would_fail_credential_readiness credential_plan=credential_plan_invalid plan_calls=%d materialize=0 upstream=0", planner.count())
	})

	// Case (1): NO credential profile -> the planner is never consulted; would_execute.
	t.Run("no_profile_planner_untouched", func(t *testing.T) {
		var hits int64
		resetShadowGlobalsForRun(t)
		planner := &gapCountingPlanner{}
		env := newGapEnv(t, &hits, controlledInventoryJSON,
			gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule), planner) // plain echo rule: no credential_profile
		_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
		_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
		env.activateShadow(controlledScope())
		tok := env.token(ctrlPrincip)
		sid := handshake(t, env.cli, env.base, ctrlServer, tok)

		st, ra := toolsCall(t, env.cli, env.base, tok, sid, "3", toolEcho, `{"text":"nocred"}`)
		req(t, st == 200 && ra["shadow_outcome"] == "would_execute" && ra["credential_plan"] == "no_credential_profile",
			"C8 no-profile: want would_execute/no_credential_profile, got %v", ra)
		req(t, planner.count() == 0, "C8 no-profile: the planner must NOT be consulted with no credential profile, got %d", planner.count())
		req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked (C8 no-profile): %d", atomic.LoadInt64(&hits))
		env.ev("C8 no-profile: shadow_outcome=would_execute credential_plan=no_credential_profile plan_calls=0 materialize=0 upstream=0")
	})
}

// ── Criterion 9 — kill honored fail-closed BEFORE Shadow evaluation ──────────

// TestShadowExitC9_KillHonoredBeforeEvaluation proves the adopted Invariant A end to end: an
// engaged emergency kill stops admission BEFORE any Shadow evaluation, so the request returns
// the deterministic rollout_emergency_active error, commits NO shadow-evaluated event, records
// exactly one evaluation error (not a would_* outcome), and causes zero upstream side effects;
// clearing the kill restores would_execute. This measures the REAL invariant the implementation
// takes — see the §12 wording correction and the Invariant-A rationale in the report.
func TestShadowExitC9_KillHonoredBeforeEvaluation(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	env := newGapEnv(t, &hits, controlledInventoryJSON,
		gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule), nil)
	_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
	env.activateShadow(controlledScope())
	tok := env.token(ctrlPrincip)
	sid := handshake(t, env.cli, env.base, ctrlServer, tok)

	// Engage the emergency kill and issue an otherwise-would_execute echo call.
	req(t, getMCPRollout().emergencyDisable(rollout.CapabilityGateway, "c9-drill") == nil, "emergencyDisable failed")
	req(t, getMCPRollout().stateFor(rollout.CapabilityGateway).Killed(), "kill must be engaged")
	before := shadowSnap()
	preIDs := committedShadowEventIDs(t)

	st, rk := toolsCall(t, env.cli, env.base, tok, sid, "6", toolEcho, `{"text":"killed"}`)
	req(t, st == 200, "C9: status=%d", st)
	errObj, _ := rk["error"].(map[string]any)
	req(t, errObj != nil && errObj["message"] == "rollout_emergency_active",
		"C9: a killed node must emergency-block with rollout_emergency_active, got %v", rk)
	req(t, rk["execution_state"] != "shadow_evaluated" && rk["shadow_outcome"] == nil,
		"C9: a killed request must NOT be shadow-evaluated, got %v", rk)

	// The decisive Invariant-A proof: NO shadow-evaluated event was committed (admission stopped
	// before evaluation), and exactly one evaluation error was counted — never a would_* outcome.
	req(t, newShadowEventCount(t, preIDs) == 0, "C9: a killed request must commit NO shadow-evaluated event (Invariant A)")
	after := shadowSnap()
	assertShadowDelta(t, before, after, shadowMetricsView{EvaluationErrors: 1})
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during kill (C9): %d", atomic.LoadInt64(&hits))

	// Clearing the kill restores normal Shadow evaluation.
	req(t, getMCPRollout().clearEmergency(rollout.CapabilityGateway) == nil, "clearEmergency failed")
	st, rr := toolsCall(t, env.cli, env.base, tok, sid, "7", toolEcho, `{"text":"recovered"}`)
	req(t, st == 200 && rr["execution_state"] == "shadow_evaluated" && rr["shadow_outcome"] == "would_execute",
		"C9: clearing the kill must restore would_execute, got %v", rr)
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked after clear (C9): %d", atomic.LoadInt64(&hits))
	env.ev("C9 kill Invariant-A: engaged -> error=rollout_emergency_active NO shadow_evaluated event evaluation_errors %d->%d not_would_execute upstream=0 -> cleared -> would_execute",
		before.EvaluationErrors, after.EvaluationErrors)
}

// errCredentialPlanUnready is the invalid-plan error the C8 planner returns; the evaluator maps
// any non-nil Plan error to credential_plan_invalid / would_fail_credential_readiness.
var errCredentialPlanUnready = errors.New("credential plan unready: profile not provisioned")

// ── Criterion 6 — same-traffic Observe-vs-Shadow denial parity ───────────────

const toolQuar = "quar" // ingested Quarantined and never approved → a hard-control decision

// parityInventoryJSON seeds the controlled server with three tools: echo (approved → ALLOW),
// danger (approved → default DENY), and quar (never approved → Quarantined hard-control).
func parityInventoryJSON(endpoint string) string {
	return `{
  "schema_version": 1,
  "tenant": "` + ctrlTenant + `",
  "servers": [
    {
      "server_id": "` + ctrlServer + `",
      "endpoint": "` + endpoint + `",
      "pinned_identity": "` + ctrlServerIdentity + `",
      "credential_profile": "profile:ro",
      "enabled": true,
      "tools": [
        {"name": "` + toolEcho + `", "input_schema": {"type":"object","properties":{"text":{"type":"string"}}}, "description": "echo", "destination_class": "none"},
        {"name": "` + toolDanger + `", "input_schema": {"type":"object","properties":{"x":{"type":"string"}}}, "description": "danger", "destination_class": "none"},
        {"name": "` + toolQuar + `", "input_schema": {"type":"object","properties":{"q":{"type":"string"}}}, "description": "quar", "destination_class": "none"}
      ]
    }
  ]
}`
}

// decisionOf extracts the mode-INVARIANT decision facts from a toolsCall result-or-envelope
// map, handling all three response shapes: shadowResult (evaluated_policy_action + shadow_outcome),
// the inline Observe allow body (policy_action + reason), and the inline Observe deny/hard error
// envelope (error.data.policy_action + error.message). action + reason are the parity carriers;
// shadowOutcome + execState are mode-specific and only used to classify the case.
func decisionOf(m map[string]any) (action, reason, shadowOutcome, execState string) {
	if e, ok := m["error"].(map[string]any); ok {
		if data, ok := e["data"].(map[string]any); ok {
			action, _ = data["policy_action"].(string)
		}
		reason, _ = e["message"].(string)
		return action, reason, "", ""
	}
	if a, ok := m["evaluated_policy_action"].(string); ok {
		action = a
	} else {
		action, _ = m["policy_action"].(string)
	}
	if r, ok := m["reason"].(string); ok && r != "" {
		reason = r
	} else {
		reason, _ = m["policy_reason"].(string)
	}
	shadowOutcome, _ = m["shadow_outcome"].(string)
	execState, _ = m["execution_state"].(string)
	return action, reason, shadowOutcome, execState
}

// TestShadowExitC6_ObserveShadowDenialParity proves criterion 6: driving the SAME corpus under
// the SAME policy/catalog/identity revisions through Observe then Shadow does NOT alter the
// denial DECISION. Parity is defined precisely as: the raw policy action and the policy reason
// code are identical across modes for every in-scope request (authentication + tenant denials
// are enforced strictly before the rollout-mode branch, so they are byte-identical), and Shadow
// never softens a non-allow decision into would_execute. The MODE-SPECIFIC record shape
// (execution_state, the added would_* prediction, the response envelope) is deliberately NOT
// compared — only the decision semantics are.
func TestShadowExitC6_ObserveShadowDenialParity(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	env := newGapEnv(t, &hits, parityInventoryJSON,
		gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule), nil)
	// echo + danger → Usable; quar stays Quarantined (hard-control).
	_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
	_, _, qElig := catRec(t, env.cat, ctrlServer, toolQuar)
	req(t, qElig == catalog.Quarantined, "quar must stay Quarantined for the hard-control case, got %v", qElig)

	inTok := env.token(ctrlPrincip)
	outTok := env.token(outsiderSub)

	// The in-scope policy-class corpus: tool → the Shadow outcome its class must map to.
	type caseSpec struct {
		tool       string
		arg        string
		wantShadow string // the faithful non-permissive Shadow mapping for this class
		label      string
	}
	corpus := []caseSpec{
		{toolEcho, `{"text":"p"}`, "would_execute", "allow"},
		{toolDanger, `{"x":"p"}`, "would_block", "policy_deny"},
		{toolQuar, `{"q":"p"}`, "would_fail_hard_control", "hard_control"},
	}

	// --- Pass 1: OBSERVE. Capture the decision for each in-scope case. ---
	env.applyGateway(mcpObserveRollout(rollout.CapabilityGateway))
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeObserve, "observe activation failed: %s", getMCPRollout().gateway.CurrentMode())
	obsSid := handshake(t, env.cli, env.base, ctrlServer, inTok)
	type dec struct{ action, reason, exec string }
	obs := map[string]dec{}
	for i, c := range corpus {
		_, m := toolsCall(t, env.cli, env.base, inTok, obsSid, itoaGap(10+i), c.tool, c.arg)
		a, r, so, es := decisionOf(m)
		req(t, so == "", "OBSERVE(%s): must NOT carry a shadow_outcome, got %q", c.label, so)
		obs[c.label] = dec{a, r, es}
		env.ev("C6 observe %s: policy_action=%q reason=%q execution_state=%q", c.label, a, r, es)
	}
	// Out-of-scope (scope admission): record-only in Observe.
	obsOutSid := handshake(t, env.cli, env.base, ctrlServer, outTok)
	_, mo := toolsCall(t, env.cli, env.base, outTok, obsOutSid, "19", toolEcho, `{"text":"x"}`)
	_, _, _, obsOutExec := decisionOf(mo)
	// Pre-branch denial (bad bearer): capture the exact rejection bytes.
	obsAuthSt, _, obsAuthBody := gwPost(t, env.cli, env.base, ctrlServer, "not.a.valid.token", "",
		`{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)

	// --- Pass 2: SHADOW. Same corpus; compare the invariant decision facts. ---
	env.activateShadow(controlledScope())
	shSid := handshake(t, env.cli, env.base, ctrlServer, inTok)
	for i, c := range corpus {
		preIDs := committedShadowEventIDs(t)
		_, m := toolsCall(t, env.cli, env.base, inTok, shSid, itoaGap(20+i), c.tool, c.arg)
		a, _, so, es := decisionOf(m)
		req(t, es == "shadow_evaluated", "SHADOW(%s): in-scope request must be shadow-evaluated, got %q", c.label, es)
		// PARITY 1 — the raw policy action is unaltered.
		req(t, a == obs[c.label].action,
			"C6 %s: policy action diverged Observe=%q Shadow=%q", c.label, obs[c.label].action, a)
		// PARITY 2 — the policy reason code is unaltered (Observe response reason == Shadow durable reason).
		de, ok := newShadowEvidence(t, preIDs)
		req(t, ok, "C6 %s: a durable shadow event must be committed", c.label)
		req(t, de.Decision.ReasonCode == obs[c.label].reason,
			"C6 %s: policy reason diverged Observe=%q Shadow(durable)=%q", c.label, obs[c.label].reason, de.Decision.ReasonCode)
		// NON-PERMISSIVE — Shadow maps the class to its faithful outcome, never softening a
		// non-allow decision into would_execute.
		req(t, so == c.wantShadow, "C6 %s: shadow_outcome=%q want %q", c.label, so, c.wantShadow)
		if c.label != "allow" {
			req(t, so != "would_execute", "SECURITY C6 %s: a non-allow decision was softened into would_execute", c.label)
		}
		env.ev("C6 shadow %s: evaluated_policy_action=%q durable_reason=%q shadow_outcome=%q PARITY(action,reason)=ok", c.label, a, de.Decision.ReasonCode, so)
	}
	// Scope admission: an out-of-scope subject is record-only in Shadow too (NOT shadow-evaluated),
	// exactly as in Observe — Shadow does not alter scope admission.
	shOutSid := handshake(t, env.cli, env.base, ctrlServer, outTok)
	_, mso := toolsCall(t, env.cli, env.base, outTok, shOutSid, "29", toolEcho, `{"text":"x"}`)
	_, _, shOutSo, shOutExec := decisionOf(mso)
	req(t, shOutExec == obsOutExec && shOutSo == "",
		"C6 scope: out-of-scope must be record-only in BOTH modes (Observe exec=%q Shadow exec=%q shadow_outcome=%q)", obsOutExec, shOutExec, shOutSo)
	env.ev("C6 scope admission: out-of-scope execution_state Observe=%q Shadow=%q shadow_outcome=absent (record-only in both)", obsOutExec, shOutExec)

	// Pre-branch denial parity: a bad bearer is rejected identically in Shadow (auth precedes the
	// rollout-mode branch, so the rejection is mode-independent by construction).
	shAuthSt, _, shAuthBody := gwPost(t, env.cli, env.base, ctrlServer, "not.a.valid.token", "",
		`{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)
	req(t, shAuthSt == obsAuthSt && bytes.Equal(shAuthBody, obsAuthBody),
		"C6 auth: a pre-branch authentication denial must be byte-identical across modes\nObserve(%d): %s\nShadow(%d): %s",
		obsAuthSt, obsAuthBody, shAuthSt, shAuthBody)
	env.ev("C6 auth denial: pre-branch rejection byte-identical across modes status=%d", obsAuthSt)

	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during C6: %d", atomic.LoadInt64(&hits))
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must stay unarmed through C6")
	env.ev("C6 VERDICT: Observe==Shadow on {policy_action, reason_code, admission}; Shadow never softened a denial; mode-specific record shape excluded from parity")
}

// itoaGap renders a small non-negative int as a JSON-RPC id string (avoids strconv import churn).
func itoaGap(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var _ = json.Marshal // json is used by C12 (appended below); keep the import stable.

// ── Criterion 12 — operator runbook driven through the real admin API ────────

// mcpAdminJSON drives one operator-facing MCP admin request through the REAL route mux
// (registerMCPRoutes) at the given role and decodes its JSON body. This is the exact
// surface an operator invokes — not the internal Go functions in the same order.
func mcpAdminJSON(t *testing.T, method, target string, role UIRole, body string) (status int, out map[string]any) {
	t.Helper()
	w := mcpReq(method, target, role, body)
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

// mcpAdminJSONAs is mcpAdminJSON issued as a NAMED authenticated human (an admin UI
// session subject). The runbook needs it because a tool-trust grant is a four-eyes
// decision: the requester and the approver must be two different principals
// (SEC-MCP-4E-2), so the two runbook steps cannot share one anonymous caller.
func mcpAdminJSONAs(t *testing.T, method, target string, role UIRole, body, sub string) (status int, out map[string]any) {
	t.Helper()
	w := mcpReqAs(t, method, target, role, body, sub, "")
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

// mcpAdminArray is the array-bodied variant (e.g. GET /api/mcp/tools).
func mcpAdminArray(t *testing.T, method, target string, role UIRole) (status int, out []any) {
	t.Helper()
	w := mcpReq(method, target, role, "")
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

// shadowStatusFrom extracts the shadow sub-map from a GET /api/mcp/rollout body.
func shadowStatusFrom(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	sh, ok := body["shadow"].(map[string]any)
	req(t, ok, "GET /api/mcp/rollout must carry a shadow block, got %v", body)
	return sh
}

// TestShadowExitC12_OperatorRunbookEndToEnd drives the documented Controlled Shadow operator
// runbook end to end through the ACTUAL operator-facing admin API surfaces — status/preflight,
// inventory, tool approval, activation (signed CP action, as documented), verification,
// evidence, kill, and rollback — asserting each surface's output, and proving the activation
// preflight is a real fail-closed gate that a pushed signed config cannot bypass (mutation:
// "make the runbook preflight bypassable"). It never edits a state file by hand.
func TestShadowExitC12_OperatorRunbookEndToEnd(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	env := newGapEnv(t, &hits, controlledInventoryJSON,
		gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule), nil)
	tenantQ := "?tenant=" + ctrlTenant

	// (1) Baseline status/health — GET /api/mcp/rollout (viewer). The operator confirms the
	// evaluator is composed, live execution is unarmed, and the node is not yet in Shadow.
	code, roll := mcpAdminJSON(t, http.MethodGet, "/api/mcp/rollout", RoleViewer, "")
	req(t, code == 200, "runbook status: GET /api/mcp/rollout = %d", code)
	sh := shadowStatusFrom(t, roll)
	req(t, sh["evaluator_composed"] == true && sh["live_execution_ready"] == false,
		"runbook status: evaluator_composed/live_execution_ready = %v/%v", sh["evaluator_composed"], sh["live_execution_ready"])
	gw, _ := roll["gateway"].(map[string]any)
	req(t, gw != nil && gw["mode"] == "disabled", "runbook status: gateway.mode = %v, want disabled", gw["mode"])
	env.ev("C12 step1 status: GET /api/mcp/rollout shadow.evaluator_composed=true live_execution_ready=false gateway.mode=disabled")

	// (2) Inventory — GET /api/mcp/tools?tenant=… (viewer). The operator sees the tools awaiting
	// approval (Quarantined).
	code, tools := mcpAdminArray(t, http.MethodGet, "/api/mcp/tools"+tenantQ, RoleViewer)
	req(t, code == 200 && len(tools) >= 2, "runbook inventory: GET /api/mcp/tools = %d, %d tools", code, len(tools))
	env.ev("C12 step2 inventory: GET /api/mcp/tools returned %d controlled tools", len(tools))

	// (3) MUTATION GUARD — the activation preflight is FAIL-CLOSED and NOT bypassable. With no
	// approved (Usable) tool in scope yet, the scope-dependent activation preflight is not ready,
	// and a pushed signed Shadow config MUST NOT activate Shadow. This proves an operator cannot
	// skip the preflight by publishing a config.
	pfEarly := evaluateShadowActivationPreflight(rollout.CapabilityGateway, controlledScope(), 1)
	req(t, !pfEarly.Ready, "runbook preflight: must be NOT ready before any tool is approved, reasons=%v", pfEarly.Reasons)
	env.applyGateway(&rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: controlledScope(),
	})
	req(t, getMCPRollout().gateway.CurrentMode() != rollout.ModeShadow,
		"SECURITY: a signed Shadow config bypassed the fail-closed preflight (mode=%s)", getMCPRollout().gateway.CurrentMode())
	env.ev("C12 step3 preflight-gate: preflight NOT ready (reasons=%v) -> signed Shadow activation REFUSED (mode stays %s); preflight is not bypassable", pfEarly.Reasons, getMCPRollout().gateway.CurrentMode())

	// (4) Tool approval — the real operator two-step over HTTP by TWO NAMED HUMANS: request
	// (operator "opal") then approve (admin "adele"). This promotes echo to catalog.Usable.
	// The runbook is deliberately driven by two distinct authenticated principals because the
	// grant is a four-eyes decision (SEC-MCP-4E-2): the requester may not approve their own
	// tool-trust request, and the refusal below is part of the evidence.
	echoFP, echoRev, _ := catRec(t, env.cat, ctrlServer, toolEcho)
	reqBody := `{"server_id":"` + ctrlServer + `","tool_name":"` + toolEcho + `","fingerprint":"` + echoFP +
		`","catalog_revision":` + strconv.FormatUint(echoRev, 10) + `,"purpose":"shadow_evaluation","reason":"reviewed for controlled shadow"}`
	code, appr := mcpAdminJSONAs(t, http.MethodPost, "/api/mcp/tool-approvals"+tenantQ, RoleOperator, reqBody, "opal")
	req(t, code == 200, "runbook approval request: POST /api/mcp/tool-approvals = %d (%v)", code, appr)
	approvalID, _ := appr["approval_id"].(string)
	req(t, approvalID != "", "runbook approval request: missing approval_id in %v", appr)
	decBody := `{"approval_id":"` + approvalID + `","action":"approve","reason":"reviewed"}`
	// SEPARATION OF DUTIES — the requester, even holding the admin role, may not grant their
	// own request. This must be refused BEFORE the legitimate approval, so the runbook proves
	// the control fires on the live HTTP surface rather than only in a unit test.
	selfCode, _ := mcpAdminJSONAs(t, http.MethodPost, "/api/mcp/tool-approval-decision"+tenantQ, RoleAdmin, decBody, "opal")
	req(t, selfCode == 403, "runbook four-eyes: the requester's own approve = %d, want 403", selfCode)
	_, _, eligAfterSelf := catRec(t, env.cat, ctrlServer, toolEcho)
	req(t, eligAfterSelf != catalog.Usable,
		"SECURITY: a refused self-approval promoted echo to Usable (elig=%v)", eligAfterSelf)
	code, dec := mcpAdminJSONAs(t, http.MethodPost, "/api/mcp/tool-approval-decision"+tenantQ, RoleAdmin, decBody, "adele")
	// StatusActive ("active") is the live grant that materializes catalog.Usable (tooltrust.go).
	req(t, code == 200 && dec["status"] == "active", "runbook approval decision: POST /api/mcp/tool-approval-decision = %d status=%v", code, dec["status"])
	// Approve danger too (needed so the scope has a usable tool set the operator expects). Use the
	// harness path for the second tool to keep the runbook narrative on echo.
	_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)
	_, _, elig := catRec(t, env.cat, ctrlServer, toolEcho)
	req(t, elig == catalog.Usable, "runbook approval: echo must be Usable after the HTTP approve, got %v", elig)
	env.ev("C12 step4 approval: POST /api/mcp/tool-approvals (operator opal) -> approval_id=%s ; "+
		"POST /api/mcp/tool-approval-decision action=approve BY THE REQUESTER -> 403 approval_self_approval (echo still not Usable) ; "+
		"same call by admin adele -> status=active ; echo now Usable", approvalID)

	// (5) Preflight dry-run — now READY. GET /api/mcp/rollout shadow.preflight + scope validate.
	code, roll = mcpAdminJSON(t, http.MethodGet, "/api/mcp/rollout", RoleViewer, "")
	req(t, code == 200, "runbook preflight: status = %d", code)
	sh = shadowStatusFrom(t, roll)
	pf, _ := sh["preflight"].(map[string]any)
	req(t, pf != nil && pf["ready"] == true, "runbook preflight: shadow.preflight.ready = %v, want true", pf)
	scopeBody, _ := json.Marshal(map[string]any{"scope": controlledScope()})
	code, sv := mcpAdminJSON(t, http.MethodPost, "/api/mcp/rollout/scope/validate", RoleViewer, string(scopeBody))
	req(t, code == 200 && sv["valid"] == true, "runbook scope validate: = %d valid=%v", code, sv["valid"])
	env.ev("C12 step5 preflight-ready: shadow.preflight.ready=true ; POST /api/mcp/rollout/scope/validate valid=true")

	// (6) Activation — the documented signed CP→DP action (no admin mutation endpoint).
	env.activateShadow(controlledScope())
	code, roll = mcpAdminJSON(t, http.MethodGet, "/api/mcp/rollout", RoleViewer, "")
	gw, _ = roll["gateway"].(map[string]any)
	req(t, code == 200 && gw["mode"] == "shadow", "runbook verify: gateway.mode = %v, want shadow", gw["mode"])
	env.ev("C12 step6 activation: signed Observe->Shadow applied ; GET /api/mcp/rollout gateway.mode=shadow")

	// (7) Drive one in-scope shadow request so metrics/evidence populate.
	tok := env.token(ctrlPrincip)
	sid := handshake(t, env.cli, env.base, ctrlServer, tok)
	st, ra := toolsCall(t, env.cli, env.base, tok, sid, "3", toolEcho, `{"text":"runbook"}`)
	req(t, st == 200 && ra["shadow_outcome"] == "would_execute", "runbook traffic: echo shadow_outcome=%v", ra["shadow_outcome"])

	// (8) Verification — execution counts (0 executed / 0 upstream) + the /metrics operator surface.
	code, execs := mcpAdminJSON(t, http.MethodGet, "/api/mcp/executions", RoleViewer, "")
	req(t, code == 200 && numEq(execs["executed"], 0) && numEq(execs["upstream_ok"], 0) && numEq(execs["upstream_err"], 0),
		"runbook verify: /api/mcp/executions must report 0 executed/upstream, got %v", execs)
	// The operator observability surface the runbook promises: drive the ACTUAL /metrics
	// serializer (writeMCPShadowMetrics, the exact function metrics.go invokes) AFTER the
	// in-scope Shadow request and assert the culvert_mcp_shadow_* rows match the live counters
	// and reflect the evaluation (would_execute >= 1). A broken/dropped serializer would pass
	// every /api check above yet fail here (Codex review).
	var mb strings.Builder
	writeMCPShadowMetrics(&mb)
	outcomes, _, errSeen := shadowMetricRows(t, mb.String())
	fin := shadowSnap()
	req(t, errSeen == 1 && fin.WouldExecute >= 1 && outcomes["would_execute"] == fin.WouldExecute,
		"runbook verify: /metrics culvert_mcp_shadow_evaluations_total{would_execute} must equal the live counter and be >=1 (rows=%v fin=%d)", outcomes, fin.WouldExecute)
	env.ev("C12 step8 verify: GET /api/mcp/executions executed=0 upstream_ok=0 upstream_err=0 ; /metrics culvert_mcp_shadow_evaluations_total{would_execute}=%d matches the live singleton", fin.WouldExecute)

	// (9) Evidence — the operator inspects durable decision evidence.
	code, ev := mcpAdminJSON(t, http.MethodGet, "/api/mcp/rollout/evidence", RoleViewer, "")
	req(t, code == 200 && ev != nil, "runbook evidence: GET /api/mcp/rollout/evidence = %d", code)
	env.ev("C12 step9 evidence: GET /api/mcp/rollout/evidence readable (qualification windows)")

	// (10) Kill — POST /api/mcp/rollout/emergency {action:disable} (admin). Admission stops.
	code, k := mcpAdminJSON(t, http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{"capability":"gateway","action":"disable"}`)
	req(t, code == 200 && k["killed"] == true, "runbook kill: POST /api/mcp/rollout/emergency disable = %d killed=%v", code, k["killed"])
	st, rk := toolsCall(t, env.cli, env.base, tok, sid, "4", toolEcho, `{"text":"killed"}`)
	kerr, _ := rk["error"].(map[string]any)
	req(t, st == 200 && kerr != nil && kerr["message"] == "rollout_emergency_active", "runbook kill: a request must emergency-block, got %v", rk)
	env.ev("C12 step10 kill: POST /api/mcp/rollout/emergency action=disable -> killed=true ; request emergency-blocked (rollout_emergency_active)")

	// (11) Clear the kill — POST /api/mcp/rollout/emergency {action:clear} (admin).
	code, kc := mcpAdminJSON(t, http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{"capability":"gateway","action":"clear"}`)
	req(t, code == 200 && kc["killed"] == false, "runbook clear: POST /api/mcp/rollout/emergency clear = %d killed=%v", code, kc["killed"])

	// (12) Rollback Shadow→Observe — the documented signed action. Assert the node returns to Observe.
	env.applyGateway(mcpObserveRollout(rollout.CapabilityGateway))
	code, roll = mcpAdminJSON(t, http.MethodGet, "/api/mcp/rollout", RoleViewer, "")
	gw, _ = roll["gateway"].(map[string]any)
	req(t, code == 200 && gw["mode"] == "observe", "runbook rollback: gateway.mode = %v, want observe", gw["mode"])
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must remain unarmed through the runbook")
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during the runbook: %d", atomic.LoadInt64(&hits))
	env.ev("C12 step11-12 clear+rollback: kill cleared (killed=false) ; signed Shadow->Observe applied ; gateway.mode=observe ; live_executor=absent upstream=0")
	env.ev("C12 VERDICT: operator runbook driven end-to-end via admin API surfaces; preflight fail-closed and non-bypassable; zero side effects")
}

// numEq compares a JSON number (decoded as float64) to an int.
func numEq(v any, want int) bool {
	f, ok := v.(float64)
	return ok && int(f) == want
}
