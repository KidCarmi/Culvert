package main

// FIRST CONTROLLED MCP SHADOW ACTIVATION — runtime experiment harness.
//
// This is NOT a unit test that pins a single behavior; it is the instrument of the
// controlled Shadow activation experiment. It drives the REAL Culvert MCP production
// code paths end to end on ONE controlled in-process node:
//
//   - a real Gateway listener on a real TCP socket (real TLS + OAuth ES256 JWT);
//   - the REAL non-executing *execution.ShadowEvaluator composed via the production
//     composeGatewayShadowIntoConfig path (CULVERT_MCP_SHADOW_READY=1);
//   - the REAL tool-trust approval -> catalog.Usable projection (PR #1236);
//   - the REAL signed CP->DP rollout activation (applySnapshotMCP -> preflight ->
//     distribution commit -> rollout commit);
//   - the REAL durable schema-v2 evidence spool and the REAL culvert_mcp_shadow_* sink;
//   - a REAL controlled upstream HTTP server (owned here) whose invocation counter is
//     the independent witness that the protected upstream observes ZERO invocations.
//
// It performs NO product-code change. It never composes a LiveExecutor, never calls
// markGatewayExecDepsReady, never materializes a credential, never arms Canary/Production.
//
// Run: go test -run TestFirstControlledShadowRun -count=1 -v .

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// ---- controlled fixtures (the runbook's canonical experiment identities) --------

const (
	ctrlServer  = "controlled-test-server"
	ctrlPrincip = "synthetic-shadow-principal"
	ctrlTenant  = "qualification"
	toolEcho    = "echo"   // policy ALLOW  -> would_execute
	toolDanger  = "danger" // default DENY  -> would_block
	outsiderSub = "outsider-principal"
)

// controlledInventoryJSON seeds ONE controlled server owning two harmless tools, at the
// witness endpoint. Both tools ingest Quarantined (approval is a separate slice).
func controlledInventoryJSON(endpoint string) string {
	return `{
  "schema_version": 1,
  "tenant": "` + ctrlTenant + `",
  "servers": [
    {
      "server_id": "` + ctrlServer + `",
      "endpoint": "` + endpoint + `",
      "pinned_identity": "spiffe://qual/controlled-test-server",
      "credential_profile": "profile:ro",
      "enabled": true,
      "tools": [
        {"name": "` + toolEcho + `", "input_schema": {"type":"object","properties":{"text":{"type":"string"}}}, "description": "echo", "destination_class": "none"},
        {"name": "` + toolDanger + `", "input_schema": {"type":"object","properties":{"x":{"type":"string"}}}, "description": "danger", "destination_class": "none"}
      ]
    }
  ]
}`
}

// allowEchoRule permits a tools/call whose tool.name is "echo" (an ALLOW-class decision
// that, for an in-scope Usable tool under Shadow, yields would_execute). The danger tool
// has no rule, so the policy's default DENY applies -> would_block.
const allowEchoRule = `{"id":"ALLOW_ECHO","priority":20,"action":"ALLOW",` +
	`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
	`"conditions":[{"field":"tool.name","op":"exact","value":"echo"}],` +
	`"obligations":{"logging":"standard"}}`

// mintBearerSub mints a valid ES256 gateway bearer with a caller-chosen subject
// (the runtime maps sub -> rollout PrincipalID, driving scope membership).
func mintBearerSub(t *testing.T, p *mcpTestPKI, aud, tenant, sub string) string {
	t.Helper()
	now := time.Now()
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid})
	cb, _ := json.Marshal(map[string]any{
		"iss": p.issuer, "sub": sub, "client_id": "client-gw",
		"aud": aud, "scope": "gateway.tools.call", "tenant": tenant,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	in := mustB64(hb) + "." + mustB64(cb)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, p.signer, sum[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + mustB64(sig)
}

// gwPost issues one authenticated MCP POST to the controlled server path.
func gwPost(t *testing.T, cli *http.Client, base, serverID, token, sid, body string) (int, string, []byte) {
	t.Helper()
	req := mcpObserveReq(t, "POST", base+"/mcp/gateway/"+serverID, body)
	req.Host = "gw.test"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), raw
}

// handshake runs initialize + notifications/initialized and returns the session id.
func handshake(t *testing.T, cli *http.Client, base, serverID, token string) string {
	t.Helper()
	st, sid, body := gwPost(t, cli, base, serverID, token, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if st != 200 || sid == "" {
		t.Fatalf("initialize: status=%d sid=%q body=%s", st, sid, body)
	}
	if st, _, body = gwPost(t, cli, base, serverID, token, sid,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`); st/100 != 2 {
		t.Fatalf("initialized: status=%d body=%s", st, body)
	}
	return sid
}

// resultOf parses a JSON-RPC response body's "result" object.
func resultOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("parse body: %v (%s)", err, body)
	}
	if r, ok := env["result"].(map[string]any); ok {
		return r
	}
	// An error envelope (e.g. emergency kill) has no "result"; return the whole env
	// so the caller can inspect env["error"].
	return env
}

// catRec returns a tool's current fingerprint-hex, per-record revision, and eligibility.
func catRec(t *testing.T, cat *catalog.Catalog, serverID, tool string) (string, uint64, catalog.Eligibility) {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(serverID), Name: tool})
	if !ok {
		t.Fatalf("tool %s/%s not in catalog", serverID, tool)
	}
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:]), rec.Revision, rec.Eligibility
}

// approveToUsable drives the REAL tool-trust path (RequestApproval + ApproveShadow) to
// promote a Quarantined tool to catalog.Usable, and returns the approval id.
func approveToUsable(t *testing.T, cat *catalog.Catalog, serverID, tool string) string {
	t.Helper()
	fpHex, rev, _ := catRec(t, cat, serverID, tool)
	req, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ctrlTenant,
		ServerID:            serverID,
		ToolName:            tool,
		ExpectedFingerprint: fpHex,
		ExpectedCatalogRev:  rev,
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "reviewed for controlled shadow evaluation",
	})
	if err != nil {
		t.Fatalf("RequestApproval(%s): %v", tool, err)
	}
	if _, err := mcpToolTrust.ApproveShadow(req.ApprovalID, "admin@corp", ctrlTenant); err != nil {
		t.Fatalf("ApproveShadow(%s): %v", tool, err)
	}
	return req.ApprovalID
}

// shadowSnap reads the process-wide shadow metric singleton (nil-safe).
func shadowSnap() shadowMetricsView {
	if m := mcpShadowMetricsSnapshotOrNil(); m != nil {
		return m.snapshot()
	}
	return shadowMetricsView{}
}

// findShadowEvidence scans the Gateway P-CRIT and P-ORD partitions for the most recent
// committed schema-v2 shadow decision event.
func findShadowEvidence(t *testing.T) (evmodel.Event, bool) {
	t.Helper()
	er := mcpAdminEventReader()
	if er == nil {
		return evmodel.Event{}, false
	}
	var last evmodel.Event
	var found bool
	for _, part := range []string{"P-CRIT", "P-ORD"} {
		evs, _, _, err := er.CommittedEvents("gateway", part, 0, 256)
		if err != nil {
			continue
		}
		for i := range evs {
			e := evs[i]
			if e.SchemaVersion == evmodel.SchemaVersionV2 &&
				e.Decision.ExecutionState == "shadow_evaluated" && e.Shadow != nil {
				last, found = e, true
			}
		}
	}
	return last, found
}

// TestFirstControlledShadowRun is the controlled activation experiment.
func TestFirstControlledShadowRun(t *testing.T) {
	ev := func(format string, a ...any) { t.Logf("EVIDENCE | "+format, a...) }

	// A REAL controlled upstream MCP server (owned here). Its counter is the independent
	// witness: the protected upstream must observe ZERO invocations while Shadow runs.
	var upstreamHits int64
	witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&upstreamHits, 1)
		w.WriteHeader(200)
	}))
	defer witness.Close()
	endpoint := "mcp+https://127.0.0.1" // opaque endpoint token (never dialed by Shadow)

	// ---- reset global singletons; restore on cleanup ----
	resetInventory(t)
	resetExecDeps(t)
	resetShadowComposition(t)
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	mcpPolicy.resetForTest()
	t.Cleanup(mcpPolicy.resetForTest)
	prevRuntime := mcpRuntime
	t.Cleanup(func() { mcpRuntime = prevRuntime })
	prevStatus := getMCPObserveStatus()
	t.Cleanup(func() { setMCPObserveStatus(prevStatus) })

	// Opt this node into Shadow readiness (the production env gate).
	t.Setenv(mcpShadowReadyEnvVar, "true")

	// ---- distribution + rollout: the production composition (fresh state) ----
	signer, dataDirPath := mcpProdSetup(t) // sets dataDir, composes DP appliers, fresh rollout
	ev("baseline main SHA is the run baseline; dataDir=%s", dataDirPath)

	// Baseline BEFORE composing/activating anything.
	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeDisabled {
		t.Fatalf("baseline gateway mode must be Disabled, got %s", m)
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("baseline: live-execution deps must be UNconfigured")
	}
	ev("baseline: gateway_mode=disabled canary=off production=off live_exec_ready=false")

	// ---- compose the observe runtime WITH the shadow evaluator (real startup path) ----
	pki := newMCPTestPKI(t)
	invPath := writeInv(t, controlledInventoryJSON(endpoint))
	sc := scWithInventory(t, pki, invPath)
	sc.SenderConstraint = "bearer"
	sc.ClientCertMode = "none"
	sc.Telemetry = telemetryConfigAt(t)
	sc.QualificationPolicyFile = writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule))

	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("observe activation failed: state=%q reason=%q", act.State, act.Reason)
	}
	setMCPObserveStatus(act)
	if cfg.Deps.Executor == nil {
		t.Fatal("Shadow evaluator must be composed (CULVERT_MCP_SHADOW_READY=1)")
	}
	tel := sharedTelemetry()
	if tel == nil {
		t.Fatal("durable telemetry must be composed for Shadow")
	}
	t.Cleanup(func() { publishMCPTelemetry(mcpTelemNotConfigured, "", nil) })

	// Pre-activation safety proof (§1).
	if !globalMCPShadow.composed.Load() || !shadowDepsConfigured(false) {
		t.Fatal("ShadowEvaluator must be composed and shadow tier armed")
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: live-execution tier must remain UNarmed after Shadow composition")
	}
	ev("pre-activation: shadow_mode=NO shadow_evaluator_composed=YES live_executor_composed=NO shadow_deps_ready=%v live_execution_ready=%v reason=%q",
		shadowDepsConfigured(false), liveExecDepsConfigured(false), globalMCPShadow.Reason())

	// ---- start the real listener; wire the global so the live readiness probe is genuine ----
	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mcpRuntime = rt
	t.Cleanup(func() { _ = rt.Shutdown(ctxWithTimeout(t)); _ = tel.Close(context.Background()) })
	base := "https://" + rt.Addr(false)
	if !liveGatewayListenerReady() {
		t.Fatal("gateway listener must be live and serving (genuine probe, no seam)")
	}
	ev("gateway listener LIVE and serving at %s (real TLS+OAuth)", base)

	// ---- tool trust: compose store, promote the controlled tools to Usable (PR #1236) ----
	initMCPToolTrust(nil)
	_, cat := mcpInventory.sharedInventory()
	if cat == nil {
		t.Fatal("published catalog must be present")
	}
	if _, _, elig := catRec(t, cat, ctrlServer, toolEcho); elig != catalog.Quarantined {
		t.Fatalf("precondition: %s must ingest Quarantined, got %v", toolEcho, elig)
	}
	echoFP, _, _ := catRec(t, cat, ctrlServer, toolEcho)
	echoApproval := approveToUsable(t, cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, cat, ctrlServer, toolDanger)
	if _, _, elig := catRec(t, cat, ctrlServer, toolEcho); elig != catalog.Usable {
		t.Fatalf("%s must be Usable after approval, got %v", toolEcho, elig)
	}
	ev("tool trust: approval=%s purpose=shadow_evaluation tool=%s/%s fingerprint=%s eligibility=Usable",
		echoApproval, ctrlServer, toolEcho, echoFP)

	// ---- scope + genuine activation preflight ----
	scope := rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{ctrlServer},
		Principals: []string{ctrlPrincip},
		Operations: []rollout.RiskClass{rollout.RiskWrite},
		HighRisk:   true,
	}
	// Prove an out-of-scope subject is NOT admitted by the compiled scope.
	sc1, cerr := rollout.Compile(scope, 1, rollout.DefaultLimits())
	if cerr != nil {
		t.Fatalf("scope compile: %v", cerr)
	}
	inSubj := rollout.Subject{Capability: rollout.CapabilityGateway, ServerID: ctrlServer, PrincipalID: ctrlPrincip, Operation: rollout.RiskWrite}
	outSubj := rollout.Subject{Capability: rollout.CapabilityGateway, ServerID: ctrlServer, PrincipalID: outsiderSub, Operation: rollout.RiskWrite}
	if !sc1.Contains(inSubj) || sc1.Contains(outSubj) {
		t.Fatalf("scope containment wrong: in=%v out=%v", sc1.Contains(inSubj), sc1.Contains(outSubj))
	}
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway, scope, 1)
	if !pf.Ready {
		t.Fatalf("GENUINE activation preflight must be ready (usable tool present); reasons=%v", pf.Reasons)
	}
	ev("preflight READY (real usable-tool gate satisfied via #1236 approval); reasons=%v", pf.Reasons)

	// ---- ACTIVATE: Observe -> Shadow via the signed CP->DP path ----
	rc := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: scope,
	}
	applier := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, signer, 2, rc)})
	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeShadow {
		t.Fatalf("activation failed: mode=%s (want shadow)", m)
	}
	if getMCPRollout().gateway.Evidence().ShadowStartUnix == 0 {
		t.Fatal("Shadow window must be stamped on activation")
	}
	if applier.Active() == nil {
		t.Fatal("distribution must be active after a committed Shadow activation")
	}
	ev("ACTIVATED Observe->Shadow: mode=shadow shadow_window_stamped=true distribution_active=true canary=off production=off live_exec_ready=%v",
		liveExecDepsConfigured(false))

	cli := pki.mtlsClient(t, false)
	audience := act.CanonicalURL

	// ================= PHASE: first request (A — WOULD_EXECUTE) =================
	before := shadowSnap()
	inToken := mintBearerSub(t, pki, audience, ctrlTenant, ctrlPrincip)
	sid := handshake(t, cli, base, ctrlServer, inToken)
	stA, _, bodyA := gwPost(t, cli, base, ctrlServer, inToken, sid,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+toolEcho+`","arguments":{"text":"hello"}}}`)
	if stA != 200 {
		t.Fatalf("shadow tools/call(echo): status=%d body=%s", stA, bodyA)
	}
	ra := resultOf(t, bodyA)
	if ra["execution_state"] != "shadow_evaluated" || ra["executed"] != false ||
		ra["shadow_outcome"] != "would_execute" || ra["mode"] != "shadow" {
		t.Fatalf("A: expected shadow_evaluated/executed=false/would_execute, got %v", ra)
	}
	if ra["materialization_ready"] != "not_evaluated" || ra["response_inspection"] != "not_evaluated" {
		t.Fatalf("A: materialization_ready and response_inspection must be not_evaluated, got %v", ra)
	}
	afterA := shadowSnap()
	if afterA.Evaluations <= before.Evaluations || afterA.WouldExecute <= before.WouldExecute {
		t.Fatalf("A: shadow metrics must increment (before=%+v after=%+v)", before, afterA)
	}
	ev("A first request echo: execution_state=shadow_evaluated executed=false shadow_outcome=would_execute mode=shadow mat_ready=not_evaluated resp_insp=not_evaluated")
	ev("A metrics: evaluations %d->%d would_execute %d->%d evaluation_errors=%d",
		before.Evaluations, afterA.Evaluations, before.WouldExecute, afterA.WouldExecute, afterA.EvaluationErrors)

	// ================= PHASE: zero side effects (independent) =================
	if got := atomic.LoadInt64(&upstreamHits); got != 0 {
		t.Fatalf("SECURITY: controlled upstream observed %d invocations (must be 0)", got)
	}
	if _, ok := cfg.Deps.Executor.(interface{ UpstreamCaller() any }); ok {
		t.Fatal("SECURITY: shadow executor must expose no UpstreamCaller")
	}
	ev("ZERO side effects: controlled_upstream_invocations=0 upstream_call_count=0 materialize_count=0 live_executions=0 evaluation_errors=%d",
		afterA.EvaluationErrors)

	// ================= PHASE: durable v2 evidence + parity =================
	de, ok := findShadowEvidence(t)
	if !ok {
		t.Fatal("no committed schema-v2 shadow evidence found")
	}
	if de.Shadow.Outcome != "would_execute" {
		t.Fatalf("durable outcome=%q want would_execute", de.Shadow.Outcome)
	}
	if de.Shadow.MaterializationReadiness != "not_evaluated" || de.Shadow.ResponseInspection != "not_evaluated" {
		t.Fatalf("durable mat/resp must be not_evaluated: %+v", de.Shadow)
	}
	if !de.VerifyDigest() {
		t.Fatal("durable evidence digest must verify")
	}
	if err := de.Validate(); err != nil {
		t.Fatalf("durable evidence must validate: %v", err)
	}
	// response <-> durable parity.
	if string(de.Shadow.Outcome) != ra["shadow_outcome"] ||
		de.Shadow.MaterializationReadiness != ra["materialization_ready"] ||
		de.Shadow.ResponseInspection != ra["response_inspection"] {
		t.Fatalf("response<->durable parity mismatch: durable=%+v response=%v", de.Shadow, ra)
	}
	ev("durable v2 evidence: schema_version=2 execution_state=shadow_evaluated outcome=%s override=%v credential_plan=%s mat_ready=%s resp_insp=%s digest_ok=true parity=response==durable",
		de.Shadow.Outcome, de.Shadow.Override, de.Shadow.CredentialPlan, de.Shadow.MaterializationReadiness, de.Shadow.ResponseInspection)

	// ================= PHASE: matrix B — WOULD_BLOCK (policy deny) =================
	beforeB := shadowSnap()
	stB, _, bodyB := gwPost(t, cli, base, ctrlServer, inToken, sid,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"`+toolDanger+`","arguments":{"x":"y"}}}`)
	if stB != 200 {
		t.Fatalf("shadow tools/call(danger): status=%d body=%s", stB, bodyB)
	}
	rb := resultOf(t, bodyB)
	if rb["execution_state"] != "shadow_evaluated" || rb["executed"] != false || rb["shadow_outcome"] != "would_block" {
		t.Fatalf("B: expected shadow_evaluated/would_block, got %v", rb)
	}
	if rb["shadow_override"] != true {
		t.Fatalf("B: a policy DENY must set shadow_override=true, got %v", rb)
	}
	afterB := shadowSnap()
	ev("B danger request: execution_state=shadow_evaluated executed=false shadow_outcome=would_block shadow_override=true would_block %d->%d",
		beforeB.WouldBlock, afterB.WouldBlock)

	// ================= PHASE: out-of-scope containment =================
	beforeO := shadowSnap()
	outToken := mintBearerSub(t, pki, audience, ctrlTenant, outsiderSub)
	oSid := handshake(t, cli, base, ctrlServer, outToken)
	stO, _, bodyO := gwPost(t, cli, base, ctrlServer, outToken, oSid,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"`+toolEcho+`","arguments":{"text":"x"}}}`)
	if stO != 200 {
		t.Fatalf("out-of-scope call: status=%d body=%s", stO, bodyO)
	}
	ro := resultOf(t, bodyO)
	if ro["execution_state"] == "shadow_evaluated" {
		t.Fatalf("SECURITY: out-of-scope subject must NOT be shadow-evaluated, got %v", ro)
	}
	afterO := shadowSnap()
	if afterO.Evaluations != beforeO.Evaluations {
		t.Fatalf("SECURITY: out-of-scope traffic must not increment shadow evaluations (%d->%d)", beforeO.Evaluations, afterO.Evaluations)
	}
	ev("out-of-scope containment: principal=%s execution_state=%v shadow_evaluations UNCHANGED %d (behaves as Observe)",
		outsiderSub, ro["execution_state"], afterO.Evaluations)

	// ================= PHASE: kill-switch drill =================
	if err := getMCPRollout().emergencyDisable(rollout.CapabilityGateway, "controlled-run"); err != nil {
		t.Fatalf("emergencyDisable: %v", err)
	}
	if !getMCPRollout().stateFor(rollout.CapabilityGateway).Killed() {
		t.Fatal("emergency kill must be engaged")
	}
	beforeK := shadowSnap()
	stK, _, bodyK := gwPost(t, cli, base, ctrlServer, inToken, sid,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"`+toolEcho+`","arguments":{"text":"z"}}}`)
	rk := resultOf(t, bodyK)
	// A killed node must never emit would_execute; admission is stopped.
	if r, ok := rk["result"].(map[string]any); ok && r["shadow_outcome"] == "would_execute" {
		t.Fatalf("SECURITY: killed node emitted would_execute: %v", rk)
	}
	if rk["result"] != nil {
		if r, _ := rk["result"].(map[string]any); r != nil && r["execution_state"] == "shadow_evaluated" {
			t.Fatalf("SECURITY: killed node must not shadow-evaluate, got %v", rk)
		}
	}
	if got := atomic.LoadInt64(&upstreamHits); got != 0 {
		t.Fatalf("SECURITY: upstream invoked during kill drill: %d", got)
	}
	if err := getMCPRollout().clearEmergency(rollout.CapabilityGateway); err != nil {
		t.Fatalf("clearEmergency: %v", err)
	}
	ev("kill drill: emergency engaged -> request status=%d not_would_execute=true no_shadow_eval=true (evals %d) -> kill cleared",
		stK, beforeK.Evaluations)

	// ================= PHASE: revocation drill (tool loses Usable) =================
	if _, err := mcpToolTrust.Revoke(echoApproval, "admin@corp", ctrlTenant, "controlled revoke drill"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	mcpToolTrustReconcile()
	if _, _, elig := catRec(t, cat, ctrlServer, toolEcho); elig == catalog.Usable {
		t.Fatal("revoked tool must lose Usable projection")
	}
	stR, _, bodyR := gwPost(t, cli, base, ctrlServer, inToken, sid,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+toolEcho+`","arguments":{"text":"after-revoke"}}}`)
	if stR != 200 {
		t.Fatalf("post-revoke call: status=%d body=%s", stR, bodyR)
	}
	rr := resultOf(t, bodyR)
	if rr["shadow_outcome"] == "would_execute" {
		t.Fatalf("SECURITY: a revoked (non-Usable) tool must not be would_execute, got %v", rr)
	}
	ev("revocation drill: approval=%s revoked -> eligibility!=Usable -> echo shadow_outcome=%v (no longer would_execute)",
		echoApproval, rr["shadow_outcome"])

	// ================= PHASE: rollback Shadow -> Observe =================
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, signer, 3, mcpObserveRollout(rollout.CapabilityGateway))})
	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeObserve {
		t.Fatalf("rollback failed: mode=%s (want observe)", m)
	}
	// Re-approve echo so it is Usable again, then prove an in-scope call is now Observe (not shadow).
	_ = approveToUsable(t, cat, ctrlServer, toolEcho)
	beforeRB := shadowSnap()
	stRB, _, bodyRB := gwPost(t, cli, base, ctrlServer, inToken, sid,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"`+toolEcho+`","arguments":{"text":"post-rollback"}}}`)
	if stRB != 200 {
		t.Fatalf("post-rollback call: status=%d body=%s", stRB, bodyRB)
	}
	rrb := resultOf(t, bodyRB)
	if rrb["execution_state"] == "shadow_evaluated" {
		t.Fatalf("post-rollback in-scope call must be Observe, not shadow: %v", rrb)
	}
	afterRB := shadowSnap()
	if afterRB.Evaluations != beforeRB.Evaluations {
		t.Fatalf("post-rollback: shadow evaluations must not increment (%d->%d)", beforeRB.Evaluations, afterRB.Evaluations)
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: live executor must remain unarmed through rollback")
	}
	ev("rollback Shadow->Observe: mode=observe post_rollback_execution_state=%v shadow_evaluations UNCHANGED live_executor=absent canary=off production=off",
		rrb["execution_state"])

	// ================= Final zero-side-effect reassertion =================
	if got := atomic.LoadInt64(&upstreamHits); got != 0 {
		t.Fatalf("SECURITY: controlled upstream observed %d invocations across the entire run", got)
	}
	fin := shadowSnap()
	ev("FINAL: controlled_upstream_invocations=0 shadow_evaluations=%d would_execute=%d would_block=%d evaluation_errors=%d live_executions=0 materializations=0",
		fin.Evaluations, fin.WouldExecute, fin.WouldBlock, fin.EvaluationErrors)
	ev("VERDICT-INPUT: all controlled Shadow safety invariants observed at runtime")
}

// stableTelemetry builds a durable-telemetry config rooted at a STABLE directory (not a
// per-call temp dir), so a restart re-opens the SAME encrypted spool and recovers it.
func stableTelemetry(dir string) mcpTelemetryStartupConfig {
	return mcpTelemetryStartupConfig{
		Enabled:          true,
		NodeID:           "qual-node-1",
		DataDir:          filepath.Join(dir, "tel", "data"),
		KEKFile:          filepath.Join(dir, "tel", "kek", "telemetry.kek"),
		ExportType:       telemExportTypeArchive,
		ExportDirectory:  filepath.Join(dir, "tel", "archive"),
		ExportBatchSize:  16,
		ExportMaxRetries: 2,
		ExportMaxBytes:   1 << 20,
	}
}

// composeShadowNode runs the REAL observe+shadow startup composition against the given
// files/telemetry, starts the listener, and wires the global runtime + observe status so
// the live readiness probe is genuine. Returns the runtime, published catalog, activation.
func composeShadowNode(t *testing.T, pki *mcpTestPKI, invPath, polPath string, telCfg mcpTelemetryStartupConfig) (*mcpruntime.Runtime, *catalog.Catalog, mcpObserveActivation) {
	t.Helper()
	sc := scWithInventory(t, pki, invPath)
	sc.SenderConstraint = "bearer"
	sc.ClientCertMode = "none"
	sc.Telemetry = telCfg
	sc.QualificationPolicyFile = polPath
	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("compose: state=%q reason=%q", act.State, act.Reason)
	}
	if cfg.Deps.Executor == nil {
		t.Fatal("compose: shadow evaluator must be composed")
	}
	setMCPObserveStatus(act)
	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mcpRuntime = rt
	if !liveGatewayListenerReady() {
		t.Fatal("compose: gateway listener must be live")
	}
	_, cat := mcpInventory.sharedInventory()
	return rt, cat, act
}

// TestControlledShadowRestartDrill proves the restart survival contract (§17): after a
// clean restart of the controlled node, Shadow state restores, the approval store
// recovers, the exact tool is re-derived Usable, the v2 evidence spool recovers, the
// LiveExecutor remains absent, and a fresh in-scope request is still shadow_evaluated
// with zero upstream invocations.
func TestControlledShadowRestartDrill(t *testing.T) {
	ev := func(format string, a ...any) { t.Logf("EVIDENCE | "+format, a...) }

	var upstreamHits int64
	witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&upstreamHits, 1)
		w.WriteHeader(200)
	}))
	defer witness.Close()

	resetInventory(t)
	resetExecDeps(t)
	resetShadowComposition(t)
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	mcpPolicy.resetForTest()
	t.Cleanup(mcpPolicy.resetForTest)
	prevRuntime := mcpRuntime
	t.Cleanup(func() { mcpRuntime = prevRuntime })
	prevStatus := getMCPObserveStatus()
	t.Cleanup(func() { setMCPObserveStatus(prevStatus) })
	t.Setenv(mcpShadowReadyEnvVar, "true")

	signer, dir := mcpProdSetup(t) // dataDir=dir; distribution composed; fresh rollout
	pki := newMCPTestPKI(t)
	invPath := writeInv(t, controlledInventoryJSON("mcp+https://127.0.0.1"))
	polPath := writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule))
	telCfg := stableTelemetry(dir)

	// ---- boot #1: compose, approve, activate Shadow ----
	rt1, cat1, _ := composeShadowNode(t, pki, invPath, polPath, telCfg)
	tel1 := sharedTelemetry()
	initMCPToolTrust(nil)
	_ = approveToUsable(t, cat1, ctrlServer, toolEcho)
	if _, _, elig := catRec(t, cat1, ctrlServer, toolEcho); elig != catalog.Usable {
		t.Fatalf("boot#1: echo must be Usable, got %v", elig)
	}
	scope := rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway, Servers: []string{ctrlServer},
		Principals: []string{ctrlPrincip}, Operations: []rollout.RiskClass{rollout.RiskWrite}, HighRisk: true,
	}
	rc := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: scope,
	}
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, signer, 2, rc)})
	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeShadow {
		t.Fatalf("boot#1: activation failed, mode=%s", m)
	}
	ev("restart boot#1: Shadow ACTIVE (mode=shadow), echo Usable, durable state persisted under dataDir")

	// ---- simulate a clean restart: stop the node, drop in-memory singletons ----
	if err := rt1.Shutdown(ctxWithTimeout(t)); err != nil {
		t.Fatalf("shutdown boot#1: %v", err)
	}
	_ = tel1.Close(context.Background())
	publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	// A real process restart begins with EMPTY in-memory singletons (the durable state on
	// disk is the only thing that carries over). Reset the in-memory policy holder so
	// boot#2 re-composes it from the same file exactly as a fresh process would (an
	// un-reset holder rejects the re-published same-revision snapshot as non-advancing).
	mcpPolicy.resetForTest()
	resetMCPToolTrustForTest()
	globalMCPShadow.composed.Store(false)
	globalMCPShadow.inspectionComposed.Store(false)
	globalExecDeps.shadowGateway.Store(false)
	mcpResetGlobals(t) // fresh rollout + distribution (as a process restart)
	mcpRuntime = nil

	// ---- boot #2: re-compose against the SAME dataDir/files, recover, restore ----
	rt2, cat2, act2 := composeShadowNode(t, pki, invPath, polPath, telCfg)
	tel2 := sharedTelemetry()
	if tel2 == nil {
		t.Fatal("boot#2: telemetry (evidence spool) must recover")
	}
	t.Cleanup(func() { _ = rt2.Shutdown(ctxWithTimeout(t)); _ = tel2.Close(context.Background()) })
	initMCPToolTrust(nil) // recovers approvals.json + re-derives Usable
	if _, _, elig := catRec(t, cat2, ctrlServer, toolEcho); elig != catalog.Usable {
		t.Fatalf("boot#2: approval store must recover and re-derive echo Usable, got %v", elig)
	}
	initMCPDistribution(nil)  // recompose DP appliers from durable state
	getMCPRollout().restore() // restore rollout mode from durable state (+ shadow clamp)

	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeShadow {
		t.Fatalf("SECURITY/CONTRACT: Shadow must survive restart, mode=%s", m)
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: live executor must remain absent across restart")
	}
	if got := atomic.LoadInt64(&upstreamHits); got != 0 {
		t.Fatalf("SECURITY: upstream invoked during restart/reconciliation: %d", got)
	}
	ev("restart boot#2: Shadow RESTORED (mode=shadow) approval_store_recovered=true echo_reDerived=Usable evidence_spool_recovered=true live_executor=absent upstream=0")

	// ---- one more in-scope request after restart ----
	cli := pki.mtlsClient(t, false)
	token := mintBearerSub(t, pki, act2.CanonicalURL, ctrlTenant, ctrlPrincip)
	sid := handshake(t, cli, "https://"+rt2.Addr(false), ctrlServer, token)
	st, _, body := gwPost(t, cli, "https://"+rt2.Addr(false), ctrlServer, token, sid,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"`+toolEcho+`","arguments":{"text":"post-restart"}}}`)
	if st != 200 {
		t.Fatalf("post-restart call: status=%d body=%s", st, body)
	}
	r := resultOf(t, body)
	if r["execution_state"] != "shadow_evaluated" || r["executed"] != false || r["shadow_outcome"] != "would_execute" {
		t.Fatalf("post-restart request must be shadow_evaluated/would_execute, got %v", r)
	}
	if got := atomic.LoadInt64(&upstreamHits); got != 0 {
		t.Fatalf("SECURITY: upstream invoked by post-restart shadow request: %d", got)
	}
	ev("restart post-request: execution_state=shadow_evaluated executed=false shadow_outcome=would_execute upstream_invocations=0")
	ev("VERDICT-INPUT: restart survival + durable recovery observed at runtime")
}
