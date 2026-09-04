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
//   - a REAL controlled upstream server (owned here), REGISTERED as the controlled
//     server's inventory endpoint, whose invocation counter is an AUXILIARY /
//     defense-in-depth check that the protected upstream observes ZERO invocations
//     (NOT the primary proof — see witnessEndpoint; the structural ShadowEvaluator
//     assertion is what proves zero upstream side effects).
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
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
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

// req fails the test unless ok. Extracting the assertion out of an `if` keeps the
// experiment phases readable and their cognitive complexity low.
func req(t *testing.T, ok bool, format string, a ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, a...)
	}
}

// controlledInventoryJSON seeds ONE controlled server owning two harmless tools, at the
// given endpoint (the auxiliary witness server; note the production upstream transport can
// reject an attempted dial during resolution/identity verification before that handler is
// reached, so the hit counter is defense-in-depth, not the proof — see witnessEndpoint).
// Both tools ingest Quarantined (approval is a separate slice).
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

// controlledScope is the bounded, enumerable Shadow scope (no wildcard).
func controlledScope() rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{ctrlServer},
		Principals: []string{ctrlPrincip},
		Operations: []rollout.RiskClass{rollout.RiskWrite},
		HighRisk:   true,
	}
}

// witnessEndpoint starts a REAL controlled upstream TLS server and returns it plus its
// https:// loopback URL, registered as the controlled server's inventory endpoint. Its
// hit counter is an AUXILIARY / defense-in-depth witness: a real HTTP server that received
// zero requests during the run. It is deliberately NOT the primary zero-invocation proof —
// that is STRUCTURAL: Shadow composes no upstream client and no materialize-capable broker
// (Layer B, enforced by the execution-posture wall, TestExecPosture_*), so it CANNOT dial
// any endpoint regardless of this witness's reachability. Wiring the production upstream
// transport's resolver policy / SPKI pin here would mean composing an upstream path the
// Shadow build structurally lacks, so it is intentionally left out.
func witnessEndpoint(t *testing.T, hits *int64) (srv *httptest.Server, endpoint string) {
	t.Helper()
	w := httptest.NewTLSServer(http.HandlerFunc(func(wr http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(hits, 1)
		wr.WriteHeader(200)
	}))
	t.Cleanup(w.Close)
	return w, w.URL // https://127.0.0.1:<port>
}

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
	req(t, err == nil, "sign token: %v", err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + mustB64(sig)
}

// gwPost issues one authenticated MCP POST to the controlled server path.
func gwPost(t *testing.T, cli *http.Client, base, serverID, token, sid, body string) (status int, sessionID string, respBody []byte) {
	t.Helper()
	r := mcpObserveReq(t, "POST", base+"/mcp/gateway/"+serverID, body)
	r.Host = "gw.test"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if sid != "" {
		r.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := cli.Do(r)
	req(t, err == nil, "post: %v", err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close of the response body in a test
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), raw
}

// handshake runs initialize + notifications/initialized and returns the session id.
func handshake(t *testing.T, cli *http.Client, base, serverID, token string) string {
	t.Helper()
	st, sid, body := gwPost(t, cli, base, serverID, token, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	req(t, st == 200 && sid != "", "initialize: status=%d sid=%q body=%s", st, sid, body)
	st, _, body = gwPost(t, cli, base, serverID, token, sid,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	req(t, st/100 == 2, "initialized: status=%d body=%s", st, body)
	return sid
}

// toolsCall posts a tools/call and returns status + the parsed result object.
func toolsCall(t *testing.T, cli *http.Client, base, token, sid, id, tool, arg string) (status int, result map[string]any) {
	t.Helper()
	st, _, body := gwPost(t, cli, base, ctrlServer, token, sid,
		`{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+arg+`}}`)
	return st, resultOf(t, body)
}

// resultOf parses a JSON-RPC response body's "result" object. An error envelope (e.g.
// emergency kill) has no "result", so the whole envelope is returned and the caller
// simply finds no shadow fields in it.
func resultOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var env map[string]any
	req(t, json.Unmarshal(body, &env) == nil, "parse body: %s", body)
	if r, ok := env["result"].(map[string]any); ok {
		return r
	}
	return env
}

// catRec returns a tool's current fingerprint-hex, per-record revision, and eligibility.
func catRec(t *testing.T, cat *catalog.Catalog, serverID, tool string) (fingerprintHex string, revision uint64, eligibility catalog.Eligibility) {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(serverID), Name: tool})
	req(t, ok, "tool %s/%s not in catalog", serverID, tool)
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:]), rec.Revision, rec.Eligibility
}

// approveToUsable drives the REAL tool-trust path (RequestApproval + ApproveShadow) to
// promote a Quarantined tool to catalog.Usable, and returns the approval id.
func approveToUsable(t *testing.T, cat *catalog.Catalog, serverID, tool string) string {
	t.Helper()
	fpHex, rev, _ := catRec(t, cat, serverID, tool)
	r, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ctrlTenant,
		ServerID:            serverID,
		ToolName:            tool,
		ExpectedFingerprint: fpHex,
		ExpectedCatalogRev:  rev,
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "reviewed for controlled shadow evaluation",
	})
	req(t, err == nil, "RequestApproval(%s): %v", tool, err)
	_, err = mcpToolTrust.ApproveShadow(r.ApprovalID, "admin@corp", ctrlTenant)
	req(t, err == nil, "ApproveShadow(%s): %v", tool, err)
	return r.ApprovalID
}

// shadowSnap reads the process-wide shadow metric singleton (nil-safe).
func shadowSnap() shadowMetricsView {
	if m := mcpShadowMetricsSnapshotOrNil(); m != nil {
		return m.snapshot()
	}
	return shadowMetricsView{}
}

// assertShadowDelta asserts that EXACTLY the named deltas were applied to the shadow metrics
// singleton between before and after and that NOTHING ELSE changed — a FULL-snapshot
// comparison. A per-field "+1" check on only the intended bucket would miss an accounting
// regression that also bumped an unrelated bucket, and the next phase would then inherit the
// inflated value as its baseline and also pass; comparing the whole snapshot closes that
// (Codex P2 on 7dfe358). Every field is compared, so an unexercised bucket moving from 0 is
// caught here rather than only at the report's "all-zero" claim.
func assertShadowDelta(t *testing.T, before, after, deltas shadowMetricsView) {
	t.Helper()
	want := shadowMetricsView{
		Evaluations:              before.Evaluations + deltas.Evaluations,
		WouldExecute:             before.WouldExecute + deltas.WouldExecute,
		WouldBlock:               before.WouldBlock + deltas.WouldBlock,
		WouldRequireApproval:     before.WouldRequireApproval + deltas.WouldRequireApproval,
		WouldRequireConfirmation: before.WouldRequireConfirmation + deltas.WouldRequireConfirmation,
		WouldFailCredential:      before.WouldFailCredential + deltas.WouldFailCredential,
		WouldFailInspection:      before.WouldFailInspection + deltas.WouldFailInspection,
		WouldFailStale:           before.WouldFailStale + deltas.WouldFailStale,
		WouldFailHardControl:     before.WouldFailHardControl + deltas.WouldFailHardControl,
		WouldOther:               before.WouldOther + deltas.WouldOther,
		EvaluationErrors:         before.EvaluationErrors + deltas.EvaluationErrors,
	}
	req(t, after == want, "shadow metric delta: only the intended buckets may change. before=%+v after=%+v want=%+v (deltas=%+v)", before, after, want, deltas)
}

// committedShadowEventIDs snapshots the ids of every currently-committed schema-v2 shadow
// event on the Gateway. Captured BEFORE a request so newShadowEvidence can identify that
// request's durable event by set difference.
func committedShadowEventIDs(t *testing.T) map[string]bool {
	t.Helper()
	return eventIDSet(committedShadowEvents(t))
}

// newShadowEvidence returns the SINGLE committed schema-v2 shadow event whose id is not in
// preIDs — the durable event produced by the one request issued after preIDs was captured.
//
// It identifies the event by its NEW id, deliberately NOT by "latest". Event.TimeUnixNano is
// stamped by events.Manager.buildEvent at event CONSTRUCTION, before Spool.Commit takes the
// partition lock, so it is not a commit-order value and is not strictly monotonic with commit
// order (and the two partitions commit under independent locks). Selecting a max timestamp
// could therefore return an unrelated event under concurrency and invalidate a parity
// assertion. Requiring exactly one new id makes the sequential-request precondition explicit
// and removes any dependence on timestamp-vs-commit-order skew.
func newShadowEvidence(t *testing.T, preIDs map[string]bool) (evmodel.Event, bool) {
	t.Helper()
	var news []evmodel.Event
	evs := committedShadowEvents(t)
	for i := range evs {
		if !preIDs[evs[i].EventID] {
			news = append(news, evs[i])
		}
	}
	if len(news) != 1 {
		t.Fatalf("expected exactly one new committed schema-v2 shadow event since the snapshot, got %d", len(news))
		return evmodel.Event{}, false
	}
	return news[0], true
}

// shadowEventByIDPresent reports whether a specific committed schema-v2 shadow event id
// is readable back from the durable spool (used to prove restart recovery of evidence).
func shadowEventByIDPresent(t *testing.T, id string) bool {
	t.Helper()
	er := mcpAdminEventReader()
	if er == nil {
		return false
	}
	const batch = 512
	for _, part := range []string{"P-CRIT", "P-ORD"} {
		afterSeq := uint64(0)
		for {
			evs, _, next, err := er.CommittedEvents("gateway", part, afterSeq, batch)
			if err != nil {
				break
			}
			for i := range evs {
				if evs[i].EventID == id && evs[i].SchemaVersion == evmodel.SchemaVersionV2 {
					return true
				}
			}
			if len(evs) < batch {
				break
			}
			afterSeq = next
		}
	}
	return false
}

// shadowRun carries the shared handles a controlled activation experiment drives.
type shadowRun struct {
	t            *testing.T
	pki          *mcpTestPKI
	cli          *http.Client
	base         string
	audience     string
	cat          *catalog.Catalog
	signer       cpdp.Signer
	inToken      string
	sid          string
	echoApproval string
	upstreamHits *int64
	cfgRev       uint64
	ev           func(string, ...any)
}

// applyGateway signs and applies a Gateway rollout config at a monotonically-increasing
// config revision.
func (r *shadowRun) applyGateway(rc *rollout.SignedConfig) {
	r.cfgRev++
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(r.t, r.signer, r.cfgRev, rc)})
}

// firstRequestWouldExecute — Phase A: an in-scope echo call predicts would_execute,
// commits schema-v2 evidence matching the response, and causes zero side effects.
func (r *shadowRun) firstRequestWouldExecute() {
	t := r.t
	before := shadowSnap()
	r.sid = handshake(t, r.cli, r.base, ctrlServer, r.inToken)
	preIDs := committedShadowEventIDs(t)
	st, ra := toolsCall(t, r.cli, r.base, r.inToken, r.sid, "3", toolEcho, `{"text":"hello"}`)
	req(t, st == 200, "A: status=%d", st)
	req(t, ra["execution_state"] == "shadow_evaluated" && ra["executed"] == false &&
		ra["shadow_outcome"] == "would_execute" && ra["mode"] == "shadow",
		"A: expected shadow_evaluated/executed=false/would_execute, got %v", ra)
	req(t, ra["materialization_ready"] == "not_evaluated" && ra["response_inspection"] == "not_evaluated",
		"A: materialization_ready and response_inspection must be not_evaluated, got %v", ra)
	after := shadowSnap()
	assertShadowDelta(t, before, after, shadowMetricsView{Evaluations: 1, WouldExecute: 1})
	r.ev("A first request echo: execution_state=shadow_evaluated executed=false shadow_outcome=would_execute mode=shadow mat_ready=not_evaluated resp_insp=not_evaluated")
	r.ev("A metrics: evaluations %d->%d would_execute %d->%d evaluation_errors=%d",
		before.Evaluations, after.Evaluations, before.WouldExecute, after.WouldExecute, after.EvaluationErrors)

	// Zero side effects (auxiliary witness; the structural ShadowEvaluator is the proof).
	req(t, atomic.LoadInt64(r.upstreamHits) == 0, "SECURITY: controlled upstream observed %d invocations (must be 0)", atomic.LoadInt64(r.upstreamHits))
	r.ev("ZERO side effects: controlled_upstream_invocations=0 upstream_call_count=0 materialize_count=0 live_executions=0 evaluation_errors=%d", after.EvaluationErrors)

	// Durable v2 evidence + response<->durable parity. Identify THIS request's event by the
	// new id since the pre-request snapshot (preIDs), never by "latest".
	de, ok := newShadowEvidence(t, preIDs)
	req(t, ok, "no committed schema-v2 shadow evidence found")
	req(t, de.Shadow.Outcome == "would_execute", "durable outcome=%q want would_execute", de.Shadow.Outcome)
	req(t, de.Shadow.MaterializationReadiness == "not_evaluated" && de.Shadow.ResponseInspection == "not_evaluated",
		"durable mat/resp must be not_evaluated: %+v", de.Shadow)
	req(t, de.VerifyDigest(), "durable evidence digest must verify")
	req(t, de.Validate() == nil, "durable evidence must validate: %v", de.Validate())
	req(t, de.Shadow.Outcome == ra["shadow_outcome"] &&
		de.Shadow.MaterializationReadiness == ra["materialization_ready"] &&
		de.Shadow.ResponseInspection == ra["response_inspection"],
		"response<->durable parity mismatch: durable=%+v response=%v", de.Shadow, ra)
	r.ev("durable v2 evidence: schema_version=2 execution_state=shadow_evaluated outcome=%s override=%v credential_plan=%s mat_ready=%s resp_insp=%s digest_ok=true parity=response==durable",
		de.Shadow.Outcome, de.Shadow.Override, de.Shadow.CredentialPlan, de.Shadow.MaterializationReadiness, de.Shadow.ResponseInspection)
}

// matrixWouldBlock — Phase B: an in-scope Usable danger call under default-DENY predicts
// would_block with a restrictive-policy override (never laundered into would_execute).
func (r *shadowRun) matrixWouldBlock() {
	t := r.t
	before := shadowSnap()
	preIDs := committedShadowEventIDs(t)
	st, rb := toolsCall(t, r.cli, r.base, r.inToken, r.sid, "4", toolDanger, `{"x":"y"}`)
	req(t, st == 200, "B: status=%d", st)
	req(t, rb["execution_state"] == "shadow_evaluated" && rb["executed"] == false && rb["shadow_outcome"] == "would_block",
		"B: expected shadow_evaluated/would_block, got %v", rb)
	req(t, rb["shadow_override"] == true, "B: a policy DENY must set shadow_override=true, got %v", rb)
	after := shadowSnap()
	assertShadowDelta(t, before, after, shadowMetricsView{Evaluations: 1, WouldBlock: 1})
	// A durable schema-v2 event must exist for THIS would_block evaluation (no evidence gap).
	de, ok := newShadowEvidence(t, preIDs)
	req(t, ok && de.Shadow.Outcome == "would_block" && de.VerifyDigest() && de.Validate() == nil,
		"B: a durable schema-v2 would_block event must be committed, got ok=%v %+v", ok, de.Shadow)
	r.ev("B danger request: execution_state=shadow_evaluated executed=false shadow_outcome=would_block shadow_override=true would_block %d->%d durable_outcome=%s",
		before.WouldBlock, after.WouldBlock, de.Shadow.Outcome)
}

// outOfScopeContainment — an out-of-scope principal must NOT be shadow-evaluated; it
// behaves as Observe and never increments shadow evaluations.
func (r *shadowRun) outOfScopeContainment() {
	t := r.t
	before := shadowSnap()
	outToken := mintBearerSub(t, r.pki, r.audience, ctrlTenant, outsiderSub)
	oSid := handshake(t, r.cli, r.base, ctrlServer, outToken)
	st, ro := toolsCall(t, r.cli, r.base, outToken, oSid, "5", toolEcho, `{"text":"x"}`)
	req(t, st == 200, "out-of-scope call: status=%d", st)
	// Assert the EXACT Observe outcome: an out-of-scope allow-class call is a non-executing
	// Observe decision (execution_state=not_implemented), never a Shadow evaluation.
	req(t, ro["execution_state"] == "not_implemented", "SECURITY: out-of-scope subject must be Observe (not_implemented), never shadow-evaluated, got %v", ro)
	after := shadowSnap()
	// Out-of-scope traffic must move NO shadow counter — the full-snapshot delta of zero
	// proves it neither shadow-evaluated nor touched any other bucket.
	assertShadowDelta(t, before, after, shadowMetricsView{})
	r.ev("out-of-scope containment: principal=%s execution_state=%v shadow_evaluations UNCHANGED %d (behaves as Observe)",
		outsiderSub, ro["execution_state"], after.Evaluations)
}

// killDrill — an engaged emergency kill stops admission: no would_execute, no
// shadow_evaluated, zero upstream, then cleared.
func (r *shadowRun) killDrill() {
	t := r.t
	req(t, getMCPRollout().emergencyDisable(rollout.CapabilityGateway, "controlled-run") == nil, "emergencyDisable failed")
	req(t, getMCPRollout().stateFor(rollout.CapabilityGateway).Killed(), "emergency kill must be engaged")
	before := shadowSnap()
	st, rk := toolsCall(t, r.cli, r.base, r.inToken, r.sid, "6", toolEcho, `{"text":"z"}`)
	// resultOf returns the result object directly, or (for the emergency block) the whole
	// error envelope. A killed node must emit the DETERMINISTIC emergency-block error, never
	// a would_execute / shadow_evaluated result — assert the exact envelope, not just its
	// absence, so an unrelated error can't pass this drill.
	req(t, st == 200, "kill: status=%d", st)
	req(t, rk["shadow_outcome"] != "would_execute" && rk["execution_state"] != "shadow_evaluated",
		"SECURITY: killed node must not would_execute / shadow-evaluate: %v", rk)
	errObj, _ := rk["error"].(map[string]any)
	req(t, errObj != nil && errObj["message"] == "rollout_emergency_active",
		"kill: expected emergency-block error rollout_emergency_active, got %v", rk)
	after := shadowSnap()
	// Exactly one fail-closed evaluation error and NO shadow evaluation (or any other bucket).
	assertShadowDelta(t, before, after, shadowMetricsView{EvaluationErrors: 1})
	req(t, atomic.LoadInt64(r.upstreamHits) == 0, "SECURITY: upstream invoked during kill drill: %d", atomic.LoadInt64(r.upstreamHits))
	req(t, getMCPRollout().clearEmergency(rollout.CapabilityGateway) == nil, "clearEmergency failed")
	r.ev("kill drill: emergency engaged -> error=rollout_emergency_active evaluation_errors %d->%d not_would_execute no_shadow_eval upstream=0 -> kill cleared",
		before.EvaluationErrors, after.EvaluationErrors)
}

// revokeDrill — revoking the echo ToolApproval withdraws its Usable projection, so the
// same in-scope echo call now predicts would_fail_hard_control (the quarantine override).
func (r *shadowRun) revokeDrill() {
	t := r.t
	_, err := mcpToolTrust.Revoke(r.echoApproval, "admin@corp", ctrlTenant, "controlled revoke drill")
	req(t, err == nil, "Revoke: %v", err)
	mcpToolTrustReconcile()
	_, _, elig := catRec(t, r.cat, ctrlServer, toolEcho)
	req(t, elig != catalog.Usable, "revoked tool must lose Usable projection, got %v", elig)
	before := shadowSnap()
	preIDs := committedShadowEventIDs(t)
	st, rr := toolsCall(t, r.cli, r.base, r.inToken, r.sid, "7", toolEcho, `{"text":"after-revoke"}`)
	req(t, st == 200, "post-revoke call: status=%d", st)
	req(t, rr["shadow_outcome"] == "would_fail_hard_control",
		"revoked/quarantined tool must predict would_fail_hard_control, got %v", rr)
	after := shadowSnap()
	assertShadowDelta(t, before, after, shadowMetricsView{Evaluations: 1, WouldFailHardControl: 1})
	// A durable schema-v2 event must exist for THIS would_fail_hard_control evaluation.
	de, ok := newShadowEvidence(t, preIDs)
	req(t, ok && de.Shadow.Outcome == "would_fail_hard_control" && de.VerifyDigest() && de.Validate() == nil,
		"revoke: a durable schema-v2 would_fail_hard_control event must be committed, got ok=%v %+v", ok, de.Shadow)
	r.ev("revocation drill: approval revoked -> eligibility!=Usable -> echo shadow_outcome=would_fail_hard_control would_fail_hard_control %d->%d durable_outcome=%s",
		before.WouldFailHardControl, after.WouldFailHardControl, de.Shadow.Outcome)
}

// rollbackToObserve — a signed mode=Observe envelope returns the node to Observe; a
// subsequent in-scope call is Observe (not shadow) and the live executor stays absent.
func (r *shadowRun) rollbackToObserve() {
	t := r.t
	r.applyGateway(mcpObserveRollout(rollout.CapabilityGateway))
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeObserve, "rollback failed: mode=%s", getMCPRollout().gateway.CurrentMode())
	_ = approveToUsable(t, r.cat, ctrlServer, toolEcho) // re-approve so Usable, to prove Observe (not shadow)
	before := shadowSnap()
	st, rrb := toolsCall(t, r.cli, r.base, r.inToken, r.sid, "8", toolEcho, `{"text":"post-rollback"}`)
	req(t, st == 200, "post-rollback call: status=%d", st)
	// Assert the EXACT Observe outcome (not merely "not shadow"): an allow-class Observe
	// decision is non-executing and reports execution_state=not_implemented.
	req(t, rrb["execution_state"] == "not_implemented", "post-rollback in-scope call must be Observe (not_implemented), got %v", rrb)
	after := shadowSnap()
	// Post-rollback Observe traffic must move NO shadow counter (full-snapshot zero delta).
	assertShadowDelta(t, before, after, shadowMetricsView{})
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must remain unarmed through rollback")
	r.ev("rollback Shadow->Observe: mode=observe post_rollback_execution_state=%v shadow_evaluations UNCHANGED live_executor=absent canary=off production=off",
		rrb["execution_state"])
}

// finalAssertions — the run-wide zero-side-effect reassertion.
func (r *shadowRun) finalAssertions() {
	req(r.t, atomic.LoadInt64(r.upstreamHits) == 0, "SECURITY: controlled upstream observed %d invocations across the run", atomic.LoadInt64(r.upstreamHits))
	fin := shadowSnap()
	r.assertOperatorObservability(fin)
	r.ev("FINAL: controlled_upstream_invocations=0 shadow_evaluations=%d would_execute=%d would_block=%d evaluation_errors=%d live_executions=0 materializations=0",
		fin.Evaluations, fin.WouldExecute, fin.WouldBlock, fin.EvaluationErrors)
	r.ev("VERDICT-INPUT: all controlled Shadow safety invariants observed at runtime")
}

// assertOperatorObservability proves the Shadow evaluation counts are visible on the
// ACTUAL operator-facing surfaces — the /metrics fan-out serializer (writeMCPShadowMetrics,
// the exact function metrics.go invokes) and the status map (mcpShadowStatus) — not merely
// in the internal mcpShadowMetrics singleton that shadowSnap() reads. A broken serializer
// (the culvert_mcp_shadow_* rows dropped, or the status "metrics" field detached from the
// live counters) would pass every shadowSnap()-based assertion in this harness yet FAIL
// here, which is exactly the gap this closes (the metrics+status exit criterion in
// docs/operator/mcp-shadow-activation.md). It calls only existing production serializers;
// it composes nothing and changes no posture.
func (r *shadowRun) assertOperatorObservability(fin shadowMetricsView) {
	t := r.t
	// (1) The real /metrics fan-out serialization for the culvert_mcp_shadow_* series. The
	// singleton is a process-global accumulator (never reset between tests — the per-phase
	// assertions above use before/after deltas for exactly this reason), so the operator
	// rows are asserted against fin's live ABSOLUTE values, not run-local constants: a
	// serializer that dropped a row, mislabeled it, or read a stale/other source diverges
	// from fin and fails here. Rows are PARSED (exact integer + uniqueness), never
	// prefix-matched, so an emitted "10" can never satisfy an expected "1" and a
	// contradictory duplicate is caught rather than masked.
	var b strings.Builder
	writeMCPShadowMetrics(&b)
	outcomes, evalErrors, errSeen := shadowMetricRows(t, b.String())
	req(t, errSeen == 1, "operator /metrics must emit exactly one evaluation_errors row, saw %d", errSeen)
	want := map[string]int64{
		"would_execute":                   fin.WouldExecute,
		"would_block":                     fin.WouldBlock,
		"would_require_approval":          fin.WouldRequireApproval,
		"would_require_confirmation":      fin.WouldRequireConfirmation,
		"would_fail_credential_readiness": fin.WouldFailCredential,
		"would_fail_inspection":           fin.WouldFailInspection,
		"would_fail_stale_decision":       fin.WouldFailStale,
		"would_fail_hard_control":         fin.WouldFailHardControl,
		"other":                           fin.WouldOther,
	}
	req(t, len(outcomes) == len(want), "operator /metrics outcome row count=%d want=%d rows=%v", len(outcomes), len(want), outcomes)
	for oc, n := range want {
		got, ok := outcomes[oc]
		req(t, ok, "operator /metrics missing outcome=%q row (rows=%v)", oc, outcomes)
		req(t, got == n, "operator /metrics outcome=%q = %d, want live counter %d", oc, got, n)
	}
	req(t, evalErrors == fin.EvaluationErrors, "operator /metrics evaluation_errors=%d, want live counter %d", evalErrors, fin.EvaluationErrors)

	// (2) The operator status map: its bounded "metrics" snapshot must EQUAL the live
	// counters (proving the status surface reads the same singleton, not a stale copy),
	// and its posture booleans must report shadow-composed / live-execution-unarmed.
	st := mcpShadowStatus()
	req(t, st["evaluator_composed"] == true, "status evaluator_composed must be true, got %v", st["evaluator_composed"])
	req(t, st["live_execution_ready"] == false, "status live_execution_ready must be false, got %v", st["live_execution_ready"])
	sv, ok := st["metrics"].(shadowMetricsView)
	req(t, ok, "status metrics must be a shadowMetricsView, got %T", st["metrics"])
	req(t, sv == fin, "status metrics snapshot must equal the final counters: status=%+v final=%+v", sv, fin)
	// The full three-state health the operator surface reports must be asserted, not merely
	// surfaced: Shadow evaluator healthy (requested+composed reason, shadow tier armed, and the
	// node-readiness PREFLIGHT actually Ready with no reasons) AND live execution unarmed
	// (already checked above). A regression that made the reported preflight/Observe posture
	// incorrect would otherwise pass this gate.
	req(t, st["requested"] == true, "status requested must be true, got %v", st["requested"])
	req(t, st["reason"] == "composed", "status reason must be \"composed\", got %v", st["reason"])
	req(t, st["shadow_deps_ready"] == true, "status shadow_deps_ready must be true, got %v", st["shadow_deps_ready"])
	pf, ok := st["preflight"].(shadowPreflightResult)
	req(t, ok, "status preflight must be a shadowPreflightResult, got %T", st["preflight"])
	req(t, pf.Ready && len(pf.Reasons) == 0,
		"status preflight must report Ready with no reasons (node is able to evaluate Shadow), got %+v", pf)
	r.ev("operator observability: /metrics culvert_mcp_shadow_* rows parsed 1:1 == live singleton (evaluations=%d would_execute=%d would_block=%d would_fail_hard_control=%d other=%d evaluation_errors=%d); status three-state: evaluator_composed=true shadow_deps_ready=true reason=composed preflight.Ready=true live_execution_ready=false; status.metrics==singleton",
		fin.Evaluations, fin.WouldExecute, fin.WouldBlock, fin.WouldFailHardControl, fin.WouldOther, fin.EvaluationErrors)
}

var (
	shadowEvalRowRE = regexp.MustCompile(`^culvert_mcp_shadow_evaluations_total\{capability="gateway",outcome="([^"]+)"\} (\d+)$`)
	shadowErrRowRE  = regexp.MustCompile(`^culvert_mcp_shadow_evaluation_errors_total\{capability="gateway"\} (\d+)$`)
)

// shadowMetricRows parses the culvert_mcp_shadow_* exposition text into the outcome->count
// map and the evaluation_errors count, and returns how many evaluation_errors rows were
// seen. It matches COMPLETE, anchored samples (never prefixes), fails on a duplicate
// outcome row, and fails on any culvert_mcp_shadow_ line that matches NEITHER anchored
// form (a mislabeled/extra sample) — so a scaling, formatting, duplicate, or mislabel
// regression cannot survive behind an exact-equality claim (Codex P2 on 5825cc4). HELP/TYPE
// (#) lines are ignored.
func shadowMetricRows(t *testing.T, text string) (outcomes map[string]int64, evalErrors int64, evalErrorsSeen int) {
	t.Helper()
	outcomes = map[string]int64{}
	for _, ln := range strings.Split(text, "\n") {
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if m := shadowEvalRowRE.FindStringSubmatch(ln); m != nil {
			n, err := strconv.ParseInt(m[2], 10, 64)
			req(t, err == nil, "unparsable evaluations count in %q: %v", ln, err)
			_, dup := outcomes[m[1]]
			req(t, !dup, "duplicate operator /metrics row for outcome=%q:\n%s", m[1], text)
			outcomes[m[1]] = n
			continue
		}
		if m := shadowErrRowRE.FindStringSubmatch(ln); m != nil {
			n, err := strconv.ParseInt(m[1], 10, 64)
			req(t, err == nil, "unparsable evaluation_errors count in %q: %v", ln, err)
			evalErrors = n
			evalErrorsSeen++
			continue
		}
		// A culvert_mcp_shadow_ line matching neither anchored form is a serializer
		// regression (mislabel/extra sample) and must fail rather than be silently ignored.
		req(t, !strings.HasPrefix(ln, "culvert_mcp_shadow_"), "unrecognized culvert_mcp_shadow_ row (possible mislabel/format regression):\n%q", ln)
	}
	return outcomes, evalErrors, evalErrorsSeen
}

// TestMCPShadowMetricsSerializationDistinct pins the operator /metrics serializer's
// label->value MAPPING with DISTINCT per-outcome counts (1..9) plus a distinct
// evaluation_errors count. In the controlled run the exercised outcomes are all 1 and the
// rest 0, so a serializer that emitted one outcome's count under another label — or
// permuted the zero-valued rows — would still produce every expected string; here every
// outcome carries a unique value, so any label permutation changes at least one parsed row
// and fails (Codex P2 on 5825cc4). It swaps in a fresh process-global metrics singleton
// (the serializer reads the global) and restores it, so it is order-independent under
// -shuffle/-count.
func TestMCPShadowMetricsSerializationDistinct(t *testing.T) {
	prev := globalMCPShadowMetrics
	t.Cleanup(func() { globalMCPShadowMetrics = prev })
	m := &mcpShadowMetrics{}
	globalMCPShadowMetrics = m

	seed := []struct {
		outcome string
		n       int
	}{
		{"would_execute", 1},
		{"would_block", 2},
		{"would_require_approval", 3},
		{"would_require_confirmation", 4},
		{"would_fail_credential_readiness", 5},
		{"would_fail_inspection", 6},
		{"would_fail_stale_decision", 7},
		{"would_fail_hard_control", 8},
		{"__unknown_outcome__", 9}, // routes to the fail-safe "other" bucket
	}
	for _, s := range seed {
		for i := 0; i < s.n; i++ {
			m.ObserveShadowOutcome("gateway", s.outcome)
		}
	}
	const wantErrs = 11
	for i := 0; i < wantErrs; i++ {
		m.ObserveBlock("gateway", mcperr.ReasonUpstreamCallFailed) // evaluation_errors path
	}

	var b strings.Builder
	writeMCPShadowMetrics(&b)
	outcomes, evalErrors, errSeen := shadowMetricRows(t, b.String())
	req(t, errSeen == 1, "expected exactly one evaluation_errors row, saw %d", errSeen)

	want := map[string]int64{
		"would_execute": 1, "would_block": 2, "would_require_approval": 3,
		"would_require_confirmation": 4, "would_fail_credential_readiness": 5,
		"would_fail_inspection": 6, "would_fail_stale_decision": 7,
		"would_fail_hard_control": 8, "other": 9,
	}
	req(t, len(outcomes) == len(want), "serializer outcome row count=%d want=%d rows=%v", len(outcomes), len(want), outcomes)
	for oc, n := range want {
		got, ok := outcomes[oc]
		req(t, ok, "serializer missing outcome=%q (rows=%v)", oc, outcomes)
		req(t, got == n, "serializer label->value mismatch: outcome=%q = %d, want %d", oc, got, n)
	}
	req(t, evalErrors == wantErrs, "serializer evaluation_errors=%d, want %d", evalErrors, wantErrs)
}

// resetShadowGlobalsForRun resets the process-global singletons a controlled run touches
// and restores them on cleanup (a fresh process starts with these empty).
func resetShadowGlobalsForRun(t *testing.T) {
	t.Helper()
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
}

// composeAndStartShadow builds the controlled files, runs the real observe+shadow
// startup, starts the listener, and asserts the pre-activation posture. Returns the
// runtime, activation, published catalog, and base URL.
func composeAndStartShadow(t *testing.T, pki *mcpTestPKI, hits *int64, ev func(string, ...any)) (act mcpObserveActivation, cat *catalog.Catalog, base string) {
	t.Helper()
	_, endpoint := witnessEndpoint(t, hits)
	invPath := writeInv(t, controlledInventoryJSON(endpoint))
	polPath := writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule))
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
	base = "https://" + rt.Addr(false)
	ev("pre-activation: shadow_mode=NO shadow_evaluator_composed=YES live_executor_composed=NO shadow_deps_ready=%v live_execution_ready=%v reason=%q",
		shadowDepsConfigured(false), liveExecDepsConfigured(false), globalMCPShadow.Reason())
	ev("gateway listener LIVE and serving at %s (real TLS+OAuth)", base)
	return act, cat, base
}

// promoteControlledTools composes tool-trust and drives the REAL approval path to promote
// both controlled tools to catalog.Usable. Returns the echo approval id + fingerprint.
func promoteControlledTools(t *testing.T, cat *catalog.Catalog, ev func(string, ...any)) (echoApproval string) {
	t.Helper()
	initMCPToolTrust(nil)
	echoFP, _, elig := catRec(t, cat, ctrlServer, toolEcho)
	req(t, elig == catalog.Quarantined, "precondition: %s must ingest Quarantined, got %v", toolEcho, elig)
	echoApproval = approveToUsable(t, cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, cat, ctrlServer, toolDanger)
	_, _, elig = catRec(t, cat, ctrlServer, toolEcho)
	req(t, elig == catalog.Usable, "%s must be Usable after approval, got %v", toolEcho, elig)
	ev("tool trust: approval=%s purpose=shadow_evaluation tool=%s/%s fingerprint=%s eligibility=Usable", echoApproval, ctrlServer, toolEcho, echoFP)
	return echoApproval
}

// activate performs the signed Observe->Shadow transition for the controlled scope and
// asserts the node is genuinely in Shadow with distribution active.
func (r *shadowRun) activate(scope rollout.ScopeSpec) {
	r.inToken = mintBearerSub(r.t, r.pki, r.audience, ctrlTenant, ctrlPrincip)
	r.applyGateway(&rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: scope,
	})
	req(r.t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "activation failed: mode=%s (want shadow)", getMCPRollout().gateway.CurrentMode())
	req(r.t, getMCPRollout().gateway.Evidence().ShadowStartUnix != 0, "Shadow window must be stamped on activation")
	req(r.t, globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway).Active() != nil, "distribution must be active after a committed Shadow activation")
	r.ev("ACTIVATED Observe->Shadow: mode=shadow shadow_window_stamped=true distribution_active=true canary=off production=off live_exec_ready=%v", liveExecDepsConfigured(false))
}

// newControlledShadowRun performs the whole setup: distribution + rollout composition,
// the real observe+shadow startup, tool-trust promotion, the genuine activation preflight,
// and the signed Observe->Shadow activation. It returns the ready run context.
func newControlledShadowRun(t *testing.T, hits *int64) *shadowRun {
	t.Helper()
	ev := func(format string, a ...any) { t.Logf("EVIDENCE | "+format, a...) }

	signer, dataDirPath := mcpProdSetup(t) // dataDir set, DP appliers composed, fresh rollout
	ev("baseline main SHA is the run baseline; dataDir=%s", dataDirPath)
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeDisabled, "baseline gateway mode must be Disabled, got %s", getMCPRollout().gateway.CurrentMode())
	req(t, !liveExecDepsConfigured(false), "baseline: live-execution deps must be UNconfigured")
	ev("baseline: gateway_mode=disabled canary=off production=off live_exec_ready=false")

	pki := newMCPTestPKI(t)
	act, cat, base := composeAndStartShadow(t, pki, hits, ev)
	echoApproval := promoteControlledTools(t, cat, ev)

	scope := controlledScope()
	sc1, cerr := rollout.Compile(scope, 1, rollout.DefaultLimits())
	req(t, cerr == nil, "scope compile: %v", cerr)
	inSubj := rollout.Subject{Capability: rollout.CapabilityGateway, ServerID: ctrlServer, PrincipalID: ctrlPrincip, Operation: rollout.RiskWrite}
	outSubj := rollout.Subject{Capability: rollout.CapabilityGateway, ServerID: ctrlServer, PrincipalID: outsiderSub, Operation: rollout.RiskWrite}
	req(t, sc1.Contains(inSubj) && !sc1.Contains(outSubj), "scope containment wrong: in=%v out=%v", sc1.Contains(inSubj), sc1.Contains(outSubj))
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway, scope, 1)
	req(t, pf.Ready, "GENUINE activation preflight must be ready (usable tool present); reasons=%v", pf.Reasons)
	ev("preflight READY (real usable-tool gate satisfied via #1236 approval); reasons=%v", pf.Reasons)

	r := &shadowRun{
		t: t, pki: pki, cli: pki.mtlsClient(t, false), base: base, audience: act.CanonicalURL,
		cat: cat, signer: signer, echoApproval: echoApproval, upstreamHits: hits, cfgRev: 1, ev: ev,
	}
	r.activate(scope)
	return r
}

// TestFirstControlledShadowRun is the controlled activation experiment.
func TestFirstControlledShadowRun(t *testing.T) {
	var upstreamHits int64
	resetShadowGlobalsForRun(t)
	r := newControlledShadowRun(t, &upstreamHits)
	r.firstRequestWouldExecute()
	r.matrixWouldBlock()
	r.outOfScopeContainment()
	r.killDrill()
	r.revokeDrill()
	r.rollbackToObserve()
	r.finalAssertions()
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
func composeShadowNode(t *testing.T, pki *mcpTestPKI, invPath, polPath string, telCfg mcpTelemetryStartupConfig) (rt *mcpruntime.Runtime, cat *catalog.Catalog, act mcpObserveActivation) {
	t.Helper()
	sc := scWithInventory(t, pki, invPath)
	sc.SenderConstraint = "bearer"
	sc.ClientCertMode = "none"
	sc.Telemetry = telCfg
	sc.QualificationPolicyFile = polPath
	var cfg mcpruntime.Config
	cfg, act = loadMCPObserveRuntime(sc)
	req(t, act.State == mcpObserveConfigured, "compose: state=%q reason=%q", act.State, act.Reason)
	// STRUCTURAL zero-side-effect proof (the primary guarantee; the upstream witness is only
	// auxiliary): the composed executor MUST be the non-executing *execution.ShadowEvaluator,
	// which structurally holds no UpstreamCaller and no materialize-capable broker (Layer B),
	// and MUST NOT be the live *execution.Executor. So Shadow cannot dial an upstream or
	// materialize a credential regardless of any endpoint/transport wiring.
	_, isShadow := cfg.Deps.Executor.(*execution.ShadowEvaluator)
	req(t, isShadow, "compose: executor must be the non-executing *execution.ShadowEvaluator, got %T", cfg.Deps.Executor)
	_, isLive := cfg.Deps.Executor.(*execution.Executor)
	req(t, !isLive, "SECURITY: the live *execution.Executor must never be composed for Shadow")
	setMCPObserveStatus(act)
	var err error
	rt, err = mcpruntime.NewRuntime(cfg)
	req(t, err == nil, "NewRuntime: %v", err)
	req(t, rt.Start() == nil, "Start failed")
	mcpRuntime = rt
	req(t, liveGatewayListenerReady(), "compose: gateway listener must be live")
	_, cat = mcpInventory.sharedInventory()
	return rt, cat, act
}

// TestControlledShadowRestartDrill proves the restart survival contract (§17): after a
// clean restart of the controlled node, Shadow state restores, the approval store
// recovers, the exact tool is re-derived Usable, the SAME schema-v2 evidence record
// recovers from the spool, the LiveExecutor remains absent, and a fresh in-scope request
// is still shadow_evaluated with zero upstream invocations.
func TestControlledShadowRestartDrill(t *testing.T) {
	ev := func(format string, a ...any) { t.Logf("EVIDENCE | "+format, a...) }
	var upstreamHits int64
	resetShadowGlobalsForRun(t)

	signer, dir := mcpProdSetup(t)
	env := &restartEnv{
		t: t, signer: signer, pki: newMCPTestPKI(t), telCfg: stableTelemetry(dir),
		hits: &upstreamHits, ev: ev,
	}
	env.cli = env.pki.mtlsClient(t, false)
	_, endpoint := witnessEndpoint(t, &upstreamHits)
	env.invPath = writeInv(t, controlledInventoryJSON(endpoint))
	env.polPath = writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule))

	preRestartID := env.boot1CommitEvent()
	simulateProcessRestart(t)
	env.boot2VerifyRecovery(preRestartID)
}

// restartEnv bundles the handles the two boots of the restart drill share.
type restartEnv struct {
	t                *testing.T
	signer           cpdp.Signer
	pki              *mcpTestPKI
	cli              *http.Client
	invPath, polPath string
	telCfg           mcpTelemetryStartupConfig
	hits             *int64
	ev               func(string, ...any)
}

// boot1CommitEvent composes+activates Shadow, commits one identifiable schema-v2 event,
// then cleanly shuts the node down. Returns the committed event id.
func (e *restartEnv) boot1CommitEvent() string {
	t := e.t
	rt1, cat1, act1 := composeShadowNode(t, e.pki, e.invPath, e.polPath, e.telCfg)
	tel1 := sharedTelemetry()
	initMCPToolTrust(nil)
	_ = approveToUsable(t, cat1, ctrlServer, toolEcho)
	_, _, elig := catRec(t, cat1, ctrlServer, toolEcho)
	req(t, elig == catalog.Usable, "boot#1: echo must be Usable, got %v", elig)
	rc := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: 1, ConnectorMode: rollout.ConnectorLocalClient, Scope: controlledScope(),
	}
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, e.signer, 2, rc)})
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "boot#1: activation failed, mode=%s", getMCPRollout().gateway.CurrentMode())
	tok := mintBearerSub(t, e.pki, act1.CanonicalURL, ctrlTenant, ctrlPrincip)
	sid := handshake(t, e.cli, "https://"+rt1.Addr(false), ctrlServer, tok)
	preIDs := committedShadowEventIDs(t)
	st, r := toolsCall(t, e.cli, "https://"+rt1.Addr(false), tok, sid, "10", toolEcho, `{"text":"pre-restart"}`)
	req(t, st == 200 && r["shadow_outcome"] == "would_execute", "boot#1: pre-restart shadow call must be would_execute, got %v", r)
	de1, ok := newShadowEvidence(t, preIDs)
	req(t, ok && de1.EventID != "", "boot#1: an identifiable schema-v2 event must be committed before restart")
	e.ev("restart boot#1: Shadow ACTIVE, echo Usable, committed schema-v2 event id=%s under durable dataDir", de1.EventID)
	req(t, rt1.Shutdown(ctxWithTimeout(t)) == nil, "shutdown boot#1 failed")
	_ = tel1.Close(context.Background())
	return de1.EventID
}

// boot2VerifyRecovery re-composes the node against the SAME dataDir and proves Shadow
// state, the approval store, the exact evidence record, and zero side effects recover.
func (e *restartEnv) boot2VerifyRecovery(preRestartID string) {
	t := e.t
	rt2, cat2, act2 := composeShadowNode(t, e.pki, e.invPath, e.polPath, e.telCfg)
	tel2 := sharedTelemetry()
	req(t, tel2 != nil, "boot#2: telemetry (evidence spool) must recover")
	t.Cleanup(func() {
		_ = rt2.Shutdown(ctxWithTimeout(t))
		_ = tel2.Close(context.Background())
		// UN-PUBLISH, not just close. Closing the runtime leaves mcpTelem.rt pointing at
		// it, so every later test in the process sees telemetry as "ready" and
		// getMCPAdmin() (a sync.Once singleton) wires its decision source to a CLOSED
		// spool whose directory is already gone — GET /api/mcp/decisions then answers 400
		// where the dormant default answers 200. Every other compose site un-publishes;
		// this one closed and stopped, which is why the leak reached the end of the run.
		// The singleton reset is the second half: un-publishing cannot un-wire a
		// singleton that was already built.
		publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
		resetMCPAdminSingleton()
	})
	initMCPToolTrust(nil)
	_, _, elig := catRec(t, cat2, ctrlServer, toolEcho)
	req(t, elig == catalog.Usable, "boot#2: approval store must recover and re-derive echo Usable, got %v", elig)
	// Mirror the PRODUCTION startup order (main.go: initMCPToolTrust -> initMCPRollout
	// [restore] -> initMCPDistribution). restore() runs the Shadow activation preflight
	// (incl. the restore-clamp) against the ORIGINAL persisted rollout file BEFORE
	// distribution composition re-commits any state, so a genuine restore/clamp failure
	// cannot be masked by a distribution-driven re-commit.
	getMCPRollout().restore()
	initMCPDistribution(nil)
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeShadow, "SECURITY/CONTRACT: Shadow must survive restart, mode=%s", getMCPRollout().gateway.CurrentMode())
	req(t, shadowEventByIDPresent(t, preRestartID), "boot#2: the SAME schema-v2 evidence record (id=%s) must recover from the spool", preRestartID)
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must remain absent across restart")
	req(t, atomic.LoadInt64(e.hits) == 0, "SECURITY: upstream invoked during restart/reconciliation: %d", atomic.LoadInt64(e.hits))
	e.ev("restart boot#2: Shadow RESTORED (mode=shadow) approval_store_recovered=true echo_reDerived=Usable evidence_record_recovered(id=%s)=true live_executor=absent upstream=0", preRestartID)

	tok := mintBearerSub(t, e.pki, act2.CanonicalURL, ctrlTenant, ctrlPrincip)
	sid := handshake(t, e.cli, "https://"+rt2.Addr(false), ctrlServer, tok)
	st, r := toolsCall(t, e.cli, "https://"+rt2.Addr(false), tok, sid, "11", toolEcho, `{"text":"post-restart"}`)
	req(t, st == 200, "post-restart call: status=%d", st)
	req(t, r["execution_state"] == "shadow_evaluated" && r["executed"] == false && r["shadow_outcome"] == "would_execute",
		"post-restart request must be shadow_evaluated/would_execute, got %v", r)
	req(t, atomic.LoadInt64(e.hits) == 0, "SECURITY: upstream invoked by post-restart shadow request: %d", atomic.LoadInt64(e.hits))
	e.ev("restart post-request: execution_state=shadow_evaluated executed=false shadow_outcome=would_execute upstream_invocations=0")
	e.ev("VERDICT-INPUT: restart survival + durable evidence recovery observed at runtime")
}

// simulateProcessRestart drops the in-memory singletons a fresh process would start
// without, leaving only the durable on-disk state under the same dataDir.
func simulateProcessRestart(t *testing.T) {
	publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	mcpPolicy.resetForTest() // a fresh process re-composes policy from file (avoids non-advancing-revision reject)
	resetMCPToolTrustForTest()
	globalMCPShadow.composed.Store(false)
	globalMCPShadow.inspectionComposed.Store(false)
	globalExecDeps.shadowGateway.Store(false)
	mcpResetGlobals(t)
	mcpRuntime = nil
}
