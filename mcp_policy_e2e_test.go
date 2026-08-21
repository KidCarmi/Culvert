package main

// QUAL-4 — authenticated end-to-end proof that a composed node-local policy is
// EVALUATED against a real request and produces truthful, durable, NON-EXECUTING
// decision evidence. It drives a real listener over TLS with a valid bearer token and
// proves:
//
//   - an authenticated discovery request (tools/list) reaches real policy evaluation,
//     the ALLOW-class decision is durably committed to the encrypted spool, is
//     readable back through the SAME EventReader the DecisionService uses, carries the
//     authenticated tenant (never a client-supplied value), the exact snapshot hash +
//     policy revision, and the response is execution_state=not_implemented (the
//     evaluated ALLOW never executes — no upstream/credential/side-effect);
//   - a tools/call on a quarantined seeded tool is hard-QUARANTINEd BEFORE the broad
//     user ALLOW rule (hard override > user policy), routed to the denial lane, and
//     still non-executing;
//   - Gateway traffic never produces a Management decision (capability isolation).

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mintBearer mints a valid ES256 gateway bearer token for the given audience/tenant.
// Real wall-clock validity: the listener validates the token against time.Now (the
// package-main runtime injects no fixed clock).
func (p *mcpTestPKI) mintBearer(t *testing.T, aud, tenant string) string {
	t.Helper()
	now := time.Now()
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid})
	cb, _ := json.Marshal(map[string]any{
		"iss": p.issuer, "sub": "user-1", "client_id": "client-gw",
		"aud": aud, "scope": "gateway.tools.call", "tenant": tenant,
		// Short lifetime — the capability config bounds MaxTokenTTL (a 10-minute token
		// mirrors the runtime test fixtures and stays under the ceiling).
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

// e2ePost issues one authenticated MCP POST to srv-1 carrying the session (when set)
// and returns the status, the returned session id, and the body.
func e2ePost(t *testing.T, cli *http.Client, base, token, sid, body string) (int, string, []byte) {
	t.Helper()
	req := mcpObserveReq(t, "POST", base+"/mcp/gateway/srv-1", body)
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

// e2ePostAdversarialTenant is e2ePost plus a client-supplied tenant in BOTH the query
// string and a header. The runtime derives tenant only from the validated token, so
// both must be ignored — proven by the caller asserting the decision event's tenant is
// the authenticated value, not "attacker-tenant".
func e2ePostAdversarialTenant(t *testing.T, cli *http.Client, base, token, sid, body string) (int, string, []byte) {
	t.Helper()
	req := mcpObserveReq(t, "POST", base+"/mcp/gateway/srv-1?tenant=attacker-tenant", body)
	req.Host = "gw.test"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("X-Tenant", "attacker-tenant")
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

func TestMCPPolicy_E2E_AuthenticatedDecisionObserveOnly(t *testing.T) {
	resetInventory(t)
	mcpPolicy.resetForTest()
	t.Cleanup(func() { mcpPolicy.resetForTest() })
	fc := withFakeClock(t)
	pki := newMCPTestPKI(t)

	// Compose inventory (srv-1 + quarantined tool "echo") + telemetry + a policy that
	// ALLOWs discovery and broadly ALLOWs everything (to prove the hard override wins).
	sc := scWithInventory(t, pki, writeInv(t, validInventoryJSON()))
	// Plain bearer posture isolates the POLICY behavior from sender-binding: the
	// qualification mTLS posture is covered by the QUAL-1 auth tests.
	sc.SenderConstraint = "bearer"
	sc.ClientCertMode = "none"
	sc.Telemetry = telemetryConfigAt(t)
	sc.QualificationPolicyFile = writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule+","+broadAllowRule))

	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q", act.State, act.Reason)
	}
	if cfg.Deps.Policy == nil || cfg.Deps.Events == nil {
		t.Fatal("policy + telemetry must both be composed")
	}
	// Observe-only remains structural.
	if cfg.Deps.Executor != nil || cfg.Deps.Inspection != nil {
		t.Fatal("no executor/inspection may be composed (Observe-only)")
	}
	// Decision telemetry now truthfully reports ready (policy + telemetry composed).
	if st := mcpTelemetryStatus(); st.DecisionTelemetry != "ready" {
		t.Fatalf("decision telemetry = %q, want ready", st.DecisionTelemetry)
	}
	tel := sharedTelemetry()
	if tel == nil {
		t.Fatal("telemetry must be published ready")
	}
	t.Cleanup(func() {
		publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	})

	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(ctxWithTimeout(t)); _ = tel.Close(context.Background()) })

	base := "https://" + rt.Addr(false)
	cli := pki.mtlsClient(t, false) // no client cert (bearer posture)
	token := pki.mintBearer(t, act.CanonicalURL, "qualification")

	// 1. initialize → 200 + a session id.
	st, sid, body := e2ePost(t, cli, base, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if st != 200 || sid == "" {
		t.Fatalf("initialize: status=%d sid=%q body=%s", st, sid, body)
	}
	// 2. notifications/initialized → steady state.
	if st, _, body = e2ePost(t, cli, base, token, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); st/100 != 2 {
		t.Fatalf("initialized: status=%d body=%s", st, body)
	}

	// 3. tools/list → reaches real policy evaluation. ALLOW-class discovery decision,
	//    non-executing (execution_state=not_implemented). The request also carries an
	//    ADVERSARIAL client-supplied tenant (query + header) that MUST be ignored — the
	//    decision tenant below is asserted to be the authenticated token tenant, never
	//    "attacker-tenant".
	st, _, body = e2ePostAdversarialTenant(t, cli, base, token, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if st != 200 {
		t.Fatalf("tools/list: status=%d body=%s", st, body)
	}
	if !bodyHasAll(body, `"execution_state"`, `"not_implemented"`) {
		t.Fatalf("discovery ALLOW must be non-executing (execution_state=not_implemented): %s", body)
	}

	// The ALLOW-class discovery decision is a durable P-ORD event. Read it back through
	// the SAME real EventReader the DecisionService uses (single source of truth).
	er := mcpAdminEventReader()
	if er == nil {
		t.Fatal("event reader must be wired when telemetry is composed")
	}
	events, _, _, err := er.CommittedEvents("gateway", "P-ORD", 0, 16)
	if err != nil {
		t.Fatalf("read committed decisions: %v", err)
	}
	dec := findDecision(events)
	if dec == nil {
		t.Fatalf("expected a durable ALLOW-class discovery decision event, got %d P-ORD events", len(events))
	}
	// Evaluated-vs-effective: the evaluated action is ALLOW-class while execution stays
	// not_implemented (the evaluated action is NOT execution authorization).
	if dec.Decision.ExecutionState != "not_implemented" {
		t.Fatalf("decision execution_state = %q, want not_implemented", dec.Decision.ExecutionState)
	}
	// Truthful evidence: exact policy revision + snapshot hash from the composed snapshot.
	gwStore, _ := mcpPolicy.stores().Store("gateway")
	snap := gwStore.Current()
	if uint64(dec.Decision.PolicyRevision) != uint64(snap.Revision()) {
		t.Fatalf("decision policy revision = %d, want %d", dec.Decision.PolicyRevision, snap.Revision())
	}
	if dec.SnapshotHash != snap.Hash() && dec.Decision.PolicySnapshotHash != snap.Hash() {
		t.Fatalf("decision snapshot hash mismatch: event=%q/%q snap=%q", dec.SnapshotHash, dec.Decision.PolicySnapshotHash, snap.Hash())
	}
	// Tenant attribution: the AUTHENTICATED tenant (from the validated token). The
	// tools/list request above injected a client-supplied tenant ("attacker-tenant") in
	// both the query string and a header; the decision tenant must be the token tenant,
	// proving a client value can never replace the authenticated tenant.
	if dec.Identity.Tenant != "qualification" {
		t.Fatalf("decision tenant = %q, want qualification (authenticated, not client-supplied)", dec.Identity.Tenant)
	}
	// Capability isolation: no Management decision was produced by Gateway traffic.
	mgtEvents, _, _, _ := er.CommittedEvents("management", "P-ORD", 0, 16)
	if len(mgtEvents) != 0 {
		t.Fatalf("gateway traffic must not produce management events, got %d", len(mgtEvents))
	}

	// 4. tools/call on the quarantined tool "echo" → hard QUARANTINE BEFORE the broad
	//    user ALLOW (hard override > user policy), still non-executing. Routed to the
	//    denial lane (P-DEN) per the accepted event model.
	st, _, body = e2ePost(t, cli, base, token, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`)
	if st != 200 {
		t.Fatalf("tools/call: status=%d body=%s", st, body)
	}
	if !bodyHasAll(body, `"error"`) || bodyHasAll(body, `"execution_state":"executed"`) {
		t.Fatalf("quarantined tools/call must be rejected (never executed): %s", body)
	}
	// Flush the denial window and confirm a durable denial aggregate (with identity).
	fc.advance(denialWindowAdvance)
	committed, _ := tel.mgr.FlushDenials(evmodel.CapGateway)
	if committed == 0 {
		t.Fatal("expected a durable denial aggregate for the quarantined tools/call")
	}
	if h := tel.mgr.Health().Domains[evmodel.CapGateway]; h.DenialAggregates == 0 {
		t.Fatal("quarantine denial must be counted in the denial lane")
	}
}

// findDecision returns the first full decision event (a PhaseDecision), or nil.
func findDecision(events []evmodel.Event) *evmodel.Event {
	for i := range events {
		if events[i].Phase == evmodel.PhaseDecision {
			return &events[i]
		}
	}
	return nil
}

// bodyHasAll reports whether s contains every substring.
func bodyHasAll(s []byte, subs ...string) bool {
	str := string(s)
	for _, sub := range subs {
		if !strings.Contains(str, sub) {
			return false
		}
	}
	return true
}
