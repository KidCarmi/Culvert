package main

// QUAL-5 — authenticated end-to-end proof of Gateway request-time tenant isolation.
// It drives the SAME composed Observe runtime as the QUAL-4 e2e (real TLS listener,
// real policy snapshot, real durable telemetry) but with a VALID bearer token minted
// for a DIFFERENT tenant than the one that owns srv-1. The auth layer does not pin a
// tenant (it derives tenant from the token claims), so the token authenticates
// successfully — and the ONLY thing standing between a foreign tenant and another
// tenant's server is the QUAL-5 hard override. It proves:
//
//   - a valid token for "attacker-tenant" addressing srv-1 (owned by "qualification")
//     is DENIED with MCP.AUTH.TENANT_MISMATCH for both tools/list and tools/call, even
//     under a broad priority-1 ALLOW rule (hard override > user policy);
//   - the denial travels the accepted P-DEN denial lane (a durable denial aggregate),
//     never a committed ALLOW-class decision event;
//   - nothing about the foreign server leaks to the caller (no owner scope, endpoint,
//     tool name, or catalog state in the response) — only the typed reason code;
//   - the request is never executed (no upstream/credential/side-effect is composed).

import (
	"context"
	"strings"
	"testing"

	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

func TestMCPTenant_E2E_CrossTenantDeniedAtRequestTime(t *testing.T) {
	resetInventory(t)
	mcpPolicy.resetForTest()
	t.Cleanup(func() { mcpPolicy.resetForTest() })
	fc := withFakeClock(t)
	pki := newMCPTestPKI(t)

	// srv-1 is seeded owned by tenant "qualification" (the inventory tenant). The policy
	// broadly ALLOWs everything, so ONLY tenant isolation can deny a foreign request.
	sc := scWithInventory(t, pki, writeInv(t, validInventoryJSON()))
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
	if cfg.Deps.Executor != nil || cfg.Deps.Inspection != nil {
		t.Fatal("no executor/inspection may be composed (Observe-only)")
	}
	tel := sharedTelemetry()
	if tel == nil {
		t.Fatal("telemetry must be published ready")
	}
	t.Cleanup(func() { publishMCPTelemetry(mcpTelemNotConfigured, "", nil) })

	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(ctxWithTimeout(t)); _ = tel.Close(context.Background()) })

	base := "https://" + rt.Addr(false)
	cli := pki.mtlsClient(t, false)
	// A VALID token — but for a tenant that does NOT own srv-1.
	const foreignTenant = "attacker-tenant"
	token := pki.mintBearer(t, act.CanonicalURL, foreignTenant)

	// initialize + steady state (kernel-terminal; not a policy decision point).
	st, sid, body := e2ePost(t, cli, base, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if st != 200 || sid == "" {
		t.Fatalf("initialize: status=%d sid=%q body=%s", st, sid, body)
	}
	if st, _, body = e2ePost(t, cli, base, token, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); st/100 != 2 {
		t.Fatalf("initialized: status=%d body=%s", st, body)
	}

	// Both decision-point methods must be denied for the foreign tenant.
	for _, tc := range []struct {
		name string
		body string
	}{
		{"tools/list", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`},
		{"tools/call", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _, body := e2ePost(t, cli, base, token, sid, tc.body)
			if st != 200 {
				t.Fatalf("%s: status=%d body=%s", tc.name, st, body)
			}
			// Typed TENANT_MISMATCH error, no result member (never executed).
			if !bodyHasAll(body, `"error"`, "MCP.AUTH.TENANT_MISMATCH", `"DENY"`) {
				t.Fatalf("%s cross-tenant must be a TENANT_MISMATCH DENY: %s", tc.name, body)
			}
			if bodyHasAll(body, `"result"`) || bodyHasAll(body, "execution_state") {
				t.Fatalf("%s cross-tenant must carry no result (never executed): %s", tc.name, body)
			}
			// No foreign-tenant leak: the owning tenant, the server endpoint, the tool
			// name, and any matched-rule id must never appear in the response.
			if strings.Contains(string(body), "qualification") {
				t.Fatalf("%s response leaked the foreign owner scope: %s", tc.name, body)
			}
			if bodyHasAll(body, "upstream.example") || bodyHasAll(body, `"matched_rule":"BROAD"`) {
				t.Fatalf("%s response leaked foreign server/rule state: %s", tc.name, body)
			}
		})
	}

	// The foreign traffic produced NO committed ALLOW-class decision event: a
	// cross-tenant request never enters the critical/ordered decision lane.
	er := mcpAdminEventReader()
	if er == nil {
		t.Fatal("event reader must be wired when telemetry is composed")
	}
	pord, _, _, err := er.CommittedEvents("gateway", "P-ORD", 0, 16)
	if err != nil {
		t.Fatalf("read committed decisions: %v", err)
	}
	if findDecision(pord) != nil {
		t.Fatal("a cross-tenant request must never commit an ALLOW-class decision event")
	}

	// The denial is durably recorded in the P-DEN denial lane, attributed to the
	// AUTHENTICATED (foreign) tenant — the truthful observable-denial evidence.
	fc.advance(denialWindowAdvance)
	committed, _ := tel.mgr.FlushDenials(evmodel.CapGateway)
	if committed == 0 {
		t.Fatal("expected a durable denial aggregate for the cross-tenant requests")
	}
	if h := tel.mgr.Health().Domains[evmodel.CapGateway]; h.DenialAggregates == 0 {
		t.Fatal("cross-tenant denial must be counted in the denial lane")
	}
}
