package mcpacceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// decisionsNonEmpty reports whether the /api/mcp/decisions response carries at
// least one committed decision. It tolerates either a bare array or an object with
// a "decisions"/"events" array.
func decisionsNonEmpty(body []byte) bool {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) == nil {
		return len(arr) > 0
	}
	var obj struct {
		Decisions []json.RawMessage `json:"decisions"`
		Events    []json.RawMessage `json:"events"`
	}
	if json.Unmarshal(body, &obj) == nil {
		return len(obj.Decisions) > 0 || len(obj.Events) > 0
	}
	return false
}

// pass/fail helpers keep scenario bodies terse.
func pass(observed string, ev ...string) (Status, string, string, []string) {
	return StatusPass, observed, "", ev
}
func fail(observed, reason string, ev ...string) (Status, string, string, []string) {
	return StatusFail, observed, reason, ev
}

// ── Startup ──────────────────────────────────────────────────────────────────

func (h *Harness) runStartup(ctx context.Context) {
	h.runCriterion("startup.ready", "gateway listener ready in observe posture", "startup", true,
		"gateway.runtime.state==ready, posture==observe, execution_enabled==false", func() (Status, string, string, []string) {
			hv, res := h.procA.health(ctx, h.uiClient)
			if res.status != 200 {
				return fail(fmt.Sprintf("health status %d", res.status), "health_unreachable")
			}
			r := hv.Gateway.Runtime
			if r.State == "ready" && r.ListenerReady && r.Posture == "observe" && !r.ExecutionEnabled {
				return pass("state=ready posture=observe execution_enabled=false")
			}
			return fail(fmt.Sprintf("state=%s ready=%v posture=%s exec=%v", r.State, r.ListenerReady, r.Posture, r.ExecutionEnabled), "posture_mismatch")
		})

	h.runCriterion("startup.tls_reachable", "TLS listener reachable", "startup", true,
		"TLS handshake succeeds on the MCP listener", func() (Status, string, string, []string) {
			// A bare initialize proves the TLS listener terminates and serves.
			sid, init := initSession(ctx, h.mcpBearer, h.procA.pc.mcpPort, h.fixture.serverA, h.tokenA)
			if sid != "" && init.status == 200 {
				return pass("initialize over TLS returned a session")
			}
			return fail(fmt.Sprintf("init status=%d tlsErr=%v", init.status, init.tlsError), "tls_unreachable")
		})

	h.runCriterion("startup.oauth_metadata", "protected-resource metadata reachable", "startup", true,
		"GET /.well-known/oauth-protected-resource/mcp/gateway returns 200", func() (Status, string, string, []string) {
			res := mcpGet(ctx, h.mcpBearer, h.procA.pc.mcpPort, "/.well-known/oauth-protected-resource/mcp/gateway", "gw.test")
			if res.status == 200 {
				return pass("metadata 200")
			}
			return fail(fmt.Sprintf("status %d", res.status), "metadata_unreachable")
		})

	h.runCriterion("startup.disabled_binds_nothing", "disabled config binds no MCP listener", "startup", true,
		"a disabled Gateway config reports state==disabled and binds no MCP port", func() (Status, string, string, []string) {
			return h.checkDisabledBindsNothing(ctx)
		})
}

// checkDisabledBindsNothing spins an auxiliary process with the Gateway disabled
// and asserts health==disabled and the configured MCP port is not listening.
func (h *Harness) checkDisabledBindsNothing(ctx context.Context) (Status, string, string, []string) {
	pc, err := h.fixture.buildProc("disabled", h.fixture.tenantA, h.fixture.serverA, "none", tripEndpoint(h.tripwireA))
	if err != nil {
		return fail("build aux", "aux_build")
	}
	if err := h.fixture.setEnabled(pc, false); err != nil {
		return fail("rewrite config", "aux_config")
	}
	proc, err := h.startProcessRaw(ctx, pc)
	if err != nil {
		return fail("start aux", "aux_start")
	}
	defer func() { _ = proc.stop(h.spec.Run.shutdown()) }()
	hv, res := proc.health(ctx, h.uiClient)
	if res.status != 200 || hv.Gateway.Runtime.State != "disabled" {
		return fail(fmt.Sprintf("health state=%s status=%d", hv.Gateway.Runtime.State, res.status), "not_disabled")
	}
	// The MCP port must not be accepting connections.
	dialer := net.Dialer{Timeout: h.spec.Run.request()}
	conn, derr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", pc.mcpPort))
	if derr == nil {
		_ = conn.Close()
		return fail("mcp port accepted a connection", "port_bound")
	}
	return pass("state=disabled, mcp port closed")
}

// ── TLS / mTLS ───────────────────────────────────────────────────────────────

func (h *Harness) runTLS(ctx context.Context) {
	pc, err := h.fixture.buildProc("mtls", h.fixture.tenantA, h.fixture.serverA, "require", tripEndpoint(h.tripwireA))
	if err != nil {
		h.record(CriterionResult{ID: "tls.mtls", Name: "mTLS accept/reject", Group: "tls", Required: true, Status: StatusFail, Reason: "aux_build"})
		return
	}
	proc, err := h.startProcess(ctx, pc)
	if err != nil {
		h.record(CriterionResult{ID: "tls.mtls", Name: "mTLS accept/reject", Group: "tls", Required: true, Status: StatusFail, Reason: "aux_start", Observed: err.Error()})
		return
	}
	defer func() { _ = proc.stop(h.spec.Run.shutdown()) }()

	h.runCriterion("tls.mtls_accept", "trusted client cert accepted", "tls", true,
		"mTLS with the fixture client cert reaches the auth layer", func() (Status, string, string, []string) {
			cli, err := mcpTLSClient(h.fixture.caPEM, h.fixture.clientCertFile, h.fixture.clientKeyFile, true, h.spec.Run.request())
			if err != nil {
				return fail("client build", "client")
			}
			sid, init := initSession(ctx, cli, pc.mcpPort, h.fixture.serverA, h.tokenA)
			if sid != "" && init.status == 200 {
				return pass("mTLS handshake + initialize succeeded")
			}
			return fail(fmt.Sprintf("status=%d tlsErr=%v", init.status, init.tlsError), "mtls_rejected")
		})

	h.runCriterion("tls.mtls_reject", "missing client cert rejected", "tls", true,
		"mTLS handshake without a client cert is rejected", func() (Status, string, string, []string) {
			cli, err := mcpTLSClient(h.fixture.caPEM, "", "", false, h.spec.Run.request())
			if err != nil {
				return fail("client build", "client")
			}
			res := mcpPost(ctx, cli, pc.mcpPort, h.fixture.serverA, h.tokenA, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
			if res.tlsError {
				return pass("no-client-cert handshake rejected: " + res.transportErr)
			}
			return fail(fmt.Sprintf("status=%d (expected TLS rejection)", res.status), "mtls_not_enforced")
		})
}

// ── OAuth ────────────────────────────────────────────────────────────────────

func (h *Harness) runOAuth(ctx context.Context) {
	mp := h.procA.pc.mcpPort
	sv := h.fixture.serverA
	// A valid token must reach a decision point (proves the positive path).
	h.runCriterion("oauth.valid", "valid token authenticates", "auth", true,
		"a valid Model-A token reaches policy evaluation (200)", func() (Status, string, string, []string) {
			sid, _ := initSession(ctx, h.mcpBearer, mp, sv, h.tokenA)
			if sid == "" {
				return fail("no session", "auth_failed")
			}
			res := mcpPost(ctx, h.mcpBearer, mp, sv, h.tokenA, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
			if res.status == 200 {
				return pass("tools/list reached policy (200)")
			}
			return fail(fmt.Sprintf("status %d", res.status), "auth_rejected")
		})

	negatives := []struct {
		id, name string
		token    func() string
	}{
		{"oauth.missing", "missing token rejected", func() string { return "" }},
		{"oauth.malformed", "malformed token rejected", func() string { return "not.a.jwt" }},
		{"oauth.expired", "expired token rejected", func() string {
			t, _ := mintExpired(h.fixture.signer, h.tokenParams(h.fixture.tenantA))
			return t
		}},
		{"oauth.wrong_issuer", "wrong issuer rejected", func() string {
			p := h.tokenParams(h.fixture.tenantA)
			p.issuer = "https://evil.test/issuer"
			t, _ := mintBearer(h.fixture.signer, p)
			return t
		}},
		{"oauth.wrong_audience", "wrong audience/resource rejected", func() string {
			p := h.tokenParams(h.fixture.tenantA)
			p.audience = "https://evil.test/mcp/gateway"
			t, _ := mintBearer(h.fixture.signer, p)
			return t
		}},
		{"oauth.missing_scope", "missing required scope rejected", func() string {
			p := h.tokenParams(h.fixture.tenantA)
			p.scope = "wrong.scope"
			t, _ := mintBearer(h.fixture.signer, p)
			return t
		}},
	}
	for _, n := range negatives {
		n := n
		h.runCriterion(n.id, n.name, "auth", true, "authentication is rejected (non-2xx)", func() (Status, string, string, []string) {
			tok := n.token()
			// initialize is kernel-terminal but still requires auth; a bad token must fail there.
			res := mcpPost(ctx, h.mcpBearer, mp, sv, tok, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
			if res.status >= 400 && res.status < 500 {
				return pass(fmt.Sprintf("rejected status=%d", res.status))
			}
			return fail(fmt.Sprintf("status=%d (expected 4xx)", res.status), "not_rejected")
		})
	}
}

// tokenParams returns the base minting params for a tenant.
func (h *Harness) tokenParams(tenant string) tokenParams {
	return tokenParams{
		issuer: h.fixture.issuer, clientID: h.fixture.clientID, audience: h.fixture.canonicalResource,
		scope: h.fixture.scope, tenant: tenant, subject: "user-1", kid: h.fixture.kid,
	}
}

// ── Host / Origin ────────────────────────────────────────────────────────────

func (h *Harness) runHostOrigin(ctx context.Context) {
	mp := h.procA.pc.mcpPort
	h.runCriterion("host.allowed", "allowed Host accepted", "host_origin", true,
		"a request with an allowed Host reaches auth", func() (Status, string, string, []string) {
			res := mcpPostRaw(ctx, h.mcpBearer, mp, "/mcp/gateway/"+h.fixture.serverA, h.tokenA,
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
				map[string]string{"Host": "gw.test", "Authorization": "Bearer " + h.tokenA})
			if res.status == 200 {
				return pass("allowed Host initialize 200")
			}
			return fail(fmt.Sprintf("status %d", res.status), "allowed_host_failed")
		})
	h.runCriterion("host.bad", "bad Host rejected", "host_origin", true,
		"a request with a foreign Host is rejected (403)", func() (Status, string, string, []string) {
			res := mcpPostRaw(ctx, h.mcpBearer, mp, "/mcp/gateway/"+h.fixture.serverA, h.tokenA,
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
				map[string]string{"Host": "evil.example", "Authorization": "Bearer " + h.tokenA})
			if res.status == 403 {
				return pass("bad Host 403")
			}
			return fail(fmt.Sprintf("status %d (expected 403)", res.status), "bad_host_admitted")
		})
	h.runCriterion("origin.bad", "bad Origin rejected", "host_origin", true,
		"a cross-origin request is rejected (403)", func() (Status, string, string, []string) {
			res := mcpPostRaw(ctx, h.mcpBearer, mp, "/mcp/gateway/"+h.fixture.serverA, h.tokenA,
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
				map[string]string{"Host": "gw.test", "Origin": "https://evil.example", "Authorization": "Bearer " + h.tokenA})
			if res.status == 403 {
				return pass("bad Origin 403")
			}
			// Origin policy may be permissive by config; treat a non-403 as a documented
			// non-failure only when the allowlist did not include origins.
			return fail(fmt.Sprintf("status %d (expected 403)", res.status), "bad_origin_admitted")
		})
}

// ── Protocol ─────────────────────────────────────────────────────────────────

func (h *Harness) runProtocol(ctx context.Context) {
	mp := h.procA.pc.mcpPort
	sv := h.fixture.serverA
	h.runCriterion("protocol.lifecycle", "initialize/initialized/ping accepted", "protocol", true,
		"the kernel-terminal lifecycle completes", func() (Status, string, string, []string) {
			sid, init := initSession(ctx, h.mcpBearer, mp, sv, h.tokenA)
			if sid == "" || init.status != 200 {
				return fail(fmt.Sprintf("init status %d", init.status), "lifecycle_failed")
			}
			ping := mcpPost(ctx, h.mcpBearer, mp, sv, h.tokenA, sid, `{"jsonrpc":"2.0","id":9,"method":"ping"}`)
			if ping.status == 200 {
				return pass("ping 200")
			}
			return fail(fmt.Sprintf("ping status %d", ping.status), "ping_failed")
		})
	h.runCriterion("protocol.malformed", "malformed JSON-RPC rejected", "protocol", true,
		"a malformed body is a 400", func() (Status, string, string, []string) {
			res := mcpPost(ctx, h.mcpBearer, mp, sv, h.tokenA, "", `{not valid json`)
			if res.status == 400 {
				return pass("malformed 400")
			}
			return fail(fmt.Sprintf("status %d (expected 400)", res.status), "malformed_admitted")
		})
	h.runCriterion("protocol.bad_version", "unsupported MCP version rejected", "protocol", true,
		"a present-but-unsupported MCP-Protocol-Version on a session request is a terminal 400", func() (Status, string, string, []string) {
			// initialize negotiates the version, so exercise rejection on a SESSION
			// request: a present-but-unsupported version header there is a terminal 400.
			sid, init := initSession(ctx, h.mcpBearer, mp, sv, h.tokenA)
			if sid == "" {
				return fail(fmt.Sprintf("init status %d", init.status), "init_failed")
			}
			res := mcpPostRaw(ctx, h.mcpBearer, mp, "/mcp/gateway/"+sv, h.tokenA,
				`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`,
				map[string]string{"Host": "gw.test", "Mcp-Session-Id": sid, "MCP-Protocol-Version": "1999-01-01", "Authorization": "Bearer " + h.tokenA})
			if res.status == 400 {
				return pass("unsupported version 400")
			}
			return fail(fmt.Sprintf("status %d (expected 400)", res.status), "bad_version_admitted")
		})
	h.runCriterion("protocol.oversized", "oversized body rejected", "protocol", true,
		"a body over the byte cap is rejected (413 or an early connection close)", func() (Status, string, string, []string) {
			big := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","pad":"` +
				strings.Repeat("A", 2<<20) + `"}}`
			res := mcpPost(ctx, h.mcpBearer, mp, sv, h.tokenA, "", big)
			// A clean 413, OR the server enforcing the cap by closing the connection
			// before the client finishes uploading (status 0 with a non-timeout
			// transport error) both prove the oversized body was NOT admitted. A 200 or
			// a timeout is a failure.
			if res.status == 413 {
				return pass("oversized 413")
			}
			if res.status == 0 && res.transportErr != "" && res.transportErr != "timeout" {
				return pass("oversized rejected by early close: " + res.transportErr)
			}
			return fail(fmt.Sprintf("status %d transport=%s", res.status, res.transportErr), "oversized_admitted")
		})
}

// ── Inventory ────────────────────────────────────────────────────────────────

func (h *Harness) runInventory(ctx context.Context) {
	mp := h.procA.pc.mcpPort
	h.runCriterion("inventory.known", "known server resolves", "inventory", true,
		"the seeded server resolves at the listener", func() (Status, string, string, []string) {
			sid, init := initSession(ctx, h.mcpBearer, mp, h.fixture.serverA, h.tokenA)
			if sid != "" && init.status == 200 {
				return pass("known server initialize 200")
			}
			return fail(fmt.Sprintf("status %d", init.status), "known_server_failed")
		})
	h.runCriterion("inventory.unknown", "unknown server fails closed", "inventory", true,
		"an unregistered server id is a 404", func() (Status, string, string, []string) {
			res := mcpPost(ctx, h.mcpBearer, mp, "srv-nonexistent", h.tokenA, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
			if res.status == 404 {
				return pass("unknown server 404")
			}
			return fail(fmt.Sprintf("status %d (expected 404)", res.status), "unknown_server_admitted")
		})
	h.runCriterion("inventory.admin_list", "admin server inventory matches fleet", "inventory", true,
		"GET /api/mcp/servers?tenant=A lists the seeded server", func() (Status, string, string, []string) {
			res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass,
				"/api/mcp/servers?tenant="+h.fixture.tenantA)
			if res.status == 200 && strings.Contains(string(res.body), h.fixture.serverA) {
				return pass("admin servers list contains srv-a")
			}
			return fail(fmt.Sprintf("status %d", res.status), "admin_list_failed")
		})
	h.runCriterion("inventory.cross_tenant_enum", "foreign tenant cannot enumerate", "inventory", true,
		"GET /api/mcp/servers?tenant=B on process A does not reveal srv-a", func() (Status, string, string, []string) {
			res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass,
				"/api/mcp/servers?tenant="+h.fixture.tenantB)
			if res.status == 200 && !strings.Contains(string(res.body), h.fixture.serverA) {
				return pass("foreign-tenant list does not reveal srv-a")
			}
			if res.status >= 400 {
				return pass(fmt.Sprintf("foreign-tenant list denied (status %d)", res.status))
			}
			return fail("foreign-tenant list revealed srv-a", "cross_tenant_enum")
		})
	h.runCriterion("inventory.quarantined", "seeded tool state truthful (quarantined)", "inventory", true,
		"the seeded tool is reported quarantined", func() (Status, string, string, []string) {
			res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass,
				"/api/mcp/tools?tenant="+h.fixture.tenantA)
			if res.status == 200 && strings.Contains(strings.ToLower(string(res.body)), "quarantin") {
				return pass("tool reported quarantined")
			}
			return fail(fmt.Sprintf("status %d", res.status), "quarantine_state_absent")
		})
}

// ── Tenant isolation matrix ──────────────────────────────────────────────────

func (h *Harness) runTenantMatrix(ctx context.Context) {
	// Same-tenant: reaches policy (200). Cross-tenant: TENANT_MISMATCH.
	cases := []struct {
		id, tokenLabel, serverLabel string
		token                       string
		mp                          int
		server                      string
		cross                       bool
	}{
		{"tenant.aa", "A", "A", h.tokenA, h.procA.pc.mcpPort, h.fixture.serverA, false},
		{"tenant.bb", "B", "B", h.tokenB, h.procB.pc.mcpPort, h.fixture.serverB, false},
		{"tenant.ab", "A", "B", h.tokenA, h.procB.pc.mcpPort, h.fixture.serverB, true},
		{"tenant.ba", "B", "A", h.tokenB, h.procA.pc.mcpPort, h.fixture.serverA, true},
	}
	for _, c := range cases {
		c := c
		expected := "reaches policy (200)"
		if c.cross {
			expected = "TENANT_MISMATCH denial"
		}
		h.runCriterion(c.id, fmt.Sprintf("tenant %s token -> tenant %s server", c.tokenLabel, c.serverLabel), "tenant", true,
			expected, func() (Status, string, string, []string) {
				sid, init := initSession(ctx, h.mcpBearer, c.mp, c.server, c.token)
				if sid == "" {
					return fail(fmt.Sprintf("init status %d", init.status), "init_failed")
				}
				res := mcpPost(ctx, h.mcpBearer, c.mp, c.server, c.token, sid, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
				reason := reasonOf(res.body)
				cell := TenantMatrixCell{Token: c.tokenLabel, Server: c.serverLabel, CrossTenant: c.cross, Expected: expected}
				if c.cross {
					if reason == "MCP.AUTH.TENANT_MISMATCH" && !hasResult(res.body) {
						cell.Observed, cell.Status = "TENANT_MISMATCH", StatusPass
						h.summary.TenantMatrix = append(h.summary.TenantMatrix, cell)
						return pass("cross-tenant denied TENANT_MISMATCH")
					}
					cell.Observed, cell.Status = reason, StatusFail
					h.summary.TenantMatrix = append(h.summary.TenantMatrix, cell)
					return fail("reason="+reason, "cross_tenant_not_denied")
				}
				if res.status == 200 {
					cell.Observed, cell.Status = "reached-policy", StatusPass
					h.summary.TenantMatrix = append(h.summary.TenantMatrix, cell)
					return pass("same-tenant reached policy")
				}
				cell.Observed, cell.Status = fmt.Sprintf("status %d", res.status), StatusFail
				h.summary.TenantMatrix = append(h.summary.TenantMatrix, cell)
				return fail(fmt.Sprintf("status %d", res.status), "same_tenant_denied")
			})
	}

	// Cross-tenant under a broad ALLOW cannot be overridden, and client-supplied
	// tenant (query + header) cannot replace the authenticated tenant.
	h.runCriterion("tenant.spoof_ignored", "client tenant spoof ignored", "tenant", true,
		"?tenant / X-Tenant do not override the authenticated tenant", func() (Status, string, string, []string) {
			sid, _ := initSession(ctx, h.mcpBearer, h.procB.pc.mcpPort, h.fixture.serverB, h.tokenA)
			if sid == "" {
				return fail("init", "init_failed")
			}
			res := mcpPostRaw(ctx, h.mcpBearer, h.procB.pc.mcpPort,
				"/mcp/gateway/"+h.fixture.serverB+"?tenant="+h.fixture.tenantB, h.tokenA,
				`{"jsonrpc":"2.0","id":6,"method":"tools/list"}`,
				map[string]string{"Host": "gw.test", "X-Tenant": h.fixture.tenantB, "Mcp-Session-Id": sid, "Authorization": "Bearer " + h.tokenA})
			if reasonOf(res.body) == "MCP.AUTH.TENANT_MISMATCH" {
				return pass("spoofed tenant still cross-tenant denied")
			}
			return fail("reason="+reasonOf(res.body), "spoof_overrode_tenant")
		})

	h.runCriterion("tenant.no_leak", "no foreign-tenant leak in denial", "tenant", true,
		"a cross-tenant denial exposes no owner/endpoint/tool state", func() (Status, string, string, []string) {
			sid, _ := initSession(ctx, h.mcpBearer, h.procB.pc.mcpPort, h.fixture.serverB, h.tokenA)
			res := mcpPost(ctx, h.mcpBearer, h.procB.pc.mcpPort, h.fixture.serverB, h.tokenA, sid, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
			body := string(res.body)
			if strings.Contains(body, "upstream") || strings.Contains(body, "spiffe") || strings.Contains(body, "127.0.0.1") {
				return fail("response leaked server state", "foreign_leak")
			}
			return pass("no owner/endpoint leaked")
		})
}

// ── Policy ───────────────────────────────────────────────────────────────────

func (h *Harness) runPolicy(ctx context.Context) {
	mp := h.procA.pc.mcpPort
	sv := h.fixture.serverA
	h.runCriterion("policy.loaded", "policy snapshot loaded with revision+hash", "policy", true,
		"health reports a policy revision and snapshot hash", func() (Status, string, string, []string) {
			hv, _ := h.procA.health(ctx, h.uiClient)
			if hv.Gateway.PolicyRevision > 0 && hv.Gateway.PolicySnapshotHash != "" {
				h.summary.PolicyRevision = hv.Gateway.PolicyRevision
				h.summary.PolicySnapshotHash = hv.Gateway.PolicySnapshotHash
				return pass(fmt.Sprintf("rev=%d hash=%s", hv.Gateway.PolicyRevision, short(hv.Gateway.PolicySnapshotHash)))
			}
			return fail("no revision/hash", "policy_not_loaded")
		})
	h.runCriterion("policy.shared_snapshot", "runtime and admin policy agree", "policy", true,
		"GET /api/mcp/policy hash matches the health snapshot hash", func() (Status, string, string, []string) {
			res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass, "/api/mcp/policy")
			if res.status != 200 {
				return fail(fmt.Sprintf("status %d", res.status), "policy_unreachable")
			}
			var pol struct {
				Hash     string `json:"hash"`
				Revision uint64 `json:"revision"`
			}
			_ = json.Unmarshal(res.body, &pol)
			if pol.Hash != "" && pol.Hash == h.summary.PolicySnapshotHash {
				return pass("admin hash == runtime hash")
			}
			return fail(fmt.Sprintf("admin=%s runtime=%s", short(pol.Hash), short(h.summary.PolicySnapshotHash)), "snapshot_divergence")
		})
	h.runCriterion("policy.discovery_allow", "same-tenant discovery reaches user ALLOW", "policy", true,
		"tools/list on A->A is a non-executing ALLOW", func() (Status, string, string, []string) {
			sid, _ := initSession(ctx, h.mcpBearer, mp, sv, h.tokenA)
			res := mcpPost(ctx, h.mcpBearer, mp, sv, h.tokenA, sid, `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`)
			if res.status == 200 && strings.Contains(string(res.body), "not_implemented") {
				return pass("ALLOW discovery, execution_state=not_implemented")
			}
			return fail(fmt.Sprintf("status %d body-has-not_implemented=%v", res.status, strings.Contains(string(res.body), "not_implemented")), "allow_not_observed")
		})
	h.runCriterion("policy.quarantine_beats_allow", "quarantined tools/call denied under ALLOW", "policy", true,
		"tools/call on a quarantined tool is a hard QUARANTINE, never executed", func() (Status, string, string, []string) {
			sid, _ := initSession(ctx, h.mcpBearer, mp, sv, h.tokenA)
			res := mcpPost(ctx, h.mcpBearer, mp, sv, h.tokenA, sid, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo"}}`)
			if reasonOf(res.body) != "" && !hasResult(res.body) && !strings.Contains(string(res.body), `"execution_state":"executed"`) {
				return pass("quarantined tools/call denied: " + reasonOf(res.body))
			}
			return fail("tools/call not denied", "quarantine_bypassed")
		})
	h.runCriterion("policy.default_deny", "default-deny is truthful", "policy", true,
		"a decision with no matching rule is NO_MATCH_DEFAULT_DENY", func() (Status, string, string, []string) {
			return h.checkDefaultDeny(ctx)
		})
}

// checkDefaultDeny spins an auxiliary process with a deny-only policy and asserts a
// discovery request produces the default-deny reason.
func (h *Harness) checkDefaultDeny(ctx context.Context) (Status, string, string, []string) {
	pc, err := h.fixture.buildProc("denyonly", h.fixture.tenantA, h.fixture.serverA, "none", tripEndpoint(h.tripwireA))
	if err != nil {
		return fail("aux build", "aux_build")
	}
	denyPolicy := map[string]any{
		"schema_version": 1, "capability": "gateway", "policy_revision": 1, "default_action": "DENY", "rules": []any{},
	}
	if err := h.fixture.setPolicy(pc, denyPolicy); err != nil {
		return fail("rewrite policy", "aux_policy")
	}
	proc, err := h.startProcess(ctx, pc)
	if err != nil {
		return fail("aux start", "aux_start")
	}
	defer func() { _ = proc.stop(h.spec.Run.shutdown()) }()
	sid, _ := initSession(ctx, h.mcpBearer, pc.mcpPort, h.fixture.serverA, h.tokenA)
	res := mcpPost(ctx, h.mcpBearer, pc.mcpPort, h.fixture.serverA, h.tokenA, sid, `{"jsonrpc":"2.0","id":11,"method":"tools/list"}`)
	if reasonOf(res.body) == "MCP.POLICY.NO_MATCH_DEFAULT_DENY" {
		return pass("default-deny reason observed")
	}
	return fail("reason="+reasonOf(res.body), "default_deny_absent")
}

// ── Durable evidence ─────────────────────────────────────────────────────────

func (h *Harness) runDurableEvidence(ctx context.Context) {
	h.runCriterion("evidence.allow_committed", "ALLOW decision durably committed", "evidence", true,
		"the ALLOW discovery decision is readable via /api/mcp/decisions", func() (Status, string, string, []string) {
			// Generate a fresh ALLOW discovery then read it back through the Admin API,
			// polling briefly for the synchronous commit to surface.
			sid, _ := initSession(ctx, h.mcpBearer, h.procA.pc.mcpPort, h.fixture.serverA, h.tokenA)
			_ = mcpPost(ctx, h.mcpBearer, h.procA.pc.mcpPort, h.fixture.serverA, h.tokenA, sid, `{"jsonrpc":"2.0","id":12,"method":"tools/list"}`)
			deadline := h.now().Add(h.spec.Run.request())
			for h.now().Before(deadline) {
				res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass,
					"/api/mcp/decisions?tenant="+h.fixture.tenantA)
				if res.status == 200 && decisionsNonEmpty(res.body) {
					h.summary.TelemetrySummary.Committed = true
					return pass("decisions readable via Admin API")
				}
				select {
				case <-ctx.Done():
					return fail("context cancelled", "decision_not_readable")
				case <-time.After(200 * time.Millisecond):
				}
			}
			return fail("decisions not readable within request timeout", "decision_not_readable")
		})
	// The cross-tenant denial is proven REQUIRED in the tenant matrix (the response
	// is TENANT_MISMATCH). Durable P-DEN aggregation flushes on a real-time window
	// the harness must not force, so aggregation is recorded as an advisory
	// (non-required) observation rather than a flaky required criterion; the durable
	// aggregation contract itself is pinned by internal/mcp/events composed tests.
	h.runCriterion("evidence.denial_aggregated", "cross-tenant denial aggregated (advisory)", "evidence", false,
		"a cross-tenant denial eventually increments the denial-lane metric", func() (Status, string, string, []string) {
			sid, _ := initSession(ctx, h.mcpBearer, h.procB.pc.mcpPort, h.fixture.serverB, h.tokenA)
			_ = mcpPost(ctx, h.mcpBearer, h.procB.pc.mcpPort, h.fixture.serverB, h.tokenA, sid, `{"jsonrpc":"2.0","id":13,"method":"tools/list"}`)
			m := metricsGet(ctx, h.metricsClient, h.procB.pc.proxyPort, h.procB.pc.metricsToken)
			if m.status == 200 && metricValueAtLeast(m.body, "culvert_mcp_denial_aggregates_total", 1) {
				h.summary.TelemetrySummary.DenialAggregated = true
				return pass("denial aggregates >= 1")
			}
			return StatusSkip, "denial not yet flushed (real-time window)", "", nil
		})
}

// ── Metrics ──────────────────────────────────────────────────────────────────

func (h *Harness) runMetrics(ctx context.Context) {
	h.runCriterion("metrics.telemetry_ready", "telemetry readiness metric present", "metrics", true,
		"culvert_mcp_telemetry_ready is scrapable", func() (Status, string, string, []string) {
			m := metricsGet(ctx, h.metricsClient, h.procA.pc.proxyPort, h.procA.pc.metricsToken)
			if m.status == 200 && strings.Contains(string(m.body), "culvert_mcp_telemetry_ready") {
				return pass("telemetry_ready present")
			}
			return fail(fmt.Sprintf("status %d", m.status), "metric_absent")
		})
	h.runCriterion("metrics.no_high_cardinality", "no high-cardinality MCP labels", "metrics", true,
		"no culvert_mcp_* series carries a tenant/principal/server/tool/event label", func() (Status, string, string, []string) {
			m := metricsGet(ctx, h.metricsClient, h.procA.pc.proxyPort, h.procA.pc.metricsToken)
			if m.status != 200 {
				return fail(fmt.Sprintf("status %d", m.status), "metrics_unreachable")
			}
			if bad := scanHighCardinality(m.body); bad != "" {
				return fail("banned label: "+bad, "high_cardinality_label")
			}
			return pass("only fixed enum labels present")
		})
}

// ── Management isolation ─────────────────────────────────────────────────────

func (h *Harness) runManagement(ctx context.Context) {
	h.runCriterion("mgmt.disabled", "no Management listener; publication rejected", "management", true,
		"overview reports execution not-implemented and Management is not active", func() (Status, string, string, []string) {
			res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass, "/api/mcp/overview")
			if res.status != 200 {
				return fail(fmt.Sprintf("status %d", res.status), "overview_unreachable")
			}
			body := string(res.body)
			if strings.Contains(body, `"execution_state":"not_implemented"`) {
				return pass("execution not-implemented; Management not active")
			}
			return fail("execution state unexpected", "management_state")
		})
}

// ── Restart / recovery ───────────────────────────────────────────────────────

func (h *Harness) runRestart(ctx context.Context) {
	h.runCriterion("restart.recovery", "evidence survives a real process restart", "restart", true,
		"restarting the same artifact recovers telemetry and preserves committed evidence", func() (Status, string, string, []string) {
			// Stop process A, then start a fresh process on the SAME config/state/KEK.
			if err := h.procA.stop(h.spec.Run.shutdown()); err != nil {
				return fail("stop failed", "restart_stop")
			}
			proc, err := h.startProcess(ctx, h.procA.pc)
			if err != nil {
				h.summary.RestartResult = StatusFail
				return fail("restart failed: "+err.Error(), "restart_start")
			}
			h.procA = proc
			// Historical evidence committed BEFORE the restart (by evidence.allow_committed)
			// must remain readable AND non-empty after a real process restart — proving the
			// durable spool persisted the decision, not merely that the endpoint recovered.
			deadline := h.now().Add(h.spec.Run.restart())
			for h.now().Before(deadline) {
				res := adminGet(ctx, h.uiClient, h.procA.pc.uiPort, h.procA.pc.adminUser, h.procA.pc.adminPass,
					"/api/mcp/decisions?tenant="+h.fixture.tenantA)
				if res.status == 200 && decisionsNonEmpty(res.body) {
					h.summary.RestartResult = StatusPass
					h.summary.TelemetrySummary.ExportedAfterRestart = true
					return pass("restarted; committed decision persisted and readable")
				}
				select {
				case <-ctx.Done():
					h.summary.RestartResult = StatusFail
					return fail("context cancelled", "evidence_lost")
				case <-time.After(200 * time.Millisecond):
				}
			}
			h.summary.RestartResult = StatusFail
			return fail("post-restart decisions not persisted within request timeout", "evidence_lost")
		})
}

// ── Emergency disable ────────────────────────────────────────────────────────

func (h *Harness) runEmergencyDisable(ctx context.Context) {
	h.runCriterion("emergency.disable", "operator disable stops MCP, SWG unaffected", "emergency", true,
		"disabling the Gateway config (restart) stops MCP admission while the SWG stays up", func() (Status, string, string, []string) {
			return h.checkEmergencyDisable(ctx)
		})
}

func (h *Harness) checkEmergencyDisable(ctx context.Context) (Status, string, string, []string) {
	pc, err := h.fixture.buildProc("emergency", h.fixture.tenantA, h.fixture.serverA, "none", tripEndpoint(h.tripwireA))
	if err != nil {
		return fail("aux build", "aux_build")
	}
	proc, err := h.startProcess(ctx, pc)
	if err != nil {
		return fail("aux start", "aux_start")
	}
	// Prove a known-good request first.
	sid, init := initSession(ctx, h.mcpBearer, pc.mcpPort, h.fixture.serverA, h.tokenA)
	if sid == "" || init.status != 200 {
		_ = proc.stop(h.spec.Run.shutdown())
		return fail("pre-disable known-good failed", "pre_disable")
	}
	// Disable via the accepted config mechanism + restart.
	if err := proc.stop(h.spec.Run.shutdown()); err != nil {
		return fail("stop", "disable_stop")
	}
	if err := h.fixture.setEnabled(pc, false); err != nil {
		return fail("rewrite config", "disable_config")
	}
	proc2, err := h.startProcessRaw(ctx, pc)
	if err != nil {
		return fail("restart disabled", "disable_restart")
	}
	defer func() { _ = proc2.stop(h.spec.Run.shutdown()) }()
	h.summary.EmergencyDisable = StatusFail
	// MCP must no longer admit.
	dialer := net.Dialer{Timeout: h.spec.Run.request()}
	conn, derr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", pc.mcpPort))
	if derr == nil {
		_ = conn.Close()
		return fail("mcp port still bound after disable", "still_admitting")
	}
	// The SWG forward proxy must remain up — probe ITS own /health endpoint on the
	// PROXY port (the admin UI on the ui-port is a different service). An artifact
	// that killed the SWG proxy while leaving the UI up must fail here.
	swg := proxyHealth(ctx, h.uiClient, pc.proxyPort)
	if swg.status != 200 {
		return fail(fmt.Sprintf("SWG proxy /health %d", swg.status), "swg_down")
	}
	// Rollout must not have advanced (overview execution still not_implemented).
	ov := adminGet(ctx, h.uiClient, pc.uiPort, pc.adminUser, pc.adminPass, "/api/mcp/overview")
	if ov.status == 200 && !strings.Contains(string(ov.body), `"execution_state":"not_implemented"`) {
		return fail("rollout advanced", "rollout_changed")
	}
	h.summary.EmergencyDisable = StatusPass
	return pass("MCP stopped, SWG up, rollout unchanged")
}

// ── Non-execution ────────────────────────────────────────────────────────────

func (h *Harness) runNonExecution(ctx context.Context) {
	h.runCriterion("nonexec.tripwire", "no tool execution reached any upstream", "nonexec", true,
		"the non-execution tripwire received zero inbound requests", func() (Status, string, string, []string) {
			a, b := h.tripwireA.inbound(), h.tripwireB.inbound()
			if a == 0 && b == 0 {
				h.summary.NonExecution = StatusPass
				return pass("tripwire inbound A=0 B=0")
			}
			h.summary.NonExecution = StatusFail
			return fail(fmt.Sprintf("tripwire inbound A=%d B=%d", a, b), "execution_detected")
		})
	h.runCriterion("nonexec.health", "health reports execution disabled", "nonexec", true,
		"gateway.runtime.execution_enabled is false on a reachable, ready gateway", func() (Status, string, string, []string) {
			hv, res := h.procA.health(ctx, h.uiClient)
			// A successful, ready health response is required before the boolean is
			// meaningful — an unreachable gateway must not read as "execution disabled".
			if res.status != 200 || hv.Gateway.Runtime.State != "ready" {
				h.summary.NonExecution = StatusFail
				return fail(fmt.Sprintf("health status=%d state=%s", res.status, hv.Gateway.Runtime.State), "health_unreachable")
			}
			if !hv.Gateway.Runtime.ExecutionEnabled {
				return pass("execution_enabled=false (gateway ready)")
			}
			h.summary.NonExecution = StatusFail
			return fail("execution_enabled=true", "execution_enabled")
		})
}

// short truncates a hash for a bounded observed value.
func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}
