//go:build uie2e

package main

// Synthetic MCP posture fixtures for the UX-audit run. Every JSON body here is
// FABRICATED to match the exact response shapes confirmed from the handlers
// (ui_mcp.go / ui_mcp_rollout.go / internal/mcp/adminapi). No real tenant data,
// no tokens, no secrets — only illustrative enum values and safe hashes.
//
// Tenants use RFC-5737-style safe names; hashes are obviously-synthetic hex.

// safe synthetic hex "hashes" (clearly not real digests).
const (
	hHealthy  = "sha256:11aa22bb33cc44dd55ee66ff77009988"
	hPrev     = "sha256:00ff11ee22dd33cc44bb55aa66998877"
	hScopeGw  = "sha256:aa00bb11cc22dd33ee44ff5566778899"
	hSnapshot = "sha256:5c0pe0fpr0duct10nqual1f1cat10n00"
)

// ── overview ───────────────────────────────────────────────────────────────

func ovBody(distState, execState string, mgmtTools int, healthJSON string) string {
	return `{"distribution_state":"` + distState + `","execution_state":"` + execState +
		`","management_tools":` + uxItoa(mgmtTools) + `,"health":` + healthJSON + `}`
}

// healthy CapabilityHealth for gateway (listener ready, some inventory).
const healthGatewayHealthy = `{"capability":"gateway","runtime":{"state":"ready","listener_ready":true,"draining":false,"active_sessions":7,"accepted_conns":1284,"rejected_conns":16,"in_flight":3},"durability":{"critical_state":"normal","denial_state":"normal","severity":"none","crit_bytes":48211,"crit_quota":1048576,"ord_bytes":91233,"ord_quota":4194304,"den_bytes":1200,"den_quota":262144,"critical_reserve_free":1000365,"commit_failures":0,"sync_failures":0,"encryption_failures":0,"denial_loss":0,"critical_degradations":0,"recovery_state":"n/a","exporter_lag":0},"servers":4,"quarantined_tools":1,"drifted_tools":2,"policy_revision":12,"policy_snapshot_hash":"` + hHealthy + `","pending_approvals":2,"pending_publications":1}`

const healthMgmtHealthy = `{"capability":"management","runtime":{"state":"ready","listener_ready":true,"draining":false,"active_sessions":1,"accepted_conns":40,"rejected_conns":0,"in_flight":0},"durability":{"critical_state":"normal","denial_state":"normal","severity":"none","crit_bytes":0,"crit_quota":1048576,"ord_bytes":0,"ord_quota":4194304,"den_bytes":0,"den_quota":262144,"critical_reserve_free":1048576,"commit_failures":0,"sync_failures":0,"encryption_failures":0,"denial_loss":0,"critical_degradations":0,"recovery_state":"n/a","exporter_lag":0},"servers":0,"quarantined_tools":0,"drifted_tools":0,"policy_revision":12,"policy_snapshot_hash":"` + hHealthy + `","pending_approvals":0,"pending_publications":1}`

// durability-degraded gateway health.
const healthGatewayDegraded = `{"capability":"gateway","runtime":{"state":"degraded","listener_ready":true,"draining":false,"active_sessions":9,"accepted_conns":2201,"rejected_conns":142,"in_flight":11},"durability":{"critical_state":"degraded","denial_state":"degraded","severity":"high","crit_bytes":1038221,"crit_quota":1048576,"ord_bytes":4100233,"ord_quota":4194304,"den_bytes":260001,"den_quota":262144,"critical_reserve_free":10355,"commit_failures":37,"sync_failures":9,"encryption_failures":0,"denial_loss":118,"critical_degradations":3,"recovery_state":"recovering","exporter_lag":42000},"servers":4,"quarantined_tools":1,"drifted_tools":2,"policy_revision":12,"policy_snapshot_hash":"` + hHealthy + `","pending_approvals":2,"pending_publications":1}`

func healthView(gw, mgmt, distState string, mgmtEnabled bool) string {
	en := "false"
	if mgmtEnabled {
		en = "true"
	}
	return `{"gateway":` + gw + `,"management":` + mgmt + `,"distribution_state":"` + distState +
		`","management_access":{"enabled":` + en + `,"endpoint_bound":` + en + `,"default_min_role":"viewer","output_max_bytes":1048576,"mutation_enabled":false}}`
}

// ── distribution ───────────────────────────────────────────────────────────

func uxCapStatus(cur, prev string, epoch, cfgRev, polRev, catRev, credRev, minDP int, keyID string, rollback bool) string {
	rb := "false"
	if rollback {
		rb = "true"
	}
	return `{"current_hash":"` + cur + `","previous_hash":"` + prev + `","epoch":` + uxItoa(epoch) +
		`,"config_revision":` + uxItoa(cfgRev) + `,"policy_revision":` + uxItoa(polRev) +
		`,"catalog_revision":` + uxItoa(catRev) + `,"credential_revision":` + uxItoa(credRev) +
		`,"signing_key_id":"` + keyID + `","minimum_dp_version":` + uxItoa(minDP) + `,"rollback_available":` + rb + `}`
}

func distBody(enabled bool, state, gw, mgmt string) string {
	en := "false"
	if enabled {
		en = "true"
	}
	return `{"enabled":` + en + `,"distribution_state":"` + state + `","gateway":` + gw + `,"management":` + mgmt + `}`
}

// ── rollout ────────────────────────────────────────────────────────────────

func rolloutCap(mode, desired, scopeHash string, killed bool, connector string, hist int) string {
	k := "false"
	if killed {
		k = "true"
	}
	return `{"mode":"` + mode + `","desired":"` + desired + `","scope_hash":"` + scopeHash +
		`","killed":` + k + `,"connector":"` + connector + `","history_len":` + uxItoa(hist) + `}`
}

func rolloutMetrics(inScope, outScope, shadowOv, hardBlk, exec, upOK, upErr, dlp, commitFail, emerg, trans int) string {
	return `{"in_scope":` + uxItoa(inScope) + `,"out_of_scope":` + uxItoa(outScope) + `,"shadow_override":` + uxItoa(shadowOv) +
		`,"hard_blocks":` + uxItoa(hardBlk) + `,"executed":` + uxItoa(exec) + `,"upstream_ok":` + uxItoa(upOK) +
		`,"upstream_err":` + uxItoa(upErr) + `,"dlp_blocks":` + uxItoa(dlp) + `,"commit_fail":` + uxItoa(commitFail) +
		`,"emergencies":` + uxItoa(emerg) + `,"transitions":` + uxItoa(trans) + `}`
}

func rolloutBody(gw, mgmt, metrics string, prodLocked bool, dist string) string {
	pl := "false"
	if prodLocked {
		pl = "true"
	}
	return `{"gateway":` + gw + `,"management":` + mgmt + `,"metrics":` + metrics +
		`,"production_locked":` + pl + `,"distribution":` + dist + `}`
}

// ── decision views (evaluated vs effective) ────────────────────────────────

// a DecisionView row.
func decRow(id string, seq int, part, tenant, prin, prinType, agent, server, tool, action, reason, rule, opClass, execState string) string {
	return `{"event_id":"` + id + `","sequence":` + uxItoa(seq) + `,"partition":"` + part +
		`","capability":"gateway","time_unix_nano":1722690000000000000,"tenant":"` + tenant +
		`","principal_id":"` + prin + `","principal_type":"` + prinType + `","agent_id":"` + agent +
		`","server_id":"` + server + `","tool_name":"` + tool + `","action":"` + action +
		`","reason_code":"` + reason + `","matched_rule_id":"` + rule + `","operation_class":"` + opClass +
		`","execution_state":"` + execState + `"}`
}

func searchResult(rows string, cursor string) string {
	return `{"decisions":[` + rows + `],"next_cursor":"` + cursor + `"}`
}

// uxItoa avoids importing strconv into every fixture.
func uxItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ── the scenario registry ──────────────────────────────────────────────────

// fixtureFor returns the fixture for a scenario slug, or nil for real-server
// scenarios ("current", "empty", "viewer-denied", "anon").
func fixtureFor(slug string) *mcpFixture {
	switch slug {

	case "healthy":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/overview", body: ovBody("fully_acknowledged", "executed", 14,
				healthView(healthGatewayHealthy, healthMgmtHealthy, "fully_acknowledged", true))},
			{match: "/api/mcp/health", body: healthView(healthGatewayHealthy, healthMgmtHealthy, "fully_acknowledged", true)},
			{match: "/api/mcp/distribution", body: distBody(true, "fully_acknowledged",
				uxCapStatus(hHealthy, hPrev, 8, 12, 12, 6, 3, 1, "cp-key-2026a", true),
				uxCapStatus(hHealthy, hPrev, 8, 12, 12, 6, 3, 1, "cp-key-2026a", true))},
			{match: "/api/mcp/rollout", body: rolloutBody(
				rolloutCap("canary", "canary", hScopeGw, false, "local-client", 6),
				rolloutCap("observe", "observe", hScopeGw, false, "", 2),
				rolloutMetrics(4210, 118, 0, 3, 4090, 4051, 39, 5, 0, 0, 6), true,
				distBody(true, "fully_acknowledged",
					uxCapStatus(hHealthy, hPrev, 8, 12, 12, 6, 3, 1, "cp-key-2026a", true),
					uxCapStatus(hHealthy, hPrev, 8, 12, 12, 6, 3, 1, "cp-key-2026a", true)))},
		}}

	case "observe":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/rollout", body: rolloutBody(
				rolloutCap("observe", "observe", hScopeGw, false, "local-client", 1),
				rolloutCap("disabled", "disabled", hScopeGw, false, "", 0),
				rolloutMetrics(980, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), true,
				distBody(true, "fully_acknowledged", uxCapStatus(hHealthy, "", 3, 5, 5, 2, 1, 1, "cp-key-2026a", false),
					uxCapStatus("", "", 0, 0, 0, 0, 0, 0, "", false)))},
			{match: "/api/mcp/executions", body: `{"executed":0,"upstream_ok":0,"upstream_err":0,"dlp_blocks":0,"hard_blocks":0,"shadow_override":0,"commit_fail":0}`},
			{match: "/api/mcp/upstream-health", body: `{"upstream_ok":0,"upstream_err":0,"enabled":false}`},
			{match: "/api/mcp/rollout/evidence", body: evidenceBody("gateway", "synthetic", 0, false, 0, true)},
		}}

	case "shadow":
		// Shadow: policy would DENY several calls, but effective action ALLOW +
		// shadow_override — the exact case the UI must never render as a plain ALLOW.
		rows := decRow("evt_9f1a", 4021, "P-CRIT", "acme-prod", "svc-agent-billing", "workload", "agent-42",
			"srv-github", "create_issue", "DENY", "rollout_out_of_scope", "rule-write-guard", "write", "shadow_recorded") + "," +
			decRow("evt_9f22", 4020, "P-ORD", "acme-prod", "u-jdoe", "human", "agent-42",
				"srv-github", "list_issues", "ALLOW", "observe_only", "rule-read-allow", "read", "executed") + "," +
			decRow("evt_9f2f", 4019, "P-CRIT", "acme-prod", "svc-agent-deploy", "workload", "agent-7",
				"srv-k8s", "delete_pod", "DENY", "credential_power_exceeded", "rule-destructive", "destructive", "shadow_recorded")
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/rollout", body: rolloutBody(
				rolloutCap("shadow", "shadow", hScopeGw, false, "local-client", 3),
				rolloutCap("observe", "observe", hScopeGw, false, "", 1),
				rolloutMetrics(2050, 40, 214, 6, 1836, 1801, 35, 12, 0, 0, 3), true,
				distBody(true, "fully_acknowledged", uxCapStatus(hHealthy, hPrev, 5, 8, 8, 4, 2, 1, "cp-key-2026a", true),
					uxCapStatus(hHealthy, "", 3, 4, 4, 1, 1, 1, "cp-key-2026a", false)))},
			{match: "/api/mcp/decisions", body: searchResult(rows, "P-CRIT:4018")},
			{match: "/api/mcp/executions", body: `{"executed":1836,"upstream_ok":1801,"upstream_err":35,"dlp_blocks":12,"hard_blocks":6,"shadow_override":214,"commit_fail":0}`},
			{match: "/api/mcp/rollout/evidence", body: evidenceBody("gateway", "synthetic", 2, false, 4, true)},
		}}

	case "canary":
		rows := decRow("evt_c101", 5610, "P-ORD", "acme-prod", "u-asmith", "human", "agent-11",
			"srv-jira", "get_ticket", "ALLOW", "none", "rule-read-allow", "read", "executed") + "," +
			decRow("evt_c102", 5609, "P-CRIT", "acme-prod", "svc-agent-ops", "workload", "agent-11",
				"srv-jira", "transition_ticket", "REQUIRE_APPROVAL", "approval_required", "rule-write-approve", "write", "blocked") + "," +
			decRow("evt_c103", 5608, "P-CRIT", "acme-prod", "svc-agent-scan", "workload", "agent-3",
				"srv-shell", "run_command", "QUARANTINE", "tool_trust", "rule-quarantine", "admin", "blocked") + "," +
			decRow("evt_c104", 5607, "P-CRIT", "acme-prod", "svc-agent-deploy", "workload", "agent-7",
				"srv-k8s", "scale_deploy", "DENY", "rollout_out_of_scope", "rule-scope", "write", "blocked")
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/rollout", body: rolloutBody(
				rolloutCap("canary", "canary", hScopeGw, false, "local-client", 5),
				rolloutCap("shadow", "shadow", hScopeGw, false, "", 2),
				rolloutMetrics(880, 3120, 0, 4, 611, 590, 21, 3, 0, 0, 5), true,
				distBody(true, "partially_acknowledged", uxCapStatus(hHealthy, hPrev, 6, 9, 9, 5, 2, 1, "cp-key-2026a", true),
					uxCapStatus(hHealthy, "", 4, 5, 5, 2, 1, 1, "cp-key-2026a", false)))},
			{match: "/api/mcp/decisions", body: searchResult(rows, "P-CRIT:5606")},
			{match: "/api/mcp/executions", body: `{"executed":611,"upstream_ok":590,"upstream_err":21,"dlp_blocks":3,"hard_blocks":4,"shadow_override":0,"commit_fail":0}`},
		}}

	case "hardfail":
		rows := decRow("evt_hf01", 7001, "P-CRIT", "acme-prod", "unknown", "unset", "agent-x",
			"srv-github", "create_issue", "DENY", "sender_constraint_required", "-", "write", "blocked") + "," +
			decRow("evt_hf02", 7000, "P-CRIT", "acme-prod", "svc-agent-x", "workload", "agent-x",
				"srv-unknown", "exfil", "DENY", "unregistered_server", "-", "unknown", "blocked")
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/decisions", body: searchResult(rows, "P-CRIT:6999")},
			{match: "/api/mcp/decision-explain", body: explainBody("evt_hf01", "DENY", "sender_constraint_required",
				"auth_identity", "", "", "The request presented a bearer token with no proof-of-possession; DPoP/mTLS sender-constraint is required for this tenant.")},
		}}

	case "unknowntool":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/servers", body: `[` +
				serverView("srv-github", "acme-prod", true, "verified", false, 6, "cp-github-ro", true) + `,` +
				serverView("srv-shell", "acme-prod", true, "identity_mismatch", true, 2, "cp-shell", true) + `]`},
			{match: "/api/mcp/tools", body: `[` +
				toolView("srv-github", "create_issue", "fp-9a1b2c", "usable", false, false, "approved", 6) + `,` +
				toolView("srv-shell", "run_command", "fp-DR1FT9", "review_required", false, true, "arbitrary", 3) + `,` +
				toolView("srv-shell", "sudo_exec", "fp-QUAR00", "quarantined", true, true, "unknown", 3) + `]`},
		}}

	case "dlpblock":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/decisions", body: searchResult(
				decRow("evt_dlp1", 8100, "P-CRIT", "acme-prod", "svc-agent-support", "workload", "agent-9",
					"srv-crm", "update_contact", "DENY", "secret_detected", "rule-dlp-req", "write", "blocked"), "P-CRIT:8099")},
			{match: "/api/mcp/decision-explain", body: explainBodyDLP("evt_dlp1", "DENY", "secret_detected",
				"inspection_privacy", "block", `["credential_secret","bearer_token"]`, "high",
				"Request arguments contained a bearer token (class credential_secret); request-DLP hard-blocks before any upstream call.")},
		}}

	case "dlpredact":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/decisions", body: searchResult(
				decRow("evt_rd1", 8200, "P-ORD", "acme-prod", "u-jdoe", "human", "agent-2",
					"srv-crm", "get_contact", "ALLOW_WITH_REDACTION", "pii_detected", "rule-resp-redact", "read", "executed"), "P-ORD:8199")},
			{match: "/api/mcp/decision-explain", body: explainBodyDLP("evt_rd1", "ALLOW_WITH_REDACTION", "pii_detected",
				"none", "redact", `["pii","financial_identifier"]`, "medium",
				"Upstream response carried PII + a financial identifier; response-DLP applied the 'default' redaction profile before returning.")},
		}}

	case "partialack":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/distribution", body: distBody(true, "partially_acknowledged",
				uxCapStatus(hHealthy, hPrev, 9, 14, 14, 7, 4, 1, "cp-key-2026a", true),
				uxCapStatus(hHealthy, hPrev, 9, 14, 14, 7, 4, 1, "cp-key-2026a", true))},
			{match: "/api/mcp/health", body: healthView(healthGatewayHealthy, healthMgmtHealthy, "partially_acknowledged", true)},
		}}

	case "dpincompat":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/distribution", body: distBody(true, "distribution_degraded",
				uxCapStatus(hHealthy, hPrev, 10, 15, 15, 7, 4, 2, "cp-key-2026a", true),
				uxCapStatus(hHealthy, hPrev, 10, 15, 15, 7, 4, 2, "cp-key-2026a", true))},
			{match: "/api/mcp/health", body: healthView(healthGatewayHealthy, healthMgmtHealthy, "distribution_degraded", true)},
		}}

	case "durability":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/health", body: healthView(healthGatewayDegraded, healthMgmtHealthy, "fully_acknowledged", true)},
			{match: "/api/mcp/overview", body: ovBody("fully_acknowledged", "degraded", 14,
				healthView(healthGatewayDegraded, healthMgmtHealthy, "fully_acknowledged", true))},
		}}

	case "killswitch":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/rollout", body: rolloutBody(
				rolloutCap("canary", "canary", hScopeGw, true, "local-client", 7),
				rolloutCap("observe", "observe", hScopeGw, false, "", 2),
				rolloutMetrics(0, 5200, 0, 5200, 0, 0, 0, 0, 0, 1, 7), true,
				distBody(true, "fully_acknowledged", uxCapStatus(hHealthy, hPrev, 8, 12, 12, 6, 3, 1, "cp-key-2026a", true),
					uxCapStatus(hHealthy, "", 4, 5, 5, 2, 1, 1, "cp-key-2026a", false)))},
			{match: "/api/mcp/executions", body: `{"executed":0,"upstream_ok":0,"upstream_err":0,"dlp_blocks":0,"hard_blocks":5200,"shadow_override":0,"commit_fail":0}`},
		}}

	case "rollback":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/distribution", body: distBody(true, "rollback_pending",
				uxCapStatus(hHealthy, hPrev, 11, 16, 16, 8, 4, 1, "cp-key-2026a", true),
				uxCapStatus(hHealthy, hPrev, 11, 16, 16, 8, 4, 1, "cp-key-2026a", true))},
			{match: "/api/mcp/health", body: healthView(healthGatewayHealthy, healthMgmtHealthy, "rollback_pending", true)},
		}}

	case "prodlocked":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/rollout/evidence", body: evidenceBody("gateway", "synthetic", 3, false, 5, true)},
			{match: "/api/mcp/rollout", body: rolloutBody(
				rolloutCap("canary", "canary", hScopeGw, false, "local-client", 4),
				rolloutCap("observe", "observe", hScopeGw, false, "", 2),
				rolloutMetrics(4200, 100, 0, 2, 4100, 4080, 20, 4, 0, 0, 4), true,
				distBody(true, "fully_acknowledged", uxCapStatus(hHealthy, hPrev, 8, 12, 12, 6, 3, 1, "cp-key-2026a", true),
					uxCapStatus(hHealthy, "", 4, 5, 5, 2, 1, 1, "cp-key-2026a", false)))},
		}}

	case "apifail":
		return &mcpFixture{name: slug, failAll: 503, failAllBody: `{"error":"event_durability_degraded"}`}

	case "approvals":
		return &mcpFixture{name: slug, routes: []mcpRoute{
			{match: "/api/mcp/approvals", body: `[` +
				approvalView("appr_1a2b", "operational", "pending", "acme-prod", "u-jdoe", "",
					"transition_ticket", "srv-jira", "write", "high", "cp-jira-rw", "write") + `,` +
				approvalView("appr_3c4d", "operational", "pending", "acme-prod", "svc-agent-ops", "",
					"delete_pod", "srv-k8s", "destructive", "high", "cp-k8s-admin", "destructive") + `]`},
		}}
	}
	return nil
}

// ── extra shape builders used above ────────────────────────────────────────

func evidenceBody(cap, origin string, openCH int, rehearsed bool, fpReviews int, locked bool) string {
	rh, lk := "false", "false"
	if rehearsed {
		rh = "true"
	}
	if locked {
		lk = "true"
	}
	return `{"capability":"` + cap + `","origin":"` + origin + `","open_critical_high":` + uxItoa(openCH) +
		`,"rollback_rehearsed":` + rh + `,"false_positive_reviews":` + uxItoa(fpReviews) +
		`,"shadow_window_target_h":336,"canary_window_target_h":168,"soak_target_h":24,"production_locked":` + lk +
		`,"production_lock_message":"Production locked — qualification required"}`
}

func serverView(id, tenant string, enabled bool, verification string, idChanged bool, rev int, credRef string, endpoint bool) string {
	en, ic, ep := "false", "false", "false"
	if enabled {
		en = "true"
	}
	if idChanged {
		ic = "true"
	}
	if endpoint {
		ep = "true"
	}
	return `{"server_id":"` + id + `","tenant":"` + tenant + `","capability":"gateway","enabled":` + en +
		`,"verification":"` + verification + `","identity_changed":` + ic + `,"revision":` + uxItoa(rev) +
		`,"credential_profile_ref":"` + credRef + `","endpoint_configured":` + ep + `}`
}

func toolView(server, name, fp, disp string, quar, review bool, destClass string, rev int) string {
	q, r := "false", "false"
	if quar {
		q = "true"
	}
	if review {
		r = "true"
	}
	return `{"server_id":"` + server + `","name":"` + name + `","fingerprint":"` + fp +
		`","disposition":"` + disp + `","quarantined":` + q + `,"review_required":` + r +
		`,"destination_class":"` + destClass + `","revision":` + uxItoa(rev) + `}`
}

func approvalView(id, kind, state, tenant, requester, approver, action, server, opClass, riskClass, credRef, power string) string {
	return `{"id":"` + id + `","kind":"` + kind + `","state":"` + state + `","tenant":"` + tenant +
		`","capability":"gateway","requester":"` + requester + `","approver":"` + approver +
		`","action":"` + action + `","resource":"","server_id":"` + server + `","tool_fingerprint":"fp-9a1b2c",` +
		`"operation_class":"` + opClass + `","risk_class":"` + riskClass + `","credential_profile_ref":"` + credRef +
		`","power_ceiling":"` + power + `","decision_event_id":"evt_c102","candidate_hash":"","base_revision":9,` +
		`"proposed_revision":10,"policy_revision":12,"catalog_revision":6,"created_unix_nano":1722690000000000000,` +
		`"expiry_unix_nano":1722693600000000000,"reason":"four-eyes approval required for write-class operation"}`
}

func explainBody(id, action, reason, hardClass, dlpDisp, findingClasses, remediation string) string {
	return explainBodyDLP(id, action, reason, hardClass, dlpDisp, findingClasses, "high", remediation)
}

func explainBodyDLP(id, action, reason, hardClass, dlpDisp, findingClasses, maxSev, remediation string) string {
	fc := findingClasses
	if fc == "" {
		fc = "[]"
	}
	return `{"event_id":"` + id + `","correlation_id":"corr_7788","replay_id":"","capability":"gateway",` +
		`"partition":"P-CRIT","time_unix_nano":1722690000000000000,"tenant":"acme-prod","principal_id":"svc-agent-support",` +
		`"principal_type":"workload","agent_id":"agent-9","client_id":"app-desktop","server_id":"srv-crm","tool_name":"update_contact",` +
		`"tool_fingerprint":"fp-9a1b2c","resource_ref":"crm://contact/482","resource_hash":"` + hHealthy + `","assurance":"medium",` +
		`"action":"` + action + `","reason_code":"` + reason + `","matched_rule_id":"rule-dlp-req","decisive_condition_id":"cond-secret-scan",` +
		`"remediation":"` + remediation + `","operation_class":"write","risk_class":"high","execution_state":"blocked",` +
		`"obligations":["durable_commit","redaction_default"],"policy_revision":12,"catalog_revision":6,"registry_revision":4,` +
		`"inspection_revision":3,"runtime_revision":2,"policy_snapshot_hash":"` + hHealthy + `","inspection_schema_status":"valid",` +
		`"finding_classes":` + fc + `,"max_severity":"` + maxSev + `","dlp_disposition":"` + dlpDisp + `","destination_class":"approved",` +
		`"credential_profile_ref":"cp-crm-rw","credential_power_ceiling":"write","source":"historical","hard_failure_class":"` + hardClass + `"}`
}
