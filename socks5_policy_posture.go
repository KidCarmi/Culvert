package main

// socks5_policy_posture.go — SWG-901 stage 1: make the legacy SOCKS5 policy
// posture VISIBLE. Nothing here changes how a SOCKS5 connection is handled.
//
// The SOCKS5 listener (socks5.go) applies the connection limit, IP filter,
// rate limit, its USER/PASS credential check, destination bounds, blocklist,
// plugin chain and SSRF guard. It does NOT call the Stage-2 policy engine (no
// rules, no default action), the threat-feed domain check, the Stage-1
// authentication rules / IdP registry, or inspection. That is the "legacy"
// posture contract SWG-901 (contracts/registry.yaml) leaves open; the owner's
// stage-1 decision is to disclose it, not to change it, so existing
// installations keep their behaviour byte for byte.
//
// Two surfaces, both only on a node that configured the listener:
//
//   - one startup log line (logSOCKS5LegacyPolicyPosture), and
//   - a report-only `socks5_policy_enforcement` WARN row on /api/diagnostics.
//
// Deliberately NOT a /readyz row: /readyz is unauthenticated on the proxy port,
// and announcing "policy is not enforced on this port" to every network client
// is a disclosure, not a health signal. Readiness (default and ?strict=1) is
// therefore unchanged.
//
// The configured marker is its own atomic, set only by initSOCKS5, rather than
// socks5Listener.configured: dozens of listener tests set that record without
// clearing it, and keying a WARN row on it would leak into every later test
// that asserts the aggregate diagnostics verdict.

import (
	"fmt"
	"sync/atomic"
)

// socks5PolicyEnforcementCode is the operator-contract code of the row below.
const socks5PolicyEnforcementCode = "socks5_policy_enforcement"

// socks5LegacyPolicyPort holds the configured SOCKS5 port once initSOCKS5 has
// configured the listener; 0 means no listener was configured on this node.
var socks5LegacyPolicyPort atomic.Int64

// logSOCKS5LegacyPolicyPosture records the legacy SOCKS5 policy posture and
// emits one startup warning when the listener is configured (port > 0). With
// SOCKS5 disabled it does nothing at all, so the ordinary appliance's startup
// log and diagnostics report are unchanged.
func logSOCKS5LegacyPolicyPosture(port int) {
	if port <= 0 {
		return
	}
	socks5LegacyPolicyPort.Store(int64(port))
	logger.Printf("WARNING: SOCKS5 listener on port %d runs in legacy mode: policy rules, the default action, "+
		"threat-feed checks, authentication rules and inspection are NOT enforced on SOCKS5 traffic "+
		"(contract SWG-901); see README \"Limitations & Known Gaps\" and docs/operator/socks5-listener-health.md", port)
}

// checkSOCKS5PolicyEnforcement is the report-only `socks5_policy_enforcement`
// row. Contributes NO row when SOCKS5 is not configured, so a normal
// appliance's report and verdict are unchanged.
func checkSOCKS5PolicyEnforcement() []OperatorContractCheck {
	port := socks5LegacyPolicyPort.Load()
	if port <= 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   socks5PolicyEnforcementCode,
		Status: diagWarn,
		Message: fmt.Sprintf("SOCKS5 policy enforcement: legacy (not enforced). The SOCKS5 listener on port %d does not apply "+
			"policy rules, the default action, threat-feed checks, authentication rules or SSL inspection, and logs no "+
			"identity or rule for SOCKS5 requests. It does apply the IP filter, rate and connection limits, its own "+
			"username/password check (local admin credential or legacy provider only, not the IdP registry), the blocklist, "+
			"plugins and the private-destination (SSRF) guard (contract SWG-901)", port),
		OperatorAction: "If SOCKS5 is not needed, remove -socks5-port / proxy.socks5_port and restart. Otherwise restrict who " +
			"can reach the port (IP filter allowlist, blocklist allow mode, host firewall) and route clients that must be " +
			"governed by policy through the HTTP/HTTPS proxy. Report-only: SOCKS5 traffic handling is unchanged.",
	}}
}

// resetSOCKS5LegacyPolicyPostureForTest clears the configured marker. Test
// isolation only.
func resetSOCKS5LegacyPolicyPostureForTest() {
	socks5LegacyPolicyPort.Store(0)
}
