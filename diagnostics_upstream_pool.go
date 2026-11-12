package main

// diagnostics_upstream_pool.go — operator-contract row for an upstream
// (parent-proxy) pool whose configuration was refused or could not be
// migrated.
//
// Three latched conditions leave configured parent proxies unpublished:
//   - the stored managed document (admin_settings.json upstream_proxies_v2)
//     failed validation at load, so its entries are not in use and every
//     managed mutation, import and key creation is refused;
//   - the config.yaml upstream seed was refused whole;
//   - the one-time legacy pool migration was abandoned (legacy file untouched).
//
// Each was visible only as a banner on Network → Upstream Proxies (and the
// /api/upstream JSON) plus a startup log line; the one-page Diagnostics report,
// where an operator checks "is this node healthy", stayed green while egress
// silently ran without the configured parents.
//
// Report-only: derived from the same getUpstreamState() snapshot that endpoint
// returns. Contributes nothing when none of the three is latched. Carries the
// bounded reason enums and counts only — never an authority, URL, username or
// credential. Pool loading, validation and egress behavior are unchanged.

import (
	"fmt"
	"strings"
)

// checkUpstreamPoolConfig returns a WARN row when the upstream pool's managed
// document, config.yaml seed or legacy migration is latched degraded.
func checkUpstreamPoolConfig() []OperatorContractCheck {
	st := getUpstreamState()
	var parts []string
	var actions []string
	if st.Degraded != nil {
		parts = append(parts, "the stored upstream document was refused at load ("+upstreamDegradedLabel(st.Degraded)+
			"): its parent proxies are NOT in use and every managed change, import and key creation is refused")
		actions = append(actions, "repair admin_settings.json (or restore a valid one) and restart the node")
	}
	if st.YAMLDegraded != nil {
		parts = append(parts, "the config.yaml upstream seed was refused whole ("+upstreamDegradedLabel(st.YAMLDegraded)+
			"): the parent proxies it lists were not applied")
		actions = append(actions, "correct the upstream section of config.yaml and reload")
	}
	if st.Migration.State == "degraded" {
		parts = append(parts, "the legacy upstream pool migration was abandoned ("+st.Migration.Reason+
			"): the legacy parent proxies are NOT in use and the legacy file was left untouched")
		actions = append(actions, "fix the cause named by the reason and restart so the migration runs again")
	}
	if len(parts) == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:    "upstream_pool_config",
		Status:  diagWarn,
		Message: "Upstream pool configuration is degraded: " + strings.Join(parts, "; "),
		OperatorAction: "Open Network → Upstream Proxies for the full state (effective mode, direct fallback, credential key). Then " +
			strings.Join(actions, "; ") + ". The row clears once the configuration loads cleanly.",
	}}
}

// upstreamDegradedLabel renders a bounded degradation: the reason enum plus
// its count when one was recorded.
func upstreamDegradedLabel(d *upstreamDegraded) string {
	if d.Count > 0 {
		return fmt.Sprintf("%s, %d", d.Reason, d.Count)
	}
	return d.Reason
}
