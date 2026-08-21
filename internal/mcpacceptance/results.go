package mcpacceptance

// expectedRequiredIDs is the canonical set of REQUIRED criteria a complete Observe
// acceptance run must emit. A required criterion that is absent (a scenario that
// could not run at all) makes the overall result FAIL — there is no "best-effort
// PASS". Advisory criteria (e.g. evidence.denial_aggregated) are intentionally
// excluded.
//
// In authoritative mode the set is EXTENDED with the QUAL-6.1 effective-environment
// criteria that prove the operator-selected controls were actually consumed at
// runtime (policy, bind host, telemetry ownership, Admin/metrics supervision). These
// have no meaning in dev (no operator environment), so they are required only when
// authoritative.
func expectedRequiredIDs(authoritative bool) []string {
	ids := []string{
		"startup.ready", "startup.tls_reachable", "startup.oauth_metadata", "startup.disabled_binds_nothing",
		"tls.mtls_accept", "tls.mtls_reject",
		"oauth.valid", "oauth.missing", "oauth.malformed", "oauth.expired", "oauth.wrong_issuer", "oauth.wrong_audience", "oauth.missing_scope",
		"host.allowed", "host.bad", "origin.bad",
		"protocol.lifecycle", "protocol.malformed", "protocol.bad_version", "protocol.oversized",
		"inventory.known", "inventory.unknown", "inventory.admin_list", "inventory.cross_tenant_enum", "inventory.quarantined",
		"tenant.aa", "tenant.bb", "tenant.ab", "tenant.ba", "tenant.spoof_ignored", "tenant.no_leak",
		"policy.loaded", "policy.shared_snapshot", "policy.discovery_allow", "policy.quarantine_beats_allow", "policy.default_deny",
		"evidence.allow_committed",
		"metrics.telemetry_ready", "metrics.no_high_cardinality",
		"mgmt.disabled",
		"restart.recovery",
		"emergency.disable",
		"nonexec.tripwire", "nonexec.health",
	}
	if authoritative {
		ids = append(ids,
			"environment.policy_operator_selected",
			"environment.bind_host_effective",
			"environment.telemetry_operator_owned",
			"supervision.admin_reachable",
			"supervision.metrics_reachable",
		)
	}
	return ids
}

// computeOverall returns PASS only when every required criterion is present AND
// passed, the artifact identity is authoritative when the mode demands it, and no
// required criterion failed. It returns the list of missing required IDs so the
// caller can record them.
func computeOverall(criteria []CriterionResult, expected []string, authoritative bool, wantAuthoritative bool) (status Status, absent []string) {
	present := map[string]Status{}
	for i := range criteria {
		present[criteria[i].ID] = criteria[i].Status
	}
	var missing []string
	for _, id := range expected {
		if _, ok := present[id]; !ok {
			missing = append(missing, id)
		}
	}
	overall := StatusPass
	for i := range criteria {
		if criteria[i].Required && criteria[i].Status != StatusPass {
			overall = StatusFail
		}
	}
	if len(missing) > 0 {
		overall = StatusFail
	}
	if wantAuthoritative && !authoritative {
		overall = StatusFail
	}
	return overall, missing
}
