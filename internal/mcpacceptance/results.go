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
//
// Requiredness is decided by MEMBERSHIP IN expected, not by the per-criterion
// Required flag. The flag is a hand-written argument at ~44 call sites that
// duplicates the canonical list in expectedRequiredIDs, and the two used to be
// consulted for different things: the list decided PRESENCE, the flag decided
// FAILURE. So a criterion recorded with the right ID, a FAIL status and a mistyped
// Required:false satisfied the presence check and was skipped by the failure check
// — a failing startup.ready produced an overall PASS with nothing reported missing.
// That is this harness certifying a system it just watched fail, which is the one
// outcome an acceptance gate must never produce.
//
// The flag is still honoured ON TOP of the list (a criterion outside the expected
// set may still declare itself required), so this only ever adds failures. A
// criterion in the expected set that is flagged non-required is itself reported as
// a harness defect rather than silently absorbed: a gate that disagrees with itself
// about what it requires has not earned the right to issue a PASS.
func computeOverall(criteria []CriterionResult, expected []string, authoritative bool, wantAuthoritative bool) (status Status, absent []string) {
	required := make(map[string]bool, len(expected))
	for _, id := range expected {
		required[id] = true
	}
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
		isRequired := criteria[i].Required || required[criteria[i].ID]
		if isRequired && criteria[i].Status != StatusPass {
			overall = StatusFail
		}
		// Declaration drift: the canonical set says required, the call site said not.
		if required[criteria[i].ID] && !criteria[i].Required {
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
