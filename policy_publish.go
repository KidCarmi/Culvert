package main

// policy_publish.go — a committed change to the RUNNING policy rulebase on a
// control plane is published to the fleet at commit.
//
// It was not. Rule create/update/delete, reorder, move, bulk delete, the
// auth-policy rule handlers, a draft commit, a policy-file reload and the
// object-rename cascades all changed the running rulebase and stopped there:
// the committed cluster snapshot kept the previous rules, every data plane
// answered "unchanged", and the edit reached the fleet only when some
// unrelated mutation that DOES publish (settings, PAC, IdP, import, rollback)
// happened to follow. That was never the design — the runtime inventory lists
// "Admin: any config mutator (e.g. policy upload) → globalConfigStore.Update"
// (roadmap/CLUSTER-RUNTIME-DISCOVERY.md), and pac.go records the same gap being
// closed for PAC exclusions ("waits for an UNRELATED mutation to bump the
// snapshot version").
//
// Every policy door publishes through publishRunningPolicyChange, so the rules
// below hold in one place:
//
//   - only on a control plane (a standalone gateway or a data plane has no
//     fleet to publish to; a data plane's rules are the control plane's);
//   - only AFTER the mutation is durably committed — each caller sits on its
//     handler's success path, past the persistence result;
//   - never for a staged (draft) edit: a candidate enforces nothing, and its
//     commit is the publish;
//   - once per request.
//
// A rejected publish (the snapshot is over a cluster-sync cap) is logged,
// alerted and latched by ConfigStore.rejectPublish exactly as for every other
// publisher (Diagnostics: LastPublishError). The local edit stands; the fleet
// stays on the last valid snapshot. Handlers whose response is a JSON object
// also report it inline as the established cluster_publish_rejected fact.

// publishRunningPolicyChange publishes the current configuration after door
// committed a change to the running policy rulebase. A no-op off a control
// plane. Returns the commit-time rejection, already logged and latched.
func publishRunningPolicyChange(door string) error {
	if !isControlPlaneRole() {
		return nil
	}
	err := publishCurrentConfigSnapshot()
	if err != nil {
		logger.Printf("Policy: %q is committed on this node but was NOT published to the fleet: %q",
			sanitizeLog(door), sanitizeLog(err.Error()))
	}
	return err
}

// runningPolicyGeneration is the running store's generation, for
// publishIfRunningPolicyChangedSince.
func runningPolicyGeneration() int64 {
	v, _ := policyStore.policyVersion()
	return v
}

// publishIfRunningPolicyChangedSince publishes when the running rulebase moved
// past before. For doors whose effect on the running rules is conditional: an
// object rename cascades onto the rules that reference the object, and a
// rename nothing references changes no rule.
func publishIfRunningPolicyChangedSince(before int64, door string) error {
	if runningPolicyGeneration() == before {
		return nil
	}
	return publishRunningPolicyChange(door)
}

// publishAfterPolicyFileReload publishes at the END of a configuration reload
// that re-read the policy file, so the snapshot carries the whole reloaded
// state. Nothing is published when no policy file is configured (path "") or
// the file was refused (accepted false: the running rules were kept).
func publishAfterPolicyFileReload(path string, accepted bool) {
	if path != "" && accepted {
		_ = publishRunningPolicyChange("config reload") // rejection is logged and latched (LastPublishError)
	}
}

// withClusterPublishRejection adds the established cluster_publish_rejected
// fact to a JSON-object response when the publish was rejected.
func withClusterPublishRejection(resp map[string]any, pubErr error) map[string]any {
	if pubErr != nil {
		resp["cluster_publish_rejected"] = pubErr.Error()
	}
	return resp
}
