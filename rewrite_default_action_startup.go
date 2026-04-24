package main

// rewrite_default_action_startup.go — startup-time loader for the
// header-rewrite + default-policy-action slice (PR3 expansion, Batch 3).
//
// Preserves the original ordering: rewrite rules are applied first so
// they're observable by the time the default-action log line is
// emitted.

// loadRewriteAndDefaultAction applies cfg. rulesLoaded is the current
// count of policy rules (supplied by the shim via policyStore.List());
// when cfg.DefaultAction is empty and no rules are configured the
// loader defaults to "allow" (passthrough) with an advisory log,
// otherwise to "deny" (zero-trust).
func loadRewriteAndDefaultAction(cfg rewriteDefaultActionStartupConfig, rulesLoaded int) {
	if len(cfg.Rules) > 0 {
		rewriter.SetRules(cfg.Rules)
		logger.Printf("Rewrite: %d rule(s) loaded", len(cfg.Rules))
	}

	action := cfg.DefaultAction
	if action == "" {
		if rulesLoaded == 0 {
			action = "allow"
			logger.Printf("Policy: no rules configured; defaulting to Allow (passthrough). Add rules and set default_action: deny for Zero Trust.")
		} else {
			action = "deny"
		}
	}
	setDefaultPolicyAction(action)
	logger.Printf("Policy: default action: %s", action)
}
