package main

import "strings"

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
		// Published under the settings writer domain (uncontended at boot);
		// YAML-seeded rules receive stable identities at publication, made
		// durable by the first ordinary settings save (2D-C §21 YAML posture).
		publishRewriteRules(cfg.Rules)
		logger.Printf("Rewrite: %d rule(s) loaded", len(cfg.Rules))
	}

	action := cfg.DefaultAction
	if action == "" {
		switch env := strings.ToLower(strings.TrimSpace(cfg.EnvDefaultAction)); env {
		case "allow", "deny":
			action = env
			logger.Printf("Policy: default action %q set by %s (boot posture; a saved admin setting still wins)", action, defaultActionEnv)
		case "":
		default:
			logger.Printf("Policy: ignoring %s=%q (want allow or deny)", defaultActionEnv, sanitizeLog(env))
		}
	}
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
