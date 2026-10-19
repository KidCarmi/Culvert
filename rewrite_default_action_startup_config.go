package main

// rewrite_default_action_startup_config.go — resolved config for the
// header-rewrite + default-policy-action slice (PR3 expansion, Batch 3).

// rewriteDefaultActionStartupConfig carries the resolved inputs for the
// rewrite + default-action slice. Value-type DTO; no methods.
type rewriteDefaultActionStartupConfig struct {
	// Rules is fc.Rewrite — the configured header-rewrite rules.
	Rules []RewriteRule
	// DefaultAction is fc.DefaultAction ("allow", "deny", or ""). When
	// empty, the loader derives a safe default from the policy-rule
	// count (see loadRewriteAndDefaultAction).
	DefaultAction string
	// EnvDefaultAction is CULVERT_DEFAULT_ACTION as read by the shim ("allow",
	// "deny", or ""). It applies ONLY when DefaultAction (YAML) is empty and
	// replaces the rule-count auto-detect with an explicit boot posture — the
	// appliance's first-boot provisioning sets it to "deny" so a freshly
	// installed gateway does not pass traffic until a rule allows it. A
	// persisted admin choice (admin_settings.json) still wins at load time,
	// exactly as it does over the auto-detect. Anything else is ignored with
	// a warning (fail-safe: a typo must not flip a posture silently).
	EnvDefaultAction string
}

// resolveRewriteDefaultActionStartupConfig is the single startup-time
// reader of fc.Rewrite and fc.DefaultAction.
func resolveRewriteDefaultActionStartupConfig(fc *FileConfig, envDefaultAction string) rewriteDefaultActionStartupConfig {
	return rewriteDefaultActionStartupConfig{
		Rules:            fc.Rewrite,
		DefaultAction:    fc.DefaultAction,
		EnvDefaultAction: envDefaultAction,
	}
}

// defaultActionEnv is the boot-time posture override consumed by the shim.
const defaultActionEnv = "CULVERT_DEFAULT_ACTION"
