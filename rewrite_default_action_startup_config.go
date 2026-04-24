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
}

// resolveRewriteDefaultActionStartupConfig is the single startup-time
// reader of fc.Rewrite and fc.DefaultAction.
func resolveRewriteDefaultActionStartupConfig(fc *FileConfig) rewriteDefaultActionStartupConfig {
	return rewriteDefaultActionStartupConfig{
		Rules:         fc.Rewrite,
		DefaultAction: fc.DefaultAction,
	}
}
