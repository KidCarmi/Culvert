package main

// metrics_token_startup_config.go — resolved config for the /metrics
// Bearer-token slice (PR3 expansion, Batch 1).

// metricsTokenStartupConfig carries the resolved Bearer token used to
// protect /metrics. Value-type DTO; no methods.
type metricsTokenStartupConfig struct {
	// Token is the Bearer value. Empty ⇒ /metrics is served without auth.
	Token string
}

// resolveMetricsTokenStartupConfig is the single startup-time reader of
// fc.Proxy.MetricsToken. cliFlag is the dereferenced --metrics-token
// override (pass "" when unset). CLI precedence: flag > FileConfig.
func resolveMetricsTokenStartupConfig(fc *FileConfig, cliFlag string) metricsTokenStartupConfig {
	return metricsTokenStartupConfig{
		Token: firstStr(cliFlag, fc.Proxy.MetricsToken),
	}
}
