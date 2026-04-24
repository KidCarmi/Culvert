package main

// metrics_token_startup.go — startup-time loader for the /metrics Bearer
// token slice (PR3 expansion, Batch 1).
//
// No error path: the load is pure assignment + informational logging.

// loadMetricsToken assigns the package global metricsToken and logs
// whether /metrics is protected or open. Matches the pre-pilot init body
// byte-for-byte.
func loadMetricsToken(cfg metricsTokenStartupConfig) {
	metricsToken = cfg.Token
	if metricsToken != "" {
		logger.Printf("Metrics: /metrics protected by Bearer token")
	} else {
		logger.Printf("Metrics: /metrics open (set -metrics-token to restrict)")
	}
}
