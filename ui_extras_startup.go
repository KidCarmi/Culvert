package main

// ui_extras_startup.go — startup-time loader for the admin-UI TLS-SAN
// and trust-forwarded-headers slice (PR3 expansion, Batch 1).
//
// No error path: pure assignment to two package globals.

// loadUIExtras writes the resolved UI extras onto their package globals.
// uiExtraSANs is read by selfSignedTLS() in tls.go; trustForwardedHeaders
// gates X-Forwarded-* parsing in request helpers.
func loadUIExtras(cfg uiExtrasStartupConfig) {
	uiExtraSANs = cfg.ExtraSANs
	trustForwardedHeaders = cfg.TrustForwardedHeaders
}
