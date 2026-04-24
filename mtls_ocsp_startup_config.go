package main

// mtls_ocsp_startup_config.go — resolved config for the upstream-mTLS
// client-certificate + OCSP/CRL revocation-checking slice (PR3
// expansion, Batch 3).

// mtlsOCSPStartupConfig carries the resolved upstream-TLS hardening
// configuration. Value-type DTO; no methods.
type mtlsOCSPStartupConfig struct {
	// ClientCertFile is fc.Proxy.ClientCertFile — the PEM-encoded
	// client certificate presented to upstream servers that require
	// mutual TLS. Empty (together with ClientKeyFile) ⇒ mTLS disabled.
	ClientCertFile string
	// ClientKeyFile is fc.Proxy.ClientKeyFile — the matching private
	// key.
	ClientKeyFile string
	// OCSPCheck is fc.Proxy.OCSPCheck — when true, enables OCSP/CRL
	// revocation checking on upstream TLS certificates.
	OCSPCheck bool
}

// resolveMTLSOCSPStartupConfig is the single startup-time reader of
// fc.Proxy.ClientCertFile, fc.Proxy.ClientKeyFile, and fc.Proxy.OCSPCheck.
func resolveMTLSOCSPStartupConfig(fc *FileConfig) mtlsOCSPStartupConfig {
	return mtlsOCSPStartupConfig{
		ClientCertFile: fc.Proxy.ClientCertFile,
		ClientKeyFile:  fc.Proxy.ClientKeyFile,
		OCSPCheck:      fc.Proxy.OCSPCheck,
	}
}
