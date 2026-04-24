package main

// mtls_ocsp_startup.go — startup-time loader for the upstream-mTLS +
// OCSP/CRL revocation-checking slice (PR3 expansion, Batch 3).
//
// Neither sub-step is fatal: a failed client-cert load is logged and
// upstream connections proceed without mTLS (matches original
// behaviour); OCSP is best-effort by design.

import "crypto/tls"

// loadMTLSAndOCSP applies cfg. No error return: the original
// initMTLSAndOCSP treated tls.LoadX509KeyPair failures as warnings and
// continued, and OCSP.Enable has no error path.
func loadMTLSAndOCSP(cfg mtlsOCSPStartupConfig) {
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			logger.Printf("mTLS: failed to load client cert: %v", err)
		} else {
			if upstreamTransport.TLSClientConfig == nil {
				upstreamTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			upstreamTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
			logger.Printf("mTLS: client cert loaded (%s)", cfg.ClientCertFile)
		}
	}

	if cfg.OCSPCheck {
		globalOCSP.Enable()
		ConfigureTransportOCSP(upstreamTransport)
		logger.Printf("OCSP: upstream certificate revocation checking enabled")
	}
}
