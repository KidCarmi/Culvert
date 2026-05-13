package main

// mtls_ocsp_startup.go — startup-time loader for the upstream-mTLS +
// OCSP/CRL revocation-checking slice (PR3 expansion, Batch 3;
// updated for P5.3 / S6 ownership).
//
// Neither sub-step is fatal: a failed client-cert load is logged and
// upstream connections proceed without mTLS (matches original
// behaviour); OCSP is best-effort by design.
//
// P5.3 ownership: BOTH branches (mTLS + OCSP) compose into ONE
// transport swap so the new transport carries the fully-resolved
// TLS config before publication. No in-place mutation of the
// published transport occurs.

import (
	"crypto/tls"
	"net/http"
)

// loadMTLSAndOCSP applies cfg.
//
// Behaviour preserved vs the pre-P5.3 implementation:
//   - Empty cfg ⇒ no-op (no swap).
//   - Bad cert ⇒ logged; mTLS not applied; OCSP still applied if
//     cfg.OCSPCheck=true.
//   - When the existing TLSClientConfig already has a non-zero
//     MinVersion (operator pre-set), it is preserved.
//   - When TLSClientConfig is fresh, the mTLS branch defaults
//     MinVersion to TLS 1.2; the OCSP-only branch defaults to TLS
//     1.3. This matches the pre-P5.3 asymmetry exactly.
//   - Existing Certificates / VerifyPeerCertificate / VerifyConnection
//     fields on a pre-set TLSClientConfig are replaced by this swap
//     (matches pre-P5.3 mutation behaviour).
func loadMTLSAndOCSP(cfg mtlsOCSPStartupConfig) {
	var clientCert *tls.Certificate
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			logger.Printf("mTLS: failed to load client cert: %v", err)
		} else {
			clientCert = &c
		}
	}

	// If neither mTLS nor OCSP applies, no transport state changes.
	if clientCert == nil && !cfg.OCSPCheck {
		return
	}

	if cfg.OCSPCheck {
		globalOCSP.Enable()
	}

	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		newT := cloneTransport(old)
		tlsCfg := cloneTLSConfig(newT.TLSClientConfig)
		if clientCert != nil {
			if tlsCfg.MinVersion == 0 {
				tlsCfg.MinVersion = tls.VersionTLS12
			}
			tlsCfg.Certificates = []tls.Certificate{*clientCert}
		}
		if cfg.OCSPCheck {
			if tlsCfg.MinVersion == 0 {
				tlsCfg.MinVersion = tls.VersionTLS13
			}
			ConfigureTLSConfigOCSP(tlsCfg)
		}
		newT.TLSClientConfig = tlsCfg
		return newT
	})

	if clientCert != nil {
		logger.Printf("mTLS: client cert loaded (%s)", cfg.ClientCertFile)
	}
	if cfg.OCSPCheck {
		logger.Printf("OCSP: upstream certificate revocation checking enabled")
	}
}
