package main

// mtls_ocsp_startup.go — startup-time loader for the upstream-mTLS +
// OCSP/CRL revocation-checking slice (PR3 expansion, Batch 3;
// updated for P5.3 / S6 ownership).
//
// Neither sub-step is fatal: a failed client-cert load is logged and
// upstream connections proceed without mTLS (matches original
// behaviour); OCSP is best-effort by design.
//
// P5.3 ownership: BOTH branches (mTLS + OCSP) update the operator's
// TLS template (upstreamOpTLSCfg) from inside a single swap closure.
// The swap then publishes a fresh transport with a Clone of the
// updated template attached. The stdlib's lazy h2 setup mutates the
// CLONE, never the template — so the next swap can read the
// template race-free.

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
//   - When the existing TLS template already has a non-zero
//     MinVersion (operator pre-set), it is preserved.
//   - When the template is fresh, the mTLS branch defaults
//     MinVersion to TLS 1.2; the OCSP-only branch defaults to TLS
//     1.3. This matches the pre-P5.3 asymmetry exactly.
//   - Existing Certificates / VerifyPeerCertificate / VerifyConnection
//     fields on a pre-set template are replaced by this update.
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

	if clientCert == nil && !cfg.OCSPCheck {
		return
	}

	if cfg.OCSPCheck {
		globalOCSP.Enable()
	}

	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		// Update upstreamOpTLSCfg under the held write mutex.
		// Subsequent swaps will attach a Clone of it.
		if upstreamOpTLSCfg == nil {
			upstreamOpTLSCfg = &tls.Config{} // #nosec G402 -- MinVersion set by the branches below
		}
		if clientCert != nil {
			if upstreamOpTLSCfg.MinVersion == 0 {
				upstreamOpTLSCfg.MinVersion = tls.VersionTLS12
			}
			upstreamOpTLSCfg.Certificates = []tls.Certificate{*clientCert}
		}
		if cfg.OCSPCheck {
			if upstreamOpTLSCfg.MinVersion == 0 {
				upstreamOpTLSCfg.MinVersion = tls.VersionTLS13
			}
			ConfigureTLSConfigOCSP(upstreamOpTLSCfg)
		}
		// Return a fresh transport carrying static config from old.
		// The swap will auto-attach a Clone of upstreamOpTLSCfg.
		return cloneTransport(old)
	})

	if clientCert != nil {
		logger.Printf("mTLS: client cert loaded (%s)", cfg.ClientCertFile)
	}
	if cfg.OCSPCheck {
		logger.Printf("OCSP: upstream certificate revocation checking enabled")
	}
}
