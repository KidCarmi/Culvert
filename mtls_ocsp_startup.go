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
	"crypto/x509"
	"net/http"
	"sync"
	"time"
)

// mtlsClientCertMu guards mtlsClientCertState, which mirrors the outcome of
// the last upstream-mTLS client-cert load for the admin API. Without this,
// "no mTLS configured" and "mTLS configured but the cert failed to load /
// has since expired" are indistinguishable from the GUI — loadMTLSAndOCSP's
// own doc says a bad cert is "logged" and nothing else, so today the only
// way to tell them apart is grepping the process log for one startup line.
var mtlsClientCertMu sync.RWMutex
var mtlsClientCertState mtlsClientCertStatus

type mtlsClientCertStatus struct {
	configured bool
	loaded     bool
	file       string
	notAfter   time.Time
	lastError  string
}

func recordMTLSClientCertStatus(file string, loaded bool, notAfter time.Time, lastErr string) {
	mtlsClientCertMu.Lock()
	defer mtlsClientCertMu.Unlock()
	mtlsClientCertState = mtlsClientCertStatus{
		configured: true,
		loaded:     loaded,
		file:       file,
		notAfter:   notAfter,
		lastError:  lastErr,
	}
}

// mtlsClientCertHealth returns the current client-cert status for the
// admin API (apiOCSPConfig). Read-only; never mutates load behavior.
func mtlsClientCertHealth() mtlsClientCertStatus {
	mtlsClientCertMu.RLock()
	defer mtlsClientCertMu.RUnlock()
	return mtlsClientCertState
}

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
			recordMTLSClientCertStatus(cfg.ClientCertFile, false, time.Time{}, err.Error())
		} else {
			clientCert = &c
			var notAfter time.Time
			if leaf, perr := x509.ParseCertificate(c.Certificate[0]); perr == nil {
				notAfter = leaf.NotAfter
			}
			recordMTLSClientCertStatus(cfg.ClientCertFile, true, notAfter, "")
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
