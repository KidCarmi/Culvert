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
	"path/filepath"
	"sync"
	"time"
)

// ocspTransportUpdate attaches the OCSP verify callbacks to the operator's
// TLS template inside a swapUpstreamTransport closure (P5.3 ownership).
// Shared by the startup slice's admin-restore path and the fenced POST
// /api/ocsp — one publication shape, never two.
func ocspTransportUpdate(old *http.Transport) *http.Transport {
	if upstreamOpTLSCfg == nil {
		upstreamOpTLSCfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if upstreamOpTLSCfg.MinVersion == 0 {
		upstreamOpTLSCfg.MinVersion = tls.VersionTLS13
	}
	ConfigureTLSConfigOCSP(upstreamOpTLSCfg)
	return cloneTransport(old)
}

// mtlsClientCertMu guards mtlsClientCertState, which mirrors the outcome of
// the last upstream-mTLS client-cert load for the admin API. Without this,
// "no mTLS configured" and "mTLS configured but the cert failed to load /
// has since expired" are indistinguishable from the GUI — loadMTLSAndOCSP's
// own doc says a bad cert is "logged" and nothing else, so today the only
// way to tell them apart is grepping the process log for one startup line.
var mtlsClientCertMu sync.RWMutex
var mtlsClientCertState mtlsClientCertStatus

// mtlsClientCertStatus is what the admin surface may learn about the
// upstream mTLS client certificate. FE-6B.0 closed the recorded finding
// that GET /api/ocsp — a VIEWER route — published the configured file PATH
// and the loader's RAW error text: the record now carries a BOUNDED reason
// (cert_file_missing | key_file_missing | load_failed) and neither the path
// nor the error ever enters it. The startup log line names the reason class
// and the file's base name only.
type mtlsClientCertStatus struct {
	configured bool
	loaded     bool
	notAfter   time.Time
	reason     string
}

func recordMTLSClientCertStatus(loaded bool, notAfter time.Time, reason string) {
	mtlsClientCertMu.Lock()
	defer mtlsClientCertMu.Unlock()
	mtlsClientCertState = mtlsClientCertStatus{
		configured: true,
		loaded:     loaded,
		notAfter:   notAfter,
		reason:     reason,
	}
}

// mtlsClientCertHealth returns the current client-cert status for the
// admin API (apiOCSPConfig). Read-only; never mutates load behavior.
func mtlsClientCertHealth() mtlsClientCertStatus {
	mtlsClientCertMu.RLock()
	defer mtlsClientCertMu.RUnlock()
	return mtlsClientCertState
}

// loadMTLSClientCert loads cfg's client cert/key pair (when both are set),
// recording the outcome via recordMTLSClientCertStatus for the admin API.
// Returns the loaded certificate, or nil if unconfigured or the load
// failed. Split out of loadMTLSAndOCSP to keep that function's cyclomatic
// complexity under the project's cyclop threshold (15).
func loadMTLSClientCert(cfg mtlsOCSPStartupConfig) *tls.Certificate {
	switch {
	case cfg.ClientCertFile != "" && cfg.ClientKeyFile != "":
		c, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			reason := mtlsClientCertReasonOf(cfg.ClientCertFile, cfg.ClientKeyFile)
			logger.Printf("mTLS: failed to load client cert %q (reason=%s)", sanitizeLog(filepath.Base(cfg.ClientCertFile)), reason)
			recordMTLSClientCertStatus(false, time.Time{}, reason)
			return nil
		}
		var notAfter time.Time
		if leaf, perr := x509.ParseCertificate(c.Certificate[0]); perr == nil {
			notAfter = leaf.NotAfter
		}
		recordMTLSClientCertStatus(true, notAfter, "")
		return &c
	case cfg.ClientCertFile != "" || cfg.ClientKeyFile != "":
		// One-sided config: FileConfig.validate doesn't reject a lone
		// client_cert_file/client_key_file, but tls.LoadX509KeyPair requires
		// both. Record this as a load failure — the operator clearly
		// attempted to configure mTLS — rather than silently reporting "not
		// configured", which would hide a broken config behind the same
		// state as "never touched this setting".
		reason := mtlsClientCertReasonOf(cfg.ClientCertFile, cfg.ClientKeyFile)
		logger.Printf("mTLS: client cert not loaded (reason=%s; both client_cert_file and client_key_file are required)", reason)
		recordMTLSClientCertStatus(false, time.Time{}, reason)
		return nil
	default:
		return nil
	}
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
	clientCert := loadMTLSClientCert(cfg)

	if clientCert == nil && !cfg.OCSPCheck {
		return
	}

	if cfg.OCSPCheck {
		globalOCSP.Enable()
		noteOCSPYAMLDesired(true) // FE-6B.0: the YAML-sourced desired state (an admin-saved one replaces it at load)
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
		logger.Printf("mTLS: client cert loaded (%s)", sanitizeLog(filepath.Base(cfg.ClientCertFile)))
	}
	if cfg.OCSPCheck {
		logger.Printf("OCSP: upstream certificate revocation checking enabled")
		// CHAOS-65 / OCSP-8: say what the control does NOT cover, at the one
		// moment an operator is reading this banner.
		logOCSPCoverageWarning()
	}
}
