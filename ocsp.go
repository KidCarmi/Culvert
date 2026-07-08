package main

// ocsp.go — package-main glue for OCSP revocation checking, moved to
// internal/ocsp (ADR-0002). The alias shim keeps the startup slice, the
// diagnostics/status surfaces, and the test suite using the original
// unqualified names; the transport wiring below stays here because it is
// upstream-transport ownership glue (P5.3 / S6) referencing the singleton.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/KidCarmi/Culvert/internal/ocsp"
)

// OCSPChecker is re-exposed unqualified (engine type is ocsp.Checker).
type OCSPChecker = ocsp.Checker

// globalOCSP is the process-wide revocation checker (disabled until the
// mtls_ocsp startup slice or the admin API enables it).
var globalOCSP = ocsp.New()

// ConfigureTLSConfigOCSP installs the OCSP verify callbacks on a
// caller-owned *tls.Config. The caller MUST own cfg exclusively —
// typically cfg is the operator template upstreamOpTLSCfg held under
// upstreamTransportWriteMu, mutated inside a swapUpstreamTransport
// closure. Mutating a tls.Config while a TLS handshake is reading
// its fields is a documented data race; the swap path attaches a
// Clone (via cloneTLSConfig) of the operator template to the
// published transport so the published config is never the same
// pointer the caller mutates here.
//
// VerifyConnection is set alongside VerifyPeerCertificate so resumed
// sessions also undergo revocation checks (gosec G123).
func ConfigureTLSConfigOCSP(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	cfg.VerifyPeerCertificate = globalOCSP.VerifyPeerCertificate // #nosec G123 -- VerifyConnection is set immediately below
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		// For resumed sessions, VerifyPeerCertificate is not called, so we
		// run the OCSP check here as well.
		if len(cs.PeerCertificates) == 0 {
			return nil
		}
		rawCerts := make([][]byte, len(cs.PeerCertificates))
		for i, c := range cs.PeerCertificates {
			rawCerts[i] = c.Raw
		}
		var chains [][]*x509.Certificate
		if len(cs.VerifiedChains) > 0 {
			chains = cs.VerifiedChains
		}
		return globalOCSP.VerifyPeerCertificate(rawCerts, chains)
	}
}

// ConfigureTransportOCSP adds OCSP verification to a caller-owned
// *http.Transport's TLS configuration. P5.3: this function is the
// back-compat wrapper around ConfigureTLSConfigOCSP and MUST only be
// called inside a swapUpstreamTransport closure on a freshly-cloned
// transport — never on the currently-published transport. Mutating a
// published transport's TLSClientConfig races against in-flight TLS
// handshakes.
//
// Semantics preserved vs pre-P5.3:
//   - If TLSClientConfig is nil, a fresh *tls.Config with
//     MinVersion=TLS1.3 is allocated (the historical OCSP-only
//     default).
//   - VerifyPeerCertificate and VerifyConnection are installed.
func ConfigureTransportOCSP(t *http.Transport) {
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	ConfigureTLSConfigOCSP(t.TLSClientConfig)
}
