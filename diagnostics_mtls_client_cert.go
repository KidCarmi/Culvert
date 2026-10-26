package main

// diagnostics_mtls_client_cert.go — operator-contract row for the upstream mTLS
// client certificate.
//
// loadMTLSClientCert records whether the configured client certificate loaded
// and when it expires (mtls_ocsp_startup.go), but only GET /api/ocsp surfaced it.
// The one-page diagnostics report, where an operator checks "is this node healthy",
// stayed green while upstream mutual-TLS was silently not being offered (failed
// load) or about to stop being accepted (expiry).
//
// Report-only: derived from the recorded status, no I/O, no change to which
// certificate is presented. Contributes nothing when no client certificate is
// configured. The message carries no file path and no load-error text (those
// can name filesystem layout); the OCSP panel keeps that detail.

import "fmt"

// mtlsClientCertWarnDays is the remaining-validity threshold below which the
// row turns to WARN, matching the 30-day Root CA rotation overlap.
const mtlsClientCertWarnDays = 30

// checkUpstreamMTLSClientCert returns zero or one row for the upstream mTLS
// client certificate.
func checkUpstreamMTLSClientCert() []OperatorContractCheck {
	mc := mtlsClientCertHealth()
	if !mc.configured {
		return nil
	}
	const action = "CA Management → OCSP revocation shows the client certificate file, expiry and last load error. " +
		"Replace the certificate and key files, then restart Culvert (client certificates are loaded at startup)."
	if !mc.loaded {
		return []OperatorContractCheck{{
			Code:           "upstream_mtls_client_cert",
			Status:         diagWarn,
			Message:        "upstream mTLS client certificate is configured but failed to load — upstream servers that require mutual TLS will reject this node",
			OperatorAction: action,
		}}
	}
	if mc.notAfter.IsZero() {
		return nil
	}
	days := daysUntil(mc.notAfter)
	switch {
	case days < 0:
		return []OperatorContractCheck{{
			Code:           "upstream_mtls_client_cert",
			Status:         diagWarn,
			Message:        "upstream mTLS client certificate has expired — upstream servers that require mutual TLS will reject this node",
			OperatorAction: action,
		}}
	case days < mtlsClientCertWarnDays:
		return []OperatorContractCheck{{
			Code:           "upstream_mtls_client_cert",
			Status:         diagWarn,
			Message:        fmt.Sprintf("upstream mTLS client certificate expires in %d days", days),
			OperatorAction: action,
		}}
	}
	return nil
}
