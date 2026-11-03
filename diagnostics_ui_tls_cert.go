package main

// diagnostics_ui_tls_cert.go — operator-contract row for the admin UI's own
// serving certificate.
//
// The admin UI's custom TLS certificate expiry, and a persisted cert/key pair
// that is corrupt (so every restart silently falls back to the self-signed
// certificate), were visible only on the Certificates panel. The one-page
// diagnostics report, where an operator checks "is this node healthy", stayed
// green until browsers started refusing the GUI.
//
// Also reports a saved-but-not-yet-serving uploaded pair (pending restart).
//
// Report-only: derived from the same state GET /api/settings/network already
// returns, no I/O, no change to TLS serving. Contributes nothing for the auto
// self-signed certificate or while a custom certificate has more than
// uiTLSCertWarnDays of validity left. Carries no certificate subject, path or
// key material — only a day count.

import "fmt"

// uiTLSCertWarnDays matches the 30-day window used for the upstream mTLS
// client certificate and the Root CA rotation overlap.
const uiTLSCertWarnDays = 30

// checkAdminUITLSCert returns zero or more rows for the admin UI certificate.
func checkAdminUITLSCert() []OperatorContractCheck {
	var rows []OperatorContractCheck
	if uiCustomTLSCorrupt {
		rows = append(rows, OperatorContractCheck{
			Code:   "ui_tls_cert_corrupt",
			Status: diagWarn,
			Message: "the uploaded admin UI certificate/key pair does not load as a matching pair — " +
				"the GUI is being served with the self-signed fallback certificate and will be after every restart",
			OperatorAction: "Upload a valid certificate and matching private key under Settings → Network & TLS (Certificates), then restart to activate it.",
		})
	}
	// A pair saved from the GUI only takes effect at the next restart. While
	// it is on disk, valid, and the running server is not using it, the
	// Certificates panel says so but the report did not. Also covers a pair
	// shadowed by explicit -tls-cert/-tls-key settings, which a restart will
	// not activate either, hence the wording below.
	if !uiCustomTLSCorrupt && !uiCustomTLSActive && customUITLSFilesPresent() {
		rows = append(rows, OperatorContractCheck{
			Code:   "ui_tls_cert_pending",
			Status: diagWarn,
			Message: "an uploaded admin UI certificate is saved but the GUI is not serving it — " +
				"it takes effect only after a restart, and not at all while -tls-cert/-tls-key (or tls_cert/tls_key in config.yaml) are set",
			OperatorAction: "Restart the proxy during a maintenance window to activate it. If the GUI still shows the old certificate after the restart, " +
				"remove the explicit -tls-cert/-tls-key setting, which takes precedence over an uploaded pair.",
		})
	}
	notAfter, known := adminUITLSCertExpiry()
	if !known {
		return rows
	}
	days := daysRemainingFloor(notAfter)
	if days > uiTLSCertWarnDays {
		return rows
	}
	msg := fmt.Sprintf("the admin UI TLS certificate expires in %d day(s) — browsers will refuse the GUI once it does", days)
	if days < 0 {
		msg = "the admin UI TLS certificate has expired — browsers will refuse the GUI until it is replaced"
	}
	return append(rows, OperatorContractCheck{
		Code:           "ui_tls_cert_expiry",
		Status:         diagWarn,
		Message:        msg,
		OperatorAction: uiTLSCertExpiryAction(uiCustomTLSActive),
	})
}

// uiTLSCertExpiryAction names the step that actually replaces the serving
// certificate for its source. A tracked expiry is always a custom pair: either
// the GUI-uploaded one (uploaded=true, uiCustomTLSActive) or an explicit
// -tls-cert/-tls-key flag or tls_cert/tls_key YAML path. resolveUITLSCertKey
// returns the explicit paths before it considers an uploaded pair, so telling
// that operator to upload and restart would leave the same certificate active.
// Names the setting, never its path: this row is not admin-only.
func uiTLSCertExpiryAction(uploaded bool) string {
	if uploaded {
		return "Upload a replacement certificate and matching key under Settings → Network & TLS (Certificates), then restart to activate it."
	}
	return "This certificate is set explicitly by the -tls-cert/-tls-key flags or tls_cert/tls_key in config.yaml, which take precedence over an uploaded pair. " +
		"Replace the certificate and key files at those configured paths, or remove the explicit setting and upload a replacement under " +
		"Settings → Network & TLS (Certificates), then restart to activate it."
}
