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
		OperatorAction: "Upload a replacement certificate and matching key under Settings → Network & TLS (Certificates), then restart to activate it.",
	})
}
