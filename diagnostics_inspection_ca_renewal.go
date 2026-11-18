package main

// diagnostics_inspection_ca_renewal.go — operator-contract row for an SSL
// inspection Root CA that is close to expiry and that Culvert will NOT renew.
//
// Only a CA Culvert generated is renewed automatically (internal/ca
// provenance.go). An imported CA, or a legacy bundle with no provenance
// record, keeps signing until it expires and then every inspected HTTPS
// connection is refused. Inside the 30-day renewal window the rotation loop
// writes one log line per day and fires cert_expiry only when a webhook
// subscribes to it, while the root_ca row kept reading "root CA initialised"
// right up to the outage — the one-page health report said nothing.
//
// Report-only: reads certMgr's expiry and provenance, the same facts
// GET /api/ca/status already returns (expiresIn, autoRotation). No change to
// rotation, signing or trust. Contributes nothing for a Culvert-managed CA,
// for a CA with more than inspectionCARenewalWarnDays left, or for an expired
// CA (root_ca already reports that as a failure). Carries a day count and a
// provenance class only — no subject, path or key material.

import (
	"fmt"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// inspectionCARenewalWarnDays matches the auto-rotation overlap window
// (rotationOverlapDays on GET /api/ca/status): the point at which a managed CA
// would have been renewed.
const inspectionCARenewalWarnDays = 30

// checkInspectionCARenewal returns zero or one row.
func checkInspectionCARenewal() []OperatorContractCheck {
	if certMgr == nil || !certMgr.Ready() || caAutoRenewed() {
		return nil
	}
	expiry := certMgr.CAExpiry()
	if expiry.IsZero() {
		return nil
	}
	days := daysRemainingFloor(expiry)
	if days < 0 || days > inspectionCARenewalWarnDays {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "inspection_ca_renewal",
		Status: diagWarn,
		Message: fmt.Sprintf("the SSL inspection Root CA expires in %d day(s) and will NOT be renewed automatically "+
			"(provenance: %s) — when it expires, inspected HTTPS is refused, not bypassed", days, inspectionCAProvenanceLabel()),
		OperatorAction: inspectionCARenewalAction(certMgr.Provenance()),
	}}
}

func inspectionCAProvenanceLabel() string {
	if p := certMgr.Provenance(); p != ca.ProvenanceUnknown {
		return string(p)
	}
	return "unknown"
}

// inspectionCARenewalAction mirrors noteCARenewalWithheld's remedy, so the
// report, the log line and the cert_expiry alert give the same instruction.
func inspectionCARenewalAction(p ca.Provenance) string {
	if p == ca.ProvenanceUnknown {
		return "This CA bundle predates provenance tracking. If Culvert generated it, set " + caProvenanceEnv +
			"=culvert-managed and restart so it is renewed automatically; if your PKI issued it, set =imported and " +
			"upload a renewed CA under Certificates → Upload Custom Certificate (Target: MITM / SSL Inspection Engine) before it expires."
	}
	return "Obtain a renewed CA certificate from the issuing PKI, distribute it to clients, and upload it under " +
		"Certificates → Upload Custom Certificate (Target: MITM / SSL Inspection Engine) before it expires."
}
