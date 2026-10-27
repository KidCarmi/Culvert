package main

// diagnostics_ocsp_coverage.go — operator-contract row for the OCSP coverage gap.
//
// With revocation checking enabled, the OCSP panel (GET /api/ocsp) reports which
// TLS handshakes actually consult the checker (ocsp_coverage.go, CHAOS-65 OCSP-8)
// and the enable path logs the same gap once. The one-page diagnostics report,
// where an operator checks "is this node protected the way I configured it", did
// not carry it: an enabled checkbox with all-zero counters read as an all-clear
// while inspected HTTPS origin certificates are never revocation-checked.
//
// Report-only: derived from the constant coverage table and the checker's
// Enabled flag, no I/O, no change to which handshakes are checked. Contributes
// nothing while checking is off (the operator has not been promised anything).
// The message carries only the fixed path identifiers.

import "strings"

// checkOCSPCoverage returns zero or one row for the OCSP coverage gap.
func checkOCSPCoverage() []OperatorContractCheck {
	if !globalOCSP.Enabled() {
		return nil
	}
	gaps := ocspUncheckedEnforcingPaths()
	if len(gaps) == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "ocsp_coverage",
		Status: diagWarn,
		Message: "OCSP revocation checking is enabled but covers the upstream transport only — " +
			"these handshakes are NOT revocation-checked: " + strings.Join(gaps, ", "),
		OperatorAction: "CA Management → OCSP revocation shows the per-path coverage and counters. Do not treat zero revoked/fail-closed counts as proof that inspected HTTPS origins were checked; " +
			"use destination policy or threat feeds to block known-revoked sites until inspected-path coverage is available.",
	}}
}
