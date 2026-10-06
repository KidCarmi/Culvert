package main

// checkReleaseVerifyPosture makes the release-catalog signature break-glass
// visible on the operator contract. CULVERT_RELEASE_CATALOG_VERIFY=permissive
// (accept an unsigned catalog) or =disabled (skip verification) is a
// deliberate, logged break-glass, but until now the only places an operator
// could discover it were a single startup log line and the verify_mode field
// of GET /api/releases — so a node left in break-glass after an incident
// looked identical to a healthy one on the one report operators actually
// read. Report-only: it never changes the mode, verification, or what the
// manager accepts, and a node with Release Management not composed (or in
// the default enforce mode) contributes an OK row.
func checkReleaseVerifyPosture() OperatorContractCheck {
	rm := currentReleaseManager()
	if rm == nil {
		return OperatorContractCheck{
			Code:    "release_catalog_verify",
			Status:  diagOK,
			Message: "release management not composed on this node — no catalog signature policy in effect",
		}
	}
	switch rm.verifyMode {
	case VerifyPermissive:
		return OperatorContractCheck{
			Code:           "release_catalog_verify",
			Status:         diagWarn,
			Message:        "release catalog signature verification is PERMISSIVE (break-glass) — an UNSIGNED catalog is accepted; only a present-but-invalid signature is still rejected",
			OperatorAction: "Unset CULVERT_RELEASE_CATALOG_VERIFY (or set it to enforce) in the proxy environment and restart so unsigned catalogs are refused again; the current mode is also shown as verify_mode on the Release Management panel.",
		}
	case VerifyDisabled:
		return OperatorContractCheck{
			Code:           "release_catalog_verify",
			Status:         diagWarn,
			Message:        "release catalog signature verification is DISABLED (break-glass) — catalog contents are trusted without any signature check",
			OperatorAction: "Unset CULVERT_RELEASE_CATALOG_VERIFY (or set it to enforce) in the proxy environment and restart to restore signature enforcement; the current mode is also shown as verify_mode on the Release Management panel.",
		}
	default:
		return OperatorContractCheck{
			Code:    "release_catalog_verify",
			Status:  diagOK,
			Message: "release catalog signatures are enforced",
		}
	}
}
