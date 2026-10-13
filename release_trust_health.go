package main

// checkReleaseCatalogTrust surfaces a break-glass release-catalog trust mode on
// the operator contract. CULVERT_RELEASE_CATALOG_VERIFY=permissive|disabled is
// read once at startup and is otherwise visible only as a startup log line and
// as a badge on the Releases panel; an appliance left in that state looks
// healthy everywhere else. Report-only: it reads the already-resolved mode and
// changes no trust, verification or release behaviour. Contributes nothing in
// enforce mode (or when release management is not wired), so a normal
// appliance's report is unchanged.
func checkReleaseCatalogTrust() []OperatorContractCheck {
	rm := currentReleaseManager()
	if rm == nil {
		return nil
	}
	var effect string
	switch rm.verifyMode {
	case VerifyPermissive:
		effect = "unsigned release catalogs are accepted (a present-but-invalid signature is still rejected)"
	case VerifyDisabled:
		effect = "release catalog signatures are not verified at all, so unsigned or forged catalogs are accepted"
	default:
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "release_catalog_trust",
		Status: diagWarn,
		Message: "release catalog signature verification is in break-glass mode (" +
			rm.verifyMode.String() + "): " + effect,
		OperatorAction: "Break-glass is meant to be temporary. Provision catalog trust keys (CULVERT_RELEASE_CATALOG_TRUST_KEYS) or rely on the baked trust roots, remove CULVERT_RELEASE_CATALOG_VERIFY from the appliance environment and restart to return to enforce. The Releases panel shows the current trust mode.",
	}}
}
