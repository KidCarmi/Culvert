package main

// checkReleaseVerifyPosture makes the release-catalog signature break-glass
// visible on the operator contract. CULVERT_RELEASE_CATALOG_VERIFY=permissive
// (accept an unsigned catalog) or =disabled (skip verification) is a
// deliberate, logged break-glass, but until now the only places an operator
// could discover it were a single startup log line and the verify_mode field
// of GET /api/releases — so a node left in break-glass after an incident
// looked identical to a healthy one on the one report operators actually
// read. Report-only: it reads the already-resolved mode and never changes the
// mode, verification, or what the manager accepts. It contributes NO row in
// the default enforce mode or when Release Management is not composed on this
// node, so a normal appliance's report is unchanged.
func checkReleaseVerifyPosture() []OperatorContractCheck {
	rm := currentReleaseManager()
	if rm == nil {
		return nil
	}
	var msg string
	switch rm.verifyMode {
	case VerifyPermissive:
		// verifyIndexSignature consults a signature only for a CONFIGURED scheme
		// (ed25519 keys or Sigstore); with neither, permissive falls straight to
		// noArtifactOutcome and accepts the catalog, invalid signature or not.
		msg = "release catalog signature verification is PERMISSIVE (break-glass) — an UNSIGNED catalog is accepted; " +
			"a present-but-invalid signature is still rejected only for a configured trust scheme (operator or baked keys, or Sigstore), " +
			"so with no trust scheme configured every catalog is accepted"
	case VerifyDisabled:
		msg = "release catalog signature verification is DISABLED (break-glass) — catalog contents are trusted without any signature check, so unsigned or forged catalogs are accepted"
	default:
		return nil
	}
	return []OperatorContractCheck{{
		Code:    "release_catalog_verify",
		Status:  diagWarn,
		Message: msg,
		OperatorAction: "Break-glass is meant to be temporary. Make sure a catalog trust root is present (the baked roots, operator keys in " +
			envReleaseCatalogTrustKeys + ", or the Sigstore trusted root) — without one, Release Management is disabled in enforce mode — then remove " +
			envReleaseCatalogVerify + " (or set it to enforce) in the proxy environment and restart. The current mode is shown as verify_mode on the Release Management panel.",
	}}
}
