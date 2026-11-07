package main

import "fmt"

// idp_persistence_health.go — operator-contract row for IdP registry durability.
//
// Without -idp-profiles-file / proxy.idp_profiles_file the IdP registry is
// in-memory only: every profile an admin creates is lost on restart or upgrade,
// and SSO/LDAP sign-in silently stops working afterwards. The state was already
// known to the process — IdPRegistry.Persisted() feeds the banner on the IdP
// panel and a log line on every mutation — but an operator reading Diagnostics
// (where the roster and audit-trail equivalents live) never saw it.
//
// This row is a side-effect-free read of that same state. It changes no
// persistence, enforcement or authentication behaviour. The flag it reports is
// already exposed to viewers by GET /api/idp, so no role redaction is needed.

// idpRegistrySnapshotCounts returns durability and profile count under one lock
// (cheaper than All(), which deep-clones every profile).
func idpRegistrySnapshotCounts() (persisted bool, profiles int) {
	if idpRegistry == nil {
		return true, 0
	}
	idpRegistry.mu.RLock()
	defer idpRegistry.mu.RUnlock()
	return idpRegistry.path != "", len(idpRegistry.profiles)
}

func checkIdPPersistence() OperatorContractCheck {
	const code = "idp_profiles_persistence"
	persisted, n := idpRegistrySnapshotCounts()
	switch {
	case persisted:
		return OperatorContractCheck{Code: code, Status: diagOK,
			Message: "identity provider profiles are persisted to disk"}
	case n == 0:
		return OperatorContractCheck{Code: code, Status: diagOK,
			Message: "no identity providers configured (profiles would not survive a restart: no idp profiles file is set)"}
	}
	return OperatorContractCheck{
		Code:   code,
		Status: diagWarn,
		Message: fmt.Sprintf("%d identity provider profile(s) exist only in memory — they will be lost on restart or upgrade, "+
			"and SSO/LDAP sign-in will stop working until they are re-created", n),
		OperatorAction: "Set -idp-profiles-file (for example /data/idp_profiles.json) or proxy.idp_profiles_file in config.yaml, " +
			"then restart. Export the current profiles first if you need to keep them.",
	}
}
