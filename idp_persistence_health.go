package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/KidCarmi/Culvert/internal/audit"
)

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
//
// An enrolled data plane has a second durable copy: the last-known-good config
// snapshot it persists after every applied full snapshot or delta carries
// IdPProfiles, and applyDPLastGoodConfigSnapshot re-syncs the registry from it
// at startup (dp_enrollment.go). Such a DP is not warned while its registry
// still equals that snapshot's profiles. A standalone node, a DP that has not
// yet persisted a snapshot, one whose snapshot carried no profiles
// (unenrolled/redacted), one whose latest persist failed, or one whose registry
// was changed locally since the last persist is.

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

// idpProfilesFingerprint is a deterministic digest of a profile set in the
// form the registry stores it: cloned (cloneIdPProfiles, which also folds an
// empty slice into nil exactly as ReplaceAll's copy does) and write-normalized
// (normalizeIdPProfileWriteInput), then JSON-encoded in list order. Order is
// kept rather than sorted because ReplaceAll restores the snapshot's order and
// routing reads the registry in that order. Secrets are part of the digest on
// purpose — a local credential change is a divergence a restart would revert.
// The digest stays in process memory; ok is false when encoding fails.
func idpProfilesFingerprint(profiles []*IdPProfile) (fp [32]byte, ok bool) {
	canonical := cloneIdPProfiles(profiles)
	for _, p := range canonical {
		normalizeIdPProfileWriteInput(p)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return fp, false
	}
	return sha256.Sum256(data), true
}

// dpLastGoodSnapshotPersistsIdPProfiles reports whether this node is a data
// plane whose on-disk last-known-good snapshot carries exactly the IdP profiles
// the registry holds now, so a restart restores the current set. A local
// mutation (apiIdPList/apiIdPItem stay writable on a DP) updates the registry
// but never the last-good file, so it fails the comparison until the next
// persisted snapshot matches again.
func dpLastGoodSnapshotPersistsIdPProfiles() bool {
	if !audit.DPMode() || activeDPClient.Load() == nil || idpRegistry == nil {
		return false
	}
	st, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	if !st.Loaded || st.SaveError != "" || !st.HasIdPProfiles {
		return false
	}
	// All() deep-copies under the registry read lock; the digest is computed
	// after the lock is released.
	current, ok := idpProfilesFingerprint(idpRegistry.All())
	return ok && current == st.IdPProfilesFingerprint
}

func checkIdPPersistence() OperatorContractCheck {
	const code = "idp_profiles_persistence"
	persisted, n := idpRegistrySnapshotCounts()
	switch {
	case persisted:
		return OperatorContractCheck{Code: code, Status: diagOK,
			Message: "identity provider profiles are persisted to disk"}
	case dpLastGoodSnapshotPersistsIdPProfiles():
		return OperatorContractCheck{Code: code, Status: diagOK,
			Message: "identity provider profiles are synced from the control plane and persisted in this data plane's last-known-good config snapshot"}
	case n == 0:
		return OperatorContractCheck{Code: code, Status: diagOK,
			Message: "no identity providers configured (profiles would not survive a restart: no idp profiles file is set)"}
	}
	return OperatorContractCheck{
		Code:   code,
		Status: diagWarn,
		Message: fmt.Sprintf("%d identity provider profile(s) exist only in memory — they will be lost on restart or upgrade, "+
			"and SSO/LDAP sign-in will stop working until they are re-created", n),
		OperatorAction: "Set -idp-profiles-file (a file in the persistent data directory) or proxy.idp_profiles_file in config.yaml, " +
			"then restart. Export the current profiles first if you need to keep them.",
	}
}
