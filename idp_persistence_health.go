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
// An enrolled data plane has a second durable copy, and it takes precedence:
// the last-known-good config snapshot it persists after every applied full
// snapshot or delta carries IdPProfiles, and applyDPLastGoodConfigSnapshot
// re-syncs the registry from it at startup (dp_enrollment.go) — after, and over,
// any -idp-profiles-file load. Such a DP is ok only while its registry equals
// that snapshot's profiles and the latest persist succeeded; otherwise a
// restart restores something else, profiles file or not, and the row warns.
// When no loaded snapshot carries profiles (a standalone node, a DP that has
// not persisted one yet, or an unenrolled/redacted snapshot), the profiles file
// decides as on any other node.

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
// routing reads the registry in that order. The five OIDC endpoints discovery
// writes back (copyDiscoveredOIDCEndpoints) are excluded: they are proxy-derived,
// not configuration, and a restart re-derives them from the restored profile.
// Secrets are part of the digest on
// purpose — a local credential change is a divergence a restart would revert.
// The digest stays in process memory; ok is false when encoding fails.
func idpProfilesFingerprint(profiles []*IdPProfile) (fp [32]byte, ok bool) {
	canonical := cloneIdPProfiles(profiles)
	for _, p := range canonical {
		normalizeIdPProfileWriteInput(p)
		clearDiscoveredOIDCEndpoints(p)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return fp, false
	}
	return sha256.Sum256(data), true
}

// clearDiscoveredOIDCEndpoints blanks, on a canonical copy, exactly the fields
// copyDiscoveredOIDCEndpoints fills in from discovery. Configured OIDC fields
// and secrets are left in place so a genuine local change still differs.
func clearDiscoveredOIDCEndpoints(p *IdPProfile) {
	if p == nil || p.OIDC == nil {
		return
	}
	p.OIDC.AuthorizationEndpoint = ""
	p.OIDC.TokenEndpoint = ""
	p.OIDC.IntrospectionEndpoint = ""
	p.OIDC.UserinfoEndpoint = ""
	p.OIDC.JWKsURI = ""
}

// dpLastGoodIdPRestore describes what an enrolled data plane's on-disk
// last-known-good snapshot does to the IdP registry at the next startup.
type dpLastGoodIdPRestore struct {
	// governs: the snapshot carries IdPProfiles, so startup replaces the
	// registry with them (after, and over, any -idp-profiles-file load).
	governs bool
	// matches: the registry holds exactly that set now, so a restart keeps it.
	matches bool
	// saveFailed: the latest persist failed, so the file on disk is older.
	saveFailed bool
	restored   int
}

// dpLastGoodIdPRestoreState reports that for this node; the zero value off an
// enrolled DP or when no loaded snapshot carries IdP profiles. A local
// mutation (apiIdPList/apiIdPItem stay writable on a DP) updates the registry
// and any profiles file but never the last-good file, so it stops matching
// until the next persisted snapshot equals the registry again.
func dpLastGoodIdPRestoreState() dpLastGoodIdPRestore {
	if !audit.DPMode() || activeDPClient.Load() == nil || idpRegistry == nil {
		return dpLastGoodIdPRestore{}
	}
	st, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	if !st.Loaded || !st.HasIdPProfiles {
		return dpLastGoodIdPRestore{}
	}
	r := dpLastGoodIdPRestore{governs: true, saveFailed: st.SaveError != "", restored: st.IdPProfileCount}
	if !r.saveFailed && st.IdPProfilesFingerprintOK {
		// All() deep-copies under the registry read lock; the digest is
		// computed after the lock is released.
		current, ok := idpProfilesFingerprint(idpRegistry.All())
		r.matches = ok && current == st.IdPProfilesFingerprint
	}
	return r
}

func checkIdPPersistence() OperatorContractCheck {
	const code = "idp_profiles_persistence"
	persisted, n := idpRegistrySnapshotCounts()
	lg := dpLastGoodIdPRestoreState()
	switch {
	case lg.governs && lg.matches:
		return OperatorContractCheck{Code: code, Status: diagOK,
			Message: "identity provider profiles are synced from the control plane and persisted in this data plane's last-known-good config snapshot"}
	case lg.governs:
		return dpLastGoodIdPDivergenceCheck(code, lg, n)
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
		OperatorAction: "Set -idp-profiles-file (a file in the persistent data directory) or proxy.idp_profiles_file in config.yaml, " +
			"then restart. Export the current profiles first if you need to keep them.",
	}
}

// dpLastGoodIdPDivergenceCheck is the warning for a data plane whose restart
// restores a last-good profile set other than the registry it runs now. A
// profiles file does not help: startup re-syncs the snapshot over it.
func dpLastGoodIdPDivergenceCheck(code string, lg dpLastGoodIdPRestore, n int) OperatorContractCheck {
	if lg.saveFailed {
		return OperatorContractCheck{Code: code, Status: diagWarn,
			Message: fmt.Sprintf("this data plane's latest last-known-good config snapshot could not be saved — a restart restores "+
				"the older snapshot's %d identity provider profile(s) over the current registry and any profiles file", lg.restored),
			OperatorAction: "Fix the data plane's last-known-good persistence (free disk space or fix data directory permissions; " +
				"see the data plane log) so the next synced snapshot is saved."}
	}
	return OperatorContractCheck{Code: code, Status: diagWarn,
		Message: fmt.Sprintf("this data plane's identity provider registry (%d profile(s)) differs from its last-known-good config "+
			"snapshot (%d profile(s)), which a restart restores over it and over any profiles file — local identity provider "+
			"changes on a data plane are not durable", n, lg.restored),
		OperatorAction: "Make identity provider changes on the control plane; the next synced snapshot replaces the " +
			"last-known-good copy and this registry."}
}
