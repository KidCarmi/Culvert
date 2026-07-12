package main

// decryptprofile_vars.go — package-main glue for named SSL-decryption profiles,
// which live in internal/decryptprofile (mirrors the categorygroup.go shim over
// internal/catgroup). The alias shim keeps the API handlers, cluster sync
// (ConfigSnapshot.DecryptionProfiles), and config-version rollback on the
// original unqualified names.
//
// main owns the hot-path RESOLVERS that turn a matched rule's DecryptionProfile
// reference into a runtime decision (resolveStripALPN and the resolve*TLS/stall
// family in proxy.go / proxy_tunnel_h2.go); the engine exposes only the store.

import "github.com/KidCarmi/Culvert/internal/decryptprofile"

// DecryptionProfile is a named decryption profile (engine type
// decryptprofile.Profile).
type DecryptionProfile = decryptprofile.Profile

// DecryptionProfileStore manages persistent decryption profiles (engine type
// decryptprofile.Store).
type DecryptionProfileStore = decryptprofile.Store

// globalDecryptionProfiles is the process-wide decryption-profile store, read on
// the proxy hot path by the profile-aware resolvers and mutated by the admin API,
// config import, and CP→DP snapshot apply.
var globalDecryptionProfiles = decryptprofile.New()

// seedDefaultDecryptionProfiles adds the documented, NON-auto-bound "recommended-h2"
// profile as a safe on-ramp. Called on FIRST RUN ONLY (no profiles file existed), so
// an operator who deletes it keeps it deleted. It is not bound to any rule — enabling
// native H2 stays a deliberate per-rule choice.
func seedDefaultDecryptionProfiles() {
	h2 := true
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "recommended-h2", InspectHTTP2: &h2}); err != nil {
		logger.Printf("DecryptionProfiles: seed recommended-h2: %v", err)
		return
	}
	globalDecryptionProfiles.Save()
	logger.Printf("DecryptionProfiles: seeded 'recommended-h2' on-ramp profile (not bound to any rule)")
}
