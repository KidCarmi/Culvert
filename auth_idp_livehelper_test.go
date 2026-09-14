package main

// liveIdPSet wraps bare providers in the liveIdP envelope the registry stores
// (CHAOS-66 paired each compiled provider with the fingerprint of the profile
// it was compiled from). Tests that hand-build a live set care only about the
// provider, so they get the zero fingerprint — which never matches a computed
// one and therefore always recompiles, the fail-safe direction.
func liveIdPSet(m map[string]IdentityProvider) map[string]*liveIdP {
	out := make(map[string]*liveIdP, len(m))
	for id, prov := range m {
		out[id] = &liveIdP{provider: prov}
	}
	return out
}
