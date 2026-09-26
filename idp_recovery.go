package main

// idp_recovery.go — CHAOS-71: the way BACK for an IdP profile that could not
// be compiled.
//
// `IdPRegistry.Load` logs a compile error and moves on, leaving the profile
// Enabled in `r.profiles` and absent from `r.live`. Every accessor keys on
// `r.live`, so the profile is operationally INVISIBLE — and, before this file,
// PERMANENTLY so: nothing in the process ever retried, so an IdP that came
// back thirty seconds later stayed dark until a restart or an admin re-save.
// The reachable trigger is ordinary: on a host reboot the container and the
// network come up concurrently, and a few seconds of unresolvable DNS or
// unreachable egress is enough.
//
// That is the same shape CHAOS-55 closed for the fencing lease and CHAOS-57
// for the admin UI listener, and the same three rules apply.
//
//  1. **Retry is RATE-bounded, never COUNT-bounded.** The terminal state of
//     "give up" is an appliance whose SSO never comes back without an
//     operator, which is exactly the outcome being fixed. "Avoid infinite
//     retries" is satisfied the CHAOS-54/55/57 way — by the retry never being
//     SILENT: onset is logged immediately, then at most one line per
//     idpMetadataLogInterval, then one recovery line naming what came back,
//     with the magnitude carried by counters and the contract row.
//
//  2. **Jittered.** A fleet restarts together and a fleet's IdP outage ends
//     for everyone at once, so a fixed cadence aims a synchronised herd at an
//     IdP that is just recovering — the WK-13 shape this sweep found in the
//     config-sync path and must not reintroduce in its own fix.
//
//  3. **Recovery is declared on OBSERVED evidence only** — a provider that
//     actually compiled. Elapsed time never clears anything, because a loop
//     that stopped failing because it stopped attempting looks identical to a
//     healthy one.
//
// The loop is a no-op on a healthy appliance: it only runs while at least one
// ENABLED profile has no live provider, and it exits as soon as that set is
// empty.

import (
	"context"
	"time"
)

const (
	// idpRecoveryInitialDelay / idpRecoveryMaxDelay bound the backoff. The
	// floor is short because the dominant cause is boot ordering, which
	// resolves in seconds; the ceiling is well under the 30 s config-sync
	// cadence so a DP never waits longer for its IdP than for its config.
	idpRecoveryInitialDelay = 2 * time.Second
	idpRecoveryMaxDelay     = 5 * time.Minute

	// idpRecoveryJitter is the proportional spread applied to every wait,
	// reusing the shared jitterDuration helper rather than inventing a second
	// scheme.
	idpRecoveryJitter = 0.2
)

// idpEnabledInteractiveCounts reports how many ENABLED interactive profiles
// exist and how many of them have a live compiled provider.
//
// The gap between the two is the state that had no surface at all before
// CHAOS-71: a profile the operator enabled, that is persisted, that the admin
// UI lists, and that cannot authenticate anybody. It is deliberately computed
// over INTERACTIVE types only — an enabled LDAP profile that failed to compile
// is a credential-path concern already covered by the CHAOS-47 `authProbeGate`
// plane, and folding it in here would put two different faults behind one row.
func idpEnabledInteractiveCounts() (enabled, live int) {
	return idpRegistry.enabledInteractiveCounts()
}

func (r *IdPRegistry) enabledInteractiveCounts() (enabled, live int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p == nil || !p.Enabled || !p.Type.Interactive() {
			continue
		}
		enabled++
		if _, ok := r.live[p.ID]; ok {
			live++
		}
	}
	return enabled, live
}

// darkEnabledProfiles returns a copy of the ENABLED profiles that have no live
// provider. Copied under the read lock so the caller compiles without holding
// it — compileIdPProfile performs an outbound fetch, and holding r.mu across it
// would block every per-request accessor (HasEnabledInteractiveProvider runs on
// the proxy path) for the length of an IdP timeout. That is the CHAOS-50
// cluster-CA rule: never hold a lock across a call that reaches the network.
// darkCandidate pairs the registry's own profile pointer — which is the
// GENERATION TOKEN publishRecompiled compares by identity — with a deep COPY
// that the compile is free to mutate.
//
// The split is required because compiling writes into the profile:
// NewOIDCFlowProvider takes `cfg := p.OIDC` and assigns the five discovered
// endpoints through it ("Persist discovered endpoints back into the profile
// config so the UI can display them"), and the recovery compile deliberately
// runs OUTSIDE r.mu — so handing out the live pointer raced those writes
// against All()'s clone under the read lock, which could also serve a
// half-updated profile to the admin API (Codex review round 4).
type darkCandidate struct {
	generation *IdPProfile // registry identity; never compiled, never written here
	candidate  *IdPProfile // deep copy the compile may mutate freely
}

func (r *IdPRegistry) darkEnabledProfiles() []darkCandidate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []darkCandidate
	for _, p := range r.profiles {
		if p == nil || !p.Enabled {
			continue
		}
		if _, ok := r.live[p.ID]; !ok {
			clones := cloneIdPProfiles([]*IdPProfile{p})
			if len(clones) != 1 || clones[0] == nil {
				continue
			}
			out = append(out, darkCandidate{generation: p, candidate: clones[0]})
		}
	}
	return out
}

// publishRecompiled installs a provider for a profile that is still enabled,
// still present and still dark. Every one of those is re-checked UNDER the
// lock: the compile ran without it, so the profile may have been deleted,
// disabled, edited, or compiled by an admin write or a config snapshot in the
// meantime, and publishing then would resurrect a deleted IdP or overwrite a
// newer provider with one built from older config. Returns whether it published.
func (r *IdPRegistry) publishRecompiled(id string, generation, compiled *IdPProfile, prov IdentityProvider) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, live := r.live[id]; live {
		return false // an admin write or a snapshot got there first
	}
	for _, p := range r.profiles {
		if p == nil || p.ID != id {
			continue
		}
		if !p.Enabled || p != generation {
			return false // disabled, or replaced by a newer generation
		}
		// The compile ran against a COPY (see darkCandidate), so the endpoints
		// it discovered are on that copy. Carry them onto the authoritative
		// profile HERE, under the write lock, or the admin UI would silently
		// stop showing discovered endpoints for any provider this loop
		// recovered — losing the behaviour the writes exist for while fixing
		// the race they caused.
		copyDiscoveredOIDCEndpoints(p, compiled)
		r.live[id] = prov
		return true
	}
	return false // deleted while we were compiling
}

// copyDiscoveredOIDCEndpoints moves the five fields NewOIDCFlowProvider fills in
// from a compiled copy onto the authoritative profile. Callers must hold the
// registry write lock. It copies ONLY those five: everything else on the
// authoritative profile is operator-owned config the compile must never edit.
func copyDiscoveredOIDCEndpoints(dst, src *IdPProfile) {
	if dst == nil || src == nil || dst.OIDC == nil || src.OIDC == nil {
		return
	}
	dst.OIDC.AuthorizationEndpoint = src.OIDC.AuthorizationEndpoint
	dst.OIDC.TokenEndpoint = src.OIDC.TokenEndpoint
	dst.OIDC.IntrospectionEndpoint = src.OIDC.IntrospectionEndpoint
	dst.OIDC.UserinfoEndpoint = src.OIDC.UserinfoEndpoint
	dst.OIDC.JWKsURI = src.OIDC.JWKsURI
}

// runIdPRecoveryLoop retries compilation of enabled-but-dark profiles until
// none are left or ctx is cancelled. Started from the IdP startup slice; a
// no-op on a node where every enabled profile compiled.
func runIdPRecoveryLoop(ctx context.Context) {
	delay := idpRecoveryInitialDelay
	announced := false
	for {
		dark := idpRegistry.darkEnabledProfiles()
		if len(dark) == 0 {
			return // nothing to recover; the loop's whole job is done
		}
		if !announced {
			announced = true
			logger.Printf("IdP: %d enabled profile(s) have no live provider — retrying compilation every %s to %s until they do (browser SSO is unavailable for them meanwhile)",
				len(dark), idpRecoveryInitialDelay, idpRecoveryMaxDelay)
		}
		if !haSleepInterruptible(ctx.Done(), jitterDuration(delay, idpRecoveryJitter)) {
			return
		}
		recovered := 0
		for _, dc := range idpRegistry.darkEnabledProfiles() {
			// Compile the COPY: compiling writes discovered endpoints into the
			// profile, and this runs without r.mu held. The registry's own
			// pointer is passed only as the generation token.
			prov, err := compileIdPProfile(dc.candidate)
			if err != nil {
				continue // already counted + rate-limit-logged by the metadata plane
			}
			if idpRegistry.publishRecompiled(dc.candidate.ID, dc.generation, dc.candidate, prov) {
				recovered++
				logger.Printf("IDP_RECOVERED idp=%q — provider compiled and is now live; browser SSO is available again without a restart",
					sanitizeLog(dc.candidate.ID))
			}
		}
		if recovered > 0 {
			// Recovery on OBSERVED evidence: back off from the floor again so
			// a partially recovered set converges quickly.
			delay = idpRecoveryInitialDelay
			continue
		}
		if delay < idpRecoveryMaxDelay {
			delay *= 2
			if delay > idpRecoveryMaxDelay {
				delay = idpRecoveryMaxDelay
			}
		}
	}
}
