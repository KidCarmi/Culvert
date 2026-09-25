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
func (r *IdPRegistry) darkEnabledProfiles() []*IdPProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*IdPProfile
	for _, p := range r.profiles {
		if p == nil || !p.Enabled {
			continue
		}
		if _, ok := r.live[p.ID]; !ok {
			out = append(out, p)
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
func (r *IdPRegistry) publishRecompiled(id string, generation *IdPProfile, prov IdentityProvider) bool {
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
		r.live[id] = prov
		return true
	}
	return false // deleted while we were compiling
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
		for _, p := range idpRegistry.darkEnabledProfiles() {
			prov, err := compileIdPProfile(p)
			if err != nil {
				continue // already counted + rate-limit-logged by the metadata plane
			}
			if idpRegistry.publishRecompiled(p.ID, p, prov) {
				recovered++
				logger.Printf("IDP_RECOVERED idp=%q — provider compiled and is now live; browser SSO is available again without a restart",
					sanitizeLog(p.ID))
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
