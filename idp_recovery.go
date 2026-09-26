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
	"sync/atomic"
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
		idpNotePublishedGeneration(id, effectiveRemoteSource(p), prov)
		return true
	}
	return false // deleted while we were compiling
}

// stillFetchesSourceLocked reports whether source is STILL the remote document a
// PRESENT, ENABLED profile of this generation depends on.
//
// It is publishRecompiled's re-check, read-only and on the FAILURE path. The
// recovery compile deliberately runs without r.mu (it reaches the network), so
// an admin delete, disable or repoint can commit while it is in flight; the
// success path already re-checks identity under the lock before publishing, and
// without this the failure path did not.
//
// THE CALLER MUST HOLD r.mu, and must still hold it when it acts on the answer:
// this used to take and release the lock itself, which made every caller a
// check-then-act across a lock release (round 17). The answer is true only for
// as long as the lock is held — that is the whole point.
func (r *IdPRegistry) stillFetchesSourceLocked(id string, generation *IdPProfile, source string) bool {
	for _, p := range r.profiles {
		if p == nil || p.ID != id {
			continue
		}
		if !p.Enabled || p != generation {
			return false // disabled, or replaced by a newer generation
		}
		return effectiveRemoteSource(p) == source
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

// retireStaleProvider stops serving a provider whose cached document has passed
// idpmeta.StaleMaxAge, leaving the profile ENABLED and STORED but with no live
// provider — i.e. DARK, exactly the state a fresh boot past the ceiling produces.
// Reports whether it changed anything, so the caller logs once per retirement.
//
// The profile is deliberately NOT disabled and NOT deleted: the operator's
// configuration is unchanged and still correct, it is the DOCUMENT that expired.
// Leaving it enabled-but-dark is what hands it to runIdPRecoveryLoop, which is
// both the fail-closed posture (browser SSO stops rather than trusting a
// withdrawn signing key) and the way back the moment the IdP answers again.
//
// THE SOURCE IS PART OF THE VERDICT, NOT DECORATION (Codex round 9). The sweep
// that selects a victim runs under idpMetadata.mu and RELEASES it before this
// lock is taken — deliberately, since retiring takes r.mu and no subsystem may
// hold another's lock across a call into it. So an admin Upsert/ReplaceAll can
// repoint the profile and publish a healthy provider for the NEW source inside
// that window, and an id-and-enabled check alone cannot tell the two apart: it
// would delete a provider that is serving correctly, taking browser SSO down
// for that profile until the recovery loop recompiles it. The expired document
// belonged to a (profile, SOURCE) pair, so the retirement is only valid while
// the profile is still serving THAT source.
//
// This is publishRecompiled's rule — re-check identity under the lock, because
// the decision was made without it — and round 8 applied it to the publish path
// and not to its twin. Skipping on a mismatch under-enforces nothing: a
// repointed profile is no longer serving the expired document at all, and if
// its new source also falls back to cache it records its own fetch time and is
// swept on its own.
func (r *IdPRegistry) retireStaleProvider(profileID, source string, servedAt time.Time) bool {
	if profileID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Only a profile this registry still holds as enabled may be retired: a
	// stale live entry for a profile that has since been deleted is not ours to
	// reason about, and deleting it here would race the mutation that removed it.
	for _, p := range r.profiles {
		if p == nil || p.ID != profileID || !p.Enabled {
			continue
		}
		// effectiveRemoteSource is the ONE derivation of a profile's remote
		// source (round 7's rule); comparing anything re-derived here is how
		// the two layers drift apart.
		if effectiveRemoteSource(p) != source {
			return false // repointed since the sweep selected it
		}
		// CLAIM THE EVIDENCE, do not merely compare the source. Round 9 closed
		// the REPOINT case with the comparison above, and a comparison is the
		// wrong instrument for the rest: a SAME-source refresh landing in the
		// sweep->lock window publishes a freshly-compiled healthy provider whose
		// source is unchanged, so the comparison passed and deleted it, taking
		// SSO dark until the recovery loop ran (Codex round 10, reproduced).
		//
		// The stale-serve stamp IS the generation token — every PUBLISH of this
		// profile rewrites it, and nothing else does (round 14: a fetch that
		// was never published must not) — so the retirement claims that exact
		// stamp atomically and refuses when it is no longer current. Three rounds of comparisons on this function is
		// what says the state was keyed wrongly rather than compared wrongly.
		if !idpClaimStaleServe(profileID, source, servedAt) {
			return false // republished or recovered since the sweep selected it
		}
		if _, live := r.live[profileID]; !live {
			return false // already dark; the recovery loop owns it
		}
		delete(r.live, profileID)
		return true
	}
	return false
}

// hasDarkEnabledProfile reports whether any enabled profile lacks a live
// provider. Cheaper than darkEnabledProfiles for the watchdog's supervision
// check, which runs every tick and clones nothing.
func (r *IdPRegistry) hasDarkEnabledProfile() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p == nil || !p.Enabled {
			continue
		}
		if _, ok := r.live[p.ID]; !ok {
			return true
		}
	}
	return false
}

// idpRecoveryRunning guards armIdPRecoveryLoop so at most one recovery loop runs.
var idpRecoveryRunning atomic.Bool

// armIdPRecoveryLoop starts the recovery loop unless one is already running.
//
// runIdPRecoveryLoop RETURNS once nothing is dark, and it was started exactly
// once from the startup slice — so before CHAOS-71 round 8 any LATER transition
// into dark (notably a staleness-ceiling retirement) had nothing retrying it, and
// SSO stayed down until a restart or a config change. That is strictly worse than
// the expired document the retirement exists to stop serving, which is why the
// retirement and this arming ship together.
//
// The CAS can lose a race against a loop that is about to exit and clear the
// flag, leaving nothing running for one interval. That is deliberate: the
// watchdog re-arms on EVERY tick while anything is dark, so the window closes by
// repetition within one idpMetadataWatchdogInterval instead of by holding a lock
// across a goroutine's lifetime.
func armIdPRecoveryLoop(ctx context.Context) {
	if !idpRecoveryRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer idpRecoveryRunning.Store(false)
		runIdPRecoveryLoop(ctx)
	}()
}

// discardSupersededRecoveryEpisode drops the failure episode a recovery compile
// just opened when the profile/source it was compiled for is no longer what the
// registry publishes. See the call site for why the failure path needs it and
// why the still-authoritative case must be left alone.
func discardSupersededRecoveryEpisode(dc darkCandidate) {
	src := idpRemoteDocumentSource(dc.candidate)
	if src == "" {
		return // fetches nothing; no episode of this kind exists
	}
	idpRegistry.forgetEpisodeIfSuperseded(dc.candidate.ID, dc.generation, src)
}

// forgetEpisodeIfSuperseded asks whether this generation still fetches source
// and, if it does not, forgets that episode — BOTH UNDER ONE HOLD OF r.mu
// (Codex round 17).
//
// Splitting them was a check-then-act across a lock release, the same class
// round 16 fixed in ReplaceAll: stillFetchesSource released r.mu before the
// forget, so a concurrent Upsert or ReplaceAll could republish the SAME profile
// and source from stale cache in the window — opening a LEGITIMATE episode
// under the identical key — which this superseded attempt then deleted. The
// published provider is then serving cached metadata with its degradation
// signal erased, and nothing restores it until the next fetch, so the alert the
// operator depends on simply never fires.
//
// A read lock is enough and a write lock would be wrong: every republisher
// takes r.mu.Lock(), so RLock excludes exactly the writers that can invalidate
// the answer, while leaving the proxy request path's own RLock unblocked. The
// order taken is r.mu -> idpMetadata.mu, the one this package already takes at
// retireEpisodeAfterCommit and at ReplaceAll's aborts.
func (r *IdPRegistry) forgetEpisodeIfSuperseded(id string, generation *IdPProfile, source string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stillFetchesSourceLocked(id, generation, source) {
		return // still in service: the episode is a live outage signal
	}
	forgetIdPMetadataEpisodeForSource(id, source)
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
				// Already counted + rate-limit-logged by the metadata plane —
				// but that episode may now belong to a source NOTHING fetches.
				//
				// The compile runs without r.mu, so an admin delete, disable or
				// repoint can commit while it is in flight. That mutation's own
				// cleanup (retireEpisodeAfterCommit) ran BEFORE this episode
				// existed, so the episode this failure just opened describes a
				// configuration no longer published: nothing will ever clear it
				// by evidence, it ages past idpMetadataDegradedAfter, and the
				// (unconditional) watchdog then pages indefinitely for a URL the
				// operator removed. Round 7's committed-repoint leak, reached
				// from the recovery loop instead of the commit path (Codex round
				// 12).
				//
				// The guard is what keeps this safe: an episode for the source
				// STILL IN SERVICE is a genuine outage signal and must survive
				// (rounds 6/7/9/10), so the discard happens ONLY once the source
				// is no longer authoritative for this profile.
				discardSupersededRecoveryEpisode(dc)
				continue
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
