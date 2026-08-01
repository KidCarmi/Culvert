package broker

import (
	"context"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// MaterializeFunc is the scoped materialization callback. It receives the credential
// kind and a lifetime-bounded Material view of only the secret fields the kind
// requires. The fields are INVALID after it returns; it MUST NOT retain them.
type MaterializeFunc func(kind profile.CredentialKind, m *provider.Material) error

// call is a single-flight in-flight fetch for one profile: concurrent cache-miss
// fetches for the same profile coalesce onto one provider call (stampede control).
type call struct {
	wg    sync.WaitGroup
	env   []byte
	lease provider.Lease
	kind  profile.CredentialKind
	err   error
}

// Materialize is phase 2. It re-validates the plan, invokes the injected
// pre-materialization gate BEFORE touching the cache or provider, then (only if the
// gate permits) obtains an encrypted envelope — from the cache for an eligible
// low-risk request, otherwise from a fresh single-flight provider fetch — and opens
// it inside a scoped, zeroizing callback. It returns a sanitized SafeResult plus the
// callback's own error. On any gate/validation failure the provider is not called,
// the cache is not decrypted, and no plaintext is created.
func (b *Broker) Materialize(ctx context.Context, plan CredentialPlan, gate PreMaterializationGate, cb MaterializeFunc) (SafeResult, error) {
	res := SafeResult{
		PlanID: plan.planID, ProfileID: plan.profileID, ProviderID: plan.providerID,
		Server: plan.server, ToolRefHash: toolRefHash(plan.tool),
		Operation: plan.operation, Risk: plan.risk, Rotation: stActive.String(),
	}
	if gate == nil || cb == nil {
		res.Reason = mcperr.ReasonMaterializationGateUnavailable
		return res, brokerErr(mcperr.ReasonMaterializationGateUnavailable, "gate and callback are required")
	}

	// Plan currency (cheap, no secret) BEFORE the gate.
	prof, ok := b.profiles.Current().Get(plan.profileID)
	if !ok {
		return fail(res, mcperr.ReasonCredentialProfileMissing, "profile no longer exists")
	}
	if !prof.Enabled() {
		return fail(res, mcperr.ReasonCredentialProfileDisabled, "profile is disabled")
	}
	if prof.Revision() != plan.profileRev {
		return fail(res, mcperr.ReasonCredentialVersionStale, "profile revision changed since planning")
	}

	// Pre-materialization gate — BEFORE any cache decrypt or provider fetch.
	decision, gerr := gate.Authorize(ctx, plan)
	if gerr != nil {
		return fail(res, mcperr.ReasonMaterializationGateUnavailable, "gate unavailable")
	}
	if !decision.Permit {
		return fail(res, mcperr.ReasonMaterializationGateDenied, "gate denied")
	}
	if plan.risk == profile.RiskHigh && !decision.DurableConfirmed {
		return fail(res, mcperr.ReasonMaterializationGateDenied, "high-risk operation lacks durable decision confirmation")
	}

	st := b.stateFor(plan.profileID)

	// Obtain an encrypted envelope (cache-serve for eligible low-risk, else fetch).
	env, lease, kind, cacheHit, err := b.obtainEnvelope(ctx, plan, prof, st)
	if err != nil {
		return fail(res, mcperr.ReasonOf(err), "materialization failed")
	}
	res.CacheHit = cacheHit
	res.Version = lease.Version
	res.IssuedAt = lease.IssuedAt
	res.Expiry = lease.Expiry
	res.Rotation = st.snapshotState().String()
	res.Revoked = st.snapshotRevoked()

	// Scoped materialization: open a FRESH handle from the envelope, run cb, zeroize.
	if err := b.runScoped(env, kind, cb); err != nil {
		// The callback's own error is returned verbatim to the caller, but the
		// SafeResult stays sanitized (no secret text).
		res.Reason = mcperr.ReasonNone
		return res, err
	}
	res.Materialized = true
	res.Reason = mcperr.ReasonNone
	return res, nil
}

// obtainEnvelope returns an encrypted envelope for the plan, either from the cache
// (only for an eligible low-risk request with a valid, fresh entry) or from a fresh
// single-flight provider fetch. High-risk requests NEVER use a cached fallback.
func (b *Broker) obtainEnvelope(ctx context.Context, plan CredentialPlan, prof profile.Profile, st *profileState) (env []byte, lease provider.Lease, kind profile.CredentialKind, cacheHit bool, err error) {
	lowRiskCacheOK := plan.risk == profile.RiskLow && prof.Failure().AllowLowRiskCachedFallback && prof.Cache().Enabled
	if lowRiskCacheOK {
		if e, ok := b.tryCacheServe(plan, prof, st); ok {
			// Re-validate the cached credential against THIS plan's scope/power (the
			// cache key is per-version, not per-plan, so a credential validated for a
			// broader/other plan must not be served to a narrower/different one).
			if verr := b.validateLeaseAgainstPlan(plan, prof, e.kind, e.lease); verr == nil {
				return e.env, e.lease, e.kind, true, nil // e.env is a private copy from get
			}
			zeroize(e.env)
			// Not usable for THIS plan ⇒ fall through to a fresh fetch (no stale fallback).
		}
	}
	env, lease, kind, err = b.fetch(ctx, plan, prof, st)
	if err != nil {
		return nil, provider.Lease{}, 0, false, err
	}
	// The leader validated its OWN plan in doFetch; a single-flight WAITER (or the
	// leader re-checked, harmlessly) validates the shared result against its plan.
	if verr := b.validateLeaseAgainstPlan(plan, prof, kind, lease); verr != nil {
		zeroize(env)
		return nil, provider.Lease{}, 0, false, verr
	}
	return env, lease, kind, false, nil
}

// tryCacheServe returns a valid, fresh, non-revoked cache entry (with a PRIVATE env
// copy) for the plan's usable version, or (nil,false). It re-checks freshness /
// revocation but NOT per-plan scope — the caller re-validates scope against its own
// plan. Consulted only for eligible low-risk requests; high-risk never reaches it.
func (b *Broker) tryCacheServe(plan CredentialPlan, prof profile.Profile, st *profileState) (*cacheEntry, bool) {
	now := b.now()
	st.mu.Lock()
	v, usable := st.usableVersion(now)
	st.mu.Unlock()
	if !usable {
		return nil, false
	}
	key := cacheKey{tenant: plan.tenant, server: plan.server, profile: plan.profileID, version: v}
	e, hit := b.cache.get(key) // e carries a private env copy made under the cache lock
	if !hit {
		return nil, false
	}
	fresh := !now.After(e.insertedAt.Add(prof.Cache().Freshness))
	if fresh && now.Before(e.lease.Expiry) && !st.snapshotRevokedVersion(v) {
		return e, true
	}
	zeroize(e.env)
	return nil, false
}

// fetch performs a single-flight provider fetch for the plan's profile, validates
// the returned lease/scope/power, seals the material into an envelope, caches it
// (encrypted), and records the current version. No lock is held during the provider
// call or the sealing.
func (b *Broker) fetch(ctx context.Context, plan CredentialPlan, prof profile.Profile, st *profileState) ([]byte, provider.Lease, profile.CredentialKind, error) {
	// Single-flight claim.
	b.stateMu.Lock()
	if c, ok := b.inflt[plan.profileID]; ok {
		b.stateMu.Unlock()
		c.wg.Wait()
		if c.err != nil {
			return nil, provider.Lease{}, 0, c.err
		}
		out := make([]byte, len(c.env))
		copy(out, c.env)
		return out, c.lease, c.kind, nil
	}
	c := &call{}
	c.wg.Add(1)
	b.inflt[plan.profileID] = c
	b.stateMu.Unlock()

	env, lease, kind, err := b.doFetch(ctx, plan, prof, st)
	c.env, c.lease, c.kind, c.err = env, lease, kind, err
	c.wg.Done()

	b.stateMu.Lock()
	delete(b.inflt, plan.profileID)
	b.stateMu.Unlock()

	if err != nil {
		return nil, provider.Lease{}, 0, err
	}
	out := make([]byte, len(env))
	copy(out, env)
	return out, lease, kind, nil
}

// doFetch is the leader path: provider call (bounded retries), validation, seal,
// cache, and current-version publication.
func (b *Broker) doFetch(ctx context.Context, plan CredentialPlan, prof profile.Profile, st *profileState) ([]byte, provider.Lease, profile.CredentialKind, error) {
	p, ok := b.provider(plan.providerID)
	if !ok {
		return nil, provider.Lease{}, 0, brokerErr(mcperr.ReasonProviderUnavailable, "provider not registered")
	}
	req := provider.Request{
		Profile: plan.profileID, Provider: plan.providerID, Tenant: plan.tenant,
		Environment: plan.environment, Server: plan.server, Resources: plan.resources,
		Operation: plan.operation, Kind: plan.kind, PowerCeiling: plan.powerCeiling,
		PlanID: plan.planID, TokenDigest: plan.tokenDigest, Deadline: plan.deadline,
	}
	if plan.tool != nil {
		req.Tools = []string{plan.tool.Name}
	}

	if err := b.acquireProvider(ctx); err != nil {
		return nil, provider.Lease{}, 0, err
	}
	result, ferr := b.fetchWithRetry(ctx, p, req)
	b.releaseProvider()
	if ferr != nil {
		_, out := sanitizeProviderError(ferr)
		return nil, provider.Lease{}, 0, out
	}
	if result == nil || result.Handle == nil {
		return nil, provider.Lease{}, 0, errInvalidMaterial("provider returned no material")
	}
	if err := b.validateLease(plan, prof, result); err != nil {
		result.Handle.Destroy() // zeroize unused material
		return nil, provider.Lease{}, 0, err
	}
	// Seal the provider handle into an encrypted envelope (consumes the handle).
	env, err := b.sealHandle(result.Handle)
	if err != nil {
		return nil, provider.Lease{}, 0, err
	}
	// Publish under the leaf lock: reject if the version was revoked during the fetch
	// (revoke racing materialization cannot publish a usable post-revoke handle).
	st.mu.Lock()
	if st.isRevoked(result.Lease.Version) {
		st.mu.Unlock()
		zeroize(env)
		return nil, provider.Lease{}, 0, brokerErr(mcperr.ReasonCredentialRevoked, "credential version was revoked during fetch")
	}
	st.setCurrent(result.Lease.Version)
	st.mu.Unlock()

	// Cache the encrypted envelope (a separate copy; eviction never touches the
	// copy returned for materialization).
	if prof.Cache().Enabled {
		cp := make([]byte, len(env))
		copy(cp, env)
		key := cacheKey{tenant: plan.tenant, server: plan.server, profile: plan.profileID, version: result.Lease.Version}
		_ = b.cache.put(&cacheEntry{
			env: cp, kind: result.Kind, lease: result.Lease,
			insertedAt: b.now(), expiry: result.Lease.Expiry, key: key,
		})
	}
	return env, result.Lease, result.Kind, nil
}

// fetchWithRetry calls the provider up to MaxRetries+1 times, retrying ONLY errors
// the provider classifies retryable. It never retries a non-retryable error (scope /
// tenant / revoked / malformed / gate / profile mismatch). It uses no wall-clock
// sleep (deterministic).
func (b *Broker) fetchWithRetry(ctx context.Context, p provider.Provider, req provider.Request) (*provider.Result, error) {
	var last error
	for attempt := 0; attempt <= b.lim.MaxRetries(); attempt++ {
		res, err := p.Fetch(ctx, req)
		if err == nil {
			return res, nil
		}
		last = err
		retryable, _ := sanitizeProviderError(err)
		if !retryable {
			return nil, err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// validateLease checks a provider Result against the plan. Thin wrapper over
// validateLeaseAgainstPlan (which is ALSO run for every consumer of a shared
// credential — cache hits and single-flight waiters — so a credential validated for
// one plan can never be materialized for a different plan without its own
// least-privilege check).
func (b *Broker) validateLease(plan CredentialPlan, prof profile.Profile, result *provider.Result) error {
	return b.validateLeaseAgainstPlan(plan, prof, result.Kind, result.Lease)
}

// validateLeaseAgainstPlan checks a lease/kind against ONE plan (never broadening):
// kind match, finite unexpired expiry, TTL within the profile maximum, and the
// effective scope/power window. It is idempotent and is run for the leader, every
// single-flight waiter, and every cache hit — so a shared credential is always
// re-validated against the plan actually consuming it.
func (b *Broker) validateLeaseAgainstPlan(plan CredentialPlan, prof profile.Profile, kind profile.CredentialKind, lease provider.Lease) error {
	if kind != plan.kind {
		return brokerErr(mcperr.ReasonCredentialKindUnsupported, "provider material kind does not match the plan")
	}
	if lease.Version == "" {
		return errInvalidMaterial("provider returned an empty credential version")
	}
	now := b.now()
	if !now.Before(lease.Expiry) {
		return brokerErr(mcperr.ReasonCredentialExpired, "provider credential is already expired")
	}
	issued := lease.IssuedAt
	if issued.IsZero() {
		issued = now
	}
	if lease.Expiry.Sub(issued) > prof.MaxTTL() {
		return brokerErr(mcperr.ReasonProviderInvalidMaterial, "provider lease TTL exceeds the profile maximum")
	}
	// Effective scope/power must not exceed the plan. High-risk requires scope proof.
	requireProof := plan.risk == profile.RiskHigh
	return profile.ValidateEffectiveScope(lease.Scope, plan.scopeBound(requireProof))
}

// sealHandle opens the provider handle's plaintext (scoped, zeroizing) and seals it
// under the broker KEK into an encrypted envelope. The handle is consumed (single
// use). The plaintext exists only inside WithPlaintext.
func (b *Broker) sealHandle(h *secret.Sealed) ([]byte, error) {
	var env []byte
	err := h.WithPlaintext(func(pt []byte) error {
		if len(pt) > b.lim.MaxEnvelopeBytes() {
			return errInvalidMaterial("provider material exceeds the maximum size")
		}
		e, serr := secret.Seal(pt, b.kek)
		if serr != nil {
			return brokerErr(mcperr.ReasonCacheIntegrityFailure, "could not seal provider material")
		}
		env = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return env, nil
}

// runScoped opens a FRESH single-use handle from the encrypted envelope, decodes the
// Material, runs the callback, and zeroizes the plaintext on success, error, and
// panic (WithPlaintext's deferred Destroy). The Material is marked dead after the
// callback so a retained reference reads nothing.
func (b *Broker) runScoped(env []byte, kind profile.CredentialKind, cb MaterializeFunc) error {
	sealed, err := secret.Open(env, b.kek)
	if err != nil {
		return brokerErr(mcperr.ReasonCacheIntegrityFailure, "could not open sealed material")
	}
	return sealed.WithPlaintext(func(pt []byte) error {
		m, derr := provider.DecodeMaterial(kind, pt, b.lim.MaxSecretFields(), b.lim.MaxSecretFieldBytes())
		if derr != nil {
			return derr
		}
		defer m.Close()
		return cb(kind, m)
	})
}

// fail stamps a reason on a SafeResult and returns it with a sanitized error.
func fail(res SafeResult, reason mcperr.Reason, detail string) (SafeResult, error) {
	res.Reason = reason
	res.Materialized = false
	return res, brokerErr(reason, detail)
}
