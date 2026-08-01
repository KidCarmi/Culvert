package broker

import (
	"context"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Rotate performs an atomic-from-readers rotation for a profile: it fetches a
// successor via the provider, validates it, and only THEN publishes it as the new
// current version while moving the previous version into a bounded grace window. The
// current valid version stays usable throughout; a failed successor fetch/validation
// leaves the current version active. Concurrent rotations for one profile are
// rejected (ReasonRotationInProgress); rotations for different profiles are
// independent. No secret is copied into an error or metric.
func (b *Broker) Rotate(ctx context.Context, id profile.ID) (SafeResult, error) {
	res := SafeResult{ProfileID: id, Rotation: stActive.String()}
	prof, p, st, err := b.rotationPreconditions(id, res)
	if err != nil {
		return res, err
	}
	// Claim the rotation (reject a concurrent one). No provider call under the lock.
	prevVersion, hadCurrent, cerr := b.claimRotation(st, res)
	if cerr != nil {
		return res, cerr
	}

	clearRotating := func(final rotationState) {
		st.mu.Lock()
		st.rotating = false
		st.state = final
		st.mu.Unlock()
	}

	req := provider.Request{
		Profile: id, Provider: prof.Provider(), Tenant: prof.Tenant(),
		Environment: prof.Environment(), Server: prof.Server(),
		Operation: profile.OpRead, Kind: prof.Kind(), PowerCeiling: prof.Power(),
		PlanID: "rotate-" + string(id),
	}
	result, ferr := p.Rotate(ctx, req)
	if ferr != nil {
		clearRotating(stActive) // current version stays active
		res.Rotation = stActive.String()
		return fail(res, mcperr.ReasonRotationFailed, "successor fetch failed")
	}

	// Validate the successor BEFORE publishing it.
	st.mu.Lock()
	st.state = stSuccessorValidating
	st.mu.Unlock()
	if result == nil || result.Handle == nil {
		clearRotating(stRotationFailed)
		return fail(res, mcperr.ReasonRotationFailed, "provider returned no successor material")
	}
	if err := b.validateRotated(prof, result); err != nil {
		result.Handle.Destroy()
		clearRotating(stRotationFailed)
		return fail(res, mcperr.ReasonRotationFailed, "successor validation failed")
	}
	env, err := b.sealHandle(result.Handle)
	if err != nil {
		clearRotating(stRotationFailed)
		return fail(res, mcperr.ReasonRotationFailed, "could not seal successor material")
	}
	if err := b.publishSuccessor(id, prof, st, result, env, prevVersion, hadCurrent); err != nil {
		return fail(res, mcperr.ReasonRotationFailed, "successor version was revoked during rotation")
	}
	res.Version = result.Lease.Version
	res.Rotation = stActive.String()
	res.Reason = mcperr.ReasonNone
	return res, nil
}

// rotationPreconditions resolves the profile + provider and verifies rotation is
// supported. It returns a sanitized error (already stamped on res) on any failure.
func (b *Broker) rotationPreconditions(id profile.ID, res SafeResult) (profile.Profile, provider.Provider, *profileState, error) {
	prof, ok := b.profiles.Current().Get(id)
	if !ok {
		_, err := fail(res, mcperr.ReasonCredentialProfileMissing, "profile no longer exists")
		return profile.Profile{}, nil, nil, err
	}
	if !prof.Rotation().Enabled {
		_, err := fail(res, mcperr.ReasonProviderUnsupportedOperation, "profile does not enable rotation")
		return profile.Profile{}, nil, nil, err
	}
	p, ok := b.provider(prof.Provider())
	if !ok {
		_, err := fail(res, mcperr.ReasonProviderUnavailable, "provider not registered")
		return profile.Profile{}, nil, nil, err
	}
	if !p.Capabilities().CanRotate {
		_, err := fail(res, mcperr.ReasonProviderUnsupportedOperation, "provider cannot rotate")
		return profile.Profile{}, nil, nil, err
	}
	return prof, p, b.stateFor(id), nil
}

// claimRotation marks the profile as rotating (rejecting a concurrent rotation or a
// revoked profile) and returns the previous version + whether one existed.
func (b *Broker) claimRotation(st *profileState, res SafeResult) (profile.CredentialVersion, bool, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rotating {
		_, err := fail(res, mcperr.ReasonRotationInProgress, "a rotation is already in progress")
		return "", false, err
	}
	if st.revoked {
		_, err := fail(res, mcperr.ReasonCredentialRevoked, "profile is revoked")
		return "", false, err
	}
	st.rotating = true
	st.state = stRotationPending
	return st.currentVersion, st.hasCurrent, nil
}

// publishSuccessor atomically installs a validated successor as the new current
// version, moving the previous version into the bounded grace window, and caches its
// encrypted envelope. It rejects (and zeroizes) if the successor version was revoked
// mid-rotation.
func (b *Broker) publishSuccessor(id profile.ID, prof profile.Profile, st *profileState, result *provider.Result, env []byte, prevVersion profile.CredentialVersion, hadCurrent bool) error {
	st.mu.Lock()
	if st.isRevoked(result.Lease.Version) {
		st.mu.Unlock()
		zeroize(env)
		return brokerErr(mcperr.ReasonRotationFailed, "successor revoked mid-rotation")
	}
	if hadCurrent && prevVersion != "" {
		st.previousVersion = prevVersion
		st.previousGraceUntil = b.now().Add(prof.Rotation().Grace)
	}
	st.currentVersion = result.Lease.Version
	st.hasCurrent = true
	st.rotating = false
	st.state = stActive
	st.mu.Unlock()

	if prof.Cache().Enabled {
		key := cacheKey{tenant: prof.Tenant(), server: prof.Server(), profile: id, version: result.Lease.Version}
		_ = b.cache.put(&cacheEntry{env: env, kind: result.Kind, lease: result.Lease, insertedAt: b.now(), expiry: result.Lease.Expiry, key: key})
	} else {
		zeroize(env)
	}
	return nil
}

// validateRotated validates a successor lease against the profile's own scope bound
// (tenant/env/server/resources/power ceiling). Rotation has no per-request plan, so
// the profile scope is the bound.
func (b *Broker) validateRotated(prof profile.Profile, result *provider.Result) error {
	if result.Kind != prof.Kind() {
		return brokerErr(mcperr.ReasonCredentialKindUnsupported, "successor kind does not match the profile")
	}
	if result.Lease.Version == "" {
		return errInvalidMaterial("successor has an empty version")
	}
	now := b.now()
	if !now.Before(result.Lease.Expiry) {
		return brokerErr(mcperr.ReasonCredentialExpired, "successor is already expired")
	}
	bound := profile.ScopeBound{
		Tenant: prof.Tenant(), Environment: prof.Environment(), Server: prof.Server(),
		Resources: prof.Resources(), PowerCeiling: prof.Power(), RequireProof: true,
	}
	// Rotation validates against the profile ceiling only (no per-op floor).
	return profile.ValidateEffectiveScope(result.Lease.Scope, bound)
}
