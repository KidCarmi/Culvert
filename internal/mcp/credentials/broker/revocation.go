package broker

import (
	"context"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// RevokeVersion revokes a specific credential version immediately for all FUTURE
// materializations: it tombstones the version and invalidates matching encrypted
// cache entries BEFORE any provider call, so a later cache hit or a late provider
// result for that version fails. Repeated revocation is idempotent. A provider-side
// revoke failure is recorded as a sanitized failure while local use stays blocked.
func (b *Broker) RevokeVersion(ctx context.Context, id profile.ID, version profile.CredentialVersion) (SafeResult, error) {
	res := SafeResult{ProfileID: id, Version: version, Revoked: true, Rotation: stRevoked.String()}
	st := b.stateFor(id)

	// Local block FIRST (fail closed), then invalidate the cache, then the provider.
	st.mu.Lock()
	st.addTombstone(version, b.lim.MaxTombstones())
	if st.currentVersion == version {
		st.state = stRevoked
	}
	st.mu.Unlock()
	b.cache.invalidateVersion(id, version)

	if err := b.providerRevoke(ctx, id, version); err != nil {
		// Local use is already blocked; surface a sanitized provider failure.
		res.Reason = mcperr.ReasonRevocationFailed
		return res, err
	}
	res.Reason = mcperr.ReasonNone
	return res, nil
}

// providerRevoke best-effort revokes the version at the provider (if the provider
// supports revoke), under the global concurrency bound. Local revocation has
// already been committed by the caller, so any failure here keeps local use blocked.
func (b *Broker) providerRevoke(ctx context.Context, id profile.ID, version profile.CredentialVersion) error {
	prof, ok := b.profiles.Current().Get(id)
	if !ok {
		return nil
	}
	p, okp := b.provider(prof.Provider())
	if !okp || !p.Capabilities().CanRevoke {
		return nil
	}
	if aerr := b.acquireProvider(ctx); aerr != nil {
		return brokerErr(mcperr.ReasonRevocationFailed, "provider concurrency limit; local use remains blocked")
	}
	err := p.Revoke(ctx, provider.RevokeRequest{Profile: id, Provider: prof.Provider(), Version: version})
	b.releaseProvider()
	if err != nil {
		return brokerErr(mcperr.ReasonRevocationFailed, "provider revoke failed; local use remains blocked")
	}
	return nil
}

// RevokeProfile revokes an ENTIRE profile immediately: it marks the profile revoked
// and invalidates every cache entry for it. All future materializations fail closed.
// Idempotent.
func (b *Broker) RevokeProfile(id profile.ID) SafeResult {
	st := b.stateFor(id)
	st.mu.Lock()
	st.revoked = true
	st.state = stRevoked
	st.mu.Unlock()
	b.cache.invalidateProfile(id)
	return SafeResult{ProfileID: id, Revoked: true, Rotation: stRevoked.String()}
}
