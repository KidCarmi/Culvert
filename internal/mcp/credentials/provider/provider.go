package provider

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// Capabilities declares, explicitly, which operations a provider supports. The
// broker never calls an unsupported operation — it returns
// ReasonProviderUnsupportedOperation instead.
type Capabilities struct {
	CanRotate  bool
	CanRevoke  bool
	CanInspect bool
}

// Request is the NON-SECRET input to a provider fetch/rotate. It is derived from the
// immutable plan and contains NO raw client token, Authorization header, DPoP proof,
// or access-token bytes — the upstream material always originates from the provider.
// The optional TokenDigest is the PR-3 one-way correlation digest, carried for safe
// correlation only and NEVER used as an upstream credential.
type Request struct {
	Profile      profile.ID
	Provider     profile.ProviderID
	Tenant       identity.TenantID
	Environment  profile.Environment
	Server       registry.ServerID
	Tools        []string
	Resources    profile.ResourceScope
	Operation    profile.OperationClass
	Kind         profile.CredentialKind
	PowerCeiling profile.CredentialPower
	PlanID       string    // sanitized correlation id
	TokenDigest  string    // PR-3 correlation digest ONLY; never a credential
	Deadline     time.Time // materialization deadline (metadata; no network in PR-4)
}

// Lease is the NON-SECRET metadata a provider returns alongside the sealed material.
// It contains no secret bytes and no provider secret path.
type Lease struct {
	Version   profile.CredentialVersion
	IssuedAt  time.Time
	Expiry    time.Time
	Scope     profile.EffectiveScope
	Rotatable bool
	Revocable bool
}

// Result is a provider fetch/rotate output: an OPAQUE single-use secret handle plus
// non-secret lease metadata and the credential kind. The handle is the only path to
// plaintext, and only through the broker's scoped callback.
type Result struct {
	Handle *secret.Sealed
	Kind   profile.CredentialKind
	Lease  Lease
}

// RevokeRequest is the non-secret input to a provider revoke.
type RevokeRequest struct {
	Profile  profile.ID
	Provider profile.ProviderID
	Version  profile.CredentialVersion
}

// Provider is the narrow, context-aware credential-provider interface. All methods
// are in-memory in PR-4 (no network). A provider returns an opaque secret handle and
// non-secret metadata, and NEVER returns raw secret material inside an error,
// string, metadata, or a loggable struct.
type Provider interface {
	// ID returns the provider's opaque identifier.
	ID() profile.ProviderID
	// Capabilities declares supported operations.
	Capabilities() Capabilities
	// Fetch materializes credential material for the request.
	Fetch(ctx context.Context, req Request) (*Result, error)
	// Rotate fetches and returns a successor version (only if CanRotate).
	Rotate(ctx context.Context, req Request) (*Result, error)
	// Revoke revokes a version at the provider (only if CanRevoke).
	Revoke(ctx context.Context, req RevokeRequest) error
	// Inspect returns non-secret lease metadata without materializing (only if
	// CanInspect).
	Inspect(ctx context.Context, req Request) (Lease, error)
}

// Classified is the OPTIONAL interface a well-behaved provider error implements so
// the broker can classify it WITHOUT reading its message text. The broker maps
// Reason() to a stable mcperr reason and honors Retryable(); it NEVER embeds the
// provider's Error() string (which may contain secret canaries) into the returned
// error.
type Classified interface {
	error
	// Reason returns a stable, non-secret classification reason.
	Reason() mcperr.Reason
	// Retryable reports whether the broker may retry (bounded).
	Retryable() bool
}

// providerError is a sanitized Classified error whose message is ONLY the reason
// code — it can carry no secret text by construction.
type providerError struct {
	reason    mcperr.Reason
	retryable bool
}

// Error is part of the error contract.
func (e *providerError) Error() string { return "credentials.provider: " + e.reason.Code() }

// Reason is part of the error contract.
func (e *providerError) Reason() mcperr.Reason { return e.reason }

// Retryable is part of the error contract.
func (e *providerError) Retryable() bool { return e.retryable }

// Common provider-error reasons (aliases for the deterministic test provider and
// adapters).
const (
	reasonUnavailable = mcperr.ReasonProviderUnavailable
	reasonUnsupported = mcperr.ReasonProviderUnsupportedOperation
)

// NewError returns a sanitized, classified provider error carrying only a reason
// code and a retryable flag — never secret text. Provider adapters should return
// this instead of a raw errors.New so their failures are safe to surface.
func NewError(reason mcperr.Reason, retryable bool) error {
	return &providerError{reason: reason, retryable: retryable}
}
