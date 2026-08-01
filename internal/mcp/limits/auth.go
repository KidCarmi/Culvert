package limits

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// AuthLimits is the immutable, validated bound set for the PR-3 identity /
// token-validation / sender-constraint core. It mirrors the Limits and
// CatalogLimits pattern (unexported Config, single Validate gate, hard-cap
// ceilings, no mutable singleton). Every temporal and cache bound an attacker can
// drive is finite and validated: a zero, negative, inverted, or over-ceiling
// value fails construction (fail closed).
//
// The zero AuthLimits is invalid — callers construct one with NewAuth or take
// DefaultAuth.

// Hard-cap ceilings for the auth surface.
const (
	capTokenTTL        = 24 * time.Hour
	capClockSkew       = 5 * time.Minute
	capFutureNbf       = time.Hour
	capAuthAge         = 24 * time.Hour
	capDPoPProofAge    = 5 * time.Minute
	capNonceLifetime   = time.Hour
	capReplayEntries   = 1 << 20 // per-capability replay-cache cap ceiling
	capReplayPartition = 1 << 16 // per-partition entry ceiling
	capAuthTokenBytes  = 64 << 10
	capClaimBytes      = 64 << 10
	capScopes          = 4096
	capAudiences       = 256
)

// AuthConfig is the mutable input to NewAuth. Every field must be set.
type AuthConfig struct {
	MaxTokenTTL      time.Duration // finite maximum accepted token lifetime (exp-iat)
	ClockSkew        time.Duration // permitted clock skew each direction
	MaxFutureNbf     time.Duration // maximum nbf allowed in the future
	MaxAuthAge       time.Duration // maximum age of auth_time when an assurance requires it
	MaxDPoPProofAge  time.Duration // DPoP proof iat acceptance window
	NonceLifetime    time.Duration // server nonce lifetime
	MaxReplayEntries int           // per-capability replay-cache entry cap
	MaxReplayPerPart int           // per-partition entry cap (bounds one key's growth)
	MaxTokenBytes    int           // maximum raw token bytes accepted
	MaxClaimBytes    int           // maximum decoded claims-JSON bytes
	MaxScopes        int           // maximum scopes in one token
	MaxAudiences     int           // maximum audiences in one token
}

// AuthLimits is an immutable, validated auth bound set.
type AuthLimits struct{ c AuthConfig }

// MaxTokenTTL returns the finite maximum accepted token lifetime.
func (l AuthLimits) MaxTokenTTL() time.Duration { return l.c.MaxTokenTTL }

// ClockSkew returns the permitted clock skew.
func (l AuthLimits) ClockSkew() time.Duration { return l.c.ClockSkew }

// MaxFutureNbf returns the maximum nbf allowed in the future.
func (l AuthLimits) MaxFutureNbf() time.Duration { return l.c.MaxFutureNbf }

// MaxAuthAge returns the maximum accepted authentication age.
func (l AuthLimits) MaxAuthAge() time.Duration { return l.c.MaxAuthAge }

// MaxDPoPProofAge returns the DPoP proof acceptance window.
func (l AuthLimits) MaxDPoPProofAge() time.Duration { return l.c.MaxDPoPProofAge }

// NonceLifetime returns the server nonce lifetime.
func (l AuthLimits) NonceLifetime() time.Duration { return l.c.NonceLifetime }

// MaxReplayEntries returns the per-capability replay-cache entry cap.
func (l AuthLimits) MaxReplayEntries() int { return l.c.MaxReplayEntries }

// MaxReplayPerPart returns the per-partition entry cap.
func (l AuthLimits) MaxReplayPerPart() int { return l.c.MaxReplayPerPart }

// MaxTokenBytes returns the maximum raw token bytes accepted.
func (l AuthLimits) MaxTokenBytes() int { return l.c.MaxTokenBytes }

// MaxClaimBytes returns the maximum decoded claims-JSON bytes.
func (l AuthLimits) MaxClaimBytes() int { return l.c.MaxClaimBytes }

// MaxScopes returns the maximum scopes in one token.
func (l AuthLimits) MaxScopes() int { return l.c.MaxScopes }

// MaxAudiences returns the maximum audiences in one token.
func (l AuthLimits) MaxAudiences() int { return l.c.MaxAudiences }

func durCap(v, ceiling time.Duration, name string) error {
	if v <= 0 {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.auth", "non-positive limit "+name)
	}
	if v > ceiling {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.auth", "limit exceeds hard cap "+name)
	}
	return nil
}

// Validate reports whether the AuthConfig is safe and internally consistent.
func (c AuthConfig) Validate() error {
	for _, ck := range []struct {
		v, ceil time.Duration
		name    string
	}{
		{c.MaxTokenTTL, capTokenTTL, "MaxTokenTTL"},
		{c.ClockSkew, capClockSkew, "ClockSkew"},
		{c.MaxFutureNbf, capFutureNbf, "MaxFutureNbf"},
		{c.MaxAuthAge, capAuthAge, "MaxAuthAge"},
		{c.MaxDPoPProofAge, capDPoPProofAge, "MaxDPoPProofAge"},
		{c.NonceLifetime, capNonceLifetime, "NonceLifetime"},
	} {
		if err := durCap(ck.v, ck.ceil, ck.name); err != nil {
			return err
		}
	}
	for _, ck := range []struct {
		v, ceil int
		name    string
	}{
		{c.MaxReplayEntries, capReplayEntries, "MaxReplayEntries"},
		{c.MaxReplayPerPart, capReplayPartition, "MaxReplayPerPart"},
		{c.MaxTokenBytes, capAuthTokenBytes, "MaxTokenBytes"},
		{c.MaxClaimBytes, capClaimBytes, "MaxClaimBytes"},
		{c.MaxScopes, capScopes, "MaxScopes"},
		{c.MaxAudiences, capAudiences, "MaxAudiences"},
	} {
		if err := posCap(ck.v, ck.ceil, ck.name); err != nil {
			return err
		}
	}
	// Internal consistency: skew must be smaller than the whole token lifetime, the
	// DPoP window can never exceed the nonce lifetime it may pair with, and a
	// partition can never hold more than the whole per-capability cache.
	if c.ClockSkew >= c.MaxTokenTTL {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.auth", "ClockSkew >= MaxTokenTTL")
	}
	if c.MaxReplayPerPart > c.MaxReplayEntries {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.auth", "MaxReplayPerPart > MaxReplayEntries")
	}
	if c.MaxClaimBytes > c.MaxTokenBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.auth", "MaxClaimBytes > MaxTokenBytes")
	}
	return nil
}

// NewAuth validates c and returns an immutable AuthLimits, or an error.
func NewAuth(c AuthConfig) (AuthLimits, error) {
	if err := c.Validate(); err != nil {
		return AuthLimits{}, err
	}
	return AuthLimits{c: c}, nil
}

// authConfig is the conservative safe-default auth bound set.
var authConfig = AuthConfig{
	MaxTokenTTL:      time.Hour,
	ClockSkew:        60 * time.Second,
	MaxFutureNbf:     5 * time.Minute,
	MaxAuthAge:       12 * time.Hour,
	MaxDPoPProofAge:  60 * time.Second,
	NonceLifetime:    5 * time.Minute,
	MaxReplayEntries: 1 << 16, // 65,536 per capability
	MaxReplayPerPart: 4096,
	MaxTokenBytes:    16 << 10,
	MaxClaimBytes:    16 << 10,
	MaxScopes:        256,
	MaxAudiences:     16,
}

// DefaultAuth returns the validated default auth bound set.
func DefaultAuth() AuthLimits {
	l, err := NewAuth(authConfig)
	if err != nil {
		panic("mcp/limits: auth default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}
