package limits

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// CredentialLimits is the immutable, validated bound set for the PR-4 credential
// broker (internal/mcp/credentials). It mirrors the AuthLimits / CatalogLimits
// pattern: an unexported Config, a single Validate gate, hard-cap ceilings, and no
// mutable singleton. Every dimension an attacker (or a misbehaving provider) can
// drive — profile count, cache entries/bytes, encrypted-material bytes, secret
// fields, provider concurrency, in-flight fetches, rotation/retry attempts, TTLs,
// freshness, grace, tombstones, cleanup work — is finite and validated. A zero,
// negative, inverted, or over-ceiling value fails construction (fail closed).
//
// These limits are Gateway-capability-scoped by construction: the broker holds
// ONE CredentialLimits for the Gateway broker; the Management capability never
// constructs or shares them (cross-capability shared limits are forbidden — a
// Management broker does not exist in PR-4).
//
// The zero CredentialLimits is invalid — construct with NewCredential or take
// DefaultCredential.

// Hard-cap ceilings for the credential surface.
const (
	capCredProfiles        = 1 << 16 // total profiles
	capCredProviders       = 4096    // registered providers
	capCredProfilesPerTen  = 1 << 14 // profiles per tenant
	capCredProfilesPerSrv  = 4096    // profiles per server
	capCredCacheEntries    = 1 << 18 // encrypted cache entries
	capCredCacheBytes      = 1 << 30 // total encrypted cache bytes (1 GiB)
	capCredEnvelopeBytes   = 1 << 20 // one encrypted credential envelope (1 MiB)
	capCredSecretFields    = 64      // secret fields in one credential
	capCredFieldBytes      = 1 << 16 // one secret field's plaintext bytes (64 KiB)
	capCredProviderConc    = 4096    // global provider-request concurrency
	capCredInflightPerProf = 256     // in-flight fetches per profile
	capCredRotationTries   = 16      // rotation attempts per cycle
	capCredRetries         = 16      // retry count per fetch
	capCredRetryDelay      = time.Minute
	capCredTTL             = 24 * time.Hour
	capCredFreshness       = 24 * time.Hour
	capCredGrace           = time.Hour
	capCredTombstones      = 1 << 18 // revocation tombstones retained
	capCredCleanupOps      = 4096    // cleanup work units per operation
)

// CredentialConfig is the mutable input to NewCredential. Every field must be set
// to a safe value.
type CredentialConfig struct {
	MaxProfiles          int           // total credential profiles
	MaxProviders         int           // registered providers
	MaxProfilesPerTenant int           // profiles per tenant
	MaxProfilesPerServer int           // profiles per server
	MaxCacheEntries      int           // encrypted cache entries (global)
	MaxCacheBytes        int           // total encrypted cache bytes (global)
	MaxEnvelopeBytes     int           // one encrypted credential envelope's bytes
	MaxSecretFields      int           // secret fields per credential
	MaxSecretFieldBytes  int           // one secret field's plaintext bytes
	MaxProviderConc      int           // global provider-request concurrency
	MaxInflightPerProf   int           // in-flight fetches per profile (stampede bound)
	MaxRotationAttempts  int           // rotation attempts per cycle
	MaxRetries           int           // retry count per fetch
	MaxRetryDelay        time.Duration // maximum retry backoff delay
	MaxCredentialTTL     time.Duration // maximum accepted credential lease TTL
	MaxCacheFreshness    time.Duration // maximum low-risk cache fallback freshness
	RotationGrace        time.Duration // bounded previous-version grace window
	MaxTombstones        int           // revocation tombstones retained
	MaxCleanupPerOp      int           // bounded cleanup work per operation
}

// CredentialLimits is an immutable, validated credential bound set.
type CredentialLimits struct{ c CredentialConfig }

// Accessors (all value receivers; the config is immutable after construction).

// MaxProfiles returns the configured bound.
func (l CredentialLimits) MaxProfiles() int { return l.c.MaxProfiles }

// MaxProviders returns the configured bound.
func (l CredentialLimits) MaxProviders() int { return l.c.MaxProviders }

// MaxProfilesPerTenant returns the configured bound.
func (l CredentialLimits) MaxProfilesPerTenant() int { return l.c.MaxProfilesPerTenant }

// MaxProfilesPerServer returns the configured bound.
func (l CredentialLimits) MaxProfilesPerServer() int { return l.c.MaxProfilesPerServer }

// MaxCacheEntries returns the configured bound.
func (l CredentialLimits) MaxCacheEntries() int { return l.c.MaxCacheEntries }

// MaxCacheBytes returns the configured bound.
func (l CredentialLimits) MaxCacheBytes() int { return l.c.MaxCacheBytes }

// MaxEnvelopeBytes returns the configured bound.
func (l CredentialLimits) MaxEnvelopeBytes() int { return l.c.MaxEnvelopeBytes }

// MaxSecretFields returns the configured bound.
func (l CredentialLimits) MaxSecretFields() int { return l.c.MaxSecretFields }

// MaxSecretFieldBytes returns the configured bound.
func (l CredentialLimits) MaxSecretFieldBytes() int { return l.c.MaxSecretFieldBytes }

// MaxProviderConc returns the configured bound.
func (l CredentialLimits) MaxProviderConc() int { return l.c.MaxProviderConc }

// MaxInflightPerProf returns the configured bound.
func (l CredentialLimits) MaxInflightPerProf() int { return l.c.MaxInflightPerProf }

// MaxRotationAttempts returns the configured bound.
func (l CredentialLimits) MaxRotationAttempts() int { return l.c.MaxRotationAttempts }

// MaxRetries returns the configured bound.
func (l CredentialLimits) MaxRetries() int { return l.c.MaxRetries }

// MaxRetryDelay returns the configured bound.
func (l CredentialLimits) MaxRetryDelay() time.Duration { return l.c.MaxRetryDelay }

// MaxCredentialTTL returns the configured bound.
func (l CredentialLimits) MaxCredentialTTL() time.Duration { return l.c.MaxCredentialTTL }

// MaxCacheFreshness returns the configured bound.
func (l CredentialLimits) MaxCacheFreshness() time.Duration { return l.c.MaxCacheFreshness }

// RotationGrace returns the configured bound.
func (l CredentialLimits) RotationGrace() time.Duration { return l.c.RotationGrace }

// MaxTombstones returns the configured bound.
func (l CredentialLimits) MaxTombstones() int { return l.c.MaxTombstones }

// MaxCleanupPerOp returns the configured bound.
func (l CredentialLimits) MaxCleanupPerOp() int { return l.c.MaxCleanupPerOp }

func credErr(detail string) error {
	return mcperr.New(mcperr.ReasonResourceLimit, "limits.credential", detail)
}

// Validate enforces positivity, hard-cap ceilings, and cross-field consistency.
func (c CredentialConfig) Validate() error {
	// Positive-and-capped integer bounds.
	posCaps := []struct {
		name string
		v    int
		cap  int
	}{
		{"MaxProfiles", c.MaxProfiles, capCredProfiles},
		{"MaxProviders", c.MaxProviders, capCredProviders},
		{"MaxProfilesPerTenant", c.MaxProfilesPerTenant, capCredProfilesPerTen},
		{"MaxProfilesPerServer", c.MaxProfilesPerServer, capCredProfilesPerSrv},
		{"MaxCacheEntries", c.MaxCacheEntries, capCredCacheEntries},
		{"MaxCacheBytes", c.MaxCacheBytes, capCredCacheBytes},
		{"MaxEnvelopeBytes", c.MaxEnvelopeBytes, capCredEnvelopeBytes},
		{"MaxSecretFields", c.MaxSecretFields, capCredSecretFields},
		{"MaxSecretFieldBytes", c.MaxSecretFieldBytes, capCredFieldBytes},
		{"MaxProviderConc", c.MaxProviderConc, capCredProviderConc},
		{"MaxInflightPerProf", c.MaxInflightPerProf, capCredInflightPerProf},
		{"MaxRotationAttempts", c.MaxRotationAttempts, capCredRotationTries},
		{"MaxRetries", c.MaxRetries, capCredRetries},
		{"MaxTombstones", c.MaxTombstones, capCredTombstones},
		{"MaxCleanupPerOp", c.MaxCleanupPerOp, capCredCleanupOps},
	}
	for _, p := range posCaps {
		if p.v <= 0 {
			return credErr(p.name + " must be positive")
		}
		if p.v > p.cap {
			return credErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	// Positive-and-capped duration bounds.
	durCaps := []struct {
		name string
		v    time.Duration
		cap  time.Duration
	}{
		{"MaxRetryDelay", c.MaxRetryDelay, capCredRetryDelay},
		{"MaxCredentialTTL", c.MaxCredentialTTL, capCredTTL},
		{"MaxCacheFreshness", c.MaxCacheFreshness, capCredFreshness},
		{"RotationGrace", c.RotationGrace, capCredGrace},
	}
	for _, p := range durCaps {
		if p.v <= 0 {
			return credErr(p.name + " must be positive")
		}
		if p.v > p.cap {
			return credErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	// Cross-field consistency.
	if c.MaxProfilesPerTenant > c.MaxProfiles {
		return credErr("MaxProfilesPerTenant cannot exceed MaxProfiles")
	}
	if c.MaxProfilesPerServer > c.MaxProfiles {
		return credErr("MaxProfilesPerServer cannot exceed MaxProfiles")
	}
	if c.MaxCacheFreshness > c.MaxCredentialTTL {
		return credErr("MaxCacheFreshness cannot exceed MaxCredentialTTL (a stale cache must not outlive the lease)")
	}
	if c.RotationGrace > c.MaxCredentialTTL {
		return credErr("RotationGrace cannot exceed MaxCredentialTTL")
	}
	// The cache must hold at least one maximum-size envelope; a cache smaller than
	// one permitted credential could never admit anything.
	if c.MaxCacheBytes < c.MaxEnvelopeBytes {
		return credErr("MaxCacheBytes must be at least one MaxEnvelopeBytes")
	}
	if c.MaxSecretFieldBytes > c.MaxEnvelopeBytes {
		return credErr("MaxSecretFieldBytes cannot exceed MaxEnvelopeBytes")
	}
	if c.MaxInflightPerProf > c.MaxProviderConc {
		return credErr("MaxInflightPerProf cannot exceed MaxProviderConc")
	}
	return nil
}

// NewCredential validates the config into an immutable CredentialLimits.
func NewCredential(c CredentialConfig) (CredentialLimits, error) {
	if err := c.Validate(); err != nil {
		return CredentialLimits{}, err
	}
	return CredentialLimits{c: c}, nil
}

// DefaultCredential returns a conservative, valid credential bound set for tests
// and the dormant default wiring.
func DefaultCredential() CredentialLimits {
	l, err := NewCredential(CredentialConfig{
		MaxProfiles:          4096,
		MaxProviders:         64,
		MaxProfilesPerTenant: 512,
		MaxProfilesPerServer: 128,
		MaxCacheEntries:      8192,
		MaxCacheBytes:        64 << 20,
		MaxEnvelopeBytes:     64 << 10,
		MaxSecretFields:      16,
		MaxSecretFieldBytes:  16 << 10,
		MaxProviderConc:      64,
		MaxInflightPerProf:   8,
		MaxRotationAttempts:  3,
		MaxRetries:           3,
		MaxRetryDelay:        5 * time.Second,
		MaxCredentialTTL:     time.Hour,
		MaxCacheFreshness:    5 * time.Minute,
		RotationGrace:        30 * time.Second,
		MaxTombstones:        8192,
		MaxCleanupPerOp:      64,
	})
	if err != nil {
		panic("limits: DefaultCredential is invalid: " + err.Error())
	}
	return l
}
