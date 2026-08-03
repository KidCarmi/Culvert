package cpdp

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Hard-cap ceilings. A Config value above its ceiling is unsafe and fails
// validation. These bound the worst-case memory/CPU a single snapshot or peer can
// force, independent of how a caller configures the safe-defaults.
const (
	capEnvelopeBytes        = 120 << 20 // 120 MiB — under the 128 MiB cluster gRPC frame
	capPayloadSectionBytes  = 64 << 20  // 64 MiB per payload section
	capRegistryServers      = 100_000
	capCatalogTools         = 500_000
	capPolicyRules          = 100_000
	capCredentialProfiles   = 100_000
	capInspectionProfiles   = 10_000
	capTrustRoots           = 64
	capKeyIDBytes           = 256
	capSignatureBytes       = 4096
	capAcksPerNodeCap       = 100_000
	capAckHistory           = 100_000
	capPendingAckRetries    = 1024
	capRetainedSnapshots    = 8
	capRetainedBytes        = 512 << 20
	capRollbackDirectives   = 4096
	capRollbackExpiry       = 24 * time.Hour
	capDryValidationCases   = 4096
	capConcurrentApplies    = 256
	capConcurrentPublish    = 256
	capConcurrentRollbacks  = 256
	capCanonicalDepth       = 256
	capCanonicalObjMembers  = 1 << 20
	capCanonicalArrElements = 1 << 20
	capCanonicalStringBytes = 8 << 20
)

// Config is the mutable input to NewLimits. Callers set every field; NewLimits
// validates it and returns an immutable Limits. A zero Config is invalid.
type Config struct {
	MaxEnvelopeBytes       int
	MaxPayloadSectionBytes int
	MaxAggregateBytes      int
	MaxRegistryServers     int
	MaxCatalogTools        int
	MaxPolicyRules         int
	MaxCredentialProfiles  int
	MaxInspectionProfiles  int
	MaxTrustRoots          int
	MaxKeyIDBytes          int
	MaxSignatureBytes      int
	MaxAcksPerNodeCap      int
	MaxAckHistory          int
	MaxPendingAckRetries   int
	MaxRetainedSnapshots   int
	MaxRetainedBytes       int
	MaxRollbackDirectives  int
	RollbackExpiry         time.Duration
	MaxDryValidationCases  int
	MaxConcurrentApplies   int
	MaxConcurrentPublish   int
	MaxConcurrentRollbacks int
}

// Limits is an immutable, validated bound set.
type Limits struct{ c Config }

// NewLimits validates a Config and returns an immutable Limits, or an error if
// any field is zero, negative, over its hard cap, or internally contradictory.
func NewLimits(c Config) (Limits, error) {
	type chk struct {
		v, ceil int
		name    string
	}
	for _, k := range []chk{
		{c.MaxEnvelopeBytes, capEnvelopeBytes, "MaxEnvelopeBytes"},
		{c.MaxPayloadSectionBytes, capPayloadSectionBytes, "MaxPayloadSectionBytes"},
		{c.MaxAggregateBytes, capEnvelopeBytes, "MaxAggregateBytes"},
		{c.MaxRegistryServers, capRegistryServers, "MaxRegistryServers"},
		{c.MaxCatalogTools, capCatalogTools, "MaxCatalogTools"},
		{c.MaxPolicyRules, capPolicyRules, "MaxPolicyRules"},
		{c.MaxCredentialProfiles, capCredentialProfiles, "MaxCredentialProfiles"},
		{c.MaxInspectionProfiles, capInspectionProfiles, "MaxInspectionProfiles"},
		{c.MaxTrustRoots, capTrustRoots, "MaxTrustRoots"},
		{c.MaxKeyIDBytes, capKeyIDBytes, "MaxKeyIDBytes"},
		{c.MaxSignatureBytes, capSignatureBytes, "MaxSignatureBytes"},
		{c.MaxAcksPerNodeCap, capAcksPerNodeCap, "MaxAcksPerNodeCap"},
		{c.MaxAckHistory, capAckHistory, "MaxAckHistory"},
		{c.MaxPendingAckRetries, capPendingAckRetries, "MaxPendingAckRetries"},
		{c.MaxRetainedSnapshots, capRetainedSnapshots, "MaxRetainedSnapshots"},
		{c.MaxRetainedBytes, capRetainedBytes, "MaxRetainedBytes"},
		{c.MaxRollbackDirectives, capRollbackDirectives, "MaxRollbackDirectives"},
		{c.MaxDryValidationCases, capDryValidationCases, "MaxDryValidationCases"},
		{c.MaxConcurrentApplies, capConcurrentApplies, "MaxConcurrentApplies"},
		{c.MaxConcurrentPublish, capConcurrentPublish, "MaxConcurrentPublish"},
		{c.MaxConcurrentRollbacks, capConcurrentRollbacks, "MaxConcurrentRollbacks"},
	} {
		if k.v <= 0 || k.v > k.ceil {
			return Limits{}, mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.limits", "bound out of range: "+k.name)
		}
	}
	if c.RollbackExpiry <= 0 || c.RollbackExpiry > capRollbackExpiry {
		return Limits{}, mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.limits", "RollbackExpiry out of range")
	}
	// A retained snapshot count of at least 2 (current + previous) is mandatory for
	// rollback; the payload section must fit inside the envelope; the aggregate
	// must not exceed the envelope.
	if c.MaxRetainedSnapshots < 2 {
		return Limits{}, mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.limits", "MaxRetainedSnapshots must be >= 2")
	}
	if c.MaxPayloadSectionBytes > c.MaxEnvelopeBytes || c.MaxAggregateBytes > c.MaxEnvelopeBytes {
		return Limits{}, mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.limits", "section/aggregate exceeds envelope bound")
	}
	return Limits{c: c}, nil
}

// DefaultLimits returns the validated production default bound set.
func DefaultLimits() Limits {
	l, err := NewLimits(Config{
		MaxEnvelopeBytes:       120 << 20,
		MaxPayloadSectionBytes: 64 << 20,
		MaxAggregateBytes:      100 << 20,
		MaxRegistryServers:     50_000,
		MaxCatalogTools:        200_000,
		MaxPolicyRules:         10_000,
		MaxCredentialProfiles:  10_000,
		MaxInspectionProfiles:  1_000,
		MaxTrustRoots:          16,
		MaxKeyIDBytes:          128,
		MaxSignatureBytes:      256,
		MaxAcksPerNodeCap:      10_000,
		MaxAckHistory:          50_000,
		MaxPendingAckRetries:   64,
		MaxRetainedSnapshots:   2,
		MaxRetainedBytes:       256 << 20,
		MaxRollbackDirectives:  256,
		RollbackExpiry:         30 * time.Minute,
		MaxDryValidationCases:  256,
		MaxConcurrentApplies:   16,
		MaxConcurrentPublish:   16,
		MaxConcurrentRollbacks: 16,
	})
	if err != nil {
		// The default set is validated by construction; a failure here is a
		// programming error, surfaced immediately rather than silently degraded.
		panic("cpdp: default limits invalid: " + err.Error())
	}
	return l
}

// Accessors (read-only; Limits is immutable once constructed).

func (l Limits) MaxEnvelopeBytes() int         { return l.c.MaxEnvelopeBytes }
func (l Limits) MaxPayloadSectionBytes() int   { return l.c.MaxPayloadSectionBytes }
func (l Limits) MaxAggregateBytes() int        { return l.c.MaxAggregateBytes }
func (l Limits) MaxRegistryServers() int       { return l.c.MaxRegistryServers }
func (l Limits) MaxCatalogTools() int          { return l.c.MaxCatalogTools }
func (l Limits) MaxPolicyRules() int           { return l.c.MaxPolicyRules }
func (l Limits) MaxCredentialProfiles() int    { return l.c.MaxCredentialProfiles }
func (l Limits) MaxInspectionProfiles() int    { return l.c.MaxInspectionProfiles }
func (l Limits) MaxTrustRoots() int            { return l.c.MaxTrustRoots }
func (l Limits) MaxKeyIDBytes() int            { return l.c.MaxKeyIDBytes }
func (l Limits) MaxSignatureBytes() int        { return l.c.MaxSignatureBytes }
func (l Limits) MaxAcksPerNodeCap() int        { return l.c.MaxAcksPerNodeCap }
func (l Limits) MaxAckHistory() int            { return l.c.MaxAckHistory }
func (l Limits) MaxPendingAckRetries() int     { return l.c.MaxPendingAckRetries }
func (l Limits) MaxRetainedSnapshots() int     { return l.c.MaxRetainedSnapshots }
func (l Limits) MaxRetainedBytes() int         { return l.c.MaxRetainedBytes }
func (l Limits) MaxRollbackDirectives() int    { return l.c.MaxRollbackDirectives }
func (l Limits) RollbackExpiry() time.Duration { return l.c.RollbackExpiry }
func (l Limits) MaxDryValidationCases() int    { return l.c.MaxDryValidationCases }
func (l Limits) MaxConcurrentApplies() int     { return l.c.MaxConcurrentApplies }
func (l Limits) MaxConcurrentPublish() int     { return l.c.MaxConcurrentPublish }
func (l Limits) MaxConcurrentRollbacks() int   { return l.c.MaxConcurrentRollbacks }

// CanonicalBounds derives the strict canonical-serializer bounds used to decode
// and hash a snapshot payload, sized from the envelope byte bound. It is exported
// so the publication coordinator can compute a content hash pre-sign with the same
// bounds the DP verifier uses.
func (l Limits) CanonicalBounds() canonical.Bounds {
	return canonical.Bounds{
		MaxBytes:         l.c.MaxEnvelopeBytes,
		MaxDepth:         capCanonicalDepth,
		MaxObjectMembers: capCanonicalObjMembers,
		MaxArrayElements: capCanonicalArrElements,
		MaxStringBytes:   capCanonicalStringBytes,
	}
}

// canonicalBounds is the unexported alias used within the package.
func (l Limits) canonicalBounds() canonical.Bounds { return l.CanonicalBounds() }
