// Package adminapi implements the tenant-scoped MCP Admin API domain services
// (inventory, decision query/explanation, policy validate/simulate/compare,
// local policy publication, approvals, health and configuration) that PR-9
// exposes through the existing Culvert admin HTTP surface and the read-only
// Management MCP tool catalog.
//
// The domain services here are transport-agnostic and RBAC-independent: HTTP
// handlers in package main and the Management MCP dispatcher both call the same
// services, and each enforces its own authorization before doing so. Nothing in
// this package performs upstream execution, materializes a credential, contacts
// a credential provider, or publishes a signed CP→DP snapshot — an ALLOW-class
// decision still returns execution_state=not_implemented, and local policy
// publication is reported as distribution_state=local_only until PR-10.
package adminapi

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Hard-cap ceilings for the admin surface. A Config value above its ceiling
// fails validation regardless of how a caller configures the defaults. The
// admin/Management surfaces are attacker-adjacent (an authenticated operator or
// Management token can drive request rate, candidate size, corpus size and
// output size), so every quantity is bounded here and construction fails closed
// on any zero, negative or over-ceiling value.
const (
	capMaxRequestBytes       = 4 << 20 // 4 MiB — one admin request body
	capMaxCandidateBytes     = 2 << 20 // 2 MiB — one candidate policy document
	capMaxPageSize           = 1000    // records per page
	capMaxQueryRange         = 366 * 24 * time.Hour
	capMaxFilters            = 32      // active filters on one query
	capMaxExplainEntries     = 4096    // trace/evidence entries in one explanation
	capMaxConcurrentSims     = 64      // concurrent simulations
	capMaxSimCorpus          = 1 << 16 // cases in one simulation corpus
	capMaxCompareSamples     = 4096    // changed-case samples in a comparison
	capMaxPendingApprovals   = 1 << 16 // pending approvals held in the projection
	capMaxApprovalsPerTenant = 4096    // pending approvals attributable to one tenant
	capMaxApprovalTTL        = 30 * 24 * time.Hour
	capMinApprovalTTL        = time.Minute
	capMaxPublicationReqs    = 4096    // pending publication requests
	capMaxMgmtTools          = 64      // Management tool catalog size
	capMaxMgmtInputBytes     = 2 << 20 // 2 MiB — one Management tool input
	capMaxMgmtOutputBytes    = 4 << 20 // 4 MiB — one Management tool result
	capMaxInventoryResults   = 1 << 16 // inventory records returned in one page set
	capMaxHealthBytes        = 1 << 20 // 1 MiB — one health snapshot
	capMaxGUIRows            = 5000    // rows a GUI view may request at once
	capMinConfigUpdateGap    = 0       // (see note) minimum gap is validated as >= 0
	capMaxProjectionScan     = 1 << 20 // records a projection rebuild may scan
	capMaxSpoolScanBytes     = 8 << 30 // bytes a bounded decision-query scan may read
)

// Config is the mutable input to NewLimits. A zero Config is invalid; every
// field must be set. Durations are validated for finiteness and range. Nothing
// here is a secret or a runtime-mutable singleton.
type Config struct {
	MaxRequestBytes       int
	MaxCandidateBytes     int
	MaxPageSize           int
	MaxQueryRange         time.Duration
	MaxFilters            int
	MaxExplainEntries     int
	MaxConcurrentSims     int
	MaxSimCorpus          int
	MaxCompareSamples     int
	MaxPendingApprovals   int
	MaxApprovalsPerTenant int
	ApprovalTTL           time.Duration
	MaxPublicationReqs    int
	MaxMgmtTools          int
	MaxMgmtInputBytes     int
	MaxMgmtOutputBytes    int
	MaxInventoryResults   int
	MaxHealthBytes        int
	MaxGUIRows            int
	MinConfigUpdateGap    time.Duration
	MaxProjectionScan     int
	MaxSpoolScanBytes     int
}

// Limits is an immutable, validated admin bound set. It mirrors the
// limits.Limits / EventLimits pattern: an unexported Config read only through
// accessors, a single Validate gate, hard-cap ceilings, and no mutable state.
type Limits struct{ c Config }

// NewLimits validates c and returns an immutable Limits, or a classified error.
func NewLimits(c Config) (Limits, error) {
	if err := c.Validate(); err != nil {
		return Limits{}, err
	}
	return Limits{c: c}, nil
}

// Validate enforces every bound is set, positive, finite and within its ceiling.
//
//nolint:gocyclo,cyclop,funlen // a flat table of independent bound checks
func (c Config) Validate() error {
	type check struct {
		name string
		val  int
		max  int
	}
	ints := []check{
		{"MaxRequestBytes", c.MaxRequestBytes, capMaxRequestBytes},
		{"MaxCandidateBytes", c.MaxCandidateBytes, capMaxCandidateBytes},
		{"MaxPageSize", c.MaxPageSize, capMaxPageSize},
		{"MaxFilters", c.MaxFilters, capMaxFilters},
		{"MaxExplainEntries", c.MaxExplainEntries, capMaxExplainEntries},
		{"MaxConcurrentSims", c.MaxConcurrentSims, capMaxConcurrentSims},
		{"MaxSimCorpus", c.MaxSimCorpus, capMaxSimCorpus},
		{"MaxCompareSamples", c.MaxCompareSamples, capMaxCompareSamples},
		{"MaxPendingApprovals", c.MaxPendingApprovals, capMaxPendingApprovals},
		{"MaxApprovalsPerTenant", c.MaxApprovalsPerTenant, capMaxApprovalsPerTenant},
		{"MaxPublicationReqs", c.MaxPublicationReqs, capMaxPublicationReqs},
		{"MaxMgmtTools", c.MaxMgmtTools, capMaxMgmtTools},
		{"MaxMgmtInputBytes", c.MaxMgmtInputBytes, capMaxMgmtInputBytes},
		{"MaxMgmtOutputBytes", c.MaxMgmtOutputBytes, capMaxMgmtOutputBytes},
		{"MaxInventoryResults", c.MaxInventoryResults, capMaxInventoryResults},
		{"MaxHealthBytes", c.MaxHealthBytes, capMaxHealthBytes},
		{"MaxGUIRows", c.MaxGUIRows, capMaxGUIRows},
		{"MaxProjectionScan", c.MaxProjectionScan, capMaxProjectionScan},
		{"MaxSpoolScanBytes", c.MaxSpoolScanBytes, capMaxSpoolScanBytes},
	}
	for _, ck := range ints {
		if ck.val <= 0 {
			return mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminlimits", ck.name+" must be > 0")
		}
		if ck.val > ck.max {
			return mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminlimits", ck.name+" exceeds ceiling")
		}
	}
	if c.MaxApprovalsPerTenant > c.MaxPendingApprovals {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminlimits", "MaxApprovalsPerTenant exceeds MaxPendingApprovals")
	}
	if c.MaxQueryRange <= 0 || c.MaxQueryRange > capMaxQueryRange {
		return mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminlimits", "MaxQueryRange out of range")
	}
	if c.ApprovalTTL < capMinApprovalTTL || c.ApprovalTTL > capMaxApprovalTTL {
		return mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminlimits", "ApprovalTTL out of range")
	}
	if c.MinConfigUpdateGap < capMinConfigUpdateGap {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminlimits", "MinConfigUpdateGap must be >= 0")
	}
	return nil
}

// Accessors — the only way to read a Limits value.

// MaxRequestBytes bounds one admin request body.
func (l Limits) MaxRequestBytes() int { return l.c.MaxRequestBytes }

// MaxCandidateBytes bounds one candidate policy document.
func (l Limits) MaxCandidateBytes() int { return l.c.MaxCandidateBytes }

// MaxPageSize bounds records per page.
func (l Limits) MaxPageSize() int { return l.c.MaxPageSize }

// MaxQueryRange bounds a query time range.
func (l Limits) MaxQueryRange() time.Duration { return l.c.MaxQueryRange }

// MaxFilters bounds active filters on one query.
func (l Limits) MaxFilters() int { return l.c.MaxFilters }

// MaxExplainEntries bounds evidence/trace entries in one explanation.
func (l Limits) MaxExplainEntries() int { return l.c.MaxExplainEntries }

// MaxConcurrentSims bounds concurrent simulations.
func (l Limits) MaxConcurrentSims() int { return l.c.MaxConcurrentSims }

// MaxSimCorpus bounds cases in one simulation corpus.
func (l Limits) MaxSimCorpus() int { return l.c.MaxSimCorpus }

// MaxCompareSamples bounds changed-case samples in a comparison.
func (l Limits) MaxCompareSamples() int { return l.c.MaxCompareSamples }

// MaxPendingApprovals bounds pending approvals held in the projection.
func (l Limits) MaxPendingApprovals() int { return l.c.MaxPendingApprovals }

// MaxApprovalsPerTenant bounds pending approvals attributable to one tenant.
func (l Limits) MaxApprovalsPerTenant() int { return l.c.MaxApprovalsPerTenant }

// ApprovalTTL is the bounded lifetime of an approval/publication request.
func (l Limits) ApprovalTTL() time.Duration { return l.c.ApprovalTTL }

// MaxPublicationReqs bounds pending publication requests.
func (l Limits) MaxPublicationReqs() int { return l.c.MaxPublicationReqs }

// MaxMgmtTools bounds the Management tool catalog size.
func (l Limits) MaxMgmtTools() int { return l.c.MaxMgmtTools }

// MaxMgmtInputBytes bounds one Management tool input.
func (l Limits) MaxMgmtInputBytes() int { return l.c.MaxMgmtInputBytes }

// MaxMgmtOutputBytes bounds one Management tool result (MCP-MGMT-004).
func (l Limits) MaxMgmtOutputBytes() int { return l.c.MaxMgmtOutputBytes }

// MaxInventoryResults bounds inventory records returned in one page set.
func (l Limits) MaxInventoryResults() int { return l.c.MaxInventoryResults }

// MaxHealthBytes bounds one health snapshot.
func (l Limits) MaxHealthBytes() int { return l.c.MaxHealthBytes }

// MaxGUIRows bounds rows a GUI view may request at once.
func (l Limits) MaxGUIRows() int { return l.c.MaxGUIRows }

// MinConfigUpdateGap is the minimum spacing between config updates.
func (l Limits) MinConfigUpdateGap() time.Duration { return l.c.MinConfigUpdateGap }

// MaxProjectionScan bounds records a projection rebuild may scan.
func (l Limits) MaxProjectionScan() int { return l.c.MaxProjectionScan }

// MaxSpoolScanBytes bounds bytes a bounded decision-query scan may read.
func (l Limits) MaxSpoolScanBytes() int { return l.c.MaxSpoolScanBytes }

// DefaultLimits returns the conservative safe-default admin bound set.
func DefaultLimits() Limits {
	return Limits{c: Config{
		MaxRequestBytes:       1 << 20,
		MaxCandidateBytes:     1 << 20,
		MaxPageSize:           200,
		MaxQueryRange:         90 * 24 * time.Hour,
		MaxFilters:            16,
		MaxExplainEntries:     1024,
		MaxConcurrentSims:     8,
		MaxSimCorpus:          4096,
		MaxCompareSamples:     512,
		MaxPendingApprovals:   8192,
		MaxApprovalsPerTenant: 1024,
		ApprovalTTL:           24 * time.Hour,
		MaxPublicationReqs:    512,
		MaxMgmtTools:          32,
		MaxMgmtInputBytes:     1 << 20,
		MaxMgmtOutputBytes:    1 << 20,
		MaxInventoryResults:   4096,
		MaxHealthBytes:        256 << 10,
		MaxGUIRows:            1000,
		MinConfigUpdateGap:    time.Second,
		MaxProjectionScan:     1 << 18,
		MaxSpoolScanBytes:     512 << 20,
	}}
}
