package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// LimitConfig is the mutable input to NewLimits. Every field bounds a rollout
// data structure so nothing an operator or a signed snapshot supplies can grow
// unbounded. Zero in any field means "use the safe default" (see DefaultLimits).
type LimitConfig struct {
	MaxSelectors       int // total selector entries across all selector kinds in one scope
	MaxSelectorValues  int // values within a single multi-value selector (e.g. tenant list)
	MaxExclusions      int // exclusion entries (which may only narrow)
	MaxResolvedMembers int // upper bound on an enumerable resolved subject set
	MaxValueBytes      int // bytes of a single selector value string
	MaxTransitions     int // mode transitions retained/permitted per rolling interval
	MaxHistory         int // retained transition-history entries
	MaxEvidenceItems   int // retained evidence-summary entries
	MaxReviewEntries   int // retained bounded false-positive review entries
}

// Limits is the immutable, validated bounds set. All access is through
// accessors; the zero Limits is never valid (construct via NewLimits/DefaultLimits).
type Limits struct {
	c     LimitConfig
	valid bool
}

// Default bound values (documented, conservative).
const (
	defMaxSelectors       = 256
	defMaxSelectorValues  = 1024
	defMaxExclusions      = 512
	defMaxResolvedMembers = 65536
	defMaxValueBytes      = 512
	defMaxTransitions     = 32
	defMaxHistory         = 128
	defMaxEvidenceItems   = 256
	defMaxReviewEntries   = 1024
)

// DefaultLimits returns the safe default bounds.
func DefaultLimits() Limits {
	l, _ := NewLimits(LimitConfig{})
	return l
}

// NewLimits validates and freezes a bounds set, filling zero fields with the safe
// defaults. It rejects any explicitly-negative field.
func NewLimits(c LimitConfig) (Limits, error) {
	fill := func(v, def int) (int, bool) {
		if v < 0 {
			return 0, false
		}
		if v == 0 {
			return def, true
		}
		return v, true
	}
	out := LimitConfig{}
	ok := true
	var o bool
	out.MaxSelectors, o = fill(c.MaxSelectors, defMaxSelectors)
	ok = ok && o
	out.MaxSelectorValues, o = fill(c.MaxSelectorValues, defMaxSelectorValues)
	ok = ok && o
	out.MaxExclusions, o = fill(c.MaxExclusions, defMaxExclusions)
	ok = ok && o
	out.MaxResolvedMembers, o = fill(c.MaxResolvedMembers, defMaxResolvedMembers)
	ok = ok && o
	out.MaxValueBytes, o = fill(c.MaxValueBytes, defMaxValueBytes)
	ok = ok && o
	out.MaxTransitions, o = fill(c.MaxTransitions, defMaxTransitions)
	ok = ok && o
	out.MaxHistory, o = fill(c.MaxHistory, defMaxHistory)
	ok = ok && o
	out.MaxEvidenceItems, o = fill(c.MaxEvidenceItems, defMaxEvidenceItems)
	ok = ok && o
	out.MaxReviewEntries, o = fill(c.MaxReviewEntries, defMaxReviewEntries)
	ok = ok && o
	if !ok {
		return Limits{}, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.limits", "negative limit value")
	}
	return Limits{c: out, valid: true}, nil
}

// Valid reports whether the limits were constructed (never the zero value).
func (l Limits) Valid() bool { return l.valid }

// MaxSelectors returns the total selector-entry bound for one scope.
func (l Limits) MaxSelectors() int { return l.c.MaxSelectors }

// MaxSelectorValues returns the per-selector value-count bound.
func (l Limits) MaxSelectorValues() int { return l.c.MaxSelectorValues }

// MaxExclusions returns the exclusion-entry bound.
func (l Limits) MaxExclusions() int { return l.c.MaxExclusions }

// MaxResolvedMembers returns the resolved-subject-set bound.
func (l Limits) MaxResolvedMembers() int { return l.c.MaxResolvedMembers }

// MaxValueBytes returns the per-value byte bound.
func (l Limits) MaxValueBytes() int { return l.c.MaxValueBytes }

// MaxTransitions returns the per-interval transition bound.
func (l Limits) MaxTransitions() int { return l.c.MaxTransitions }

// MaxHistory returns the transition-history retention bound.
func (l Limits) MaxHistory() int { return l.c.MaxHistory }

// MaxEvidenceItems returns the evidence-summary retention bound.
func (l Limits) MaxEvidenceItems() int { return l.c.MaxEvidenceItems }

// MaxReviewEntries returns the false-positive-review retention bound.
func (l Limits) MaxReviewEntries() int { return l.c.MaxReviewEntries }
