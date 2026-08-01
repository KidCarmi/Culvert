package policy

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// Hard-cap ceilings for policy bounds. A configured value above its ceiling is
// unsafe and fails validation — the ceilings bound the worst-case memory/CPU a
// single snapshot or evaluation can force, independent of caller configuration.
const (
	capSnapshotBytes   = 8 << 20 // 8 MiB
	capRulesPerSnap    = 4096
	capConditions      = 64
	capSetValues       = 256
	capStringBytes     = 4096
	capPatternBytes    = 512
	capPatternSegments = 32
	capResourceAttrs   = 32
	capGroupsScopes    = 256
	capObligations     = 32
	capTraceEntries    = 512
	capSimCases        = 100000
	capCompareSamples  = 1024
	capEvalOps         = 1 << 20
	capSnapHistory     = 64
)

// Limits is the immutable, validated policy bound set. Every dimension a snapshot
// author or an attacker-influenced input can drive is finite and validated. A
// zero, negative, inverted or over-ceiling value fails construction (fail closed).
type Limits struct{ c LimitConfig }

// LimitConfig is the mutable input to NewLimits.
type LimitConfig struct {
	MaxSnapshotBytes   int // strict-parse byte cap for a policy document
	MaxRulesPerSnap    int // rules per snapshot
	MaxConditions      int // conditions per rule
	MaxSetValues       int // values per one-of/set matcher
	MaxStringBytes     int // bytes of any one policy string value
	MaxPatternBytes    int // bytes of a glob pattern
	MaxPatternSegments int // segments in a glob pattern
	MaxResourceAttrs   int // resource attributes in an input
	MaxGroupsScopes    int // groups/scopes in an input
	MaxObligations     int // obligation entries per rule
	MaxTraceEntries    int // explain-trace entries
	MaxSimCases        int // simulator corpus cases
	MaxCompareSamples  int // sample case ids in a comparison summary
	MaxEvalOps         int // bounded evaluation-operation budget
	MaxSnapHistory     int // retained snapshots in a store
}

func limitErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicyLimitExceeded, "policy.limits", detail)
}

// Validate enforces positivity and hard-cap ceilings on every bound.
func (c LimitConfig) Validate() error {
	checks := []struct {
		name string
		v, c int
	}{
		{"MaxSnapshotBytes", c.MaxSnapshotBytes, capSnapshotBytes},
		{"MaxRulesPerSnap", c.MaxRulesPerSnap, capRulesPerSnap},
		{"MaxConditions", c.MaxConditions, capConditions},
		{"MaxSetValues", c.MaxSetValues, capSetValues},
		{"MaxStringBytes", c.MaxStringBytes, capStringBytes},
		{"MaxPatternBytes", c.MaxPatternBytes, capPatternBytes},
		{"MaxPatternSegments", c.MaxPatternSegments, capPatternSegments},
		{"MaxResourceAttrs", c.MaxResourceAttrs, capResourceAttrs},
		{"MaxGroupsScopes", c.MaxGroupsScopes, capGroupsScopes},
		{"MaxObligations", c.MaxObligations, capObligations},
		{"MaxTraceEntries", c.MaxTraceEntries, capTraceEntries},
		{"MaxSimCases", c.MaxSimCases, capSimCases},
		{"MaxCompareSamples", c.MaxCompareSamples, capCompareSamples},
		{"MaxEvalOps", c.MaxEvalOps, capEvalOps},
		{"MaxSnapHistory", c.MaxSnapHistory, capSnapHistory},
	}
	for _, p := range checks {
		if p.v <= 0 {
			return limitErr(p.name + " must be positive")
		}
		if p.v > p.c {
			return limitErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	// The trace must be able to record at least the hard overrides plus every rule.
	if c.MaxTraceEntries < c.MaxRulesPerSnap {
		return limitErr("MaxTraceEntries must be at least MaxRulesPerSnap")
	}
	return nil
}

// NewLimits validates c into an immutable Limits.
func NewLimits(c LimitConfig) (Limits, error) {
	if err := c.Validate(); err != nil {
		return Limits{}, err
	}
	return Limits{c: c}, nil
}

// DefaultLimits returns a conservative, valid policy bound set.
func DefaultLimits() Limits {
	l, err := NewLimits(LimitConfig{
		MaxSnapshotBytes: 1 << 20, MaxRulesPerSnap: 512, MaxConditions: 32,
		MaxSetValues: 128, MaxStringBytes: 1024, MaxPatternBytes: 256,
		MaxPatternSegments: 16, MaxResourceAttrs: 16, MaxGroupsScopes: 128,
		MaxObligations: 16, MaxTraceEntries: 512, MaxSimCases: 10000,
		MaxCompareSamples: 256, MaxEvalOps: 1 << 16, MaxSnapHistory: 16,
	})
	if err != nil {
		panic("policy: DefaultLimits invalid: " + err.Error())
	}
	return l
}

// Accessors (immutable).

// MaxSnapshotBytes returns the strict-parse byte cap for a policy document.
func (l Limits) MaxSnapshotBytes() int { return l.c.MaxSnapshotBytes }

// MaxRulesPerSnap returns the rules-per-snapshot cap.
func (l Limits) MaxRulesPerSnap() int { return l.c.MaxRulesPerSnap }

// MaxConditions returns the conditions-per-rule cap.
func (l Limits) MaxConditions() int { return l.c.MaxConditions }

// MaxSetValues returns the values-per-set-matcher cap.
func (l Limits) MaxSetValues() int { return l.c.MaxSetValues }

// MaxStringBytes returns the per-string byte cap.
func (l Limits) MaxStringBytes() int { return l.c.MaxStringBytes }

// MaxPatternBytes returns the glob-pattern byte cap.
func (l Limits) MaxPatternBytes() int { return l.c.MaxPatternBytes }

// MaxPatternSegments returns the glob-pattern segment cap.
func (l Limits) MaxPatternSegments() int { return l.c.MaxPatternSegments }

// MaxResourceAttrs returns the resource-attribute cap.
func (l Limits) MaxResourceAttrs() int { return l.c.MaxResourceAttrs }

// MaxGroupsScopes returns the groups/scopes cap.
func (l Limits) MaxGroupsScopes() int { return l.c.MaxGroupsScopes }

// MaxObligations returns the obligations-per-rule cap.
func (l Limits) MaxObligations() int { return l.c.MaxObligations }

// MaxTraceEntries returns the explain-trace entry cap.
func (l Limits) MaxTraceEntries() int { return l.c.MaxTraceEntries }

// MaxSimCases returns the simulator corpus cap.
func (l Limits) MaxSimCases() int { return l.c.MaxSimCases }

// MaxCompareSamples returns the comparison-sample cap.
func (l Limits) MaxCompareSamples() int { return l.c.MaxCompareSamples }

// MaxEvalOps returns the per-evaluation operation budget.
func (l Limits) MaxEvalOps() int { return l.c.MaxEvalOps }

// MaxSnapHistory returns the retained-snapshot cap for a store.
func (l Limits) MaxSnapHistory() int { return l.c.MaxSnapHistory }
