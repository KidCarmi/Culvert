// Package limits defines the immutable, validated structural resource bounds the
// MCP protocol kernel enforces. Management and Gateway carry INDEPENDENT limit
// sets: one capability's bound never affects the other (isolation is asserted by
// tests). Every value is a conservative safe-default with a hard-cap ceiling per
// decision D-14 (the MCP-PROTO-006/007/008 requirements are defined; only the
// numeric values were open, and are fixed here).
//
// A Limits value is immutable once constructed: fields are unexported and read
// through accessors, and there is no package-level mutable singleton. Construct
// one with New (validating a Config) or take a validated default via
// DefaultManagement / DefaultGateway.
package limits

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Hard-cap ceilings. A Config value above its ceiling is "unsafe" and fails
// validation — the ceilings bound the worst-case memory/CPU a single peer can
// force, independent of how a caller configures the safe-defaults.
const (
	capFrameBytes         = 16 << 20 // 16 MiB
	capDepth              = 256
	capObjectMembers      = 1 << 16 // 65536
	capArrayElements      = 1 << 16 // 65536
	capStringBytes        = 1 << 20 // 1 MiB
	capMethodBytes        = 128
	capIDBytes            = 1024
	capErrorDataBytes     = 256 << 10 // 256 KiB
	capSessions           = 1 << 20
	capOutstandingSession = 4096
	capTotalOutstanding   = 1 << 20
	capSessionTTL         = 24 * time.Hour
)

// Config is the mutable input to New. Callers set every field; New validates it
// and returns an immutable Limits. A zero Config is invalid.
type Config struct {
	MaxFrameBytes            int           // max bytes of a single wire frame
	MaxDepth                 int           // max JSON nesting depth
	MaxObjectMembers         int           // max members in any one JSON object
	MaxArrayElements         int           // max elements in any one JSON array
	MaxStringBytes           int           // max bytes of any one JSON string
	MaxMethodBytes           int           // max bytes of a method name
	MaxIDBytes               int           // max encoded bytes of a request/response id
	MaxErrorDataBytes        int           // max bytes of an error `data` member
	MaxSessions              int           // max concurrent sessions
	MaxOutstandingPerSession int           // max in-flight requests per (session,direction)
	MaxTotalOutstanding      int           // max in-flight requests across all sessions
	SessionTTL               time.Duration // lifecycle idle timeout / expiry window
}

// Limits is an immutable, validated bound set.
type Limits struct{ c Config }

func (l Limits) MaxFrameBytes() int            { return l.c.MaxFrameBytes }
func (l Limits) MaxDepth() int                 { return l.c.MaxDepth }
func (l Limits) MaxObjectMembers() int         { return l.c.MaxObjectMembers }
func (l Limits) MaxArrayElements() int         { return l.c.MaxArrayElements }
func (l Limits) MaxStringBytes() int           { return l.c.MaxStringBytes }
func (l Limits) MaxMethodBytes() int           { return l.c.MaxMethodBytes }
func (l Limits) MaxIDBytes() int               { return l.c.MaxIDBytes }
func (l Limits) MaxErrorDataBytes() int        { return l.c.MaxErrorDataBytes }
func (l Limits) MaxSessions() int              { return l.c.MaxSessions }
func (l Limits) MaxOutstandingPerSession() int { return l.c.MaxOutstandingPerSession }
func (l Limits) MaxTotalOutstanding() int      { return l.c.MaxTotalOutstanding }
func (l Limits) SessionTTL() time.Duration     { return l.c.SessionTTL }

// posCap validates that v is strictly positive and does not exceed ceiling.
func posCap(v, ceiling int, name string) error {
	if v <= 0 {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "non-positive limit "+name)
	}
	if v > ceiling {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "limit exceeds hard cap "+name)
	}
	return nil
}

// Validate reports whether the Config is safe and internally consistent. Zero,
// negative, over-cap, or inconsistent limits are rejected. It is the single
// gate every Limits passes through.
func (c Config) Validate() error {
	for _, ck := range []struct {
		v, cap int
		name   string
	}{
		{c.MaxFrameBytes, capFrameBytes, "MaxFrameBytes"},
		{c.MaxDepth, capDepth, "MaxDepth"},
		{c.MaxObjectMembers, capObjectMembers, "MaxObjectMembers"},
		{c.MaxArrayElements, capArrayElements, "MaxArrayElements"},
		{c.MaxStringBytes, capStringBytes, "MaxStringBytes"},
		{c.MaxMethodBytes, capMethodBytes, "MaxMethodBytes"},
		{c.MaxIDBytes, capIDBytes, "MaxIDBytes"},
		{c.MaxErrorDataBytes, capErrorDataBytes, "MaxErrorDataBytes"},
		{c.MaxSessions, capSessions, "MaxSessions"},
		{c.MaxOutstandingPerSession, capOutstandingSession, "MaxOutstandingPerSession"},
		{c.MaxTotalOutstanding, capTotalOutstanding, "MaxTotalOutstanding"},
	} {
		if err := posCap(ck.v, ck.cap, ck.name); err != nil {
			return err
		}
	}
	if c.SessionTTL <= 0 || c.SessionTTL > capSessionTTL {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "SessionTTL out of range")
	}
	// Internal consistency: a string / method / id / error-data field can never be
	// larger than a whole frame, and per-session outstanding can never exceed the
	// global total. An inconsistent set is unsafe even if each field is in range.
	if c.MaxStringBytes > c.MaxFrameBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "MaxStringBytes > MaxFrameBytes")
	}
	if c.MaxErrorDataBytes > c.MaxFrameBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "MaxErrorDataBytes > MaxFrameBytes")
	}
	if c.MaxMethodBytes > c.MaxFrameBytes || c.MaxIDBytes > c.MaxFrameBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "method/id larger than frame")
	}
	if c.MaxOutstandingPerSession > c.MaxTotalOutstanding {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "per-session outstanding > total")
	}
	return nil
}

// New validates c and returns an immutable Limits, or an error.
func New(c Config) (Limits, error) {
	if err := c.Validate(); err != nil {
		return Limits{}, err
	}
	return Limits{c: c}, nil
}

// gatewayConfig is the conservative safe-default for the Gateway capability
// (business tool traffic — the higher-throughput surface).
var gatewayConfig = Config{
	MaxFrameBytes:            1 << 20, // 1 MiB
	MaxDepth:                 64,
	MaxObjectMembers:         4096,
	MaxArrayElements:         4096,
	MaxStringBytes:           256 << 10, // 256 KiB
	MaxMethodBytes:           64,
	MaxIDBytes:               256,
	MaxErrorDataBytes:        16 << 10, // 16 KiB
	MaxSessions:              4096,
	MaxOutstandingPerSession: 256,
	MaxTotalOutstanding:      1 << 16, // 65536
	SessionTTL:               10 * time.Minute,
}

// managementConfig is the conservative safe-default for the Management
// capability (read-only + draft/validate/simulate — deliberately tighter and
// INDEPENDENT of the Gateway set).
var managementConfig = Config{
	MaxFrameBytes:            512 << 10, // 512 KiB
	MaxDepth:                 48,
	MaxObjectMembers:         2048,
	MaxArrayElements:         2048,
	MaxStringBytes:           128 << 10, // 128 KiB
	MaxMethodBytes:           64,
	MaxIDBytes:               256,
	MaxErrorDataBytes:        8 << 10, // 8 KiB
	MaxSessions:              1024,
	MaxOutstandingPerSession: 64,
	MaxTotalOutstanding:      8192,
	SessionTTL:               10 * time.Minute,
}

// DefaultGateway returns the validated Gateway default limit set.
func DefaultGateway() Limits {
	l, err := New(gatewayConfig)
	if err != nil {
		panic("mcp/limits: gateway default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}

// DefaultManagement returns the validated Management default limit set.
func DefaultManagement() Limits {
	l, err := New(managementConfig)
	if err != nil {
		panic("mcp/limits: management default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}
