package limits

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestDefaultsValid(t *testing.T) {
	// Panics if a default is invalid; also assert the accessors are non-zero.
	g := DefaultGateway()
	m := DefaultManagement()
	if g.MaxFrameBytes() <= 0 || m.MaxFrameBytes() <= 0 {
		t.Fatal("defaults must have positive frame bytes")
	}
}

// Isolation: Management and Gateway are INDEPENDENT sets (a single shared object
// would make one capability's bound leak into the other — forbidden).
func TestGatewayManagementIndependent(t *testing.T) {
	g := DefaultGateway()
	m := DefaultManagement()
	if g.MaxOutstandingPerSession() == m.MaxOutstandingPerSession() &&
		g.MaxFrameBytes() == m.MaxFrameBytes() {
		t.Fatal("gateway and management limits are indistinguishable; they must be independent")
	}
	// Value semantics: taking a copy and there being no shared pointer means a
	// caller cannot mutate one set through the other. Constructing a fresh one
	// does not disturb the defaults.
	c := gatewayConfig
	c.MaxFrameBytes = 123
	if DefaultGateway().MaxFrameBytes() == 123 {
		t.Fatal("mutating a local Config changed the default set (shared mutable state)")
	}
}

func TestValidateRejectsUnsafe(t *testing.T) {
	base := gatewayConfig
	bad := []struct {
		name string
		mut  func(c *Config)
	}{
		{"zero-frame", func(c *Config) { c.MaxFrameBytes = 0 }},
		{"negative-depth", func(c *Config) { c.MaxDepth = -1 }},
		{"over-cap-frame", func(c *Config) { c.MaxFrameBytes = capFrameBytes + 1 }},
		{"over-cap-method", func(c *Config) { c.MaxMethodBytes = capMethodBytes + 1 }},
		{"zero-ttl", func(c *Config) { c.SessionTTL = 0 }},
		{"over-ttl", func(c *Config) { c.SessionTTL = capSessionTTL + time.Hour }},
		{"string-gt-frame", func(c *Config) { c.MaxStringBytes = c.MaxFrameBytes + 1 }},
		{"errdata-gt-frame", func(c *Config) { c.MaxErrorDataBytes = c.MaxFrameBytes + 1 }},
		{"persession-gt-total", func(c *Config) { c.MaxOutstandingPerSession = c.MaxTotalOutstanding + 1 }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			if err := c.Validate(); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
				t.Fatalf("expected resource_limit validation failure, got %v", err)
			}
			if _, err := New(c); err == nil {
				t.Fatal("New must reject an invalid config")
			}
		})
	}
}

func TestZeroConfigInvalid(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("a zero Config must be invalid")
	}
}
