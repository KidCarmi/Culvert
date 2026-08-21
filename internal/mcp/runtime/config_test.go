package runtime

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

func validLimitConfig() LimitConfig {
	return LimitConfig{
		MaxConns: 1024, MaxConcurrent: 64, QueueDepth: 256, MaxSessions: 4096,
		MaxOutstanding: 8192, MaxHeaderBytes: 64 << 10, MaxBodyBytes: 1 << 20,
		MaxResponseBytes: 1 << 20, AuthConcurrency: 32, DPoPConcurrency: 32,
		MaxObservations: 4096, AdmissionBudget: 256, CleanupPerOp: 256,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		HandshakeTimeout: 5 * time.Second, RequestDeadline: 30 * time.Second,
		SessionTTL: 5 * time.Minute, ShutdownTimeout: 20 * time.Second,
	}
}

func TestRuntimeLimits_ValidateRejects(t *testing.T) {
	tests := []struct {
		name  string
		patch func(*LimitConfig)
	}{
		{"zero MaxConcurrent", func(c *LimitConfig) { c.MaxConcurrent = 0 }},
		{"negative QueueDepth", func(c *LimitConfig) { c.QueueDepth = -1 }},
		{"over-ceiling body", func(c *LimitConfig) { c.MaxBodyBytes = capBodyBytes + 1 }},
		{"outstanding below concurrent", func(c *LimitConfig) { c.MaxOutstanding = c.MaxConcurrent - 1 }},
		{"read below header", func(c *LimitConfig) { c.ReadTimeout = c.ReadHeaderTimeout - 1 }},
		{"response below body", func(c *LimitConfig) { c.MaxResponseBytes = c.MaxBodyBytes - 1 }},
		{"zero timeout", func(c *LimitConfig) { c.WriteTimeout = 0 }},
		{"over-ceiling timeout", func(c *LimitConfig) { c.ReadTimeout = capTimeout + time.Second }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validLimitConfig()
			tc.patch(&c)
			if _, err := NewLimits(c); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			} else if mcperr.ReasonOf(err) != mcperr.ReasonListenerConfigInvalid {
				t.Fatalf("reason = %v, want listener_config_invalid", mcperr.ReasonOf(err))
			}
		})
	}
}

func TestRuntimeLimits_ValidAccepts(t *testing.T) {
	if _, err := NewLimits(validLimitConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	_ = DefaultLimits() // must not panic
}

func TestListenerConfig_ValidateRejects(t *testing.T) {
	base := func() ListenerConfig {
		return ListenerConfig{
			Enabled: true, Capability: protocol.Gateway, BindAddress: "127.0.0.1",
			Port: 8443, AllowInsecure: true, AllowedHosts: []string{"h"},
			Limits: DefaultLimits(),
		}
	}
	tests := []struct {
		name  string
		patch func(*ListenerConfig)
	}{
		{"port zero non-test", func(c *ListenerConfig) { c.Port = 0; c.AllowInsecure = false; c.TLS = nil }},
		{"negative port", func(c *ListenerConfig) { c.Port = -5 }},
		{"port too high", func(c *ListenerConfig) { c.Port = 70000 }},
		{"empty bind", func(c *ListenerConfig) { c.BindAddress = "" }},
		{"wildcard without allow", func(c *ListenerConfig) { c.BindAddress = "0.0.0.0" }},
		{"empty host allowlist", func(c *ListenerConfig) { c.AllowedHosts = nil }},
		{"no TLS non-test", func(c *ListenerConfig) { c.AllowInsecure = false }},
		{"mTLS without TLS", func(c *ListenerConfig) { c.ClientCertMode = ClientCertRequire }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.patch(&c)
			if err := c.validate(); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestListenerConfig_WildcardAllowed(t *testing.T) {
	c := ListenerConfig{
		Enabled: true, Capability: protocol.Gateway, BindAddress: "0.0.0.0",
		Port: 8443, AllowInsecure: true, AllowWildcard: true,
		AllowedHosts: []string{"h"}, Limits: DefaultLimits(),
	}
	if err := c.validate(); err != nil {
		t.Fatalf("wildcard with AllowWildcard rejected: %v", err)
	}
}

func TestRuntimeConfig_RejectsSharedAddr(t *testing.T) {
	g := gwListenerConfig(t)
	m := mgmtListenerConfig(t)
	g.Port, m.Port = 9000, 9000 // same addr/port
	g.BindAddress, m.BindAddress = "127.0.0.1", "127.0.0.1"
	cfg := Config{Gateway: g, Management: m}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected shared-address rejection")
	}
}

func TestRuntimeConfig_RejectsSharedResource(t *testing.T) {
	g := gwListenerConfig(t)
	m := mgmtListenerConfig(t)
	g.Port, m.Port = 9000, 9001
	// Force the same canonical resource on both — capability isolation violated.
	m.AuthConfig = gwAuthConfig(t) // gateway resource under the management listener
	m.Capability = protocol.Management
	cfg := Config{Gateway: g, Management: m}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected shared-resource rejection")
	}
}

func TestRuntimeConfig_DisabledValidatesTrivially(t *testing.T) {
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("disabled config failed validation: %v", err)
	}
	if (Config{}).Enabled() {
		t.Fatal("empty config reports enabled")
	}
}

func TestRuntimeConfig_WrongCapabilityRejected(t *testing.T) {
	g := gwListenerConfig(t)
	g.Capability = protocol.Management // gateway slot holding a management capability
	cfg := Config{Gateway: g}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected wrong-capability rejection")
	}
}
