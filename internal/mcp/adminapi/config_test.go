package adminapi

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestConfig_DefaultsDisabled(t *testing.T) {
	c := DefaultMCPConfig()
	if c.Gateway.Enabled || c.Management.Enabled {
		t.Fatal("both capabilities must default to disabled")
	}
	if c.Management.MutationEnabled {
		t.Fatal("management mutation must default off (V1)")
	}
	if c.Gateway.Port == c.Management.Port {
		t.Fatal("default ports must differ (no shared port)")
	}
	if isWildcardBind(c.Gateway.BindAddress) || isWildcardBind(c.Management.BindAddress) {
		t.Fatal("default binds must not be wildcard")
	}
	if err := c.Validate(1 << 20); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
}

func TestConfig_WildcardRejected(t *testing.T) {
	c := DefaultMCPConfig()
	c.Gateway.Enabled = true
	c.Gateway.BindAddress = "0.0.0.0"
	if mcperr.ReasonOf(c.Validate(1<<20)) != mcperr.ReasonConfigInvalid {
		t.Fatal("wildcard gateway bind must be rejected")
	}
}

func TestConfig_SharedEndpointRejected(t *testing.T) {
	c := DefaultMCPConfig()
	c.Gateway.Enabled = true
	c.Management.Enabled = true
	c.Management.BindAddress = c.Gateway.BindAddress
	c.Management.Port = c.Gateway.Port
	if mcperr.ReasonOf(c.Validate(1<<20)) != mcperr.ReasonConfigInvalid {
		t.Fatal("shared bind endpoint must be rejected")
	}
}

func TestConfig_MutationMustStayOff(t *testing.T) {
	c := DefaultMCPConfig()
	c.Management.Enabled = true
	c.Management.MutationEnabled = true
	if mcperr.ReasonOf(c.Validate(1<<20)) != mcperr.ReasonConfigInvalid {
		t.Fatal("management mutation must be rejected in V1")
	}
}

func TestConfig_MinRoleBelowViewerRejected(t *testing.T) {
	c := DefaultMCPConfig()
	c.Management.Enabled = true
	c.Management.DefaultMinRole = "public"
	if mcperr.ReasonOf(c.Validate(1<<20)) != mcperr.ReasonConfigInvalid {
		t.Fatal("management default_min_role below viewer must be rejected")
	}
}

func TestConfig_OutputBytesBounded(t *testing.T) {
	c := DefaultMCPConfig()
	c.Management.Enabled = true
	c.Management.OutputMaxBytes = 1 << 30 // over the ceiling passed in
	if mcperr.ReasonOf(c.Validate(1<<20)) != mcperr.ReasonConfigInvalid {
		t.Fatal("management output_max_bytes over ceiling must be rejected")
	}
}

func TestConfigStore_RetainsOnFailure(t *testing.T) {
	s := NewConfigStore(1 << 20)
	good := DefaultMCPConfig()
	good.Gateway.Enabled = true
	good.Gateway.Port = 9001
	if err := s.Set(good); err != nil {
		t.Fatalf("Set good: %v", err)
	}
	bad := s.Current()
	bad.Gateway.BindAddress = "0.0.0.0" // invalid
	if err := s.Set(bad); err == nil {
		t.Fatal("invalid Set must fail")
	}
	if got := s.Current(); got.Gateway.Port != 9001 || got.Gateway.BindAddress == "0.0.0.0" {
		t.Fatal("store must retain the previous valid config after a failed Set")
	}
}
