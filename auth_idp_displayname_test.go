package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression test for the IdP selection screen showing the machine-readable
// "type:ID" key (Name()) instead of the admin-configured label — DisplayName()
// exists specifically so a human-facing surface can show the real label while
// Name() stays the stable machine key used for policy/filtering lookups.

func TestSAMLProvider_DisplayName(t *testing.T) {
	p := &SAMLProvider{profile: &IdPProfile{ID: "abc123", Name: "Corporate Okta"}}
	if got := p.DisplayName(); got != "Corporate Okta" {
		t.Errorf("DisplayName() = %q, want %q", got, "Corporate Okta")
	}
	if got := p.Name(); got != "saml:abc123" {
		t.Errorf("Name() = %q, want %q", got, "saml:abc123")
	}
}

func TestSAMLProvider_DisplayName_FallsBackToMachineKey(t *testing.T) {
	p := &SAMLProvider{profile: &IdPProfile{ID: "abc123", Name: ""}}
	if got, want := p.DisplayName(), p.Name(); got != want {
		t.Errorf("DisplayName() = %q, want fallback to Name() %q", got, want)
	}
}

func TestOIDCFlowProvider_DisplayName(t *testing.T) {
	p := &OIDCFlowProvider{profile: &IdPProfile{ID: "xyz789", Name: "Corporate Google"}}
	if got := p.DisplayName(); got != "Corporate Google" {
		t.Errorf("DisplayName() = %q, want %q", got, "Corporate Google")
	}
	if got := p.Name(); got != "oidc:xyz789" {
		t.Errorf("Name() = %q, want %q", got, "oidc:xyz789")
	}
}

func TestOIDCFlowProvider_DisplayName_FallsBackToMachineKey(t *testing.T) {
	p := &OIDCFlowProvider{profile: &IdPProfile{ID: "xyz789", Name: ""}}
	if got, want := p.DisplayName(), p.Name(); got != want {
		t.Errorf("DisplayName() = %q, want fallback to Name() %q", got, want)
	}
}

// labeledTestProvider distinguishes Name() (machine key) from DisplayName()
// (human label), unlike ssoTestProvider in authpolicy_phase3_slice4_test.go
// which intentionally keeps them equal for its own filtering tests.
type labeledTestProvider struct{ machineKey, label string }

func (p *labeledTestProvider) Verify(string, string) bool                       { return false }
func (p *labeledTestProvider) ResolveIdentity(string, string) (*Identity, bool) { return nil, false }
func (p *labeledTestProvider) Name() string                                     { return p.machineKey }
func (p *labeledTestProvider) DisplayName() string                              { return p.label }
func (p *labeledTestProvider) CaptiveLoginURL(relay string, _ *http.Request) string {
	return "/auth/test?relay=" + relay
}

func TestAuthSelectProvider_RendersDisplayNameNotMachineKey(t *testing.T) {
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	profile := &IdPProfile{ID: "a1b2c3d4e5f6", Name: "Corporate Okta", Enabled: true}
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{profile},
		live: map[string]IdentityProvider{
			profile.ID: &labeledTestProvider{machineKey: "oidc:" + profile.ID, label: profile.Name},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/select", nil)
	rec := httptest.NewRecorder()
	authSelectProvider(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Continue with Corporate Okta") {
		t.Errorf("expected login page to show the admin-configured label, got: %s", body)
	}
	if strings.Contains(body, "Continue with oidc:") {
		t.Errorf("login page leaked the machine key instead of the display name: %s", body)
	}
}
