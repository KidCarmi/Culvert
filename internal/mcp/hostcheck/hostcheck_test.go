package hostcheck

import "testing"

// All tests are table-driven and socket-free (MCP-INSP-008 is a pure primitive).

func mustValidator(t *testing.T, cfg Config) *Validator {
	t.Helper()
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestEmptyAllowlistFailsClosed(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty host allowlist must fail closed")
	}
	if _, err := New(Config{AllowedHosts: []string{"  "}}); err == nil {
		t.Fatal("blank host entry must be rejected")
	}
	if _, err := New(Config{AllowedHosts: []string{"h"}, AllowedOrigins: []string{"not-an-origin"}}); err == nil {
		t.Fatal("invalid origin allowlist entry must be rejected")
	}
}

func TestCheckTable(t *testing.T) {
	v := mustValidator(t, Config{
		AllowedHosts:   []string{"mcp.example.com", "internal:9443"},
		AllowedOrigins: []string{"https://app.example.com"},
	})
	cases := []struct {
		name       string
		host       string
		hasOrigin  bool
		origin     string
		wantAllow  bool
		wantReason string
	}{
		{"host-ok-no-origin", "mcp.example.com", false, "", true, ReasonAllowed},
		{"host-ok-exact-port-entry", "internal:9443", false, "", true, ReasonAllowed},
		{"host-ok-incoming-port-vs-bare-entry", "mcp.example.com:8443", false, "", true, ReasonAllowed},
		{"host-reject-bare-vs-port-entry", "internal", false, "", false, ReasonHostNotAllowed},
		{"host-case-insensitive", "MCP.Example.com", false, "", true, ReasonAllowed},
		{"host-missing", "", false, "", false, ReasonHostMissing},
		{"host-not-allowed", "evil.example.com", false, "", false, ReasonHostNotAllowed},
		{"origin-ok", "mcp.example.com", true, "https://app.example.com", true, ReasonAllowed},
		{"origin-case", "mcp.example.com", true, "https://APP.example.com", true, ReasonAllowed},
		{"origin-not-allowed", "mcp.example.com", true, "https://evil.example.com", false, ReasonOriginNotAllowed},
		{"origin-invalid", "mcp.example.com", true, "://nope", false, ReasonOriginInvalid},
		{"origin-null", "mcp.example.com", true, "null", false, ReasonOriginInvalid},
		{"origin-with-path", "mcp.example.com", true, "https://app.example.com/x", false, ReasonOriginInvalid},
		{"origin-bad-scheme", "mcp.example.com", true, "ftp://app.example.com", false, ReasonOriginInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := v.Check(tc.host, tc.hasOrigin, tc.origin)
			if r.Allowed() != tc.wantAllow || r.Reason != tc.wantReason {
				t.Fatalf("Check = %v/%q, want allow=%v reason=%q", r.Decision, r.Reason, tc.wantAllow, tc.wantReason)
			}
		})
	}
}

func TestRequireOrigin(t *testing.T) {
	// By default, a missing Origin is allowed (non-browser clients need not send it).
	def := mustValidator(t, Config{AllowedHosts: []string{"h"}})
	if !def.Check("h", false, "").Allowed() {
		t.Fatal("missing Origin should be allowed by default")
	}
	// With RequireOrigin, a missing Origin is rejected.
	req := mustValidator(t, Config{AllowedHosts: []string{"h"}, RequireOrigin: true})
	if r := req.Check("h", false, ""); r.Allowed() || r.Reason != ReasonOriginRequired {
		t.Fatalf("missing Origin with RequireOrigin = %v/%q", r.Decision, r.Reason)
	}
}
