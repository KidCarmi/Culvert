package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── cidrToIPMask ─────────────────────────────────────────────────────────────

func TestCIDRToIPMask(t *testing.T) {
	cases := []struct {
		cidr    string
		wantIP  string
		wantMsk string
		wantOK  bool
	}{
		{"192.168.0.0/16", "192.168.0.0", "255.255.0.0", true},
		{"10.0.0.0/8", "10.0.0.0", "255.0.0.0", true},
		{"172.16.0.0/12", "172.16.0.0", "255.240.0.0", true},
		{"192.168.1.0/24", "192.168.1.0", "255.255.255.0", true},
		{"0.0.0.0/0", "0.0.0.0", "0.0.0.0", true},
		{"10.1.2.3/32", "10.1.2.3", "255.255.255.255", true},

		// Invalid inputs.
		{"not-a-cidr", "", "", false},
		{"192.168.0.0/33", "", "", false}, // prefix > 32
		{"192.168.0.0/-1", "", "", false}, // negative prefix
	}
	for _, c := range cases {
		ip, msk, ok := cidrToIPMask(c.cidr)
		if ok != c.wantOK {
			t.Errorf("cidrToIPMask(%q): ok=%v, want %v", c.cidr, ok, c.wantOK)
			continue
		}
		if !c.wantOK {
			continue
		}
		if ip != c.wantIP {
			t.Errorf("cidrToIPMask(%q): ip=%q, want %q", c.cidr, ip, c.wantIP)
		}
		if msk != c.wantMsk {
			t.Errorf("cidrToIPMask(%q): mask=%q, want %q", c.cidr, msk, c.wantMsk)
		}
	}
}

// ─── isIPCIDR ─────────────────────────────────────────────────────────────────

func TestIsIPCIDR(t *testing.T) {
	if !isIPCIDR("10.0.0.0/8") {
		t.Error("10.0.0.0/8 should be CIDR")
	}
	if isIPCIDR("example.com") {
		t.Error("example.com should not be CIDR")
	}
	if isIPCIDR("*.example.com") {
		t.Error("*.example.com should not be CIDR")
	}
}

// ─── PACStore ─────────────────────────────────────────────────────────────────

func newTestPACStore() *PACStore {
	return &PACStore{}
}

func TestPACStore_GetDefault(t *testing.T) {
	s := newTestPACStore()
	c := s.Get()
	if c.ProxyHost != "" {
		t.Errorf("default ProxyHost should be empty, got %q", c.ProxyHost)
	}
	if c.ProxyPort != 0 {
		t.Errorf("default ProxyPort should be 0, got %d", c.ProxyPort)
	}
	if len(c.Exclusions) != 0 {
		t.Errorf("default Exclusions should be empty, got %v", c.Exclusions)
	}
}

func TestPACStore_SetAndGet(t *testing.T) {
	s := newTestPACStore()
	cfg := PACConfig{
		ProxyHost:  "proxy.corp.com",
		ProxyPort:  3128,
		Exclusions: []string{"corp.local", "*.internal.corp"},
	}
	if err := s.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := s.Get()
	if got.ProxyHost != cfg.ProxyHost {
		t.Errorf("ProxyHost = %q, want %q", got.ProxyHost, cfg.ProxyHost)
	}
	if got.ProxyPort != cfg.ProxyPort {
		t.Errorf("ProxyPort = %d, want %d", got.ProxyPort, cfg.ProxyPort)
	}
	if len(got.Exclusions) != 2 {
		t.Errorf("Exclusions len = %d, want 2", len(got.Exclusions))
	}

	// Mutating the returned slice must not affect internal state.
	got.Exclusions[0] = "mutated"
	got2 := s.Get()
	if got2.Exclusions[0] == "mutated" {
		t.Error("Get() should return a copy of Exclusions")
	}
}

func TestPACStore_LoadMissingFile(t *testing.T) {
	s := newTestPACStore()
	if err := s.Load("/no/such/file.json"); err != nil {
		t.Errorf("Load of missing file should not error, got: %v", err)
	}
}

func TestPACStore_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pac.json")
	_ = os.WriteFile(path, []byte("not json"), 0o600)
	s := newTestPACStore()
	if err := s.Load(path); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestPACStore_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pac.json")

	s := newTestPACStore()
	if err := s.Load(path); err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if err := s.Set(PACConfig{ProxyHost: "proxy.example.com", ProxyPort: 8080}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Verify the file was written.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var stored PACConfig
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if stored.ProxyHost != "proxy.example.com" {
		t.Errorf("stored ProxyHost = %q", stored.ProxyHost)
	}

	// Load into a new store and verify round-trip.
	s2 := newTestPACStore()
	if err := s2.Load(path); err != nil {
		t.Fatalf("Load after Set: %v", err)
	}
	got := s2.Get()
	if got.ProxyHost != "proxy.example.com" || got.ProxyPort != 8080 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

// ─── GeneratePAC ──────────────────────────────────────────────────────────────

func TestGeneratePAC_Basic(t *testing.T) {
	s := newTestPACStore()
	_ = s.Set(PACConfig{ProxyHost: "proxy.corp.com", ProxyPort: 3128})

	pac := s.GeneratePAC("proxy.corp.com:3128")

	if !strings.Contains(pac, "function FindProxyForURL") {
		t.Error("PAC should contain FindProxyForURL function")
	}
	if !strings.Contains(pac, "PROXY proxy.corp.com:3128") {
		t.Errorf("PAC should contain PROXY directive, got:\n%s", pac)
	}
	// Must always bypass loopback and RFC-1918.
	if !strings.Contains(pac, "127.0.0.0") {
		t.Error("PAC should bypass loopback (127.0.0.0)")
	}
	if !strings.Contains(pac, "10.0.0.0") {
		t.Error("PAC should bypass 10.0.0.0/8")
	}
	if !strings.Contains(pac, "192.168.0.0") {
		t.Error("PAC should bypass 192.168.0.0/16")
	}
}

func TestGeneratePAC_FallbackHost(t *testing.T) {
	// ProxyHost empty — should use hostname from proxyAddr argument.
	s := newTestPACStore()
	_ = s.Set(PACConfig{ProxyPort: 8080})

	pac := s.GeneratePAC("10.0.0.1:8080")

	if !strings.Contains(pac, "PROXY 10.0.0.1:8080") {
		t.Errorf("PAC should derive host from proxyAddr, got:\n%s", pac)
	}
}

func TestGeneratePAC_FallbackPort(t *testing.T) {
	// ProxyPort zero, pacDefaultProxyPort set.
	origDefault := pacDefaultProxyPort
	pacDefaultProxyPort = 9999
	defer func() { pacDefaultProxyPort = origDefault }()

	s := newTestPACStore()
	_ = s.Set(PACConfig{ProxyHost: "proxy.corp.com"})

	pac := s.GeneratePAC("proxy.corp.com:9999")
	if !strings.Contains(pac, "PROXY proxy.corp.com:9999") {
		t.Errorf("PAC should use pacDefaultProxyPort=9999, got:\n%s", pac)
	}
}

func TestGeneratePAC_FallbackPortDefault8080(t *testing.T) {
	// ProxyPort zero, pacDefaultProxyPort zero — falls back to 8080.
	origDefault := pacDefaultProxyPort
	pacDefaultProxyPort = 0
	defer func() { pacDefaultProxyPort = origDefault }()

	s := newTestPACStore()
	_ = s.Set(PACConfig{ProxyHost: "proxy.corp.com"})

	pac := s.GeneratePAC("proxy.corp.com")
	if !strings.Contains(pac, "PROXY proxy.corp.com:8080") {
		t.Errorf("PAC should fall back to port 8080, got:\n%s", pac)
	}
}

func TestGeneratePAC_Exclusions_BareDomain(t *testing.T) {
	s := newTestPACStore()
	_ = s.Set(PACConfig{
		ProxyHost:  "proxy",
		ProxyPort:  8080,
		Exclusions: []string{"corp.local"},
	})

	pac := s.GeneratePAC("proxy:8080")

	// Bare domain: should have both === check and dnsDomainIs check.
	if !strings.Contains(pac, `host === "corp.local"`) {
		t.Errorf("PAC missing exact match for corp.local:\n%s", pac)
	}
	if !strings.Contains(pac, `dnsDomainIs(host, ".corp.local")`) {
		t.Errorf("PAC missing subdomain match for corp.local:\n%s", pac)
	}
}

func TestGeneratePAC_Exclusions_Wildcard(t *testing.T) {
	s := newTestPACStore()
	_ = s.Set(PACConfig{
		ProxyHost:  "proxy",
		ProxyPort:  8080,
		Exclusions: []string{"*.corp.com"},
	})

	pac := s.GeneratePAC("proxy:8080")

	if !strings.Contains(pac, `dnsDomainIs(host, ".corp.com")`) {
		t.Errorf("PAC missing wildcard exclusion:\n%s", pac)
	}
}

func TestGeneratePAC_Exclusions_CIDR(t *testing.T) {
	s := newTestPACStore()
	_ = s.Set(PACConfig{
		ProxyHost:  "proxy",
		ProxyPort:  8080,
		Exclusions: []string{"172.16.0.0/12"},
	})

	pac := s.GeneratePAC("proxy:8080")

	if !strings.Contains(pac, "isInNet") {
		t.Errorf("PAC missing isInNet for CIDR exclusion:\n%s", pac)
	}
	if !strings.Contains(pac, "172.16.0.0") {
		t.Errorf("PAC missing CIDR network address:\n%s", pac)
	}
	if !strings.Contains(pac, "255.240.0.0") {
		t.Errorf("PAC missing CIDR mask 255.240.0.0 for /12:\n%s", pac)
	}
}

func TestGeneratePAC_EmptyExclusionsSkipped(t *testing.T) {
	s := newTestPACStore()
	_ = s.Set(PACConfig{
		ProxyHost:  "proxy",
		ProxyPort:  8080,
		Exclusions: []string{"", "  ", "valid.com"},
	})

	pac := s.GeneratePAC("proxy:8080")

	// The blank/whitespace-only entries should be silently skipped.
	if !strings.Contains(pac, "valid.com") {
		t.Errorf("PAC should include non-empty exclusion valid.com:\n%s", pac)
	}
}

func TestGeneratePAC_HostFromBareAddr(t *testing.T) {
	// proxyAddr without port (no colon).
	s := newTestPACStore()
	_ = s.Set(PACConfig{ProxyPort: 8080})

	pac := s.GeneratePAC("barehost")
	if !strings.Contains(pac, "PROXY barehost:8080") {
		t.Errorf("PAC should handle bare address, got:\n%s", pac)
	}
}

func TestGeneratePAC_HTTPSPrefixStripped(t *testing.T) {
	// proxyAddr with https:// prefix (from window.location in browser).
	s := newTestPACStore()
	_ = s.Set(PACConfig{ProxyPort: 8080})

	pac := s.GeneratePAC("https://proxy.corp.com:9090")
	if !strings.Contains(pac, "PROXY proxy.corp.com:8080") {
		t.Errorf("PAC should strip https:// and use configured port:\n%s", pac)
	}
}
