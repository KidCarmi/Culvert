package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		path, prefix, want string
	}{
		{"/api/cluster/bootstrap/abc123", "/api/cluster/bootstrap/", "abc123"},
		{"/api/cluster/bootstrap/abc123/compose", "/api/cluster/bootstrap/", "abc123"},
		{"/api/cluster/bootstrap/", "/api/cluster/bootstrap/", ""},
		{"/api/cluster/bootstrap/a/b/c", "/api/cluster/bootstrap/", ""},
		{"/other/path", "/api/cluster/bootstrap/", ""},
	}
	for _, tt := range tests {
		got := ExtractToken(tt.path, tt.prefix)
		if got != tt.want {
			t.Errorf("ExtractToken(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestBaseURL(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cp.example.com:9090/test", http.NoBody)
	req.Host = "cp.example.com:9090"
	got := BaseURL(req, false)
	if got != "https://cp.example.com:9090" {
		t.Errorf("BaseURL = %q, want https://cp.example.com:9090", got)
	}
}

func TestBaseURL_XForwarded(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://cp.internal/test", http.NoBody)
	req.Host = "cp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "proxy.example.com")
	got := BaseURL(req, true)
	if got != "https://proxy.example.com" {
		t.Errorf("BaseURL = %q, want https://proxy.example.com", got)
	}
}

func TestBaseURL_XForwardedIgnoredByDefault(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://cp.internal/test", http.NoBody)
	req.Host = "cp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "proxy.example.com")
	got := BaseURL(req, false)
	// Should use r.Host, not X-Forwarded-Host
	if got != "http://cp.example.com" {
		t.Errorf("BaseURL = %q, want http://cp.example.com (forwarded headers untrusted)", got)
	}
}

func TestBaseURL_PlainHTTP(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://cp.internal/test", http.NoBody)
	req.Host = "cp.internal:9090"
	req.Header.Set("X-Forwarded-Proto", "http")
	got := BaseURL(req, true)
	if got != "http://cp.internal:9090" {
		t.Errorf("BaseURL = %q, want http://cp.internal:9090", got)
	}
}

func TestEnrollmentAddr(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		grpcAddr string
		fwdHost  string
		trustFwd bool
		want     string
	}{
		{"IPv4 host", "10.0.0.5:9090", ":50051", "", false, "10.0.0.5:50051"},
		{"hostname", "cp.example.com:9090", ":50051", "", false, "cp.example.com:50051"},
		{"IPv6 host", "[::1]:9090", ":50051", "", false, "[::1]:50051"},
		{"grpc has routable host", "10.0.0.5:9090", "192.168.1.1:50051", "", false, "192.168.1.1:50051"},
		{"grpc wildcard", "10.0.0.5:9090", "0.0.0.0:50051", "", false, "10.0.0.5:50051"},
		{"forwarded trusted", "10.0.0.5:9090", ":50051", "proxy.example.com", true, "proxy.example.com:50051"},
		{"forwarded untrusted", "10.0.0.5:9090", ":50051", "evil.com", false, "10.0.0.5:50051"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+tt.host+"/bootstrap", http.NoBody)
			req.Host = tt.host
			if tt.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}
			got := EnrollmentAddr(req, tt.grpcAddr, tt.trustFwd)
			if got != tt.want {
				t.Errorf("EnrollmentAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestImage_Defaults(t *testing.T) {
	// Missing settings file → default image with version tag mapping.
	missing := filepath.Join(t.TempDir(), "nope.json")
	if got := Image(missing, "dev"); got != DefaultImage+":latest" {
		t.Errorf("Image(dev) = %q, want %s:latest", got, DefaultImage)
	}
	if got := Image(missing, "1.2.3"); got != DefaultImage+":1.2.3" {
		t.Errorf("Image(1.2.3) = %q, want %s:1.2.3", got, DefaultImage)
	}
	if got := UpdaterImage(missing, "dev"); got != DefaultImage+"-updater:latest" {
		t.Errorf("UpdaterImage(dev) = %q, want %s-updater:latest", got, DefaultImage)
	}
	if got := UpdaterImage(missing, "1.2.3"); got != DefaultImage+"-updater:1.2.3" {
		t.Errorf("UpdaterImage(1.2.3) = %q, want %s-updater:1.2.3", got, DefaultImage)
	}
}

func TestImage_RegistryOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry_settings.json")
	if err := os.WriteFile(path, []byte(`{"registry_url":"registry.corp/culvert"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Image(path, "2.0.0"); got != "registry.corp/culvert:2.0.0" {
		t.Errorf("Image override = %q, want registry.corp/culvert:2.0.0", got)
	}
	if got := UpdaterImage(path, "dev"); got != "registry.corp/culvert-updater:latest" {
		t.Errorf("UpdaterImage override = %q, want registry.corp/culvert-updater:latest", got)
	}

	// Corrupt settings fall back to the default.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Image(bad, "dev"); got != DefaultImage+":latest" {
		t.Errorf("Image(corrupt settings) = %q, want default fallback", got)
	}
}

func TestRenderScript_And_Compose(t *testing.T) {
	var sb strings.Builder
	if err := RenderScript(&sb, "cp.example.com:9090", "https://cp.example.com:9090", "tok123"); err != nil {
		t.Fatalf("RenderScript: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		`CP_BASE="https://cp.example.com:9090"`,
		`TOKEN_PATH="tok123"`,
		"Generated by Control Plane at cp.example.com:9090",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("script missing %q", want)
		}
	}

	sb.Reset()
	if err := RenderCompose(&sb, "img:1", "img-updater:1", "culvert://enroll/x"); err != nil {
		t.Fatalf("RenderCompose: %v", err)
	}
	out = sb.String()
	for _, want := range []string{
		"image: img:1",
		"image: img-updater:1",
		"ENROLL_URL=culvert://enroll/x",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q", want)
		}
	}
}
