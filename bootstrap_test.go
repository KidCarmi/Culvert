package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractBootstrapToken(t *testing.T) {
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
		got := extractBootstrapToken(tt.path, tt.prefix)
		if got != tt.want {
			t.Errorf("extractBootstrapToken(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestCPBaseURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://cp.example.com:9090/test", nil)
	req.Host = "cp.example.com:9090"
	got := cpBaseURL(req)
	if got != "https://cp.example.com:9090" {
		t.Errorf("cpBaseURL = %q, want https://cp.example.com:9090", got)
	}
}

func TestCPBaseURL_XForwarded(t *testing.T) {
	old := trustForwardedHeaders
	trustForwardedHeaders = true
	defer func() { trustForwardedHeaders = old }()

	req := httptest.NewRequest(http.MethodGet, "http://cp.internal/test", nil)
	req.Host = "cp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "proxy.example.com")
	got := cpBaseURL(req)
	if got != "https://proxy.example.com" {
		t.Errorf("cpBaseURL = %q, want https://proxy.example.com", got)
	}
}

func TestCPBaseURL_XForwardedIgnoredByDefault(t *testing.T) {
	old := trustForwardedHeaders
	trustForwardedHeaders = false
	defer func() { trustForwardedHeaders = old }()

	req := httptest.NewRequest(http.MethodGet, "http://cp.internal/test", nil)
	req.Host = "cp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "proxy.example.com")
	got := cpBaseURL(req)
	// Should use r.Host, not X-Forwarded-Host
	if got != "http://cp.example.com" {
		t.Errorf("cpBaseURL = %q, want http://cp.example.com (forwarded headers untrusted)", got)
	}
}

func TestCPBaseURL_PlainHTTP(t *testing.T) {
	old := trustForwardedHeaders
	trustForwardedHeaders = true
	defer func() { trustForwardedHeaders = old }()

	req := httptest.NewRequest(http.MethodGet, "http://cp.internal/test", nil)
	req.Host = "cp.internal:9090"
	req.Header.Set("X-Forwarded-Proto", "http")
	got := cpBaseURL(req)
	if got != "http://cp.internal:9090" {
		t.Errorf("cpBaseURL = %q, want http://cp.internal:9090", got)
	}
}

func TestEnrollmentCPAddr(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		grpcAddr  string
		fwdHost   string
		trustFwd  bool
		want      string
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
			old := trustForwardedHeaders
			trustForwardedHeaders = tt.trustFwd
			defer func() { trustForwardedHeaders = old }()

			req := httptest.NewRequest(http.MethodGet, "https://"+tt.host+"/bootstrap", nil)
			req.Host = tt.host
			if tt.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}
			got := enrollmentCPAddr(req, tt.grpcAddr)
			if got != tt.want {
				t.Errorf("enrollmentCPAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBootstrapImage(t *testing.T) {
	img := bootstrapImage()
	if img == "" {
		t.Error("bootstrapImage returned empty")
	}
	// Should contain the default image
	if img != "ghcr.io/kidcarmi/culvert:latest" && img[:len(defaultImage)] != defaultImage {
		t.Errorf("bootstrapImage = %q, unexpected prefix", img)
	}
}

func TestUpdaterImage(t *testing.T) {
	img := updaterImage()
	if img == "" {
		t.Error("updaterImage returned empty")
	}
	if img != "ghcr.io/kidcarmi/culvert-updater:latest" && img[:len(defaultImage)] != defaultImage {
		t.Errorf("updaterImage = %q, unexpected prefix", img)
	}
}

func TestBootstrapScript_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/invalidtoken123", nil)
	w := httptest.NewRecorder()
	apiBootstrapScript(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for invalid token", w.Code)
	}
}

func TestBootstrapScript_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/bootstrap/sometoken", nil)
	w := httptest.NewRecorder()
	apiBootstrapScript(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestBootstrapScript_EmptyToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/", nil)
	w := httptest.NewRecorder()
	apiBootstrapScript(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty token", w.Code)
	}
}

func TestBootstrapScript_SlashInToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/a/b", nil)
	w := httptest.NewRecorder()
	apiBootstrapScript(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for slashes in token", w.Code)
	}
}

func TestBootstrapCompose_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/invalidtoken123/compose", nil)
	w := httptest.NewRecorder()
	apiBootstrapCompose(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for invalid token", w.Code)
	}
}

func TestBootstrapCompose_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/bootstrap/sometoken/compose", nil)
	w := httptest.NewRecorder()
	apiBootstrapCompose(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestBootstrapCompose_EmptyToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap//compose", nil)
	w := httptest.NewRecorder()
	apiBootstrapCompose(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty token", w.Code)
	}
}

func TestBootstrapCompose_BadPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/wrong/path/compose", nil)
	w := httptest.NewRecorder()
	apiBootstrapCompose(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for bad path", w.Code)
	}
}

func TestBootstrapRouter_Script(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/testtoken", nil)
	w := httptest.NewRecorder()
	apiBootstrapRouter(w, req)
	// Should route to script handler (which returns 404 for invalid token)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (routed to script)", w.Code)
	}
}

func TestBootstrapRouter_Compose(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/testtoken/compose", nil)
	w := httptest.NewRecorder()
	apiBootstrapRouter(w, req)
	// Should route to compose handler (which returns 404 for invalid token)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (routed to compose)", w.Code)
	}
}
