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
	// Without TLS on the test request, it checks X-Forwarded-Proto; absent = https default
	if got != "https://cp.example.com:9090" {
		t.Errorf("cpBaseURL = %q, want https://cp.example.com:9090", got)
	}
}

func TestCPBaseURL_XForwarded(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://cp.internal/test", nil)
	req.Host = "cp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "proxy.example.com")
	got := cpBaseURL(req)
	if got != "https://proxy.example.com" {
		t.Errorf("cpBaseURL = %q, want https://proxy.example.com", got)
	}
}

func TestBootstrapImage(t *testing.T) {
	img := bootstrapImage()
	if img == "" {
		t.Error("bootstrapImage returned empty")
	}
}

func TestUpdaterImage(t *testing.T) {
	img := updaterImage()
	if img == "" {
		t.Error("updaterImage returned empty")
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

func TestBootstrapCompose_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/bootstrap/invalidtoken123/compose", nil)
	w := httptest.NewRecorder()
	apiBootstrapCompose(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for invalid token", w.Code)
	}
}
