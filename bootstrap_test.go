package main

// bootstrap_test.go — HTTP handler tests for the bootstrap endpoints. The
// pure-helper and image-resolution tests moved in-package to
// internal/bootstrap with the extraction (ADR-0002).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
