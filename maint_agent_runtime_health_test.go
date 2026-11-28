package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveAgentStatus(t *testing.T, body string) {
	t.Helper()
	resetMaintAgentStatusCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(agent.Close)
	t.Setenv(envMaintAgentURL, agent.URL)
}

// The agent's runtime health evidence (ADR-0062 slice 5) reaches the admin API:
// state, reason and the last-known-good image.
func TestAPIMaintAgentStatus_SurfacesRuntimeHealth(t *testing.T) {
	dig := "sha256:" + strings.Repeat("9", 64)
	serveAgentStatus(t, `{"agent_version":"v1","compose_stack_up":true,
		"runtime_health":{"state":"unhealthy","reason":"not_ready","observed_at":"2026-11-27T10:00:00Z",
		"image_id":"sha256:`+strings.Repeat("1", 64)+`","interval_seconds":300,
		"last_good":{"image_id":"sha256:`+strings.Repeat("2", 64)+`","ref":"ghcr.io/kidcarmi/culvert@`+dig+`","digest":"`+dig+`","passed_at":"2026-11-27T09:00:00Z","gate":"runtime_observer"}}}`)
	_, body := callAPIMaintAgentStatus(t)
	rh, ok := body["runtime_health"].(map[string]any)
	if !ok {
		t.Fatalf("runtime_health missing: %v", body)
	}
	if rh["state"] != "unhealthy" || rh["reason"] != "not_ready" || rh["interval_seconds"] != float64(300) {
		t.Fatalf("runtime_health = %v", rh)
	}
	lg, ok := rh["last_good"].(map[string]any)
	if !ok || lg["digest"] != dig || lg["ref"] != "ghcr.io/kidcarmi/culvert@"+dig {
		t.Fatalf("last_good = %v", rh["last_good"])
	}
}

// An agent with the observer off (or one that predates it) leaves the payload
// as it was.
func TestAPIMaintAgentStatus_NoRuntimeHealthWhenTheAgentReportsNone(t *testing.T) {
	serveAgentStatus(t, `{"agent_version":"v1","compose_stack_up":true}`)
	_, body := callAPIMaintAgentStatus(t)
	if _, has := body["runtime_health"]; has {
		t.Fatalf("runtime_health invented: %v", body)
	}
}

// A state this build does not know is shown as unknown, and agent strings are
// bounded.
func TestAPIMaintAgentStatus_RuntimeHealthIsNormalised(t *testing.T) {
	serveAgentStatus(t, `{"agent_version":"v1","runtime_health":{"state":"healthy-ish","reason":"`+strings.Repeat("x", 5000)+`","interval_seconds":60}}`)
	_, body := callAPIMaintAgentStatus(t)
	rh, _ := body["runtime_health"].(map[string]any)
	if rh["state"] != "unknown" {
		t.Fatalf("an unknown state passed through: %v", rh["state"])
	}
	if r, _ := rh["reason"].(string); len(r) > maintAgentFieldBound {
		t.Fatalf("reason not bounded: %d bytes", len(r))
	}
}
