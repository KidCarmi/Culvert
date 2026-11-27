package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// resetMaintAgentStatusCache isolates the process-global status cache per test.
func resetMaintAgentStatusCache(t *testing.T) {
	t.Helper()
	maintAgentStatusCache.mu.Lock()
	prevAt, prevPayload := maintAgentStatusCache.at, maintAgentStatusCache.payload
	maintAgentStatusCache.at, maintAgentStatusCache.payload = time.Time{}, nil
	maintAgentStatusCache.mu.Unlock()
	t.Cleanup(func() {
		maintAgentStatusCache.mu.Lock()
		maintAgentStatusCache.at, maintAgentStatusCache.payload = prevAt, prevPayload
		maintAgentStatusCache.mu.Unlock()
	})
}

func callAPIMaintAgentStatus(t *testing.T) (status int, body map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/maintenance-agent", http.NoBody)
	apiMaintAgentStatus(w, r)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w.Code, body
}

// TestAPIMaintAgentStatus_ReportsHealthFieldsAndIsCached pins the primary
// value of this endpoint: fields the agent already reports (version,
// privilege posture, compose-stack state) reach the admin API instead of
// being discarded, and repeated viewer GETs are served from the short cache
// (mirrors apiBackups: a refresh click must not shell out to `docker compose
// ps` on the host per click).
func TestAPIMaintAgentStatus_ReportsHealthFieldsAndIsCached(t *testing.T) {
	resetMaintAgentStatusCache(t)
	var hits atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{
			"agent_version": "v1.4.2",
			"privilege_mode": "sudo_scoped",
			"compose_stack_up": true
		}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	for i := 0; i < 3; i++ {
		code, body := callAPIMaintAgentStatus(t)
		if code != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200", i, code)
		}
		if body["available"] != true {
			t.Fatalf("call %d: available = %v, want true (body %v)", i, body["available"], body)
		}
		if body["agent_version"] != "v1.4.2" {
			t.Fatalf("call %d: agent_version = %v, want v1.4.2 (body %v)", i, body["agent_version"], body)
		}
		if body["compose_stack_up"] != true {
			t.Fatalf("call %d: compose_stack_up = %v, want true (body %v)", i, body["compose_stack_up"], body)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("agent hit %d times for 3 GETs inside the TTL, want exactly 1 (cache lost)", got)
	}
}

// TestAPIMaintAgentStatus_SurfacesComposeErrorAndPrivilegeWarning pins that the
// two fields most likely to explain a degraded-but-reachable agent (compose_error,
// privilege_warning) pass through rather than being silently dropped.
func TestAPIMaintAgentStatus_SurfacesComposeErrorAndPrivilegeWarning(t *testing.T) {
	resetMaintAgentStatusCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"agent_version": "v1.4.2",
			"privilege_mode": "docker_group_lab",
			"privilege_warning": "docker_group_lab is dev/lab only and effectively root-equivalent; not for production",
			"compose_stack_up": false,
			"compose_error": "exit status 1: no such service: proxy"
		}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	_, body := callAPIMaintAgentStatus(t)
	if body["compose_stack_up"] != false {
		t.Fatalf("compose_stack_up = %v, want false (body %v)", body["compose_stack_up"], body)
	}
	if body["compose_error"] == "" || body["compose_error"] == nil {
		t.Fatal("compose_error missing — the operator needs the cause on the panel")
	}
	if body["privilege_warning"] == "" || body["privilege_warning"] == nil {
		t.Fatal("privilege_warning missing — a broad-privilege agent must be flagged")
	}
}

// TestAPIMaintAgentStatus_AgentDownIsHTTP200Unavailable pins the same contract
// apiBackups established: the OpenAPI contract declares 200/403 only and the
// GUI's api() helper throws on any non-2xx, so agent-down must answer 200
// {available:false} — never 503 — exactly while the operator is diagnosing
// the agent.
func TestAPIMaintAgentStatus_AgentDownIsHTTP200Unavailable(t *testing.T) {
	resetMaintAgentStatusCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	agent.Close() // connection refused from here on
	t.Setenv(envMaintAgentURL, agent.URL)

	code, body := callAPIMaintAgentStatus(t)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with available:false", code)
	}
	if body["available"] != false {
		t.Fatalf("available = %v, want false (body %v)", body["available"], body)
	}
	if body["reason"] == "" || body["reason"] == nil {
		t.Fatal("reason missing — the operator needs the cause on the panel")
	}
}

// TestAPIMaintAgentStatus_RelaysRecoveryState pins that the agent's crash-recovery
// journal reaches the admin API: an interrupted upgrade, the reconcile verdict
// and pinned-tag drift were previously discarded, leaving SSH + curl on the
// agent socket as the only way to see them. The actor identity is not relayed.
func TestAPIMaintAgentStatus_RelaysRecoveryState(t *testing.T) {
	resetMaintAgentStatusCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"agent_version": "v1.4.2",
			"privilege_mode": "sudo_scoped",
			"compose_stack_up": false,
			"interrupted_operations": [{
				"op_id": "op-123", "kind": "upgrade.apply", "actor": "alice",
				"journal_phase": "tag_moved", "docker_state": "indeterminate",
				"running_image": "prior", "died_in_command": "compose up",
				"docker_reconciled": false, "prior_ref": "ghcr.io/x/proxy@sha256:ab",
				"operator_action": "Roll back to prior_ref.",
				"started_at": "2026-11-25T10:00:00Z"
			}],
			"recovery_required": true,
			"pinned_tag": {"image_id": "sha256:cd", "matches_running": false}
		}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	_, body := callAPIMaintAgentStatus(t)
	if body["recovery_required"] != true {
		t.Fatalf("recovery_required = %v, want true (body %v)", body["recovery_required"], body)
	}
	if body["pinned_tag_matches_running"] != false {
		t.Fatalf("pinned_tag_matches_running = %v, want false (body %v)", body["pinned_tag_matches_running"], body)
	}
	ops, _ := body["interrupted_operations"].([]any)
	if len(ops) != 1 {
		t.Fatalf("interrupted_operations = %v, want 1 entry", body["interrupted_operations"])
	}
	op, _ := ops[0].(map[string]any)
	for k, want := range map[string]string{
		"op_id": "op-123", "kind": "upgrade.apply", "docker_state": "indeterminate",
		"died_in_command": "compose up", "operator_action": "Roll back to prior_ref.",
		"prior_ref": "ghcr.io/x/proxy@sha256:ab", "started_at": "2026-11-25T10:00:00Z",
	} {
		if op[k] != want {
			t.Errorf("%s = %v, want %q", k, op[k], want)
		}
	}
	if _, leaked := op["actor"]; leaked {
		t.Error("actor relayed to a viewer-role surface; it must stay on the agent")
	}
}

// TestAPIMaintAgentStatus_HealthyPayloadHasNoRecoveryKeys pins that an agent
// with nothing to recover (or an older agent) leaves the payload unchanged.
func TestAPIMaintAgentStatus_HealthyPayloadHasNoRecoveryKeys(t *testing.T) {
	resetMaintAgentStatusCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"agent_version":"v1","privilege_mode":"sudo_scoped","compose_stack_up":true}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	_, body := callAPIMaintAgentStatus(t)
	for _, k := range []string{"interrupted_operations", "interrupted_operations_error", "recovery_required", "pinned_tag_matches_running", "interrupted_operations_truncated"} {
		if _, ok := body[k]; ok {
			t.Errorf("%s present on a healthy agent (body %v)", k, body)
		}
	}
}
