package main

import (
	"strings"
	"testing"
)

// The agent's runtime recovery (ADR-0062 slice 6) reaches the admin API: its
// policy, how close the trigger is, and the last attempt.
func TestAPIMaintAgentStatus_SurfacesRuntimeRecovery(t *testing.T) {
	x, r := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	serveAgentStatus(t, `{"agent_version":"v1","compose_stack_up":true,
		"runtime_recovery":{"policy":"restore_last_gated","threshold":3,"not_ready_streak":1,"running":false,
		"last":{"at":"2026-11-28T12:00:00Z","op_id":"01M8H2N15N3P3GN95EF1HHVDQB","outcome":"recovered",
		"reason":"rollback_armed_tag_not_moved","image_id":"`+x+`","restore_image_id":"`+r+`"}}}`)
	_, body := callAPIMaintAgentStatus(t)
	rr, ok := body["runtime_recovery"].(map[string]any)
	if !ok {
		t.Fatalf("runtime_recovery missing: %v", body)
	}
	if rr["policy"] != "restore_last_gated" || rr["threshold"] != float64(3) || rr["not_ready_streak"] != float64(1) || rr["running"] != false {
		t.Fatalf("runtime_recovery = %v", rr)
	}
	last, ok := rr["last"].(map[string]any)
	if !ok || last["outcome"] != "recovered" || last["reason"] != "rollback_armed_tag_not_moved" ||
		last["op_id"] != "01M8H2N15N3P3GN95EF1HHVDQB" || last["image_id"] != x || last["restore_image_id"] != r ||
		last["at"] != "2026-11-28T12:00:00Z" {
		t.Fatalf("last = %v", rr["last"])
	}
}

// A refusal begins no operation: it reaches the admin with no op_id.
func TestAPIMaintAgentStatus_RuntimeRecoveryRefusalHasNoOp(t *testing.T) {
	serveAgentStatus(t, `{"agent_version":"v1","runtime_recovery":{"policy":"restore_last_gated","threshold":3,"not_ready_streak":0,"running":false,
		"last":{"at":"2026-11-28T12:00:00Z","outcome":"refused","reason":"no_provenance","image_id":"sha256:`+strings.Repeat("3", 64)+`"}}}`)
	_, body := callAPIMaintAgentStatus(t)
	rr, _ := body["runtime_recovery"].(map[string]any)
	last, _ := rr["last"].(map[string]any)
	if last["outcome"] != "refused" || last["reason"] != "no_provenance" {
		t.Fatalf("last = %v", last)
	}
	if _, has := last["op_id"]; has {
		t.Fatalf("an op_id was invented for a refusal: %v", last)
	}
}

// An agent with the recovery off (or one that predates it) leaves the payload
// as it was.
func TestAPIMaintAgentStatus_NoRuntimeRecoveryWhenTheAgentReportsNone(t *testing.T) {
	serveAgentStatus(t, `{"agent_version":"v1","compose_stack_up":true}`)
	_, body := callAPIMaintAgentStatus(t)
	if _, has := body["runtime_recovery"]; has {
		t.Fatalf("runtime_recovery invented: %v", body)
	}
}

// A policy or outcome this build does not know is shown as unknown, and agent
// strings are bounded.
func TestAPIMaintAgentStatus_RuntimeRecoveryIsNormalised(t *testing.T) {
	serveAgentStatus(t, `{"agent_version":"v1","runtime_recovery":{"policy":"restore_anything","threshold":3,"not_ready_streak":0,"running":false,
		"last":{"at":"2026-11-28T12:00:00Z","outcome":"partly","reason":"`+strings.Repeat("x", 5000)+`","op_id":"`+strings.Repeat("y", 5000)+`"}}}`)
	_, body := callAPIMaintAgentStatus(t)
	rr, _ := body["runtime_recovery"].(map[string]any)
	if rr["policy"] != "unknown" {
		t.Fatalf("an unknown policy passed through: %v", rr["policy"])
	}
	last, _ := rr["last"].(map[string]any)
	if last["outcome"] != "unknown" {
		t.Fatalf("an unknown outcome passed through: %v", last["outcome"])
	}
	for _, k := range []string{"reason", "op_id"} {
		if s, _ := last[k].(string); len(s) > maintAgentFieldBound {
			t.Fatalf("%s not bounded: %d bytes", k, len(s))
		}
	}
}
