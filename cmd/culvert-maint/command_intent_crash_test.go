package main

// command_intent_crash_test.go — command attribution (ADR-0062 slice 3) on the
// REAL agent binary, SIGKILLed at chosen points of a real upgrade flow against
// the process-level Docker model of startup_crash_recovery_test.go.
//
// What is asserted is what an agent start can conclude from the operation's
// own record: `died_in_command` in GET /v1/status. The action that will use
// it (restore_prior, slice 4) is not in this change; these are its
// preconditions, and the sequences are the ones on which three reviews of the
// earlier, marker-based design (#2093) found a wrong recovery.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// journalFenceFile is the downgrade fence's file name (journal/schema.go).
const journalFenceFile = "00000000000000000000000000.json"

type intentStatus struct {
	Interrupted []struct {
		OpID          string `json:"op_id"`
		DiedInCommand string `json:"died_in_command"`
		Starts        int    `json:"agent_starts_seen"`
	} `json:"interrupted_operations"`
}

// diedIn returns what status says about opID after an agent start.
func (r *crashRig) diedIn(opID string) (command string, starts int) {
	r.t.Helper()
	var st intentStatus
	if code := r.get("/v1/status", &st); code != http.StatusOK {
		r.t.Fatalf("status: HTTP %d", code)
	}
	for _, o := range st.Interrupted {
		if o.OpID == opID {
			return o.DiedInCommand, o.Starts
		}
	}
	r.t.Fatalf("op %s is not listed as interrupted: %+v", opID, st.Interrupted)
	return "", 0
}

type intentRecordFile struct {
	Schema int `json:"schema"`
	Intent *struct {
		Command string `json:"command"`
	} `json:"intent"`
	Cut *struct {
		Command string `json:"command"`
		Seen    int    `json:"seen"`
	} `json:"cut"`
}

func (r *crashRig) recordFile(opID string) intentRecordFile {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.state, "reconcile", opID+".json")) // #nosec G304 -- rig-owned temp dir
	if err != nil {
		r.t.Fatalf("journal record of %s: %v", opID, err)
	}
	var f intentRecordFile
	if err := json.Unmarshal(raw, &f); err != nil {
		r.t.Fatalf("journal record of %s: %v\n%s", opID, err, raw)
	}
	return f
}

// TestCommandIntent_DiedInsideUp: the agent is killed inside the upgrade's
// `compose up`. The record on disk says so (an open intent, behind the
// downgrade fence). The first start after it, with reconcile_on_startup at its
// default "off", reports it; the start after that does not (cases A and E:
// a start has looked, whatever its mode; nothing that happens to the stack
// afterwards is that command's doing).
func TestCommandIntent_DiedInsideUp(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1")
	if f := r.recordFile(opID); f.Intent == nil || f.Intent.Command != "compose up" || f.Schema < 2 {
		t.Fatalf("record after the kill = %+v, want an open compose up intent at schema 2", f)
	}
	if _, err := os.Stat(filepath.Join(r.state, "reconcile", journalFenceFile)); err != nil {
		t.Errorf("no downgrade fence beside a record with an open intent: %v", err)
	}
	r.start()
	if cmd, starts := r.diedIn(opID); cmd != "compose up" || starts != 1 {
		t.Errorf("first start: died_in_command=%q agent_starts_seen=%d, want compose up / 1", cmd, starts)
	}
	if f := r.recordFile(opID); f.Intent != nil || f.Cut == nil || f.Cut.Seen != 1 || f.Schema != 0 {
		t.Errorf("record after the first start = %+v, want the intent consumed into cut.seen=1 at schema 1", f)
	}
	// The fence stood for as long as the intent was open, and no longer: an
	// agent downgrade is not held up by an interrupted record.
	if _, err := os.Stat(filepath.Join(r.state, "reconcile", journalFenceFile)); !os.IsNotExist(err) {
		t.Errorf("the downgrade fence is still there after the start consumed the intent (err=%v)", err)
	}
	r.kill()
	r.start()
	if cmd, starts := r.diedIn(opID); cmd != "" || starts != 2 {
		t.Errorf("second start: died_in_command=%q agent_starts_seen=%d, want none / 2", cmd, starts)
	}
}

// TestCommandIntent_KilledAfterTheCommandReturned (case C in its forward
// form): `compose up` returned, and the agent is killed later, in the health
// gate. No start may conclude that the agent died inside `compose up`.
func TestCommandIntent_KilledAfterTheCommandReturned(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("health")
	if f := r.recordFile(opID); f.Intent != nil {
		t.Fatalf("record after the kill = %+v, want no open intent (the command had returned)", f)
	}
	r.start()
	if cmd, _ := r.diedIn(opID); cmd != "" {
		t.Errorf("died_in_command = %q for an agent killed in the health gate, want none", cmd)
	}
}
