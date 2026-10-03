// Deliverable D: a CP retry with the same idempotency_key after an agent
// restart dedupes to the prior op's terminal result (never a second mutation).
package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestIdempotency_SurvivesAgentRestart(t *testing.T) {
	tmp := t.TempDir()
	rig1 := startApplyRigAt(t, tmp)
	body := map[string]interface{}{"image_ref": targetRef, "idempotency_key": "cp-retry-1"}
	op, opID := rig1.acceptAndWait(t, body)
	if op["state"] != "succeeded" {
		t.Fatalf("first apply: %+v", op)
	}
	rig1.stop()

	rig2 := startApplyRigAt(t, tmp) // same state dir ⇒ same idempotency.json
	defer rig2.stop()
	status, rb := rig2.post(t, body)
	if status != http.StatusOK {
		t.Fatalf("retry after restart must dedupe (200), got %d: %s", status, rb)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	if ack["op_id"] != opID || ack["state"] != "succeeded" {
		t.Fatalf("retry must return the PRIOR op's terminal result: %+v", ack)
	}
	if len(rig2.snapshot()) != 0 {
		t.Errorf("a deduped retry must run NO docker command: %v", rig2.snapshot())
	}
	// A different key is new work.
	status, _ = rig2.post(t, map[string]interface{}{"image_ref": targetRef, "idempotency_key": "cp-retry-2"})
	if status != http.StatusAccepted {
		t.Errorf("a fresh key must admit: %d", status)
	}
}
