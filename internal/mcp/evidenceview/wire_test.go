package evidenceview

import (
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// notStartedProductionWire is the exact response body the root handler served
// for the shipped default posture before IM-009 moved the projection (captured
// from buildMCPEvidenceDTO at main 348a2cf). The move must not change one byte.
const notStartedProductionWire = `{"capability":"gateway","mode":"shadow","production_locked":true,"production_lock_message":"Production locked - external qualification required","lock_reason":"External qualification required: this build ships no qualification issuer or verifier, so Production is unreachable. No config, env, CLI, API, or GUI control can bypass it.","origin":"production","as_of_unix_nano":1000000000000000000,"shadow_start_unix":0,"shadow_elapsed_seconds":0,"shadow_target_seconds":1209600,"shadow_state":"not_started","canary_start_unix":0,"canary_elapsed_seconds":0,"canary_target_seconds":604800,"canary_state":"not_started","soak_start_unix":0,"soak_elapsed_seconds":0,"soak_target_seconds":86400,"soak_state":"not_started","open_critical_high":0,"zero_defect_state":"met","rollback_rehearsed":false,"rollback_rehearsal_state":"not_met","false_positive_reviews":0,"shadow_window_target_h":336,"canary_window_target_h":168,"soak_target_h":24,"requirements":[{"key":"shadow_window","label":"Shadow window floor","state":"not_started","origin":"production","measured_seconds":0,"target_seconds":1209600,"next_action":"Enter Shadow to begin the window."},{"key":"canary_window","label":"Canary window floor","state":"not_started","origin":"production","measured_seconds":0,"target_seconds":604800,"next_action":"Complete Shadow, then enter Canary to begin the window."},{"key":"soak_window","label":"Stable soak floor","state":"not_started","origin":"production","measured_seconds":0,"target_seconds":86400,"next_action":"The soak window begins on the next mode entry."},{"key":"zero_open_defects","label":"Zero open critical/high defects","state":"met","origin":"production","count":0,"next_action":"No open critical/high defects recorded."},{"key":"rollback_rehearsal","label":"Rollback rehearsal recorded","state":"not_met","origin":"production","next_action":"Rehearse rollback to record this evidence."},{"key":"false_positive_reviews","label":"Recorded false-positive reviews","state":"not_applicable","origin":"production","count":0,"next_action":"Informational: recorded reviews (no defined threshold)."}],"summary":{"measured_total":5,"met":1,"not_met":1,"not_started":3,"synthetic_non_qualifying":0,"unavailable":0},"unsupported_categories":["Signed SBOM","Build provenance","Privacy review","Support readiness","Operations readiness","Incident-response exercise","Documentation signoff","External penetration testing","Release approval","SLO achievement"]}`

func TestEvidenceView_WireBytesUnchanged(t *testing.T) {
	b, err := json.Marshal(Build("gateway", "shadow", rollout.EvidenceSummary{Origin: rollout.OriginProduction}, ux6Now, ux6Now.UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != notStartedProductionWire {
		t.Fatalf("wire shape drifted:\n got %s\nwant %s", b, notStartedProductionWire)
	}
}

// TestEvidenceView_IndependentResults proves two Builds share no mutable state:
// the unsupported-categories list is a fresh slice per call, so a caller that
// edits one result cannot change another result or a later response.
func TestEvidenceView_IndependentResults(t *testing.T) {
	ev := rollout.EvidenceSummary{Origin: rollout.OriginProduction}
	a := Build("gateway", "shadow", ev, ux6Now, ux6Now.UnixNano())
	b := Build("management", "disabled", ev, ux6Now, ux6Now.UnixNano())
	a.UnsupportedCategories[0] = "tampered"
	a.Requirements[0].State = stateMet
	if b.UnsupportedCategories[0] != "Signed SBOM" || b.Requirements[0].State != stateNotStarted {
		t.Fatalf("results alias each other: %+v", b)
	}
	if c := Build("gateway", "shadow", ev, ux6Now, ux6Now.UnixNano()); c.UnsupportedCategories[0] != "Signed SBOM" {
		t.Fatalf("a caller mutation leaked into a later Build: %q", c.UnsupportedCategories[0])
	}
	if b.Capability != "management" || b.Mode != "disabled" {
		t.Fatalf("capability/mode not echoed: %q/%q", b.Capability, b.Mode)
	}
}
