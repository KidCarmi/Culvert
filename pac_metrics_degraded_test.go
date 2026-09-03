package main

// pac_metrics_degraded_test.go — Enterprise Product Experience finding:
// serve-time PAC compile warnings (dropped rule, unresolvable pool
// reference, secure-mode conflict) used to be discoverable only via a log
// line, a Prometheus counter, or a one-shot alert. pacDegraded now keeps the
// last-observed state so GET /api/pac/profiles (and the PAC panel) can
// answer "is my PAC currently degraded" without SSH or a webhook.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// resetPACDegraded isolates pacDegraded across tests (parallel/-shuffle
// hermeticity), mirroring resetPACProfilesGlobals.
func resetPACDegraded(t *testing.T) {
	t.Helper()
	pacDegraded.mu.Lock()
	orig := pacDegraded.state
	pacDegraded.state = map[string]pacDegradedProfile{}
	pacDegraded.mu.Unlock()
	t.Cleanup(func() {
		pacDegraded.mu.Lock()
		pacDegraded.state = orig
		pacDegraded.mu.Unlock()
	})
}

func TestPacObserveServe_RecordsAndClearsDegradedState(t *testing.T) {
	resetPACDegraded(t)

	warn := pac.ValidationIssue{Field: "profiles", Entry: "branch-il", Code: "pool_not_found", Message: "pool \"gone\" not found; rule dropped"}
	pacObserveServe("branch-il", pac.Artifact{Warnings: []pac.ValidationIssue{warn}}, false)

	snap := pacDegradedSnapshot()
	got, ok := snap["branch-il"]
	if !ok {
		t.Fatal("expected branch-il to be recorded as degraded")
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Message != warn.Message {
		t.Errorf("unexpected warnings recorded: %+v", got.Warnings)
	}
	if got.At.IsZero() {
		t.Error("expected a non-zero observation timestamp")
	}

	// A later clean serve is the ONLY thing that clears it (recovery on
	// observed evidence, not elapsed time or an admin's edit).
	pacObserveServe("branch-il", pac.Artifact{}, false)
	if _, stillThere := pacDegradedSnapshot()["branch-il"]; stillThere {
		t.Error("a clean serve must clear the degraded entry")
	}
}

func TestPacObserveServe_UnrelatedProfileUnaffected(t *testing.T) {
	resetPACDegraded(t)
	pacObserveServe("a", pac.Artifact{Warnings: []pac.ValidationIssue{{Message: "x"}}}, false)
	pacObserveServe("b", pac.Artifact{}, false)
	snap := pacDegradedSnapshot()
	if _, ok := snap["a"]; !ok {
		t.Error("profile a must stay degraded")
	}
	if _, ok := snap["b"]; ok {
		t.Error("profile b never had a warning and must not appear")
	}
}

func TestPacForgetDegraded_DropsDeletedProfile(t *testing.T) {
	resetPACDegraded(t)
	pacObserveServe("gone", pac.Artifact{Warnings: []pac.ValidationIssue{{Message: "x"}}}, false)
	if _, ok := pacDegradedSnapshot()["gone"]; !ok {
		t.Fatal("setup: expected gone to be recorded")
	}
	pacForgetDegraded("gone")
	if _, ok := pacDegradedSnapshot()["gone"]; ok {
		t.Error("pacForgetDegraded must remove the entry")
	}
}

func TestApiPACProfiles_SurfacesDegradedState(t *testing.T) {
	resetPACProfilesGlobals(t)
	resetPACDegraded(t)
	seedProfilesConfig(t)
	pacObserveServe("branch-il", pac.Artifact{Warnings: []pac.ValidationIssue{
		{Field: "profiles", Entry: "branch-il", Code: "pool_not_found", Message: "pool \"il\" not found; rule dropped"},
	}}, false)

	req := httptest.NewRequest(http.MethodGet, "/api/pac/profiles", nil)
	rec := httptest.NewRecorder()
	apiPACProfiles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/pac/profiles: got %d, body %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Degraded map[string]pacDegradedProfile `json:"degraded"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	dg, ok := resp.Degraded["branch-il"]
	if !ok {
		t.Fatalf("expected \"degraded\" to include branch-il, got %+v", resp.Degraded)
	}
	if len(dg.Warnings) != 1 || dg.Warnings[0].Code != "pool_not_found" {
		t.Errorf("unexpected degraded warnings in API response: %+v", dg.Warnings)
	}

	// A profile that always served clean must not appear at all.
	if _, ok := resp.Degraded[pac.DefaultProfileID]; ok {
		t.Error("the never-degraded default profile must not appear in the response")
	}
}

func TestPacProfileDelete_ForgetsDegradedState(t *testing.T) {
	resetPACProfilesGlobals(t)
	resetPACDegraded(t)
	seedProfilesConfig(t)
	pacObserveServe("branch-il", pac.Artifact{Warnings: []pac.ValidationIssue{{Message: "x"}}}, false)
	if _, ok := pacDegradedSnapshot()["branch-il"]; !ok {
		t.Fatal("setup: expected branch-il to be recorded as degraded")
	}

	rec := pacAPIReq(t, http.MethodDelete, "/api/pac/profiles/branch-il", "", RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE profile: got %d, body %s", rec.Code, rec.Body.String())
	}
	if _, ok := pacDegradedSnapshot()["branch-il"]; ok {
		t.Error("deleting a profile must forget its degraded state")
	}
}
