package main

// pac_exceptions_api_test.go — PAC Exception Intelligence P2: governance API
// for DIRECT bypasses (owner/reason/expiry/review-cadence over DIRECT-capable
// profiles).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// pacExcTestSetup isolates the global PAC stores + the exceptions store and
// wires a temp-file backing so Put/Delete persistence is exercised.
func pacExcTestSetup(t *testing.T) {
	t.Helper()
	oc := pacStore.Snapshot()
	op := pacProfiles.Snapshot()
	oe := pacExceptions.Snapshot()
	t.Cleanup(func() { pacStore.Restore(oc); pacProfiles.Restore(op); pacExceptions.Restore(oe) })

	// A DIRECT-capable custom profile (broad wildcard DIRECT rule) plus a
	// proxy-only profile (still DIRECT-capable via the universal plain-host
	// bypass) so the listing has real rows.
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{
			{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
				Rules: []pac.Rule{{Kind: pac.RuleKindWildcard, Pattern: "*.cdn.example", Action: pac.ActionDirect}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	pacExceptions.Restore(pac.ExceptionState{ByID: map[string]pac.ExceptionRecord{}, Path: filepath.Join(t.TempDir(), "pac_exceptions.json")})
}

func pacExcReq(t *testing.T, method, path, body string, role UIRole) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	fenced := pacTestWithTokens(method, path, body)
	if body != "" {
		r = httptest.NewRequest(method, fenced, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, fenced, http.NoBody)
	}
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	switch path {
	case "/api/pac/posture/exceptions":
		apiPACExceptions(rec, r)
	default:
		apiPACExceptionItem(rec, r)
	}
	return rec
}

func TestAPIPACExceptions_ListAndStatus(t *testing.T) {
	pacExcTestSetup(t)

	rec := pacExcReq(t, http.MethodGet, "/api/pac/posture/exceptions", "", RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Exceptions []pacExceptionView `json:"exceptions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// default (legacy synthetic) + hq = 2 DIRECT-capable profiles (both carry
	// at least the universal plain-host bypass).
	if len(out.Exceptions) != 2 {
		t.Fatalf("want 2 DIRECT-capable rows, got %d: %+v", len(out.Exceptions), out.Exceptions)
	}
	for _, e := range out.Exceptions {
		if !e.DirectCapable {
			t.Errorf("row %q not DIRECT-capable", e.ProfileID)
		}
		if e.Status != pac.GovUngoverned {
			t.Errorf("row %q status = %q, want ungoverned (no record yet)", e.ProfileID, e.Status)
		}
	}
}

func TestAPIPACExceptions_PutValidation(t *testing.T) {
	pacExcTestSetup(t)

	// Missing owner+reason → 400 (the whole point of the feature).
	rec := pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq", `{"businessApp":"x"}`, RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty owner/reason: %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	// Unknown profile → 404.
	rec = pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/nope", `{"owner":"a","reason":"b"}`, RoleAdmin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown profile: %d, want 404 (%s)", rec.Code, rec.Body.String())
	}

	// Bad cadence → 400.
	rec = pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq", `{"owner":"a","reason":"b","reviewCadenceDays":99999}`, RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad cadence: %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	// Bad expiry format → 400.
	rec = pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq", `{"owner":"a","reason":"b","expiresAt":"not-a-date"}`, RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad expiry: %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	// Over-long field → 400 (defense-in-depth length cap).
	long := strings.Repeat("x", pacExceptionFieldMax+1)
	rec = pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq", `{"owner":"`+long+`","reason":"b"}`, RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-long owner: %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	// Viewer cannot PUT.
	rec = pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq", `{"owner":"a","reason":"b"}`, RoleViewer)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT: %d, want 403", rec.Code)
	}
}

func TestAPIPACExceptions_PutGetDeleteRoundTrip(t *testing.T) {
	pacExcTestSetup(t)

	// Govern hq: owned + justified + future expiry + review-current.
	future := time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	reviewed := time.Now().UTC().Format(time.RFC3339)
	body := `{"owner":"neteng","reason":"vendor SaaS bypass","businessApp":"Zoom","ticket":"JIRA-1",` +
		`"expiresAt":"` + future + `","reviewCadenceDays":90,"lastReviewedAt":"` + reviewed + `"}`
	rec := pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq", body, RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d (%s)", rec.Code, rec.Body.String())
	}
	var saved pac.ExceptionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.CreatedAt == "" || saved.CreatedBy == "" || saved.UpdatedAt == "" {
		t.Errorf("server must stamp created/updated: %+v", saved)
	}

	// GET one → governed.
	rec = pacExcReq(t, http.MethodGet, "/api/pac/posture/exceptions/hq", "", RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("get one: %d (%s)", rec.Code, rec.Body.String())
	}
	var view pacExceptionView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Status != pac.GovGoverned {
		t.Errorf("status = %q, want governed", view.Status)
	}
	if view.Record.Owner != "neteng" {
		t.Errorf("owner not persisted: %+v", view.Record)
	}

	// Update preserves CreatedAt/CreatedBy.
	rec = pacExcReq(t, http.MethodPut, "/api/pac/posture/exceptions/hq",
		`{"owner":"neteng2","reason":"still needed"}`, RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d (%s)", rec.Code, rec.Body.String())
	}
	var updated pac.ExceptionRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.CreatedAt != saved.CreatedAt || updated.CreatedBy != saved.CreatedBy {
		t.Errorf("update must preserve CreatedAt/CreatedBy: was (%s,%s) now (%s,%s)",
			saved.CreatedAt, saved.CreatedBy, updated.CreatedAt, updated.CreatedBy)
	}

	// DELETE → 204, then GET one shows ungoverned again.
	rec = pacExcReq(t, http.MethodDelete, "/api/pac/posture/exceptions/hq", "", RoleAdmin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d (%s)", rec.Code, rec.Body.String())
	}
	rec = pacExcReq(t, http.MethodDelete, "/api/pac/posture/exceptions/hq", "", RoleAdmin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing: %d, want 404", rec.Code)
	}
	rec = pacExcReq(t, http.MethodGet, "/api/pac/posture/exceptions/hq", "", RoleViewer)
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Status != pac.GovUngoverned {
		t.Errorf("after delete status = %q, want ungoverned", view.Status)
	}
}

// TestAPIPACExceptions_ClearedOnProfileDelete pins the Codex finding fix:
// deleting a profile must clear its governance record so a later profile
// recreated under the same id cannot inherit stale attestation.
func TestAPIPACExceptions_ClearedOnProfileDelete(t *testing.T) {
	resetPACProfilesGlobals(t)
	oe := pacExceptions.Snapshot()
	t.Cleanup(func() { pacExceptions.Restore(oe) })
	pacExceptions.Restore(pac.ExceptionState{ByID: map[string]pac.ExceptionRecord{}, Path: filepath.Join(t.TempDir(), "pac_exceptions.json")})

	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{
			{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
				Rules: []pac.Rule{{Kind: pac.RuleKindWildcard, Pattern: "*.cdn.example", Action: pac.ActionDirect}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := pacExceptions.Put(pac.ExceptionRecord{ProfileID: "hq", Owner: "neteng", Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := pacExceptions.Get("hq"); !ok {
		t.Fatal("precondition: exception should exist")
	}

	rec := pacAPIReq(t, http.MethodDelete, "/api/pac/profiles/hq", "", RoleAdmin, "198.51.100.90:0")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete profile: %d (%s)", rec.Code, rec.Body.String())
	}
	if _, ok := pacExceptions.Get("hq"); ok {
		t.Error("exception record must be cleared when its profile is deleted (stale-attestation guard)")
	}
}

func TestAPIPACExceptions_MethodNotAllowed(t *testing.T) {
	pacExcTestSetup(t)
	rec := pacExcReq(t, http.MethodPost, "/api/pac/posture/exceptions", "", RoleViewer)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST list: %d, want 405", rec.Code)
	}
	rec = pacExcReq(t, http.MethodPatch, "/api/pac/posture/exceptions/hq", "", RoleAdmin)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH item: %d, want 405", rec.Code)
	}
}
