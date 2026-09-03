package main

// pac_exception_intelligence_behavior_test.go — end-to-end behavioral proofs
// that PAC Exception Intelligence does what it is intended to do, driven through
// the REAL HTTP handlers and stores (not unit stubs):
//
//   - the DIRECT inventory surfaces full-security-path bypasses, including the
//     empty-proxy-host fail-open of the legacy default;
//   - governance status walks ungoverned → governed → expired → review_due and
//     back through the admin API;
//   - deleting a profile cascades to its governance (no stale attestation for a
//     recreated id);
//   - governance is NODE-LOCAL: it never rides the CP→DP config snapshot or the
//     config-version rollback capture.
//
// Real bugs found while writing these are recorded in
// roadmap/PEI-TEST-BACKLOG.md and the corresponding case is skipped with a
// BACKLOG reference, so the intent stays pinned without breaking the suite.

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

// peiResetGlobals isolates all three PAC stores for -shuffle hermeticity and
// gives the exception store a temp-file backing.
func peiResetGlobals(t *testing.T) {
	t.Helper()
	oc := pacStore.Snapshot()
	op := pacProfiles.Snapshot()
	oe := pacExceptions.Snapshot()
	t.Cleanup(func() { pacStore.Restore(oc); pacProfiles.Restore(op); pacExceptions.Restore(oe) })
	pacExceptions.Restore(pac.ExceptionState{ByID: map[string]pac.ExceptionRecord{}, Path: filepath.Join(t.TempDir(), "pac_exceptions.json")})
}

// peiExcItem drives the /{id} governance handler and returns the recorder.
func peiExcItem(t *testing.T, method, id, body string, role UIRole) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	// 2F-A: echo the authoritative record revision like a well-formed client.
	fenced := pacTestWithTokens(method, "/api/pac/posture/exceptions/"+id, body)
	if body != "" {
		r = httptest.NewRequest(method, fenced, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, fenced, http.NoBody)
	}
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	apiPACExceptionItem(rec, r)
	return rec
}

// peiStatusOf GETs the governance view for id and returns its computed status.
func peiStatusOf(t *testing.T, id string) string {
	t.Helper()
	rec := peiExcItem(t, http.MethodGet, id, "", RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d (%s)", id, rec.Code, rec.Body.String())
	}
	var v pacExceptionView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v.Status
}

// seedDirectCapableProfile installs one enabled DIRECT-capable custom profile.
func seedDirectCapableProfile(t *testing.T, id string) {
	t.Helper()
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{{
			ID: id, Name: id, Enabled: true, PoolID: "p",
			PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
			Rules: []pac.Rule{{Kind: pac.RuleKindWildcard, Pattern: "*.cdn.example", Action: pac.ActionDirect}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

// ── The full governance lifecycle through the admin API ──────────────────────

func TestPEI_Lifecycle_UngovernedToGovernedToExpiredToReviewDue(t *testing.T) {
	peiResetGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	seedDirectCapableProfile(t, "vendor")

	// 1. Fresh DIRECT-capable profile: inventory sees it, governance is ungoverned.
	if s := peiStatusOf(t, "vendor"); s != pac.GovUngoverned {
		t.Fatalf("fresh profile status = %q, want ungoverned", s)
	}

	// 2. Govern it (owned, justified, future expiry, review current) → governed.
	future := time.Now().UTC().Add(120 * 24 * time.Hour).Format(time.RFC3339)
	reviewedNow := time.Now().UTC().Format(time.RFC3339)
	body := `{"owner":"neteng","reason":"vendor SaaS","expiresAt":"` + future + `","reviewCadenceDays":90,"lastReviewedAt":"` + reviewedNow + `"}`
	if rec := peiExcItem(t, http.MethodPut, "vendor", body, RoleAdmin); rec.Code != http.StatusOK {
		t.Fatalf("govern PUT: %d (%s)", rec.Code, rec.Body.String())
	}
	if s := peiStatusOf(t, "vendor"); s != pac.GovGoverned {
		t.Fatalf("after govern status = %q, want governed", s)
	}

	// 3. Same record but with a PAST expiry → expired (renew/remove signal).
	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	body = `{"owner":"neteng","reason":"vendor SaaS","expiresAt":"` + past + `","reviewCadenceDays":90,"lastReviewedAt":"` + reviewedNow + `"}`
	if rec := peiExcItem(t, http.MethodPut, "vendor", body, RoleAdmin); rec.Code != http.StatusOK {
		t.Fatalf("expire PUT: %d (%s)", rec.Code, rec.Body.String())
	}
	if s := peiStatusOf(t, "vendor"); s != pac.GovExpired {
		t.Fatalf("past expiry status = %q, want expired", s)
	}

	// 4. No expiry, but review overdue (last review older than cadence) → review_due.
	oldReview := time.Now().UTC().Add(-200 * 24 * time.Hour).Format(time.RFC3339)
	body = `{"owner":"neteng","reason":"vendor SaaS","reviewCadenceDays":30,"lastReviewedAt":"` + oldReview + `"}`
	if rec := peiExcItem(t, http.MethodPut, "vendor", body, RoleAdmin); rec.Code != http.StatusOK {
		t.Fatalf("review PUT: %d (%s)", rec.Code, rec.Body.String())
	}
	if s := peiStatusOf(t, "vendor"); s != pac.GovReviewDue {
		t.Fatalf("overdue review status = %q, want review_due", s)
	}

	// 5. Clear → back to ungoverned.
	if rec := peiExcItem(t, http.MethodDelete, "vendor", "", RoleAdmin); rec.Code != http.StatusNoContent {
		t.Fatalf("clear DELETE: %d (%s)", rec.Code, rec.Body.String())
	}
	if s := peiStatusOf(t, "vendor"); s != pac.GovUngoverned {
		t.Fatalf("after clear status = %q, want ungoverned", s)
	}
}

// ── Fresh-attestation guard: recreate under the same id must be ungoverned ────

func TestPEI_RecreatedProfileRequiresFreshAttestation(t *testing.T) {
	peiResetGlobals(t)
	seedDirectCapableProfile(t, "hq")

	// Govern it.
	if rec := peiExcItem(t, http.MethodPut, "hq", `{"owner":"secops","reason":"legacy bypass"}`, RoleAdmin); rec.Code != http.StatusOK {
		t.Fatalf("govern: %d (%s)", rec.Code, rec.Body.String())
	}
	if s := peiStatusOf(t, "hq"); s != pac.GovGoverned {
		t.Fatalf("precondition status = %q, want governed", s)
	}

	// Delete the profile through the real profile handler (cascades governance).
	if rec := pacAPIReq(t, http.MethodDelete, "/api/pac/profiles/hq", "", RoleAdmin, "198.51.100.201:0"); rec.Code != http.StatusNoContent {
		t.Fatalf("profile delete: %d (%s)", rec.Code, rec.Body.String())
	}

	// Recreate a profile under the SAME id — a NEW bypass must read ungoverned,
	// never inherit the deleted profile's attestation.
	seedDirectCapableProfile(t, "hq")
	if s := peiStatusOf(t, "hq"); s != pac.GovUngoverned {
		t.Errorf("recreated profile status = %q, want ungoverned (fresh attestation)", s)
	}
}

// ── Node-local isolation: governance must not leak to sync or rollback ────────

func TestPEI_GovernanceNotInSnapshotOrRollbackCapture(t *testing.T) {
	peiResetGlobals(t)
	seedDirectCapableProfile(t, "leaky")

	// Govern with a unique token we can grep for in the serialized surfaces.
	const tok = "PEIISOLATIONTOKEN_owner_xyz"
	body := `{"owner":"` + tok + `","reason":"` + tok + `-reason"}`
	if rec := peiExcItem(t, http.MethodPut, "leaky", body, RoleAdmin); rec.Code != http.StatusOK {
		t.Fatalf("govern: %d (%s)", rec.Code, rec.Body.String())
	}
	// Sanity: the token really is stored.
	if r, ok := pacExceptions.Get("leaky"); !ok || r.Owner != tok {
		t.Fatalf("precondition: token not stored (%+v ok=%v)", r, ok)
	}

	// CP→DP config snapshot must not carry it.
	snap := CurrentConfigSnapshot()
	if b, _ := json.Marshal(snap); strings.Contains(string(b), tok) {
		t.Error("LEAK: governance metadata appears in the CP→DP ConfigSnapshot")
	}
	// Config-version rollback capture must not carry it.
	if cb := captureConfigBackup(); cb != nil {
		if b, _ := json.Marshal(cb); strings.Contains(string(b), tok) {
			t.Error("LEAK: governance metadata appears in the config-version rollback capture")
		}
	}
}

// ── Fail-open inventory through the HTTP endpoint ─────────────────────────────

func TestPEI_InventorySurfacesFailOpenViaHTTP(t *testing.T) {
	peiResetGlobals(t)
	// Empty ProxyHost = legacy /proxy.pac fails OPEN to DIRECT for all traffic.
	if err := pacStore.Set(PACConfig{ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pac/posture/inventory", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	rec := httptest.NewRecorder()
	apiPACPostureInventory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory: %d (%s)", rec.Code, rec.Body.String())
	}
	var inv pac.DirectInventory
	if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	var failOpen bool
	for _, p := range inv.Profiles {
		if p.ProfileID != pac.DefaultProfileID {
			continue
		}
		for _, d := range p.DirectPaths {
			if d.Kind == pac.BypassFailOpen && d.Broad {
				failOpen = true
			}
		}
	}
	if !failOpen {
		t.Error("empty ProxyHost must surface a broad fail_open DIRECT path on the default profile via HTTP")
	}
}

// ── Governance is audited (accountability) but NOT versioned (node-local) ─────

func TestPEI_GovernanceIsAuditedButNotVersioned(t *testing.T) {
	peiResetGlobals(t)
	tmp := snapshotConfigVersionsDir(t)
	seedDirectCapableProfile(t, "vendor")

	const actorIP = "198.51.100.180"

	// PUT govern → audited, not versioned.
	baselineTS := time.Now().UnixMilli()
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodPut, "/api/pac/posture/exceptions/vendor", []byte(`{"owner":"neteng","reason":"vendor SaaS"}`))
	r.RemoteAddr = actorIP + ":0"
	apiPACExceptionItem(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("govern: %d (%s)", w.Code, w.Body.String())
	}
	if !hasMatchingAuditEntry(auditGet(), actorIP, "pac.exception_set", "vendor", baselineTS) {
		t.Errorf("governance set must be audited (actor=%s action=pac.exception_set object=vendor)", actorIP)
	}
	assertNoConfigVersionWithAction(t, tmp, "pac.exception_set")

	// DELETE clear → audited, not versioned.
	baselineTS2 := time.Now().UnixMilli()
	w = httptest.NewRecorder()
	r = newAdminRequest(http.MethodDelete, pacTestWithTokens(http.MethodDelete, "/api/pac/posture/exceptions/vendor", ""), nil) // 2F-A: echo the loaded revision
	r.RemoteAddr = actorIP + ":0"
	apiPACExceptionItem(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("clear: %d (%s)", w.Code, w.Body.String())
	}
	if !hasMatchingAuditEntry(auditGet(), actorIP, "pac.exception_clear", "vendor", baselineTS2) {
		t.Errorf("governance clear must be audited")
	}
	assertNoConfigVersionWithAction(t, tmp, "pac.exception_clear")
}

// ── fail_open is default-only: a custom profile never gets it ─────────────────

func TestPEI_FailOpenIsDefaultProfileOnly(t *testing.T) {
	peiResetGlobals(t)
	// Empty ProxyHost (fail-open condition for the DEFAULT), plus a custom
	// profile whose pool is empty/unresolvable.
	if err := pacStore.Set(PACConfig{ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Profiles: []pac.Profile{{
			ID: "custom", Name: "Custom", Enabled: true, PoolID: "missing",
			PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	inv := pacDirectInventory()
	for _, p := range inv.Profiles {
		if p.ProfileID == pac.DefaultProfileID {
			continue
		}
		for _, d := range p.DirectPaths {
			if d.Kind == pac.BypassFailOpen {
				t.Errorf("custom profile %q must NOT carry fail_open (default-only): %+v", p.ProfileID, p.DirectPaths)
			}
		}
	}
}

// ── Unknown profile: governance not applicable ───────────────────────────────

func TestPEI_UnknownProfileHasNoGovernanceStatus(t *testing.T) {
	peiResetGlobals(t)
	seedDirectCapableProfile(t, "known")

	// GET a profile id that does not exist → directCapable false, empty status.
	rec := peiExcItem(t, http.MethodGet, "ghost", "", RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET ghost: %d", rec.Code)
	}
	var v pacExceptionView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.DirectCapable {
		t.Errorf("unknown profile must not be DIRECT-capable: %+v", v)
	}
	if v.Status != "" {
		t.Errorf("unknown profile status = %q, want empty (not applicable)", v.Status)
	}
	// PUT governance for an unknown profile must be rejected (no orphan records).
	if rec := peiExcItem(t, http.MethodPut, "ghost", `{"owner":"a","reason":"b"}`, RoleAdmin); rec.Code != http.StatusNotFound {
		t.Errorf("govern unknown profile: %d, want 404", rec.Code)
	}
}
