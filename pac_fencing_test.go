package main

// pac_fencing_test.go — 2F-A PAC concurrency-fencing matrix (R11–R14 of the
// approved 2F contract, docs/design/FRONTEND-MIGRATION-PLAN.md).
//
// RED-before evidence: every test in this file was committed against the
// frozen 2F-0 baseline (694a9f79) BEFORE the fencing correction and fails
// there, because the baseline (a) lets `revision: 0` / an omitted token skip
// the profile fence, (b) leaves DELETE, save_draft, and the posture-exception
// mutations unfenced, (c) answers a stale write with a plain-text 409 that
// carries no authoritative token, and (d) accepts collection creates with no
// collection token, so an admin acting on a stale listing silently commits
// on top of a peer's change.
//
// Target contract (identical for every fenced mutation):
//   - absent or zero token → 428 {code:"precondition_required", current:{…}}
//   - stale token          → 409 {code:"stale", current:{…}}
//   - vanished identity    → 404
// and for EVERY refusal: no persisted mutation, no in-memory mutation, no
// success audit for the refused actor, no config-version advancement.
// Concurrency proofs are deterministic (channels through the
// pacWriteStateDecision seam) — no sleeps, no probabilistic races.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/configver"
	"github.com/KidCarmi/Culvert/internal/pac"
)

// pacFenceLoserIP is the refused actor's client IP (TEST-NET-2), used as the
// audit-content discriminator (never a len() delta — see CLAUDE.md pitfalls).
const pacFenceLoserIP = "198.51.100.88"

const pacFenceWinnerIP = "198.51.100.89"

// pacFenceState is the complete observable state of the four PAC stores plus
// the config-version count; a refusal must leave it byte-identical.
type pacFenceState struct {
	profiles    pac.ProfilesConfig
	profileFile []byte
	legacy      pac.Config
	legacyFile  []byte
	lifecycle   map[string]*pac.ProfileLifecycle
	lcFile      []byte
	exceptions  map[string]pac.ExceptionRecord
	excFile     []byte
	versions    int
}

var pacFencePaths struct{ profiles, legacy, lifecycle, exceptions string }

func pacFenceCapture(t *testing.T) pacFenceState {
	t.Helper()
	rd := func(p string) []byte { b, _ := os.ReadFile(p); return b }
	return pacFenceState{
		profiles: pacProfiles.Get(), profileFile: rd(pacFencePaths.profiles),
		legacy: pacStore.Get(), legacyFile: rd(pacFencePaths.legacy),
		lifecycle: pacLifecycle.All(), lcFile: rd(pacFencePaths.lifecycle),
		exceptions: pacExceptions.All(), excFile: rd(pacFencePaths.exceptions),
		versions: len(configVersions.ListMeta()),
	}
}

func pacFenceAssertUnchanged(t *testing.T, before pacFenceState, since int64, actions ...string) {
	t.Helper()
	after := pacFenceCapture(t)
	if !reflect.DeepEqual(before.profiles, after.profiles) {
		t.Fatalf("refused mutation changed the in-memory profile store")
	}
	if !bytes.Equal(before.profileFile, after.profileFile) {
		t.Fatalf("refused mutation changed the persisted profile store")
	}
	if !reflect.DeepEqual(before.legacy, after.legacy) || !bytes.Equal(before.legacyFile, after.legacyFile) {
		t.Fatalf("refused mutation changed the legacy PAC config (memory or disk)")
	}
	if !reflect.DeepEqual(before.lifecycle, after.lifecycle) || !bytes.Equal(before.lcFile, after.lcFile) {
		t.Fatalf("refused mutation changed the lifecycle store (memory or disk)")
	}
	if !reflect.DeepEqual(before.exceptions, after.exceptions) || !bytes.Equal(before.excFile, after.excFile) {
		t.Fatalf("refused mutation changed the exception store (memory or disk)")
	}
	if after.versions != before.versions {
		t.Fatalf("refused mutation advanced the config-version store by %d", after.versions-before.versions)
	}
	for _, a := range actions {
		entries := auditGet()
		for i := range entries { // index-based: audit.Entry is large (rangeValCopy)
			e := &entries[i]
			if e.TS >= since && e.Action == a && strings.Contains(e.Actor, pacFenceLoserIP) {
				t.Fatalf("refused actor produced a success audit %q on %q", a, e.Object)
			}
		}
	}
}

// pacFenceRefusal decodes a structured refusal and asserts status, code and
// the presence of the authoritative current token.
func pacFenceRefusal(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode, tokenKey string) any {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status %d, want %d; body %s", rec.Code, wantStatus, rec.Body.String())
	}
	var body struct {
		Error   string         `json:"error"`
		Code    string         `json:"code"`
		Current map[string]any `json:"current"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal must be structured JSON, got %q: %v", rec.Body.String(), err)
	}
	if body.Code != wantCode || body.Error == "" {
		t.Fatalf("refusal code %q (error %q), want %q", body.Code, body.Error, wantCode)
	}
	cur, ok := body.Current[tokenKey]
	if !ok || cur == nil || cur == "" || cur == float64(0) {
		t.Fatalf("refusal must carry the authoritative current %q; got %v", tokenKey, body.Current)
	}
	return cur
}

// pacFenceEnv isolates every PAC store on temp files (so persisted-mutation
// checks are real), swaps the config-version store to a temp dir, seeds a
// pool + profile + spare pool + lifecycle draft + governance record, and
// restores everything on cleanup.
func pacFenceEnv(t *testing.T) {
	t.Helper()
	oc, op, ol, oe := pacStore.Snapshot(), pacProfiles.Snapshot(), pacLifecycle.Snapshot(), pacExceptions.Snapshot()
	ov, oh := configVersions, pacWriteStateDecisionHook
	t.Cleanup(func() {
		pacStore.Restore(oc)
		pacProfiles.Restore(op)
		pacLifecycle.Restore(ol)
		pacExceptions.Restore(oe)
		configVersions = ov
		pacWriteStateDecisionHook = oh
	})
	dir := t.TempDir()
	pacFencePaths.profiles = filepath.Join(dir, "pac_profiles.json")
	pacFencePaths.legacy = filepath.Join(dir, "pac_config.json")
	pacFencePaths.lifecycle = filepath.Join(dir, "pac_profiles_lifecycle.json")
	pacFencePaths.exceptions = filepath.Join(dir, "pac_exceptions.json")
	configVersions = configver.New(filepath.Join(dir, "config_versions"), 0)
	pacWriteStateDecisionHook = nil

	pacProfiles.Restore(pac.ProfileState{Path: pacFencePaths.profiles})
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Profiles: []pac.Profile{{
			ID: "branch-il", Name: "Branch IL", Enabled: true, PoolID: "il",
			PrivateNetworks: pac.PrivateDirect, AvailabilityMode: pac.ModeAvailability, Revision: 1,
			Rules: []pac.Rule{{Kind: pac.RuleKindSuffix, Pattern: "corp.example", Action: pac.ActionDirect}},
		}},
		Pools: []pac.Pool{
			{ID: "il", Name: "IL", Endpoints: []pac.PoolEndpoint{{Host: "proxy-il.example", Port: 8080}}},
			{ID: "spare", Name: "Spare", Endpoints: []pac.PoolEndpoint{{Host: "proxy-spare.example", Port: 8080}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	pacStore.Restore(pac.State{Path: pacFencePaths.legacy})
	if err := pacStore.Set(pac.Config{ProxyHost: "proxy.example", ProxyPort: 8080, Exclusions: []string{"corp.local"}}); err != nil {
		t.Fatal(err)
	}
	pacLifecycle.Restore(pac.LifecycleState{ByID: map[string]*pac.ProfileLifecycle{}, Path: pacFencePaths.lifecycle})
	pacExceptions.Restore(pac.ExceptionState{ByID: map[string]pac.ExceptionRecord{}, Path: pacFencePaths.exceptions})

	// Seed a lifecycle draft (first save_draft = create, no token needed) and a
	// governance record (first PUT = create) as the WINNER actor.
	rec := pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
		`{"action":"save_draft","draft":{"id":"branch-il","name":"Draft IL","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]}}`, pacFenceWinnerIP)
	if rec.Code != 200 {
		t.Fatalf("seed save_draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = pacFenceReq(t, "PUT", "/api/pac/posture/exceptions/branch-il",
		`{"owner":"netops","reason":"branch carve-out"}`, pacFenceWinnerIP)
	if rec.Code != 200 {
		t.Fatalf("seed exception PUT: %d %s", rec.Code, rec.Body.String())
	}
}

// pacFenceReq dispatches an admin request to the PAC handler owning the path.
func pacFenceReq(t *testing.T, method, path, body, ip string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body == "" {
		rd = bytes.NewReader(nil)
	} else {
		rd = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40001"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	switch p := req.URL.Path; {
	case p == "/api/pac-config":
		apiPACConfig(rec, req)
	case p == "/api/pac/profiles":
		apiPACProfiles(rec, req)
	case strings.HasPrefix(p, "/api/pac/profiles/"):
		apiPACProfileItem(rec, req)
	case p == "/api/pac/pools":
		apiPACPools(rec, req)
	case strings.HasPrefix(p, "/api/pac/pools/"):
		apiPACPoolItem(rec, req)
	case p == "/api/pac/posture/exceptions":
		apiPACExceptions(rec, req)
	case strings.HasPrefix(p, "/api/pac/posture/exceptions/"):
		apiPACExceptionItem(rec, req)
	default:
		t.Fatalf("unmapped path %s", path)
	}
	return rec
}

// pacFenceTokens reads every authoritative token the contract exposes.
type pacFenceTokens struct {
	profileRevision   int64
	collectionEtag    string
	poolEtags         map[string]string
	legacyRevision    int64
	draftRevision     int64
	exceptionRevision int64
}

func pacFenceReadTokens(t *testing.T) pacFenceTokens {
	t.Helper()
	var tk pacFenceTokens
	rec := pacFenceReq(t, "GET", "/api/pac/profiles", "", pacFenceWinnerIP)
	var list struct {
		Profiles       []pac.Profile     `json:"profiles"`
		CollectionEtag string            `json:"collectionEtag"`
		PoolEtags      map[string]string `json:"poolEtags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for i := range list.Profiles {
		if list.Profiles[i].ID == "branch-il" {
			tk.profileRevision = list.Profiles[i].Revision
		}
	}
	tk.collectionEtag, tk.poolEtags = list.CollectionEtag, list.PoolEtags
	if tk.collectionEtag == "" || tk.poolEtags["spare"] == "" {
		t.Fatalf("GET /api/pac/profiles must expose collectionEtag and poolEtags; got %s", rec.Body.String())
	}
	rec = pacFenceReq(t, "GET", "/api/pac-config", "", pacFenceWinnerIP)
	var legacy struct {
		Revision int64 `json:"revision"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &legacy)
	if legacy.Revision == 0 {
		t.Fatalf("GET /api/pac-config must expose a non-zero revision; got %s", rec.Body.String())
	}
	tk.legacyRevision = legacy.Revision
	rec = pacFenceReq(t, "GET", "/api/pac/profiles/branch-il/lifecycle", "", pacFenceWinnerIP)
	var lc struct {
		DraftRevision int64 `json:"draftRevision"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &lc)
	if lc.DraftRevision == 0 {
		t.Fatalf("lifecycle GET must expose a non-zero draftRevision; got %s", rec.Body.String())
	}
	tk.draftRevision = lc.DraftRevision
	rec = pacFenceReq(t, "GET", "/api/pac/posture/exceptions/branch-il", "", pacFenceWinnerIP)
	var ex struct {
		Record struct {
			Revision int64 `json:"revision"`
		} `json:"record"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ex)
	if ex.Record.Revision == 0 {
		t.Fatalf("exception GET must expose a non-zero record.revision; got %s", rec.Body.String())
	}
	tk.exceptionRevision = ex.Record.Revision
	return tk
}

const pacFenceProfileBody = `{"id":"branch-il","name":"Renamed IL","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]%s}`

func pacFenceProfileJSON(extra string) string { return fmt.Sprintf(pacFenceProfileBody, extra) }

// ── R11: revision 0 / omitted token must not bypass an existing-object fence ──

func TestPACFence_R11_ProfilePUT_RevisionZero_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", pacFenceProfileJSON(`,"revision":0`), pacFenceLoserIP)
	if cur := pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "revision"); cur != float64(1) {
		t.Fatalf("current.revision = %v, want 1", cur)
	}
	pacFenceAssertUnchanged(t, before, since, "pac.profile_update")
}

func TestPACFence_R11_ProfilePUT_OmittedRevision_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", pacFenceProfileJSON(""), pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "revision")
	pacFenceAssertUnchanged(t, before, since, "pac.profile_update")
}

func TestPACFence_R11_LegacyConfigPOST_OmittedRevision_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "POST", "/api/pac-config", `{"proxyHost":"other.example","proxyPort":3128,"exclusions":[]}`, pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "revision")
	pacFenceAssertUnchanged(t, before, since, "pac.update")
}

func TestPACFence_R11_PoolPUT_OmittedEtag_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "PUT", "/api/pac/pools/spare", `{"id":"spare","name":"Spare 2","endpoints":[{"host":"x.example","port":8080}]}`, pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "etag")
	pacFenceAssertUnchanged(t, before, since, "pac.pool_update")
}

func TestPACFence_R11_TokensAreExposedOnEveryReadSurface(t *testing.T) {
	pacFenceEnv(t)
	tk := pacFenceReadTokens(t)
	if tk.profileRevision != 1 {
		t.Fatalf("profile revision %d, want 1", tk.profileRevision)
	}
	// A correct token is accepted and the object's token advances exactly once.
	rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", pacFenceProfileJSON(fmt.Sprintf(`,"revision":%d`, tk.profileRevision)), pacFenceWinnerIP)
	if rec.Code != 200 {
		t.Fatalf("fresh-token PUT: %d %s", rec.Code, rec.Body.String())
	}
	if got := pacFenceReadTokens(t); got.profileRevision != 2 || got.collectionEtag == tk.collectionEtag {
		t.Fatalf("after one PUT: revision %d (want 2), collectionEtag changed=%v", got.profileRevision, got.collectionEtag != tk.collectionEtag)
	}
}

// ── R12: DELETE, save_draft and exception mutations must be fenced ──

func TestPACFence_R12_ProfileDELETE_OmittedRevision_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "DELETE", "/api/pac/profiles/branch-il", "", pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "revision")
	pacFenceAssertUnchanged(t, before, since, "pac.profile_delete")
	if _, ok := pacProfiles.ProfileByID("branch-il"); !ok {
		t.Fatal("profile was deleted by an unfenced DELETE")
	}
}

func TestPACFence_R12_PoolDELETE_OmittedEtag_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "DELETE", "/api/pac/pools/spare", "", pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "etag")
	pacFenceAssertUnchanged(t, before, since, "pac.pool_delete")
}

func TestPACFence_R12_SaveDraft_OmittedDraftRevision_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
		`{"action":"save_draft","draft":{"id":"branch-il","name":"Clobber","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]}}`, pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "draftRevision")
	pacFenceAssertUnchanged(t, before, since, "pac.profile_draft")
}

func TestPACFence_R12_ExceptionPUT_OmittedRevision_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "PUT", "/api/pac/posture/exceptions/branch-il", `{"owner":"someone-else","reason":"overwrite"}`, pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "revision")
	pacFenceAssertUnchanged(t, before, since, "pac.exception_set")
}

func TestPACFence_R12_ExceptionDELETE_OmittedRevision_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "DELETE", "/api/pac/posture/exceptions/branch-il", "", pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "revision")
	pacFenceAssertUnchanged(t, before, since, "pac.exception_clear")
}

// ── R13: a stale token yields a STRUCTURED 409 carrying the current token ──

func TestPACFence_R13_StaleTokens_AreStructured409(t *testing.T) {
	pacFenceEnv(t)
	tk := pacFenceReadTokens(t)
	cases := []struct {
		name, method, path, body, key, action string
	}{
		{"profile-put", "PUT", "/api/pac/profiles/branch-il", pacFenceProfileJSON(`,"revision":77`), "revision", "pac.profile_update"},
		{"profile-delete", "DELETE", "/api/pac/profiles/branch-il?revision=77", "", "revision", "pac.profile_delete"},
		{"pool-put", "PUT", "/api/pac/pools/spare", `{"id":"spare","name":"Spare 2","endpoints":[{"host":"x.example","port":8080}],"etag":"stale-etag"}`, "etag", "pac.pool_update"},
		{"pool-delete", "DELETE", "/api/pac/pools/spare?etag=stale-etag", "", "etag", "pac.pool_delete"},
		{"legacy-config", "POST", "/api/pac-config", `{"proxyHost":"other.example","proxyPort":3128,"exclusions":[],"revision":77}`, "revision", "pac.update"},
		{"save-draft", "POST", "/api/pac/profiles/branch-il/lifecycle", `{"action":"save_draft","draftRevision":77,"draft":{"id":"branch-il","name":"Clobber","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]}}`, "draftRevision", "pac.profile_draft"},
		{"publish", "POST", "/api/pac/profiles/branch-il/lifecycle", `{"action":"publish","expectedActiveRevision":77,"draft":{"id":"branch-il","name":"Pub","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]}}`, "revision", "pac.profile_publish"},
		{"exception-put", "PUT", "/api/pac/posture/exceptions/branch-il", `{"owner":"someone-else","reason":"overwrite","revision":77}`, "revision", "pac.exception_set"},
		{"exception-delete", "DELETE", "/api/pac/posture/exceptions/branch-il?revision=77", "", "revision", "pac.exception_clear"},
		{"profile-create-stale-collection", "POST", "/api/pac/profiles", `{"id":"new-one","name":"New","enabled":false,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[],"collectionEtag":"stale-etag"}`, "collectionEtag", "pac.profile_create"},
		{"pool-create-stale-collection", "POST", "/api/pac/pools", `{"id":"new-pool","name":"New","endpoints":[{"host":"x.example","port":8080}],"collectionEtag":"stale-etag"}`, "collectionEtag", "pac.pool_create"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before, since := pacFenceCapture(t), time.Now().UnixMilli()
			rec := pacFenceReq(t, c.method, c.path, c.body, pacFenceLoserIP)
			cur := pacFenceRefusal(t, rec, http.StatusConflict, "stale", c.key)
			switch c.key {
			case "revision":
				want := tk.profileRevision
				if c.name == "legacy-config" {
					want = tk.legacyRevision
				} else if strings.HasPrefix(c.name, "exception") {
					want = tk.exceptionRevision
				}
				if cur != float64(want) {
					t.Fatalf("current.revision = %v, want %d", cur, want)
				}
			case "draftRevision":
				if cur != float64(tk.draftRevision) {
					t.Fatalf("current.draftRevision = %v, want %d", cur, tk.draftRevision)
				}
			case "collectionEtag":
				if cur != tk.collectionEtag {
					t.Fatalf("current.collectionEtag = %v, want %s", cur, tk.collectionEtag)
				}
			case "etag":
				if cur != tk.poolEtags["spare"] {
					t.Fatalf("current.etag = %v, want %s", cur, tk.poolEtags["spare"])
				}
			}
			pacFenceAssertUnchanged(t, before, since, c.action)
		})
	}
}

func TestPACFence_R13_RollbackStaleExpectedActiveRevision_Is409(t *testing.T) {
	pacFenceEnv(t)
	tk := pacFenceReadTokens(t)
	// Publish once with the correct token so a rollback target exists.
	rec := pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
		fmt.Sprintf(`{"action":"publish","expectedActiveRevision":%d,"draft":{"id":"branch-il","name":"Pub","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]}}`, tk.profileRevision), pacFenceWinnerIP)
	if rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec = pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle", `{"action":"rollback","targetN":1,"expectedActiveRevision":77}`, pacFenceLoserIP)
	if cur := pacFenceRefusal(t, rec, http.StatusConflict, "stale", "revision"); cur != float64(tk.profileRevision+1) {
		t.Fatalf("current.revision = %v, want %d", cur, tk.profileRevision+1)
	}
	pacFenceAssertUnchanged(t, before, since, "pac.profile_rollback")
}

func TestPACFence_R13_VanishedIdentity_Is404(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/pac/profiles/ghost", `{"id":"ghost","name":"G","enabled":false,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[],"revision":3}`},
		{"DELETE", "/api/pac/profiles/ghost?revision=3", ""},
		{"PUT", "/api/pac/pools/ghost", `{"id":"ghost","name":"G","endpoints":[{"host":"x.example","port":8080}],"etag":"whatever"}`},
		{"DELETE", "/api/pac/pools/ghost?etag=whatever", ""},
		{"DELETE", "/api/pac/posture/exceptions/branch-eu?revision=3", ""},
	} {
		if rec := pacFenceReq(t, c.method, c.path, c.body, pacFenceLoserIP); rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s: %d, want 404", c.method, c.path, rec.Code)
		}
	}
	pacFenceAssertUnchanged(t, before, since)
}

// ── R14: collection creates need a collection token ──

func TestPACFence_R14_Create_OmittedCollectionEtag_Is428(t *testing.T) {
	pacFenceEnv(t)
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacFenceReq(t, "POST", "/api/pac/profiles", `{"id":"new-one","name":"New","enabled":false,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[]}`, pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "collectionEtag")
	rec = pacFenceReq(t, "POST", "/api/pac/pools", `{"id":"new-pool","name":"New","endpoints":[{"host":"x.example","port":8080}]}`, pacFenceLoserIP)
	pacFenceRefusal(t, rec, http.StatusPreconditionRequired, "precondition_required", "collectionEtag")
	pacFenceAssertUnchanged(t, before, since, "pac.profile_create", "pac.pool_create")
}

func TestPACFence_R14_CreateOnStaleListing_Is409(t *testing.T) {
	pacFenceEnv(t)
	e0 := pacFenceReadTokens(t).collectionEtag
	// Peer admin creates a pool against the same listing — accepted.
	rec := pacFenceReq(t, "POST", "/api/pac/pools", `{"id":"peer-pool","name":"Peer","endpoints":[{"host":"peer.example","port":8080}],"collectionEtag":"`+e0+`"}`, pacFenceWinnerIP)
	if rec.Code != 200 {
		t.Fatalf("peer create: %d %s", rec.Code, rec.Body.String())
	}
	e1 := pacFenceReadTokens(t).collectionEtag
	if e1 == e0 {
		t.Fatal("collectionEtag must change after a peer create")
	}
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec = pacFenceReq(t, "POST", "/api/pac/profiles", `{"id":"new-one","name":"New","enabled":false,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[],"collectionEtag":"`+e0+`"}`, pacFenceLoserIP)
	if cur := pacFenceRefusal(t, rec, http.StatusConflict, "stale", "collectionEtag"); cur != e1 {
		t.Fatalf("current.collectionEtag = %v, want %s", cur, e1)
	}
	pacFenceAssertUnchanged(t, before, since, "pac.profile_create")
}

// TestPACFence_R14_InterleavedCreates_FenceDecidedInsideTheLock parks admin
// A's create (token e0) at the "resolved" seam — decoded, token captured, lock
// NOT held — while admin B creates with the same e0 and commits; A is then
// released and must be refused with the post-B token. Deterministic:
// channels only.
func TestPACFence_R14_InterleavedCreates_FenceDecidedInsideTheLock(t *testing.T) {
	pacFenceEnv(t)
	e0 := pacFenceReadTokens(t).collectionEtag
	parked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	pacWriteStateDecisionHook = func(r *http.Request, stage string) {
		if stage == "resolved" && strings.HasPrefix(r.RemoteAddr, pacFenceLoserIP) {
			once.Do(func() { close(parked) })
			<-release
		}
	}
	versionsBefore := len(configVersions.ListMeta())
	since := time.Now().UnixMilli()
	var recA *httptest.ResponseRecorder
	done := make(chan struct{})
	go func() {
		defer close(done)
		recA = pacFenceReq(t, "POST", "/api/pac/profiles", `{"id":"a-profile","name":"A","enabled":false,"poolId":"il","privateNetworks":"proxy","availabilityMode":"secure","rules":[],"collectionEtag":"`+e0+`"}`, pacFenceLoserIP)
	}()
	<-parked
	recB := pacFenceReq(t, "POST", "/api/pac/pools", `{"id":"b-pool","name":"B","endpoints":[{"host":"b.example","port":8080}],"collectionEtag":"`+e0+`"}`, pacFenceWinnerIP)
	if recB.Code != 200 {
		t.Fatalf("B create: %d %s", recB.Code, recB.Body.String())
	}
	e1 := pacFenceReadTokens(t).collectionEtag
	before := pacFenceCapture(t)
	close(release)
	<-done
	if cur := pacFenceRefusal(t, recA, http.StatusConflict, "stale", "collectionEtag"); cur != e1 {
		t.Fatalf("A's refusal must carry B's token %s, got %v", e1, cur)
	}
	pacFenceAssertUnchanged(t, before, since, "pac.profile_create")
	if _, ok := pacProfiles.ProfileByID("a-profile"); ok {
		t.Fatal("loser's profile was created")
	}
	if _, ok := pacProfiles.PoolByID("b-pool"); !ok {
		t.Fatal("winner's pool is missing")
	}
	if got := len(configVersions.ListMeta()) - versionsBefore; got != 1 {
		t.Fatalf("config versions advanced by %d, want exactly 1 (winner only)", got)
	}
}
