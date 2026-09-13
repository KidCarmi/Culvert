package main

// fe6a0_red_test.go — FE-6A.0 RED matrix (R1–R14), committed on the exact
// merged baseline BEFORE any product change (FRONTEND-MIGRATION-PLAN.md,
// FE-6-0 §I "6A.0"). Every test here encodes the CORRECTED backend contract
// for FE-V27 Identity Providers and FE-V37 Administrators and is expected to
// FAIL on the baseline it is committed on; the FE-6A.0 product commits turn
// each row GREEN without editing the assertions.
//
// Contract dialect (FE-6-0 C1/C2/C3, the 2F-A PAC fence shape reused
// verbatim): a fenced write asserts the server-minted integer `revision`
// (JSON body or `?revision=` query, query wins); absent/zero ⇒
// 428 {error, code:"precondition_required", current:{revision}}; stale ⇒
// 409 {error, code:"stale", current:{revision}}; vanished identity ⇒ 404
// {error, code:"vanished"|"not_found"}; every refusal is application/json
// with a bounded `code`, mutates nothing, audits no success, publishes no
// cluster snapshot and advances no config version; a persist failure is
// 500 {code:"persist_failed"} with the pre-mutation state fully
// authoritative in memory, on disk and after a restart.
//
// Determinism: channel-controlled seams (the dial seam for R1), filesystem-
// level persist-failure injection (a registry/roster path whose parent is a
// regular file), and sequential stale-fence replays for the concurrency rows
// (R3/R11/R12) — no sleeps as correctness evidence; the single timer in R1
// bounds only the FAILURE branch (a blocked reader), never the success path.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ─── Harness ─────────────────────────────────────────────────────────────────

// fe6aBrokenPath returns a path whose parent is a regular file, so every
// atomic write attempt fails deterministically (the auth_idp_registry_txn
// precedent).
func fe6aBrokenPath(t *testing.T, name string) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(blocker, name)
}

// fe6aSwapRegistry installs a fresh PERSISTED registry at path (a temp file
// when path == "") and restores the previous singleton afterwards.
func fe6aSwapRegistry(t *testing.T, path string) (reg *IdPRegistry, regPath string) {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	if path == "" {
		path = filepath.Join(t.TempDir(), "idp_profiles.json")
	}
	reg = &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := reg.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	idpRegistry = reg
	return reg, path
}

// fe6aSwapConfigStore isolates the CP publication store and returns it.
func fe6aSwapConfigStore(t *testing.T) *ConfigStore {
	t.Helper()
	orig := globalConfigStore
	globalConfigStore = &ConfigStore{}
	t.Cleanup(func() { globalConfigStore = orig })
	return globalConfigStore
}

// fe6aSwapCfg installs a fresh admin roster persisted at usersPath (temp when
// "") with one bootstrap admin, isolates the session revocation list and the
// login limiter, and restores everything afterwards.
func fe6aSwapCfg(t *testing.T, usersPath string) (c *Config, path string) {
	t.Helper()
	orig := cfg
	t.Cleanup(func() { cfg = orig })
	if usersPath == "" {
		usersPath = filepath.Join(t.TempDir(), "ui_users.json")
	}
	c = newTestConfig()
	c.SetUIUsersFile(usersPath)
	if err := c.SetAuth("root", "RootPass1"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	cfg = c
	t.Cleanup(sessionRevoked.SwapForTest())
	return c, usersPath
}

// fe6aRosterFromDisk reloads the persisted roster into a FRESH Config — the
// "truthful state after restart" probe.
func fe6aRosterFromDisk(t *testing.T, path string) map[string]UIRole {
	t.Helper()
	fresh := newTestConfig()
	fresh.SetUIUsersFile(path)
	if err := fresh.LoadUIUsersFile(); err != nil {
		t.Fatalf("reload roster: %v", err)
	}
	out := map[string]UIRole{}
	for _, u := range fresh.ListUIUsers() {
		out[u.Username] = u.Role
	}
	return out
}

// fe6aRegistryFromDisk reloads the persisted registry into a FRESH registry.
func fe6aRegistryFromDisk(t *testing.T, path string) []*IdPProfile {
	t.Helper()
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("reload registry: %v", err)
	}
	return fresh.All()
}

func fe6aReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		return nil // absent — including a deliberately broken parent path
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fe6aJSON decodes a JSON object response body.
func fe6aJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not a JSON object (status %d, content-type %q): %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	return m
}

// fe6aAssertRefusal pins the ONE refusal shape: contracted status,
// application/json, bounded `code`.
func fe6aAssertRefusal(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode string) map[string]any {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, wantStatus, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("refusal content-type = %q, want application/json (body=%q)", ct, w.Body.String())
	}
	m := fe6aJSON(t, w)
	if got, _ := m["code"].(string); got != wantCode {
		t.Fatalf("refusal code = %q, want %q; body=%s", got, wantCode, w.Body.String())
	}
	if _, ok := m["error"].(string); !ok {
		t.Fatalf("refusal must carry a string `error`; body=%s", w.Body.String())
	}
	return m
}

// fe6aCurrentRevision extracts current.revision from a fence refusal.
func fe6aCurrentRevision(t *testing.T, m map[string]any) int64 {
	t.Helper()
	cur, _ := m["current"].(map[string]any)
	v, ok := cur["revision"].(float64)
	if !ok {
		t.Fatalf("refusal must carry current.revision; body=%v", m)
	}
	return int64(v)
}

// fe6aAssertNoAudit fails when any of the named SUCCESS actions was emitted
// at or after since (the audit ring is bounded — assert on content, never
// on length).
func fe6aAssertNoAudit(t *testing.T, since int64, actions ...string) {
	t.Helper()
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS < since {
			continue
		}
		for _, a := range actions {
			if e.Action == a {
				t.Fatalf("refusal emitted a success audit entry: %+v", e)
			}
		}
	}
}

// fe6aFindAudit returns the newest entry with action at or after since.
func fe6aFindAudit(since int64, action string) *auditEntryView {
	var found *auditEntryView
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS >= since && e.Action == action {
			cp := auditEntryView{Actor: e.Actor, Object: e.Object, Detail: e.Detail, Before: e.Before, After: e.After}
			found = &cp
		}
	}
	return found
}

type auditEntryView struct{ Actor, Object, Detail, Before, After string }

// fe6aCountAudit counts entries with action at or after since.
func fe6aCountAudit(since int64, action string) int {
	n := 0
	entries := auditGet()
	for i := range entries {
		if entries[i].TS >= since && entries[i].Action == action {
			n++
		}
	}
	return n
}

// fe6aIdPRevision reads the entry revision from GET /api/idp/{id}.
func fe6aIdPRevision(t *testing.T, id string) int64 {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPItem(w, getReq("/api/idp/"+id), id)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/idp/%s = %d: %s", id, w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	v, _ := m["revision"].(float64)
	return int64(v)
}

// fe6aRosterRevision reads the roster revision from GET /api/auth/users.
func fe6aRosterRevision(t *testing.T) int64 {
	t.Helper()
	w := httptest.NewRecorder()
	apiAuthUsers(w, getReq("/api/auth/users"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/users = %d: %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	v, _ := m["revision"].(float64)
	return int64(v)
}

func fe6aIdPCreate(t *testing.T, body map[string]any) string {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath(), body))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/idp = %d: %s", w.Code, w.Body.String())
	}
	id, _ := fe6aJSON(t, w)["id"].(string)
	if id == "" {
		t.Fatal("create returned no id")
	}
	return id
}

// fe6aStateProbe captures every "zero unintended mutation" fact a refusal
// test pins: memory, durable bytes, publication version, config versions.
type fe6aStateProbe struct {
	registryJSON   string
	fileBytes      []byte
	storeVersion   int64
	configVersions int
	auditSince     int64
}

func fe6aProbeIdP(t *testing.T, reg *IdPRegistry, path string) fe6aStateProbe {
	t.Helper()
	b, err := json.Marshal(reg.All())
	if err != nil {
		t.Fatal(err)
	}
	return fe6aStateProbe{
		registryJSON:   string(b),
		fileBytes:      fe6aReadFile(t, path),
		storeVersion:   globalConfigStore.Version(),
		configVersions: len(configVersions.List()),
		auditSince:     fe6aSince(),
	}
}

func (p fe6aStateProbe) assertIdPUnchanged(t *testing.T, reg *IdPRegistry, path string, successActions ...string) {
	t.Helper()
	b, _ := json.Marshal(reg.All())
	if string(b) != p.registryJSON {
		t.Fatalf("refusal mutated the published registry:\n before=%s\n after=%s", p.registryJSON, b)
	}
	if !bytes.Equal(fe6aReadFile(t, path), p.fileBytes) {
		t.Fatal("refusal changed the durable registry file")
	}
	if v := globalConfigStore.Version(); v != p.storeVersion {
		t.Fatalf("refusal published a cluster snapshot (version %d → %d)", p.storeVersion, v)
	}
	if n := len(configVersions.List()); n != p.configVersions {
		t.Fatalf("refusal created a config version (%d → %d)", p.configVersions, n)
	}
	fe6aAssertNoAudit(t, p.auditSince, successActions...)
}

// fe6aBlockingDialer replaces the SSRF-safe dial seam with a dialer that
// reports the first dial on `dialing` and blocks until `release` is closed
// (or the caller's context ends). Restored on cleanup.
func fe6aBlockingDialer(t *testing.T) (dialing <-chan struct{}, release func()) {
	t.Helper()
	d := make(chan struct{}, 1)
	rel := make(chan struct{})
	var once sync.Once
	orig := ssrfSafeDialContext
	ssrfSafeDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case d <- struct{}{}:
		default:
		}
		select {
		case <-rel:
		case <-ctx.Done():
		}
		return nil, errors.New("fe6a0: dial held by the test")
	}
	t.Cleanup(func() { ssrfSafeDialContext = orig })
	return d, func() { once.Do(func() { close(rel) }) }
}

// ─── R1 — network I/O under the registry write lock ─────────────────────────

// R1: Upsert of an ENABLED OIDC profile runs discovery (network) while
// holding r.mu; every reader — RouteByDomain on the captive-portal path,
// EnabledProviders on the credential path — blocks behind it for the whole
// discovery timeout. Corrected: compile OUTSIDE the lock; a reader completes
// while the compile is held.
func TestFE6A0_R1_UpsertCompileDoesNotBlockReaders(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	dialing, release := fe6aBlockingDialer(t)
	defer release()

	upsertDone := make(chan error, 1)
	go func() {
		upsertDone <- reg.Upsert(&IdPProfile{
			Name: "Held OIDC", Type: IdPTypeOIDC, Enabled: true,
			EmailDomains: []string{"held.example"},
			// A public IP literal: passes the SSRF pre-check without DNS and
			// reaches the dial seam, which the test holds.
			OIDC: &OIDCProfileConfig{Issuer: "https://203.0.113.10", ClientID: "c", ClientSecret: "s"},
		})
	}()
	select {
	case <-dialing:
	case err := <-upsertDone:
		t.Fatalf("Upsert returned before dialing (%v) — the seam was not reached", err)
	}

	readerDone := make(chan struct{})
	go func() {
		reg.RouteByDomain("other.example")
		_ = reg.EnabledProviders()
		close(readerDone)
	}()
	select {
	case <-readerDone:
	case <-time.After(3 * time.Second):
		release()
		t.Fatal("R1: a registry READER blocked behind Upsert's network compile (write lock held across discovery I/O)")
	}
	release()
	if err := <-upsertDone; err == nil {
		t.Fatal("held dial must fail the compile, not publish a provider")
	}
	if _, ok := reg.LiveProvider("held"); ok {
		t.Fatal("a failed compile must publish nothing")
	}
}

// ─── R2 — PUT on an unknown id must not create ───────────────────────────────

func TestFE6A0_R2_PutUnknownIdIsVanishedNotCreate(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	probe := fe6aProbeIdP(t, reg, path)

	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/ghost?revision=1", ldapProfileBodyForPut("Ghost", nil)), "ghost")
	fe6aAssertRefusal(t, w, http.StatusNotFound, "vanished")
	if reg.Get("ghost") != nil {
		t.Fatal("PUT on an unknown id created a profile")
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.update", "idp.create")
	if got := fe6aRegistryFromDisk(t, path); len(got) != 0 {
		t.Fatalf("durable registry gained %d profile(s) after the refusal", len(got))
	}
}

// ─── R3 — stale/absent fences: resurrection and last-writer-wins ─────────────

func TestFE6A0_R3_DeleteThenStalePutDoesNotResurrect(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Victim", nil))
	rev := fe6aIdPRevision(t, id)
	if rev <= 0 {
		t.Fatalf("GET must expose a server-minted positive revision, got %d", rev)
	}

	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), nil), id)
	if w.Code != http.StatusOK {
		t.Fatalf("fenced DELETE = %d, want 200 {deleted:true}; body=%s", w.Code, w.Body.String())
	}
	if del, _ := fe6aJSON(t, w)["deleted"].(bool); !del {
		t.Fatalf("DELETE success must carry deleted:true; body=%s", w.Body.String())
	}
	probe := fe6aProbeIdP(t, reg, path)

	// The other admin's PUT, still carrying the pre-delete fence.
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("Resurrected", nil)), id)
	fe6aAssertRefusal(t, w, http.StatusNotFound, "vanished")
	if reg.Get(id) != nil {
		t.Fatal("stale PUT resurrected a deleted profile")
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.update", "idp.create")
}

func TestFE6A0_R3_StaleSecondWriterIsRefusedWithCurrentRevision(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Shared", nil))
	rev := fe6aIdPRevision(t, id)

	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("First writer", nil)), id)
	if w.Code != http.StatusOK {
		t.Fatalf("first fenced PUT = %d: %s", w.Code, w.Body.String())
	}
	newRev, _ := fe6aJSON(t, w)["revision"].(float64)
	if int64(newRev) <= rev {
		t.Fatalf("a successful PUT must advance the entry revision (%d → %v)", rev, newRev)
	}
	probe := fe6aProbeIdP(t, reg, path)

	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("Second writer", nil)), id)
	m := fe6aAssertRefusal(t, w, http.StatusConflict, "stale")
	if cur := fe6aCurrentRevision(t, m); cur != int64(newRev) {
		t.Fatalf("stale refusal current.revision = %d, want %v", cur, newRev)
	}
	if got := reg.Get(id).Name; got != "First writer" {
		t.Fatalf("stale writer overwrote the profile (name=%q)", got)
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.update")
	if fe6aIdPRevision(t, id) != int64(newRev) {
		t.Fatal("refusal moved the fencing token")
	}
}

func TestFE6A0_R3_MissingFenceIs428CarryingCurrent(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Unfenced", nil))
	rev := fe6aIdPRevision(t, id)
	probe := fe6aProbeIdP(t, reg, path)

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		var body any
		if method == http.MethodPut {
			body = ldapProfileBodyForPut("Unfenced edit", nil)
		}
		apiIdPItem(w, jsonReq(method, "/api/idp/"+id, body), id)
		m := fe6aAssertRefusal(t, w, http.StatusPreconditionRequired, "precondition_required")
		if cur := fe6aCurrentRevision(t, m); cur != rev {
			t.Fatalf("%s 428 current.revision = %d, want %d", method, cur, rev)
		}
	}
	if reg.Get(id) == nil || reg.Get(id).Name != "Unfenced" {
		t.Fatal("an unfenced write mutated the profile")
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.update", "idp.delete")
}

// ─── R4 — delete of a provider referenced by an SSORequired rule ─────────────

func TestFE6A0_R4_DeleteReferencedProviderIsRefused(t *testing.T) {
	withFreshPolicyStore(t)
	withConfigVersionsDir(t)
	fe6aSwapConfigStore(t)
	// An enabled interactive profile that needs no network to exist in the
	// registry (registry-level seed; the live map is irrelevant for the
	// reference check, exactly as validateSSOProviderRefsLive reads it).
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	path := filepath.Join(t.TempDir(), "idp_profiles.json")
	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := reg.Load(path); err != nil {
		t.Fatal(err)
	}
	idpRegistry = reg
	saml := &IdPProfile{ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: false,
		SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}
	if err := reg.Upsert(saml); err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	reg.profiles[0].Enabled = true // enabled-without-live: reference semantics only
	reg.mu.Unlock()

	rule := validSSORule()
	rule.Auth.ProviderRefs = []string{"corp-saml"}
	added := policyStore.Add(rule)
	rev := fe6aIdPRevision(t, "corp-saml")
	probe := fe6aProbeIdP(t, reg, path)

	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/corp-saml?revision="+strconv.FormatInt(rev, 10), nil), "corp-saml")
	m := fe6aAssertRefusal(t, w, http.StatusConflict, "referenced")
	cur, _ := m["current"].(map[string]any)
	refs, _ := cur["references"].([]any)
	if len(refs) != 1 {
		t.Fatalf("refusal must name the referencing rule(s); current=%v", cur)
	}
	ref, _ := refs[0].(map[string]any)
	if ref["id"] != added.ID || ref["consumerType"] != "auth-rule" {
		t.Fatalf("reference fact = %v, want auth-rule %s", ref, added.ID)
	}
	if reg.Get("corp-saml") == nil {
		t.Fatal("a referenced provider was deleted")
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.delete")
}

// ─── R5 — an emptied registry must reach the DPs ─────────────────────────────

func TestFE6A0_R5_LastProfileDeleteReachesDataPlane(t *testing.T) {
	withIdPSyncGlobals(t)
	store := fe6aSwapConfigStore(t)
	profile := &IdPProfile{ID: "only-one", Name: "Only", Type: IdPTypeSAML, Enabled: false,
		SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}
	if err := idpRegistry.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	if n := len(store.Get().IdPProfiles); n != 1 {
		t.Fatalf("precondition: published %d profiles, want 1", n)
	}
	if err := idpRegistry.Delete("only-one"); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	// The wire form the GetConfig RPC serves.
	wire, err := json.Marshal(store.Get())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`"idp_profiles"`)) {
		t.Fatalf("an emptied registry vanished from the wire (omitempty) — a DP can never observe the last delete:\n%s", wire)
	}
	var dpSnap ConfigSnapshot
	if err := json.Unmarshal(wire, &dpSnap); err != nil {
		t.Fatal(err)
	}
	// DP side: a node that still holds the profile applies the snapshot.
	dpReg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := dpReg.ReplaceAll([]*IdPProfile{profile}); err != nil {
		t.Fatal(err)
	}
	idpRegistry = dpReg
	if err := syncSnapshotIdPProfiles(dpSnap); err != nil {
		t.Fatal(err)
	}
	if n := len(dpReg.All()); n != 0 {
		t.Fatalf("DP still holds %d deleted profile(s) after applying the CP snapshot", n)
	}
}

// ─── R6 — secret configured-state on the read model ──────────────────────────

func TestFE6A0_R6_SecretConfiguredIndicatorsOnRead(t *testing.T) {
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider), profiles: []*IdPProfile{
		{ID: "oidc-with", Name: "With", Type: IdPTypeOIDC,
			OIDC: &OIDCProfileConfig{Issuer: "https://idp.example.com", ClientID: "c", ClientSecret: "s3cret"}},
		{ID: "oidc-without", Name: "Without", Type: IdPTypeOIDC,
			OIDC: &OIDCProfileConfig{Issuer: "https://idp.example.com", ClientID: "c"}},
		{ID: "saml-xml", Name: "XML", Type: IdPTypeSAML,
			SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}},
	}}
	get := func(id string) map[string]any {
		w := httptest.NewRecorder()
		apiIdPItem(w, getReq("/api/idp/"+id), id)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", id, w.Code)
		}
		assertNoOIDCSecretLeak(t, w.Body.String())
		if strings.Contains(w.Body.String(), "<EntityDescriptor/>") {
			t.Fatal("GET leaked inline SAML metadata XML")
		}
		return fe6aJSON(t, w)
	}
	oidc, _ := get("oidc-with")["oidc"].(map[string]any)
	if v, _ := oidc["clientSecretConfigured"].(bool); !v {
		t.Fatalf("oidc.clientSecretConfigured must be true for a stored secret; oidc=%v", oidc)
	}
	if _, present := oidc["clientSecret"]; present {
		t.Fatal("clientSecret must not be present on the read model, not even empty")
	}
	oidc, _ = get("oidc-without")["oidc"].(map[string]any)
	if v, _ := oidc["clientSecretConfigured"].(bool); v {
		t.Fatal("oidc.clientSecretConfigured must be false when no secret is stored")
	}
	saml, _ := get("saml-xml")["saml"].(map[string]any)
	if v, _ := saml["inlineMetadataConfigured"].(bool); !v {
		t.Fatalf("saml.inlineMetadataConfigured must be true for inline metadata; saml=%v", saml)
	}
}

// ─── R7 — legacy LDAP cutover: durable-before-publish, op-identified ─────────

func fe6aLegacyLDAPFixture(t *testing.T, adminSettings string) (reg *IdPRegistry, regPath string) {
	t.Helper()
	reg, regPath = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	adminSettingsSaveWG.Wait()
	prev := legacyLDAPRetiredFlag.Load()
	legacyLDAPRetiredFlag.Store(false)
	t.Cleanup(func() { legacyLDAPRetiredFlag.Store(prev) })
	adminSettingsMu.Lock()
	prevPath := adminSettingsPath
	adminSettingsPath = adminSettings
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsSaveWG.Wait()
		adminSettingsMu.Lock()
		adminSettingsPath = prevPath
		adminSettingsMu.Unlock()
	})
	withLegacyLDAPYAML(t, &LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetProvider(legacy)
	return reg, regPath
}

func TestFE6A0_R7_CutoverSentinelPersistFailureRefusesTheEnable(t *testing.T) {
	reg, regPath := fe6aLegacyLDAPFixture(t, fe6aBrokenPath(t, "admin_settings.json"))
	probe := fe6aProbeIdP(t, reg, regPath)

	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = true
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath("operationId="+testOperationID(), "cutoverConfirm=ldap://legacy.corp.example:389"), body))
	fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")

	if legacyLDAPRetired() {
		t.Fatal("cutover was recorded in memory although the durable sentinel could not be written")
	}
	if _, still := cfg.snapshotAuthBackend().provider.(*LDAPAuth); !still {
		t.Fatal("legacy LDAP authenticator was deactivated on a refused mutation — no authenticator left")
	}
	if n := len(reg.All()); n != 0 {
		t.Fatalf("refused enable published %d profile(s)", n)
	}
	probe.assertIdPUnchanged(t, reg, regPath, "idp.create", "idp.legacy_ldap.retired")
	if got := fe6aRegistryFromDisk(t, regPath); len(got) != 0 {
		t.Fatalf("refused enable left %d profile(s) on disk", len(got))
	}
}

func TestFE6A0_R7_CutoverIsOperationIdentifiedAndAtMostOnce(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	since := fe6aSince()

	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = true
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath("operationId="+testOperationID(), "cutoverConfirm=ldap://legacy.corp.example:389"), body))
	if w.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	id, _ := fe6aJSON(t, w)["id"].(string)
	if !legacyLDAPRetired() {
		t.Fatal("enabling a registry LDAP profile must cut over")
	}
	adminSettingsSaveWG.Wait()
	if b := fe6aReadFile(t, settings); !bytes.Contains(b, []byte(`"legacy_ldap_retired": true`)) {
		t.Fatalf("cutover must be durable before the 2xx; admin_settings=%s", b)
	}
	e := fe6aFindAudit(since, "idp.legacy_ldap.retired")
	if e == nil {
		t.Fatal("cutover audit entry missing")
	}
	if e.Actor == "system" || e.Actor == "" {
		t.Fatalf("an admin-triggered cutover must be attributed to the admin, got actor %q", e.Actor)
	}
	// Facts on the read model: operation identity + candidate binding.
	w = httptest.NewRecorder()
	apiIdPLegacyLDAP(w, getReq("/api/idp/legacy-ldap"))
	m := fe6aJSON(t, w)
	cut, _ := m["cutover"].(map[string]any)
	if op, _ := cut["operationId"].(string); op == "" {
		t.Fatalf("legacy-ldap read model must carry cutover.operationId; body=%s", w.Body.String())
	}
	if pid, _ := cut["profileId"].(string); pid != id {
		t.Fatalf("cutover.profileId = %q, want the enabling profile %q", pid, id)
	}
	// At-most-once: a second enabling write re-emits nothing (counted, so the
	// check is exact even when both writes land inside one millisecond).
	before := fe6aCountAudit(since, "idp.legacy_ldap.retired")
	rev := fe6aIdPRevision(t, id)
	body["name"] = "Registry AD (renamed)"
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), body), id)
	if w.Code != http.StatusOK {
		t.Fatalf("second enable = %d: %s", w.Code, w.Body.String())
	}
	if after := fe6aCountAudit(since, "idp.legacy_ldap.retired"); after != before {
		t.Fatalf("cutover audit emitted again on a repeat enable (%d → %d)", before, after)
	}
}

// ─── R8 — corrupt registry: degraded posture + fenced repair ─────────────────

func TestFE6A0_R8_CorruptRegistryDegradesAndRepairsUnderFence(t *testing.T) {
	resetStateCorruption()
	t.Cleanup(resetStateCorruption)
	dir := t.TempDir()
	path := filepath.Join(dir, "idp_profiles.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	idpRegistry = reg
	fe6aSwapConfigStore(t)

	if err := reg.Load(path); err != nil {
		t.Fatalf("a corrupt registry must degrade, not fail the boot: %v", err)
	}
	quarantined, _ := filepath.Glob(path + ".corrupt.*")
	if len(quarantined) != 1 {
		t.Fatalf("corrupt file must be quarantined beside the store, found %v", quarantined)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if deg, _ := fe6aJSON(t, w)["degraded"].(bool); !deg {
		t.Fatalf("read model must report degraded:true; body=%s", w.Body.String())
	}
	since := fe6aSince()
	w = httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath(), ldapProfileBodyForPut("While degraded", nil)))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "registry_degraded")
	if n := len(reg.All()); n != 0 {
		t.Fatalf("degraded registry accepted a write (%d profiles)", n)
	}
	if fe6aReadFile(t, path) != nil {
		t.Fatal("degraded registry wrote a replacement file before the repair was acknowledged")
	}
	fe6aAssertNoAudit(t, since, "idp.create")

	// Fenced repair: the admin acknowledges the exact quarantine evidence.
	mux := d0WireMux(t)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, jsonReq(http.MethodPost, "/api/idp/repair", map[string]any{"confirm": filepath.Base(quarantined[0])}))
	if w.Code != http.StatusOK {
		t.Fatalf("repair = %d: %s", w.Code, w.Body.String())
	}
	if rep, _ := fe6aJSON(t, w)["repaired"].(bool); !rep {
		t.Fatalf("repair success must carry repaired:true; body=%s", w.Body.String())
	}
	w = httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if deg, _ := fe6aJSON(t, w)["degraded"].(bool); deg {
		t.Fatal("registry still degraded after the acknowledged repair")
	}
	w = httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath(), ldapProfileBodyForPut("After repair", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("write after repair = %d: %s", w.Code, w.Body.String())
	}
	// A wrong confirm never repairs.
	if err := os.WriteFile(path, []byte("{again"), 0o600); err == nil {
		fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
		idpRegistry = fresh
		if err := fresh.Load(path); err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, jsonReq(http.MethodPost, "/api/idp/repair", map[string]any{"confirm": "wrong-evidence"}))
		fe6aAssertRefusal(t, w, http.StatusConflict, "confirm_mismatch")
	}
}

// ─── R9 — TOTP survives an administrative password set ───────────────────────

func fe6aEnrollTOTP(t *testing.T, c *Config, user string) {
	t.Helper()
	if !c.SetTOTPSecret(user, "JBSWY3DPEHPK3PXP", []string{"hash-a", "hash-b"}) {
		t.Fatalf("SetTOTPSecret(%s) = false", user)
	}
	if !c.SetTOTPLastCounter(user, 42) {
		t.Fatal("SetTOTPLastCounter = false")
	}
}

func fe6aAssertTOTPIntact(t *testing.T, c *Config, user string) {
	t.Helper()
	if c.GetTOTPSecret(user) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("TOTP secret for %s was destroyed by the password set", user)
	}
	if c.GetTOTPLastCounter(user) != 42 {
		t.Fatalf("TOTP replay counter for %s was reset by the password set", user)
	}
}

func TestFE6A0_R9_SelfServicePasswordChangePreservesTOTP(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("alice", "AlicePass1", RoleOperator); err != nil {
		t.Fatal(err)
	}
	fe6aEnrollTOTP(t, c, "alice")
	r := jsonReq(http.MethodPost, fencedChangePasswordPath("alice"), map[string]string{
		"current_password": "AlicePass1", "new_password": "AliceNew2",
	})
	r = withRoleCtx(r, RoleOperator)
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "alice"))
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("change-password = %d: %s", w.Code, w.Body.String())
	}
	if _, ok := c.VerifyUIUser("alice", "AliceNew2"); !ok {
		t.Fatal("new password not accepted")
	}
	fe6aAssertTOTPIntact(t, c, "alice")
}

func TestFE6A0_R9_AdminPasswordSetPreservesTOTP(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("alice", "AlicePass1", RoleOperator); err != nil {
		t.Fatal(err)
	}
	fe6aEnrollTOTP(t, c, "alice")
	rev := fe6aRosterRevision(t)
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{
		"username": "alice", "password": "AliceNew2", "role": "operator",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/auth/users = %d: %s", w.Code, w.Body.String())
	}
	fe6aAssertTOTPIntact(t, c, "alice")
	fresh := newTestConfig()
	fresh.SetUIUsersFile(path)
	if err := fresh.LoadUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	fe6aAssertTOTPIntact(t, fresh, "alice")
}

// ─── R10 — administrators: persist-before-publish ────────────────────────────

func TestFE6A0_R10_UserMutationsRefuseOnPersistFailure(t *testing.T) {
	c, path := fe6aSwapCfg(t, fe6aBrokenPath(t, "ui_users.json"))
	if err := c.SetUIUser("bob", "BobPass123", RoleViewer); err != nil {
		t.Fatal(err)
	}
	rev := fe6aRosterRevision(t)
	since := fe6aSince()

	// Create.
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, fencedUsersPath(), map[string]any{
		"username": "carol", "password": "CarolPass1", "role": "operator",
	}))
	fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")
	if c.UIUserExists("carol") {
		t.Fatal("failed create published the user in memory")
	}
	// Update.
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{
		"username": "bob", "role": "admin",
	}))
	fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")
	if role, _ := c.VerifyUIUser("bob", "BobPass123"); role != RoleViewer {
		t.Fatalf("failed update changed bob's role to %q", role)
	}
	// Delete.
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=bob&revision="+strconv.FormatInt(rev, 10), nil))
	fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")
	if !c.UIUserExists("bob") {
		t.Fatal("failed delete removed bob from memory")
	}
	if sessionRevoked.IsUserRevoked("bob") {
		t.Fatal("failed delete revoked bob's sessions — revocation must follow the durable commit")
	}
	// Self-service password change.
	r := jsonReq(http.MethodPost, fencedChangePasswordPath("bob"), map[string]string{
		"current_password": "BobPass123", "new_password": "BobNewPass2",
	})
	r = withRoleCtx(r, RoleViewer)
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "bob"))
	w = httptest.NewRecorder()
	apiAuthChangePassword(w, r)
	fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")
	if _, ok := c.VerifyUIUser("bob", "BobPass123"); !ok {
		t.Fatal("failed password change replaced the credential in memory")
	}
	if fe6aRosterRevision(t) != rev {
		t.Fatal("refusals moved the roster revision")
	}
	fe6aAssertNoAudit(t, since, "auth.users.set", "auth.users.create", "auth.users.update", "auth.users.delete", "auth.password_change")
	if fe6aReadFile(t, path) != nil {
		t.Fatal("a refusal wrote the roster file")
	}
}

// ─── R11 — a demoted admin loses authority now, not at TTL ───────────────────

type fe6aChain struct {
	srv *httptest.Server
}

func fe6aFullChain(t *testing.T) *fe6aChain {
	t.Helper()
	prevDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDataDir })
	handler := uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(uiMetadataEnforcement(d0WireMux(t)))))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &fe6aChain{srv: srv}
}

func (ch *fe6aChain) login(t *testing.T, user, pass string) *http.Client {
	t.Helper()
	loginLimiter.ResetUser(user)
	t.Cleanup(func() { loginLimiter.ResetUser(user) })
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ch.srv.URL+"/api/auth/login",
		strings.NewReader(fmt.Sprintf(`{"user":%q,"pass":%q}`, user, pass)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s: %d %s", user, resp.StatusCode, body)
	}
	return client
}

func (ch *fe6aChain) get(t *testing.T, client *http.Client, path string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ch.srv.URL+path, http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestFE6A0_R11_DemotedAdminSessionLosesAuthority(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	ch := fe6aFullChain(t)
	bob := ch.login(t, "bob", "BobPass123")
	if got := ch.get(t, bob, "/api/auth/users"); got != http.StatusOK {
		t.Fatalf("precondition: bob (admin) GET users = %d", got)
	}

	// root demotes bob through the corrected update verb.
	rev := fe6aRosterRevision(t)
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{
		"username": "bob", "role": "viewer",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("demote = %d: %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	if revoked, _ := m["sessionsRevoked"].(bool); !revoked {
		t.Fatalf("role change must report sessionsRevoked:true; body=%s", w.Body.String())
	}
	if self, _ := m["selfAffected"].(bool); self {
		t.Fatal("root demoting bob is not self-affecting")
	}
	if got := ch.get(t, bob, "/api/auth/users"); got != http.StatusUnauthorized {
		t.Fatalf("bob's pre-demotion admin session still answers admin routes (%d), want 401 (revoked)", got)
	}
	bob2 := ch.login(t, "bob", "BobPass123")
	if got := ch.get(t, bob2, "/api/auth/users"); got != http.StatusForbidden {
		t.Fatalf("bob's fresh session after demotion = %d on an admin route, want 403", got)
	}
	if got := ch.get(t, bob2, "/api/auth/status"); got != http.StatusOK {
		t.Fatalf("bob's viewer session must still work on a viewer route (%d)", got)
	}
}

// ─── R12 — last admin protection on demotion ─────────────────────────────────

func TestFE6A0_R12_LastAdminCannotBeDemoted(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("viewer1", "ViewerPass1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	// Store level: the guard lives with the mutation, not only in the handler.
	if err := c.SetUIUser("root", "", RoleViewer); err == nil {
		t.Fatal("SetUIUser demoted the last admin")
	}
	if role, _ := c.VerifyUIUser("root", "RootPass1"); role != RoleAdmin {
		t.Fatalf("root role after refused demotion = %q", role)
	}
	rev := fe6aRosterRevision(t)
	before := fe6aReadFile(t, path)
	since := fe6aSince()
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{
		"username": "root", "role": "viewer",
	}))
	fe6aAssertRefusal(t, w, http.StatusConflict, "last_admin")
	if role, _ := c.VerifyUIUser("root", "RootPass1"); role != RoleAdmin {
		t.Fatalf("API demoted the last admin (role %q)", role)
	}
	if !bytes.Equal(fe6aReadFile(t, path), before) {
		t.Fatal("refusal changed the roster file")
	}
	if fe6aRosterRevision(t) != rev {
		t.Fatal("refusal moved the roster revision")
	}
	fe6aAssertNoAudit(t, since, "auth.users.set", "auth.users.update")
	if got := fe6aRosterFromDisk(t, path)["root"]; got != RoleAdmin {
		t.Fatalf("after restart root is %q", got)
	}
}

// ─── R13 — create is not an upsert ───────────────────────────────────────────

func TestFE6A0_R13_CreateExistingUserIsConflict(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("alice", "AlicePass1", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	before := fe6aReadFile(t, path)
	rev := fe6aRosterRevision(t)
	since := fe6aSince()

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, fencedUsersPath(), map[string]any{
		"username": "alice", "password": "Hijacked99", "role": "viewer",
	}))
	fe6aAssertRefusal(t, w, http.StatusConflict, "user_exists")
	if role, ok := c.VerifyUIUser("alice", "AlicePass1"); !ok || role != RoleAdmin {
		t.Fatalf("POST overwrote an existing user (ok=%v role=%q)", ok, role)
	}
	if _, ok := c.VerifyUIUser("alice", "Hijacked99"); ok {
		t.Fatal("the attacker's password was installed")
	}
	if !bytes.Equal(fe6aReadFile(t, path), before) {
		t.Fatal("refusal changed the roster file")
	}
	if fe6aRosterRevision(t) != rev {
		t.Fatal("refusal moved the roster revision")
	}
	fe6aAssertNoAudit(t, since, "auth.users.set", "auth.users.create")
	if got := fe6aRosterFromDisk(t, path)["alice"]; got != RoleAdmin {
		t.Fatalf("after restart alice is %q", got)
	}
}

// ─── R14 — every refusal is typed JSON with a bounded code ───────────────────

func TestFE6A0_R14_RefusalsAreTypedJSON(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	reg, _ := fe6aSwapRegistry(t, "")
	if err := reg.Upsert(ldapTestProfile("ldap-one", "One")); err != nil {
		t.Fatal(err)
	}
	_ = c
	viewer := func(r *http.Request) *http.Request { return withRoleCtx(r, RoleViewer) }
	raw := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "127.0.0.1:9999"
		return adminCtx(r)
	}
	rows := []struct {
		name   string
		run    func(w *httptest.ResponseRecorder)
		status int
		code   string
	}{
		{"users POST malformed JSON", func(w *httptest.ResponseRecorder) { apiAuthUsers(w, raw(http.MethodPost, "/api/auth/users", "{nope")) }, 400, "invalid_input"},
		{"users POST bad role", func(w *httptest.ResponseRecorder) {
			apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{"username": "x", "password": "GoodPass1", "role": "superuser"}))
		}, 400, "invalid_input"},
		{"users DELETE missing user", func(w *httptest.ResponseRecorder) {
			apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=nobody&revision=1", nil))
		}, 404, "not_found"},
		{"users GET viewer", func(w *httptest.ResponseRecorder) {
			apiAuthUsers(w, viewer(httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)))
		}, 403, "forbidden"},
		{"lockouts POST missing username", func(w *httptest.ResponseRecorder) {
			apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts", map[string]any{"username": " "}))
		}, 400, "invalid_input"},
		{"change-password wrong current", func(w *httptest.ResponseRecorder) {
			r := jsonReq(http.MethodPost, "/api/auth/change-password", map[string]string{"current_password": "Wrong1234", "new_password": "NewPass123"})
			r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "root"))
			apiAuthChangePassword(w, r)
		}, 403, "invalid_credentials"},
		{"idp POST malformed JSON", func(w *httptest.ResponseRecorder) { apiIdPList(w, raw(http.MethodPost, "/api/idp", "{nope")) }, 400, "invalid_input"},
		{"idp POST invalid profile", func(w *httptest.ResponseRecorder) {
			bad := ldapProfileBodyForPut("Bad", nil)
			bad["ldap"].(map[string]any)["url"] = "https://not-ldap"
			apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath(), bad))
		}, 400, "invalid_input"},
		{"idp POST viewer", func(w *httptest.ResponseRecorder) {
			apiIdPList(w, viewer(jsonReq(http.MethodPost, "/api/idp", ldapProfileBodyForPut("V", nil))))
		}, 403, "forbidden"},
		{"idp GET unknown", func(w *httptest.ResponseRecorder) { apiIdPItem(w, getReq("/api/idp/zzz"), "zzz") }, 404, "not_found"},
		{"idp DELETE unknown", func(w *httptest.ResponseRecorder) {
			apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/zzz?revision=1", nil), "zzz")
		}, 404, "vanished"},
		{"idp groups unknown", func(w *httptest.ResponseRecorder) { apiIdPGroups(w, getReq("/api/idp/zzz/groups"), "zzz") }, 404, "not_found"},
		{"idp test non-ldap", func(w *httptest.ResponseRecorder) {
			apiIdPTest(w, jsonReq(http.MethodPost, "/api/idp/test", map[string]any{"profile": map[string]any{"type": "oidc"}}))
		}, 400, "invalid_input"},
		{"idp legacy import absent", func(w *httptest.ResponseRecorder) {
			withLegacyLDAPYAML(t, nil)
			apiIdPLegacyLDAPImport(w, jsonReq(http.MethodPost, "/api/idp/legacy-ldap/import", nil))
		}, 404, "not_found"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			row.run(w)
			fe6aAssertRefusal(t, w, row.status, row.code)
		})
	}
}
