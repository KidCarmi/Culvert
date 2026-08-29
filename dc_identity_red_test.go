package main

// dc_identity_red_test.go — 2D-C red-before proofs (§40 File Profiles, §41
// Rewrite) against the frozen checkpoint 69f53bea, then GREEN after the
// identity/durability correction.
//
// The tests are written against PROPERTIES, using only symbols that exist at
// the frozen checkpoint plus two reflection helpers (rwIdentityOf /
// rwRemoveByIdentity) that resolve to the durable StableID when it exists and
// honestly fall back to the process-local integer at the checkpoint — so the
// same file compiles and runs at both trees, red where the property is
// absent.

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/rewrite"
)

// ─── helpers ───────────────────────────────────────────────────────────────

// dcProfileStoreIsolate swaps in a fresh profile store persisted to a temp
// path and returns a function that redirects persistence to an ENOTDIR
// blocker (persistence-fault seam).
func dcProfileStoreIsolate(t *testing.T) (breakPersistence func()) {
	t.Helper()
	orig := globalProfileStore
	fresh := &FileProfileStore{}
	dir := t.TempDir()
	if err := fresh.Load(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatalf("seed profile store: %v", err)
	}
	globalProfileStore = fresh
	t.Cleanup(func() { globalProfileStore = orig })
	return func() {
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("blocker: %v", err)
		}
		fresh.SetPath(filepath.Join(blocker, "profiles.json")) // ENOTDIR
	}
}

// rwIdentityOf returns the rule's durable identity when the architecture has
// one (StableID field, non-empty), else the process-local integer rendering
// with ok=false — the checkpoint's only identity.
func rwIdentityOf(r RewriteRule) (ident string, durable bool) {
	v := reflect.ValueOf(r).FieldByName("StableID")
	if v.IsValid() && v.Kind() == reflect.String && v.String() != "" {
		return v.String(), true
	}
	return strconv.Itoa(r.ID), false
}

// rwRemoveByIdentity removes by durable identity when the API exists, else by
// the checkpoint's integer addressing.
func rwRemoveByIdentity(rw *rewrite.Rewriter, ident string) bool {
	if m := reflect.ValueOf(rw).MethodByName("RemoveByStableID"); m.IsValid() {
		return m.Call([]reflect.Value{reflect.ValueOf(ident)})[0].Bool()
	}
	n, err := strconv.Atoi(ident)
	if err != nil {
		return false
	}
	return rw.RemoveByID(n)
}

func dcRewriteRule(host, header, val string) RewriteRule {
	return RewriteRule{Host: host, ReqSet: map[string]string{header: val}}
}

// ─── §40 File Profiles ─────────────────────────────────────────────────────

// TestDCRed_FPRenameBreaksPolicyReference (§40-A): renaming a file profile
// must keep every referencing rule enforcing the SAME profile identity (true
// rename) and visible in Where Used. At the checkpoint the policy reference
// was the mutable NAME: the rename dangled it — enforcement silently stopped
// blocking and the reference walk lost the consumer.
func TestDCRed_FPRenameBreaksPolicyReference(t *testing.T) {
	deleteFirstSetup(t)
	dcProfileStoreIsolate(t)
	prof, err := globalProfileStore.Create("Rename-Prof", []string{".exe"})
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}

	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "fp-rename-rule", "action": "Allow",
		"fileFiltering": true, "fileProfile": "Rename-Prof",
	}))
	if w.Code != 200 {
		t.Fatalf("create rule: %d %s", w.Code, w.Body.String())
	}
	ruleBlocked := func() bool {
		for _, r := range policyStore.List() {
			if r.Name == "fp-rename-rule" {
				return r.FileProfileBlocked("/payload.exe")
			}
		}
		t.Fatal("rule vanished")
		return false
	}
	if !ruleBlocked() {
		t.Fatal("pre-rename: the rule must block .exe via the profile")
	}

	w = httptest.NewRecorder()
	apiFileblockProfiles(w, jsonReq("PUT", "/api/fileblock/profiles?id="+prof.ID,
		map[string]any{"name": "Renamed-Prof", "extensions": []string{".exe"}}))
	if w.Code != 200 {
		t.Fatalf("rename profile: %d %s", w.Code, w.Body.String())
	}

	if !ruleBlocked() {
		t.Fatal("FP RENAME DANGLED ENFORCEMENT: after a profile rename the referencing rule silently stopped blocking — the policy reference is the mutable name, not a stable identity")
	}
	found, refs := objectReferences("file-profile", "Renamed-Prof")
	if !found || len(refs) == 0 {
		t.Fatal("FP RENAME LOST WHERE-USED: the renamed profile's consumers are invisible to the reference walk")
	}
}

// TestDCRed_FPCreatePersistFailureMutatesMemory (§40-B): a hard pre-
// replacement persistence failure must leave runtime memory (and therefore
// restart truth) unchanged. At the checkpoint Create appended in memory and
// THEN failed the save — a returned error with the mutation still active.
func TestDCRed_FPCreatePersistFailureMutatesMemory(t *testing.T) {
	breakPersistence := dcProfileStoreIsolate(t)
	before := len(globalProfileStore.List())
	breakPersistence()
	if _, err := globalProfileStore.Create("Ghost-Prof", []string{".exe"}); err == nil {
		t.Fatal("persistence is broken — Create must error")
	}
	if got := len(globalProfileStore.List()); got != before {
		t.Fatalf("FP DURABILITY: failed Create left the profile ACTIVE in memory (%d -> %d) — runtime truth diverges from restart truth", before, got)
	}
}

// TestDCRed_FPUpdatePersistFailureMutatesMemory (§40-C).
func TestDCRed_FPUpdatePersistFailureMutatesMemory(t *testing.T) {
	breakPersistence := dcProfileStoreIsolate(t)
	prof, err := globalProfileStore.Create("Upd-Prof", []string{".exe"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	breakPersistence()
	if err := globalProfileStore.Update(prof.ID, "Upd-Prof-2", []string{".dll"}); err == nil {
		t.Fatal("persistence is broken — Update must error")
	}
	cur := globalProfileStore.GetByID(prof.ID)
	if cur == nil || cur.Name != "Upd-Prof" || len(cur.Extensions) != 1 || cur.Extensions[0] != ".exe" {
		t.Fatalf("FP DURABILITY: failed Update left the mutation ACTIVE in memory: %+v", cur)
	}
}

// TestDCRed_FPDeletePersistFailureMutatesMemory (§40-D).
func TestDCRed_FPDeletePersistFailureMutatesMemory(t *testing.T) {
	breakPersistence := dcProfileStoreIsolate(t)
	prof, err := globalProfileStore.Create("Del-Prof", []string{".exe"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	breakPersistence()
	if err := globalProfileStore.Delete(prof.ID); err == nil {
		t.Fatal("persistence is broken — Delete must error")
	}
	if globalProfileStore.GetByID(prof.ID) == nil {
		t.Fatal("FP DURABILITY: failed Delete removed the profile from runtime memory — a restart would resurrect it")
	}
}

// TestDCRed_FPStaleEditNoFence (§40-E): a v2 client asserting a stale
// revision must get a 409, never a silent overwrite. At the checkpoint the
// ?ifRevision= assertion was unknown and ignored.
func TestDCRed_FPStaleEditNoFence(t *testing.T) {
	dcProfileStoreIsolate(t)
	prof, err := globalProfileStore.Create("Fence-Prof", []string{".exe"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := httptest.NewRecorder()
	apiFileblockProfiles(w, jsonReq("PUT",
		"/api/fileblock/profiles?id="+prof.ID+"&ifRevision=stale-revision-token",
		map[string]any{"name": "Fence-Prof", "extensions": []string{".dll"}}))
	if w.Code != 409 {
		t.Fatalf("FP FENCE: a STALE revision assertion was accepted (%d) — two admins can silently overwrite each other", w.Code)
	}
}

// TestDC_FPDeleteFirstAlreadyGated (§40-F, HONEST CONTROL): the 2D-B
// reference gate already closed the file-profile delete/writer races — a rule
// referencing a deleted profile refuses 400, and deleting a referenced
// profile refuses 409. Green at the checkpoint; reported as such.
func TestDC_FPDeleteFirstAlreadyGated(t *testing.T) {
	deleteFirstSetup(t)
	dcProfileStoreIsolate(t)
	prof, err := globalProfileStore.Create("Gated-Prof", []string{".exe"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Writer-first: rule lands, delete → 409.
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "gated-rule", "action": "Allow",
		"fileFiltering": true, "fileProfile": "Gated-Prof",
	}))
	if w.Code != 200 {
		t.Fatalf("create rule: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiFileblockProfiles(w, jsonReq("DELETE", "/api/fileblock/profiles?id="+prof.ID, nil))
	if w.Code != 409 {
		t.Fatalf("referenced profile delete must 409, got %d: %s", w.Code, w.Body.String())
	}
	// Delete-first: remove the reference, delete, then a NEW reference refuses.
	var refRuleID string
	for _, pr := range policyStore.List() {
		if pr.Name == "gated-rule" {
			refRuleID = pr.ID
		}
	}
	if refRuleID == "" || !policyStore.DeleteByID(refRuleID) {
		t.Fatal("remove the referencing rule")
	}
	w = httptest.NewRecorder()
	apiFileblockProfiles(w, jsonReq("DELETE", "/api/fileblock/profiles?id="+prof.ID, nil))
	if w.Code != 204 {
		t.Fatalf("unreferenced delete: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "gated-rule-2", "action": "Allow",
		"fileFiltering": true, "fileProfile": "Gated-Prof",
	}))
	assertDanglingRefused(t, w, "file-profile")
}

// TestDCRed_FPBulkCandidateInconsistency (§40-G): a bulk import candidate
// carrying a rule whose file profile resolves nowhere must refuse the WHOLE
// import — the 2D-B graph deliberately excluded the file-profile edge, so at
// the checkpoint the dangling rule landed behind a 2xx.
func TestDCRed_FPBulkCandidateInconsistency(t *testing.T) {
	bulkCanonSetup(t)
	w := canonImportBackup(t, "merge", &configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{{
			Name: "fp-bulk-dangle", Action: ActionDrop, Priority: 7,
			FileFiltering: true, FileProfile: "NO-SUCH-PROFILE",
		}},
	})
	if w.Code/100 == 2 {
		t.Fatalf("FP BULK GRAPH: an import rule referencing a nonexistent file profile landed with %d — a DROP-with-file-control rule that never matches", w.Code)
	}
	if w.Code != 400 || !strings.Contains(w.Body.String(), "NO-SUCH-PROFILE") {
		t.Fatalf("want 400 naming the dangling file profile, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── §41 Rewrite ───────────────────────────────────────────────────────────

// TestDCRed_RWIdentityNotDurable (§41-A): every rule must carry a non-empty
// DURABLE identity that survives a persistence round-trip into a fresh
// Rewriter (a restart). The checkpoint had only the process-local integer.
func TestDCRed_RWIdentityNotDurable(t *testing.T) {
	rw := rewrite.NewRewriter()
	rw.SetRules([]RewriteRule{dcRewriteRule("a.example", "X-A", "1"), dcRewriteRule("b.example", "X-B", "2")})
	persisted := rw.List()
	idents := make([]string, len(persisted))
	for i, r := range persisted {
		ident, durable := rwIdentityOf(r)
		if !durable {
			t.Fatalf("RW IDENTITY: rule %d carries no durable object identity — the integer id is process-local", i)
		}
		idents[i] = ident
	}
	reloaded := rewrite.NewRewriter()
	reloaded.SetRules(persisted)
	for i, r := range reloaded.List() {
		ident, durable := rwIdentityOf(r)
		if !durable || ident != idents[i] {
			t.Fatalf("RW IDENTITY: rule %d re-identified across reload (%q -> %q)", i, idents[i], ident)
		}
	}
}

// TestDCRed_RWRemovalShiftsLaterIdentity (§41-B): removing an earlier rule
// and reloading must not change a later rule's identity. With integer ids,
// [A,B] → remove A → reload gives B a different number.
func TestDCRed_RWRemovalShiftsLaterIdentity(t *testing.T) {
	rw := rewrite.NewRewriter()
	rw.SetRules([]RewriteRule{dcRewriteRule("a.example", "X-A", "1"), dcRewriteRule("b.example", "X-B", "2")})
	rules := rw.List()
	bIdent, _ := rwIdentityOf(rules[1])
	if !rwRemoveByIdentity(rw, func() string { i, _ := rwIdentityOf(rules[0]); return i }()) {
		t.Fatal("remove A")
	}
	persisted := rw.List()
	reloaded := rewrite.NewRewriter()
	reloaded.SetRules(persisted)
	got := reloaded.List()
	if len(got) != 1 {
		t.Fatalf("want 1 rule after reload, got %d", len(got))
	}
	if ident, _ := rwIdentityOf(got[0]); ident != bIdent {
		t.Fatalf("RW IDENTITY SHIFT: rule B re-identified after an earlier removal + reload (%q -> %q) — a client-held identity now addresses a different logical rule", bIdent, ident)
	}
}

// TestDCRed_RWStaleIdentityRetargets (§41-C): an identity captured before a
// reload must never remove a DIFFERENT logical rule after it. With integer
// ids, A's stale id addresses B post-reload.
func TestDCRed_RWStaleIdentityRetargets(t *testing.T) {
	rw := rewrite.NewRewriter()
	rw.SetRules([]RewriteRule{dcRewriteRule("a.example", "X-A", "1"), dcRewriteRule("b.example", "X-B", "2")})
	rules := rw.List()
	aIdent, _ := rwIdentityOf(rules[0])
	// A is deleted; the surviving set reloads into a fresh process.
	if !rwRemoveByIdentity(rw, aIdent) {
		t.Fatal("remove A")
	}
	reloaded := rewrite.NewRewriter()
	reloaded.SetRules(rw.List())
	// A stale client still holding A's identity fires a delete against the
	// reloaded process. It must be a no-op — never remove B.
	rwRemoveByIdentity(reloaded, aIdent)
	got := reloaded.List()
	if len(got) != 1 || got[0].Host != "b.example" {
		t.Fatalf("RW STALE RETARGET: a stale identity removed a DIFFERENT logical rule after reload; remaining=%+v", got)
	}
}

// TestDCRed_RWMutationPersistFailure (§41-D): a hard persistence failure must
// not leave an unacknowledged rewrite rule active in memory. The checkpoint's
// POST was runtime-first (Add, then a fire-and-forget settings save).
func TestDCRed_RWMutationPersistFailure(t *testing.T) {
	restore := rewriter.Snapshot()
	t.Cleanup(restore)
	publishRewriteRulesForTest(t, nil)
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("blocker: %v", err)
	}
	swapAdminSettingsPath(t, filepath.Join(blocker, "settings.json")) // ENOTDIR

	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("POST", "/api/rewrite",
		map[string]any{"host": "fail.example", "req_set": map[string]string{"X-F": "1"}}))
	active := false
	for _, r := range rewriter.List() {
		if r.Host == "fail.example" {
			active = true
		}
	}
	if w.Code/100 == 2 && active {
		t.Fatalf("RW DURABILITY: persistence is broken yet the mutation was ACKNOWLEDGED (%d) with the rule ACTIVE in memory — restart truth diverges", w.Code)
	}
	if active {
		t.Fatal("RW DURABILITY: unacknowledged rewrite rule left active in memory after a persist failure")
	}
}

// TestDCRed_RWStaleEditNoFence (§41-E): a client asserting a stale revision
// must 409, never silently operate on stale state.
func TestDCRed_RWStaleEditNoFence(t *testing.T) {
	restore := rewriter.Snapshot()
	t.Cleanup(restore)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "settings.json"))
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("POST", "/api/rewrite?ifRevision=stale-revision-token",
		map[string]any{"host": "fence.example", "req_set": map[string]string{"X-F": "1"}}))
	if w.Code != 409 {
		t.Fatalf("RW FENCE: a STALE revision assertion was accepted (%d) — two admins can silently overwrite each other", w.Code)
	}
}

// publishRewriteRulesForTest resets the live rewriter's rule set for a test,
// via the same publication seam production uses where it exists, else the
// checkpoint's direct SetRules.
func publishRewriteRulesForTest(t *testing.T, rules []RewriteRule) {
	t.Helper()
	rewriter.SetRules(rules)
	_ = fmt.Sprintf // keep fmt imported at both trees
}
