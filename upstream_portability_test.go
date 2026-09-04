package main

// upstream_portability_test.go — GREEN proofs beside the 2F-D RED matrix:
// import-plan edge cases (duplicate ids, declared credentials on unknown
// identities, export → import onto a second node, YAML-owned skips, the
// legacy xxxxx compatibility rule), the counts-only commit summary, the
// operator-contract row, the legacy panel pin, and a pre-2F-D backup
// (no credentialsOmitted marker) still restoring.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

func TestUpstreamV2D_Import_DuplicateIncomingIDIsRefusedWhole(t *testing.T) {
	upEnv(t)
	pdSeed(t)
	before := upSettingsFile(t)
	rec := pdImport(t, pdV2Payload(pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FAV", "a.test", "none"), pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FAV", "b.test", "none")), "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate_id") {
		t.Fatalf("want 400 duplicate_id, got %d %s", rec.Code, rec.Body.String())
	}
	if upSettingsFile(t) != before {
		t.Fatal("zero mutation on a refused import")
	}
	// A non-ULID id is an invalid entry.
	rec = pdImport(t, pdV2Payload(pdEntry("not-a-ulid", "a.test", "none")), "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_entry") {
		t.Fatalf("want 400 invalid_entry, got %d %s", rec.Code, rec.Body.String())
	}
	// Both sections at once is ambiguous.
	rec = pdImport(t, `{"version":2,"upstreamProxies":[{"url":"http://x.test:3128"}],"upstream_proxies_v2":{"entries":[]},"upstream_credentials":"omitted"}`, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ambiguous_upstream_sections") {
		t.Fatalf("want 400 ambiguous_upstream_sections, got %d %s", rec.Code, rec.Body.String())
	}
}

// An export imported onto a SECOND node (unknown identities) never inherits
// material: every entry that declared a credential lands in the durable
// requiresReplacement state, ineligible, counted, and resolvable by T2.
func TestUpstreamV2D_Import_ExportOntoSecondNodeLandsInRequiresReplacement(t *testing.T) {
	upEnv(t)
	id, ciphertext := pdSeed(t)
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"plain.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	export := pdExport(t, "upstream").Body.String()
	if strings.Contains(export, ciphertext) || strings.Contains(export, pdCanaryPW) {
		t.Fatal("export carries material")
	}
	// Second node: fresh env, no key, no entries (the pool document is reset —
	// Configure only replaces the YAML seed).
	upEnv(t)
	upstreamPool.Restore(upstream.PoolState{CBThreshold: 5, CBTimeout: time.Minute})
	rec = pdImport(t, export, "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("dry-run on the second node: %d %s", rec.Code, rec.Body.String())
	}
	plan := pdPlan(t, rec)
	if a := pdPlanAction(plan, "incoming", id); a != planRequiresReplacement {
		t.Fatalf("a declared credential on an unknown identity must be requiresReplacement, got %q", a)
	}
	rec = pdImport(t, export, "")
	if rec.Code != 200 {
		t.Fatalf("commit on the second node: %d %s", rec.Code, rec.Body.String())
	}
	up, _ := upJSON(t, rec)["upstream"].(map[string]any)
	if up["requiresReplacement"] != float64(1) || up["omitted"] != float64(1) || up["preserved"] != float64(0) {
		t.Fatalf("counts: %v", up)
	}
	e := upEntry(t, id)
	if e == nil || e["credentialState"] != upstream.CredentialRequiresReplacement || e["eligible"] != false {
		t.Fatalf("the imported entry must keep its stable id and land in requiresReplacement: %v", e)
	}
	v := upGet(t)
	if v["credentialsRequiringReplacement"] != float64(1) || v["mode"] != upstream.ModeChained {
		// The credential-free plain entry is still eligible, so the pool is
		// chained through IT only; the requiresReplacement entry is never
		// selected (R40 pins the all-ineligible ⇒ no_eligible_parent case).
		t.Fatalf("read model: %v %v", v["credentialsRequiringReplacement"], v["mode"])
	}
	for i := 0; i < 8; i++ {
		if u := upProxyURL(t); u != nil && u.Hostname() == pdCanaryHost {
			t.Fatal("a requiresReplacement entry must never be selected")
		}
	}
	// Durable across a save + reload.
	if err := SaveAdminSettings(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(adminSettingsPath)
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	upstreamPool.Configure(nil, 5, 60*time.Second)
	applyAdminNetwork(&s)
	if e := upEntry(t, id); e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("requiresReplacement must survive reload, got %v", e["credentialState"])
	}
	// T3 clear resolves it too (the entry is then knowingly credential-free).
	rev := int64(upEntry(t, id)["revision"].(float64))
	rec = upReq(t, "POST", "/api/upstream/entries/"+id+"/credential", fmt.Sprintf(`{"action":"clear","confirm":%q,"revision":%d}`, id, rev))
	if rec.Code != 200 {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, id); e["credentialState"] != upstream.CredentialNone {
		t.Fatalf("T3 clear must resolve requiresReplacement, got %v", e["credentialState"])
	}
	// The plain entry imported as create, with its stable id.
	entries, _ := upGet(t)["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("both entries must exist: %v", entries)
	}
}

// A same-id import that only changes the authority of a credential-FREE
// entry is an update; with a declared credential it lands in
// requiresReplacement (never inherits).
func TestUpstreamV2D_Import_UpdateVsRequiresReplacementOnCredentialFreeEntry(t *testing.T) {
	upEnv(t)
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"plain.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	id, _ := upJSON(t, rec)["entry"].(map[string]any)["id"].(string)
	rec = pdImport(t, pdV2Payload(pdEntry(id, "moved.test", "none")), "")
	if rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, id); e["host"] != "moved.test" || e["credentialState"] != upstream.CredentialNone {
		t.Fatalf("update must move the authority and keep none: %v", e)
	}
	rec = pdImport(t, pdV2Payload(pdEntry(id, "moved-again.test", "configured")), "dryRun=1")
	if a := pdPlanAction(pdPlan(t, rec), "incoming", id); a != planRequiresReplacement {
		t.Fatalf("declared credential on a changed authority must be requiresReplacement, got %q", a)
	}
	rec = pdImport(t, pdV2Payload(pdEntry(id, "moved-again.test", "configured")), "")
	if rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, id); e["host"] != "moved-again.test" || e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("%v", e)
	}
}

// YAML-owned authorities are skipped (read-only, never adopted) and counted.
func TestUpstreamV2D_Import_YAMLOwnedAuthorityIsSkippedAndCounted(t *testing.T) {
	upEnv(t)
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://parent-y.test:3128"}}, 5, 60*time.Second)
	yamlOwned := map[string]any{"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "scheme": "http", "host": "parent-y.test", "port": 3128, "username": "", "credentialState": "none"}
	rec := pdImport(t, pdV2Payload(yamlOwned, pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FAW", "parent-z.test", "none")), "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	plan := pdPlan(t, rec)
	if plan["yamlOwnedSkipped"] != float64(1) || pdPlanAction(plan, "incoming", "01ARZ3NDEKTSV4RRFFQ69G5FAV") != "" {
		t.Fatalf("the YAML-owned incoming entry must be skipped + counted: %v", plan)
	}
	if a := pdPlanAction(plan, "incoming", "01ARZ3NDEKTSV4RRFFQ69G5FAW"); a != planCreate {
		t.Fatalf("got %q", a)
	}
}

// Legacy list (no identity): xxxxx preserves only an exact, unique authority
// match; a replace-mode omission of a credentialed entry RETAINS it (2F-C
// rule, a legacy list cannot name identities); the plan says so.
func TestUpstreamV2D_Import_LegacyListCompatibilityRule(t *testing.T) {
	upEnv(t)
	id, _ := pdSeed(t)
	rec := pdImport(t, fmt.Sprintf(`{"version":1,"upstreamProxies":[{"url":"http://svc:xxxxx@%s:3128"},{"url":"http://other.test:3128"}]}`, pdCanaryHost), "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	plan := pdPlan(t, rec)
	if plan["legacy"] != true || pdPlanAction(plan, "incoming", id) != planPreserve {
		t.Fatalf("exact unique authority match must preserve: %v", plan)
	}
	// Replace-mode omission retains the credentialed entry.
	rec = pdImport(t, `{"version":1,"upstreamProxies":[{"url":"http://other.test:3128"}]}`, "mode=replace&dryRun=1")
	if a := pdPlanAction(pdPlan(t, rec), "existing", id); a != planRetain {
		t.Fatalf("legacy omission must retain the credentialed entry, got %q", a)
	}
	// A different username is a different authority: no preserve, and the
	// authority would collide only on host — it is simply a new entry.
	rec = pdImport(t, fmt.Sprintf(`{"version":1,"upstreamProxies":[{"url":"http://other-user:xxxxx@%s:3128"}]}`, pdCanaryHost), "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	plan = pdPlan(t, rec)
	if c := plan["counts"].(map[string]any); c[planCreate] != float64(1) || c[planPreserve] != float64(0) {
		t.Fatalf("a non-matching authority must never inherit: %v", c)
	}
}

func TestUpstreamV2D_OperatorContractRowAndLegacyPanelPin(t *testing.T) {
	upEnv(t)
	row := checkUpstreamCredentials()
	if row.Code != "upstream_credentials" || row.Status != diagOK {
		t.Fatalf("empty pool must be ok: %+v", row)
	}
	// One entry in requiresReplacement (imported with a declared credential).
	rec := pdImport(t, pdV2Payload(pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FAV", "parent-r.test", "configured")), "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	row = checkUpstreamCredentials()
	if row.Status != diagWarn || !strings.Contains(row.Message, "1 parent prox") || row.OperatorAction == "" {
		t.Fatalf("row must warn with a count: %+v", row)
	}
	for _, leak := range []string{"parent-r.test", "01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		if strings.Contains(row.Message, leak) || strings.Contains(row.OperatorAction, leak) {
			t.Fatalf("the contract row carries counts only (found %q)", leak)
		}
	}
	// The shipping legacy panel understands the state and the count.
	html, err := os.ReadFile(filepath.Join("static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"requiresReplacement: ['blocked', 'requires replacement']", "v.credentialsRequiringReplacement", "a credential to be set again"} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("legacy upstream panel must carry %q", want)
		}
	}
}

// A backup taken before 2F-D (no credentialsOmitted marker, no
// requiresReplacement markers) still validates and reports 0.
func TestUpstreamV2D_Restore_PreMarkerBackupStillRestores(t *testing.T) {
	src := makeValidBackup(t)
	dst := t.TempDir()
	repacked := filepath.Join(t.TempDir(), "old.tar.gz")
	repackTarball(t, src, repacked, func(files map[string][]byte, order *[]string) {
		var m map[string]any
		_ = json.Unmarshal(files["manifest.json"], &m)
		delete(m, "credentialsOmitted")
		files["manifest.json"], _ = json.MarshalIndent(m, "", "  ")
	})
	out, err := captureStdout(t, func() error { return runRestoreDryRun(repacked, dst, "", restoreOpts{Mode: modeFull}) })
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "pre-2F-D backup") || !strings.Contains(out, "credentials requiring replacement: 0") {
		t.Fatalf("output:\n%s", out)
	}
}

// A hand-built tarball carrying a node-local key is refused whole.
func TestUpstreamV2D_Restore_RefusesArchivedKeyMaterial(t *testing.T) {
	src := makeValidBackup(t)
	dst := t.TempDir()
	repacked := filepath.Join(t.TempDir(), "keyed.tar.gz")
	repackTarball(t, src, repacked, func(files map[string][]byte, order *[]string) {
		files["data/"+upstream.KeyFileName] = []byte("0123456789abcdef0123456789abcdef")
		*order = append(*order, "data/"+upstream.KeyFileName)
		rebuildManifest(t, files, *order)
	})
	if err := runRestoreDryRun(repacked, dst, "", restoreOpts{Mode: modeFull}); err == nil || !strings.Contains(err.Error(), "node-local key material") {
		t.Fatalf("want refusal, got %v", err)
	}
}
