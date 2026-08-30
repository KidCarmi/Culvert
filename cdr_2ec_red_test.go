package main

// cdr_2ec_red_test.go — 2E-C CDR/Sluice management-surface backend contract
// matrix. Written RED-FIRST against the 2E-B frozen predecessor
// (42296756e9af777ce4a67aa93db61e20e467bb3b): every test in this file
// compiles and runs at that commit, and the R-numbered tests FAIL there,
// pinning the defect each 2E-C backend correction closes. The control test
// is green at the predecessor and must stay green after the corrections.
//
//	R1  PUT /api/cdr/config route metadata hides the audit event the
//	    handler emits (auditEventDiff "cdr.config.toggle", cdr_ui.go) —
//	    AuditExpected is unset with a stale "no direct auditEvent
//	    observed" note, so C2c never verifies the route.
//	R2  DELETE /api/cdr/instances shreds the client cert + key and prunes
//	    the registry WITHOUT recording the client-cert SHA-256 fingerprint
//	    anywhere durable. That fingerprint is the ONLY key Sluice accepts
//	    for revocation, so a delete leaves Sluice trusting a credential
//	    this appliance can no longer identify — an untraceable trust
//	    orphan. The audit entry and the response must carry it.
//	R3  The health poller mutates registry entries through shared
//	    pointers with no lock (updateRegistryMetadataFromPool writes
//	    inst.Version / inst.LastHealth) while GET /api/cdr/instances
//	    reads the same fields — a data race on the management read path
//	    (fails under -race at the predecessor).
//	R4  Registry mutations persist OUTSIDE the mutation lock: Save()
//	    snapshots under RLock and writes unlocked, so a concurrent
//	    poller Save (server-cert rotation path) can write a PRE-removal
//	    snapshot AFTER RemoveByName persisted — resurrecting a deleted
//	    (or revoked) instance on disk for the next boot.
//	R5  CDR policy rules use the name as the only deletion key, but POST
//	    /api/cdr/policies accepts duplicate names — the identity a later
//	    DELETE acts on is ambiguous.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── R1: config-toggle audit truth in route metadata ───────────────────────

// TestCDR2EC_ConfigPutMetadataDeclaresAudit requires the uiRoutes entry for
// PUT /api/cdr/config to declare AuditExpected=true. The handler HAS emitted
// auditEventDiff("cdr.config.toggle", ...) since Phase 2c (pinned by
// TestCDRHygiene_ConfigToggle_NoConfigVersion), so metadata that says
// otherwise hides the audit contract from the C2c completion observer.
func TestCDR2EC_ConfigPutMetadataDeclaresAudit(t *testing.T) {
	for _, r := range uiRoutes {
		if r.Path != "/api/cdr/config" {
			continue
		}
		for _, m := range r.Methods {
			if m.Method != http.MethodPut {
				continue
			}
			if !m.AuditExpected {
				t.Fatalf("uiRoutes PUT /api/cdr/config: AuditExpected=false (note=%q) — the handler emits auditEventDiff \"cdr.config.toggle\" (cdr_ui.go apiCDRConfigToggle), so the metadata is hiding a real audit contract from C2c", m.Note)
			}
			return // found and correct
		}
		t.Fatal("uiRoutes /api/cdr/config has no PUT method entry")
	}
	t.Fatal("uiRoutes has no /api/cdr/config entry")
}

// ─── R2: delete must durably record the orphaned trust identity ─────────────

// TestCDR2EC_DeleteRecordsOrphanedTrustIdentity enrolls a registry entry
// with a real on-disk client cert, deletes it through the handler, and
// requires the client-cert SHA-256 fingerprint — the Sluice-side revocation
// key — in BOTH the audit entry and the DELETE response. At the predecessor
// the fingerprint is recorded nowhere and the shred makes it unrecoverable.
func TestCDR2EC_DeleteRecordsOrphanedTrustIdentity(t *testing.T) {
	resetCDRState(t)

	const name = "cdr-2ec-del-target"
	certDir, err := cdrInstanceCertsDir(name)
	if err != nil {
		t.Fatalf("cdrInstanceCertsDir(%q): %v", name, err)
	}
	if mkErr := os.MkdirAll(certDir, 0o700); mkErr != nil {
		t.Skipf("cannot write %s (test env restricted): %v", certDir, mkErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(certDir) })

	clientCertPath := filepath.Join(certDir, "client.pem")
	if werr := os.WriteFile(clientCertPath, mustGenerateTestCertPEM(t), 0o600); werr != nil {
		t.Fatalf("write client cert: %v", werr)
	}
	fp, err := loadCertFingerprint(clientCertPath)
	if err != nil {
		t.Fatalf("loadCertFingerprint: %v", err)
	}

	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name:           name,
		Endpoint:       "sluice-2ec-del:8443",
		ClientCertPath: clientCertPath,
	}); err != nil {
		t.Fatalf("cdrInstances.Add: %v", err)
	}

	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodDelete, "/api/cdr/instances?name="+name, nil)
	r.RemoteAddr = "198.51.100.71:0"
	apiCDRInstances(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE status %d; body=%s", w.Code, w.Body.String())
	}

	// The local prune + shred themselves must still have happened.
	if cdrInstances.Get(name) != nil {
		t.Fatal("registry entry survived DELETE")
	}
	if _, statErr := os.Stat(clientCertPath); !os.IsNotExist(statErr) {
		t.Fatalf("client cert not shredded (stat err=%v)", statErr)
	}

	// RED at predecessor: the response must name the trust identity that
	// remains valid on the Sluice side after this local-only delete.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode DELETE response: %v", err)
	}
	got, _ := resp["clientCertFingerprint"].(string)
	if got != fp {
		t.Errorf("DELETE response clientCertFingerprint = %q, want %q — without it the operator cannot revoke the still-trusted credential on Sluice after the local shred", got, fp)
	}

	// RED at predecessor: the durable audit record must carry the same
	// fingerprint (the audit JSONL outlives the shredded PEM).
	assertAuditEntryWithDiscriminator(t, "cdr.instance.remove", fp)
}

// ─── R3: management GET must not race the health poller ────────────────────

// TestCDR2EC_InstanceListDoesNotRaceHealthPoller runs the poller's registry
// metadata write-back concurrently with the GET /api/cdr/instances handler.
// At the predecessor updateRegistryMetadataFromPool writes inst.Version /
// inst.LastHealth through the shared registry pointer with no lock while the
// handler renders the same fields — the race detector fails the run.
func TestCDR2EC_InstanceListDoesNotRaceHealthPoller(t *testing.T) {
	resetCDRState(t)

	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name:     "cdr-2ec-race",
		Endpoint: "sluice-2ec-race:8443",
	}); err != nil {
		t.Fatalf("cdrInstances.Add: %v", err)
	}

	// A pool member with a health snapshot is all the write-back path
	// needs — no live connection required.
	pc := &cdrPooledClient{Name: "cdr-2ec-race", Breaker: newCDRCircuitBreaker(cdrBreakerConfig{})}
	pc.setHealth(&pb.HealthResponse{Healthy: true, Version: "v-a"})
	withTempPool(t, pc)
	members := []*cdrPooledClient{pc}

	const rounds = 400
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if i%2 == 0 {
				pc.setHealth(&pb.HealthResponse{Healthy: true, Version: "v-a"})
			} else {
				pc.setHealth(&pb.HealthResponse{Healthy: true, Version: "v-b"})
			}
			updateRegistryMetadataFromPool(members)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			w := httptest.NewRecorder()
			apiCDRInstances(w, newViewerRequest("/api/cdr/instances"))
			if w.Code != http.StatusOK {
				t.Errorf("GET status %d", w.Code)
				return
			}
		}
	}()
	wg.Wait()
}

// ─── R4: a removal must not be resurrected on disk by a concurrent Save ────

// TestCDR2EC_RemovalIsNotResurrectedByConcurrentSave drives RemoveByName
// concurrently with the poller-shaped bare Save() (the server-cert rotation
// path calls cdrInstances.Save() from the health poller goroutine) and then
// compares the durable file against memory. At the predecessor Save()
// snapshots under RLock and writes with no lock held, so a pre-removal
// snapshot can land AFTER the removal's own write — the deleted instance
// comes back at the next boot while its shredded certs do not.
func TestCDR2EC_RemovalIsNotResurrectedByConcurrentSave(t *testing.T) {
	reg := &CDRInstanceRegistry{}
	path := filepath.Join(t.TempDir(), "cdr_instances.json")
	if err := reg.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Filler entries widen the marshal+write window of a stale snapshot.
	for i := 0; i < 40; i++ {
		if _, err := reg.Add(CDREnrolledInstance{
			Name:     "filler-" + strings.Repeat("x", 3) + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Endpoint: "sluice-filler:8443",
		}); err != nil {
			t.Fatalf("Add filler %d: %v", i, err)
		}
	}

	const rounds = 1500
	for i := 0; i < rounds; i++ {
		if _, err := reg.Add(CDREnrolledInstance{Name: "victim", Endpoint: "sluice-victim:8443"}); err != nil {
			t.Fatalf("round %d: Add victim: %v", i, err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = reg.Save() // the poller's rotation-path write
		}()
		go func() {
			defer wg.Done()
			if ok, err := reg.RemoveByName("victim"); !ok || err != nil {
				t.Errorf("RemoveByName: ok=%v err=%v", ok, err)
			}
		}()
		wg.Wait()

		if reg.Get("victim") != nil {
			t.Fatalf("round %d: victim still in memory after RemoveByName", i)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("round %d: read registry file: %v", i, err)
		}
		var onDisk []*CDREnrolledInstance
		if err := json.Unmarshal(data, &onDisk); err != nil {
			t.Fatalf("round %d: parse registry file: %v", i, err)
		}
		for _, inst := range onDisk {
			if inst.Name == "victim" {
				t.Fatalf("round %d: removed instance %q resurrected in the durable file — a concurrent Save wrote a pre-removal snapshot after the removal persisted (next boot re-loads a deleted/revoked instance whose certs are shredded)", i, inst.Name)
			}
		}
	}
}

// ─── R5: policy rule identity — the deletion key must be unique ────────────

// TestCDR2EC_DuplicatePolicyNameRefused adds a rule, then posts a second
// rule with the SAME name. Name is the only key DELETE /api/cdr/policies
// accepts, so a duplicate makes the deletion target ambiguous — the second
// add must be refused with 409 and must not enlarge the ruleset.
func TestCDR2EC_DuplicatePolicyNameRefused(t *testing.T) {
	resetCDRState(t)

	body := []byte(`{"name":"dup-2ec","priority":10,"mode":"ENFORCE","profileName":"default"}`)
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", body))
	if w.Code != http.StatusOK {
		t.Fatalf("first add status %d; body=%s", w.Code, w.Body.String())
	}

	dup := []byte(`{"name":"dup-2ec","priority":20,"mode":"REPORT_ONLY","profileName":"default"}`)
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", dup))
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate-name add: status %d, want 409 — name is the sole DELETE key, so duplicates make the deletion target ambiguous (body=%s)", w.Code, w.Body.String())
	}
	if n := len(cdrPolicyStore.List()); n != 1 {
		t.Errorf("ruleset has %d rules after duplicate add, want 1", n)
	}
}

// ─── Control: distinct names keep working (green at predecessor AND after) ──

// TestCDR2EC_Control_DistinctPolicyNamesStillAdd guards the R5 correction
// against overblocking: two rules with different names must both land, and
// deleting one by name must remove exactly that one.
func TestCDR2EC_Control_DistinctPolicyNamesStillAdd(t *testing.T) {
	resetCDRState(t)

	for _, body := range []string{
		`{"name":"ctl-2ec-a","priority":10,"mode":"ENFORCE"}`,
		`{"name":"ctl-2ec-b","priority":20,"mode":"REPORT_ONLY"}`,
	} {
		w := httptest.NewRecorder()
		apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", []byte(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("add %s: status %d; body=%s", body, w.Code, w.Body.String())
		}
	}
	if n := len(cdrPolicyStore.List()); n != 2 {
		t.Fatalf("ruleset has %d rules, want 2", n)
	}

	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=ctl-2ec-a", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete status %d; body=%s", w.Code, w.Body.String())
	}
	rules := cdrPolicyStore.List()
	if len(rules) != 1 || rules[0].Name != "ctl-2ec-b" {
		t.Fatalf("after delete: %d rules (first=%v), want exactly ctl-2ec-b", len(rules), rules)
	}
	// Ruleset changes must remain audited (frozen no-versioning posture:
	// audit yes, config version no).
	assertAuditEntryWithDiscriminator(t, "cdr.policy.remove", "removed CDR policy rule")
}

// Keep time import anchored for future timestamp assertions in this matrix.
var _ = time.Now
