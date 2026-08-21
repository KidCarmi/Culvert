package main

// M3 root-level tests: pre-dispatch negative evidence, the H2-drop emission
// (exactly-once), and the production category-epoch wiring.

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// TestObservationE2E_PreDispatchBlocklistNegativeEvidence: a blocklisted host
// emits a pre-dispatch observation (Status BLOCKED, Action "predispatch") that
// the aggregation model files as threat/negative evidence — never positive.
func TestObservationE2E_PreDispatchBlocklistNegativeEvidence(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "any-allow", DestFQDN: "*", Action: ActionAllow}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	u, _ := url.Parse(backend.URL)
	hostOnly := u.Hostname()
	bl.Add(hostOnly)
	t.Cleanup(func() { bl.Remove(hostOnly) })

	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", nil); got != http.StatusForbidden {
		t.Fatalf("blocklisted GET: %d, want 403", got)
	}
	if cb.hitCount() != 0 {
		t.Fatal("blocklisted request reached upstream")
	}
	_ = eng.Close()

	o, ok := obsForHost(t, col, hostOnly)
	if !ok {
		t.Fatalf("no pre-dispatch observation (got %v)", col.all())
	}
	if o.Status != "BLOCKED" || o.Action != "predispatch" {
		t.Fatalf("pre-dispatch observation: %+v", o)
	}
}

// TestObservationE2E_DropEmitsExactlyOnce: an ActionDrop decision emits ONE
// observation (the pre-abort emission), never two — pinning the H2-gap fix's
// double-emit guard.
func TestObservationE2E_DropEmitsExactlyOnce(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "drop-all", DestFQDN: "*", Action: ActionDrop}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	p := *proxyURL
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&p)}, Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/", http.NoBody)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close() // a silent RST usually surfaces as a transport error; tolerate either
	}
	if cb.hitCount() != 0 {
		t.Fatal("dropped request reached upstream")
	}
	_ = eng.Close()

	u, _ := url.Parse(backend.URL)
	hostOnly := u.Hostname()
	count := 0
	var got policylearn.Observation
	for _, o := range col.all() {
		if o.Host == hostOnly {
			count++
			got = o
		}
	}
	if count != 1 {
		t.Fatalf("Drop emitted %d observations, want exactly 1 (%v)", count, col.all())
	}
	if got.Status != "POLICY_DROP" || got.RuleID == "" {
		t.Fatalf("drop observation: %+v", got)
	}
}

// TestLearnCategoryEpoch_TracksAdminTaxonomy: the production epoch composition
// changes when the admin taxonomy changes (urlcat revision), so a mid-session
// admin category edit surfaces as churn rather than a silently blended window.
func TestLearnCategoryEpoch_TracksAdminTaxonomy(t *testing.T) {
	before := learnCategoryEpoch()
	if err := catStore.Set("m3-epoch-test", []string{"m3-epoch.example"}, false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = catStore.Delete("m3-epoch-test") })
	after := learnCategoryEpoch()
	if before == after {
		t.Fatalf("epoch unchanged across an admin taxonomy edit: %q", before)
	}
}

// TestObservationE2E_NoRawSubjectOnDisk: end-to-end through the real proxy
// with a DURABLE engine — the persisted learning store carries the pseudonym
// token, never the raw subject.
func TestObservationE2E_NoRawSubjectOnDisk(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())

	dir := t.TempDir()
	eng, err := policylearn.New(policylearn.Config{
		Now:            time.Now,
		StorePath:      dir + "/policy_learning.json",
		SubjectKeyPath: dir + "/subject.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.StartSession("m3"); err != nil {
		t.Fatal(err)
	}
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(eng)
	t.Cleanup(func() { policyLearnEngine.Store(prev); _ = eng.Close() })

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "alice", "eng-token", nil); got != http.StatusOK {
		t.Fatalf("GET: %d", got)
	}
	_ = eng.Close() // drain + flush

	rawBytes, err := os.ReadFile(dir + "/policy_learning.json") // absolute temp path: CWD-independent
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"alice", "eng-token"} {
		if containsSrc(string(rawBytes), forbidden) {
			t.Fatalf("raw credential/subject %q persisted in the learning store", forbidden)
		}
	}
}
