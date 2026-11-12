package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A SourceIP the matcher can never match: accepted before this change, and
// silently inert (fail-open for a Drop rule under first-match-wins).
var inertSourceIPs = []string{
	" 10.0.0.5",         // leading space
	"10.0.0.5 ",         // trailing space
	"10.0.0.1-10.0.0.9", // a range, not a CIDR
	"10.0.0.0/33",       // prefix length out of range
	"garbage/24",        // not an address
	"host.example",      // a name, not an address
	"010.0.0.1",         // leading zero, rejected by both parsers
	"fe80::/10%eth0",    // zone on a CIDR
	"2001:db8::1/129",   // IPv6 prefix length out of range
}

// Forms the matcher does handle, which must keep being accepted.
var matchableSourceIPs = []string{
	"", // any source
	"10.0.0.5",
	"2001:DB8::10",    // any IPv6 spelling
	"::ffff:10.0.0.5", // 4-in-6
	"fe80::1%eth0",    // zoned literal (exact-string comparison)
	"10.0.0.0/8",
	"10.0.0.5/24", // host bits set; net.ParseCIDR accepts it
	"2001:db8::/32",
}

func TestValidateRuleSourceIP(t *testing.T) {
	for _, s := range inertSourceIPs {
		if err := validateRuleSourceIP(s); err == nil {
			t.Errorf("SourceIP %q: accepted, want rejected", s)
		}
	}
	for _, s := range matchableSourceIPs {
		if err := validateRuleSourceIP(s); err != nil {
			t.Errorf("SourceIP %q: rejected (%v), want accepted", s, err)
		}
	}
}

// Negative control for the premise: each rejected value really is inert at
// Evaluate, so refusing it on write removes nothing an operator could rely on.
func TestValidateRuleSourceIP_RejectedValuesNeverMatch(t *testing.T) {
	for _, s := range inertSourceIPs {
		ps := &PolicyStore{}
		ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "inert", SourceIP: s, DestFQDN: "*", Action: ActionDrop}})
		for _, client := range []string{"10.0.0.5", "10.0.0.1", "10.0.0.0", "2001:db8::1", "fe80::1%eth0"} { // addresses as a real peer reports them
			if m := ps.Evaluate(client, "", "unauth", "example.com", nil); m != nil {
				t.Errorf("SourceIP %q matched client %q; the premise that it is inert is wrong", s, client)
			}
		}
	}
}

func TestPolicyAPI_RejectsUnmatchableSourceIP(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)

	create := func(name, src string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		apiPolicyCreate(w, jsonReq(http.MethodPost, "/api/policy",
			map[string]any{"name": name, "action": "Drop", "destFqdn": "*", "sourceIP": src}))
		return w
	}
	has := func(name string) bool {
		for _, r := range policyStore.List() {
			if r.Name == name {
				return true
			}
		}
		return false
	}

	if w := create("srcip-bad-create", "10.0.0.1-10.0.0.9"); w.Code != http.StatusBadRequest {
		t.Fatalf("create with a range SourceIP: got %d (%s), want 400", w.Code, w.Body.String())
	} else if !strings.Contains(w.Body.String(), "sourceIP") {
		t.Errorf("400 body should name the field, got %q", w.Body.String())
	}
	if has("srcip-bad-create") {
		t.Fatal("rejected rule was stored anyway")
	}

	// Control: the same request with a valid address is accepted.
	if w := create("srcip-good", "2001:DB8::10"); w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("create with a valid SourceIP: got %d (%s)", w.Code, w.Body.String())
	}
	var id string
	for _, r := range policyStore.List() {
		if r.Name == "srcip-good" {
			id = r.ID
		}
	}
	if id == "" {
		t.Fatal("valid rule not stored")
	}

	// Update by ID must refuse it too, and leave the stored rule unchanged.
	w := httptest.NewRecorder()
	apiPolicyUpdateByID(w, jsonReq(http.MethodPut, "/api/policy?id="+id,
		map[string]any{"name": "srcip-good", "action": "Drop", "destFqdn": "*", "sourceIP": "10.0.0.0/33"}), id)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("update with an out-of-range CIDR: got %d (%s), want 400", w.Code, w.Body.String())
	}
	for _, r := range policyStore.List() {
		if r.ID == id && r.SourceIP != "2001:DB8::10" {
			t.Fatalf("rejected update changed SourceIP to %q", r.SourceIP)
		}
	}
}

// Load is the tolerant side: a policy file that already holds such a rule
// keeps loading, keeps the rule, and says so in the log.
func TestPolicyLoad_KeepsAndWarnsOnUnmatchableSourceIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	body := `[{"priority":1,"name":"inert-src","action":"Drop","destFqdn":"*","sourceIP":" 10.0.0.5"},` +
		`{"priority":2,"name":"fine-src","action":"Drop","destFqdn":"*","sourceIP":"10.0.0.0/8"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}
	out := captureLogger(t, func() {
		if err := ps.Load(path); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
	names := map[string]bool{}
	for _, r := range ps.List() {
		names[r.Name] = true
	}
	if !names["inert-src"] || !names["fine-src"] {
		t.Fatalf("Load must keep both rules, got %v", names)
	}
	if !strings.Contains(out, `"inert-src" never matches any client`) {
		t.Errorf("no warning for the unmatchable rule; log was:\n%s", out)
	}
	if strings.Contains(out, `"fine-src" never matches`) {
		t.Errorf("warned about a valid rule; log was:\n%s", out)
	}
}
