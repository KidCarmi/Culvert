package main

// policy_ruleid_logentry_test.go — the request-log Entry carries the matched
// forward-proxy rule's stable ULID (RuleID) alongside its mutable name
// (RuleMatched). This is the §1 rename-safe decision-attribution seam: "find
// the rule that made this decision" becomes an ID lookup instead of a
// name string-match (names are not guaranteed unique).
//
// Contract pinned here:
//   - an allowed request logs RuleID == the matched rule's ID;
//   - a blocked (block-page) request logs RuleID == the matched rule's ID;
//   - a no-rule/default-deny request logs an empty RuleID (omitempty on the wire).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ruleIDByName returns the store-assigned ULID for the named rule (IDs are
// backfilled on Add, so the caller reads it back after inserting).
func ruleIDByName(t *testing.T, name string) string {
	t.Helper()
	rules := policyStore.List()
	for i := range rules { // index-based: PolicyRule is large (CLAUDE.md rangeValCopy)
		if rules[i].Name == name {
			if rules[i].ID == "" {
				t.Fatalf("rule %q has no ID assigned", name)
			}
			return rules[i].ID
		}
	}
	t.Fatalf("rule %q not found in store", name)
	return ""
}

func TestRuleID_AllowPath_StampsMatchedRuleID(t *testing.T) {
	setupProxyTest(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)
	host := strings.TrimPrefix(backend.URL, "http://")
	hostOnly := host[:strings.LastIndex(host, ":")]

	policyStore.Add(PolicyRule{Priority: 1, Name: "allow-known", Action: ActionAllow, DestFQDN: hostOnly})
	wantID := ruleIDByName(t, "allow-known")

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest(backend.URL+"/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("allow rule should pass: got %d", w.Code)
	}

	e := findLogByHost(t, host)
	if e.RuleMatched != "allow-known" {
		t.Errorf("RuleMatched = %q, want allow-known", e.RuleMatched)
	}
	if e.RuleID != wantID {
		t.Errorf("RuleID = %q, want the matched rule's ULID %q", e.RuleID, wantID)
	}
}

func TestRuleID_BlockPath_StampsMatchedRuleID(t *testing.T) {
	setupProxyTest(t)
	const host = "blocked.example.com"

	policyStore.Add(PolicyRule{Priority: 1, Name: "block-known", Action: ActionBlockPage, DestFQDN: host})
	wantID := ruleIDByName(t, "block-known")

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	e := findLogByHost(t, host)
	if e.Status != "POLICY_BLOCK" {
		t.Fatalf("expected POLICY_BLOCK, got %q", e.Status)
	}
	if e.RuleMatched != "block-known" {
		t.Errorf("RuleMatched = %q, want block-known", e.RuleMatched)
	}
	if e.RuleID != wantID {
		t.Errorf("RuleID = %q, want the matched rule's ULID %q", e.RuleID, wantID)
	}
}

func TestRuleID_NoMatch_LeavesRuleIDEmpty(t *testing.T) {
	setupProxyTest(t) // default-deny, no rules
	const host = "unmatched.example.com"

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	e := findLogByHost(t, host)
	if e.RuleMatched != "" {
		t.Errorf("no rule should match: RuleMatched = %q", e.RuleMatched)
	}
	if e.RuleID != "" {
		t.Errorf("no-match entry must leave RuleID empty (omitempty), got %q", e.RuleID)
	}
}
