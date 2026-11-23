package main

// POL-004 end to end, over a real proxy socket.
//
// The decision-layer tests in policy_unknown_action_test.go prove Evaluate and
// applyPolicyDecision separately. This file proves the chain a customer runs:
// a rulebase carrying an action this build does not know is published
// (ReplaceAll) or read from disk (Load), a client asks the proxy for the
// destination that rule covers, and the upstream is NOT reached — under an
// explicit default ALLOW, which is the configuration in which silently dropping
// the rule forwarded the traffic.
//
// Before the fix the same sequence ended in 200 with one backend hit: the rule
// was removed at the door, nothing matched, and the default allowed it.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pol004FutureAction = "Quarantine" // an action a newer release might add

// pol004Get issues one GET for the backend through the proxy and reports the
// status plus how many requests the backend saw because of it.
func pol004Get(t *testing.T, client *http.Client, cb *countingBackend, target string) (status int, backendHits int64) {
	t.Helper()
	rl = newRateLimiter()
	before := cb.hitCount()
	resp, err := ctxGet(client, target)
	if err != nil {
		t.Fatalf("GET %s through the proxy: %v", target, err)
	}
	resp.Body.Close()
	return resp.StatusCode, cb.hitCount() - before
}

func pol004Setup(t *testing.T) (client *http.Client, cb *countingBackend, target, host string) {
	t.Helper()
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t) // restores rules and the default action on cleanup
	snapshotPolicyStoreForTest(t) // restores the store's path too (the Load variant adopts one)
	setDefaultPolicyAction("allow")
	client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	host = strings.Split(strings.TrimPrefix(backend.URL, "http://"), ":")[0]
	return client, cb, backend.URL + "/", host
}

// pol004AssertBlocksAndControlsHold runs the acceptance sequence against
// whatever rulebase publish() installs, so ReplaceAll and Load are held to the
// identical standard.
func pol004AssertBlocksAndControlsHold(t *testing.T, client *http.Client, cb *countingBackend, target, host string, publish func(rules []PolicyRule)) {
	t.Helper()

	// 1. The unknown-action rule covers the backend. Default is ALLOW.
	publish([]PolicyRule{{Priority: 1, Name: "future-restriction", DestFQDN: host, Action: pol004FutureAction}})
	if n := len(policyStore.List()); n != 1 {
		t.Fatalf("published rulebase has %d rule(s), want 1: the unknown-action rule was dropped at the door", n)
	}
	status, hits := pol004Get(t, client, cb, target)
	if hits != 0 {
		t.Fatalf("POL-004 violated: backend reached %d time(s) through a rule with an unknown action under default allow (status %d)", hits, status)
	}
	if status != http.StatusForbidden {
		t.Errorf("unknown-action match: status %d, want 403 (terminal policy block)", status)
	}
	if h := ruleHitCount("future-restriction"); h < 1 {
		t.Errorf("the unknown-action rule did not record the match (HitCount=%d): something other than the rule refused the request", h)
	}

	// 2. First match is terminal: a lower-priority Allow for the same
	// destination must not rescue the request.
	publish([]PolicyRule{
		{Priority: 1, Name: "future-restriction", DestFQDN: host, Action: pol004FutureAction},
		{Priority: 2, Name: "later-allow", DestFQDN: host, Action: ActionAllow},
	})
	if status, hits := pol004Get(t, client, cb, target); hits != 0 || status != http.StatusForbidden {
		t.Errorf("unknown action ahead of an Allow: status %d, backend hits %d; want 403 and 0", status, hits)
	}

	// 3. Not-vacuous controls. A gate that blocked everything would pass 1 and 2.
	// 3a. A known Allow rule for the same destination forwards.
	publish([]PolicyRule{{Priority: 1, Name: "known-allow", DestFQDN: host, Action: ActionAllow}})
	if status, hits := pol004Get(t, client, cb, target); hits != 1 || status != http.StatusOK {
		t.Errorf("control, known Allow: status %d, backend hits %d; want 200 and 1", status, hits)
	}
	// 3b. An unknown-action rule for ANOTHER destination leaves this one to the
	// explicit default allow: retention must not turn into a global deny.
	publish([]PolicyRule{{Priority: 1, Name: "future-elsewhere", DestFQDN: "elsewhere.example.invalid", Action: pol004FutureAction}})
	if status, hits := pol004Get(t, client, cb, target); hits != 1 || status != http.StatusOK {
		t.Errorf("control, unrelated unknown-action rule under default allow: status %d, backend hits %d; want 200 and 1", status, hits)
	}
	// 3c. An intentionally empty rulebase under explicit default allow forwards.
	publish(nil)
	if status, hits := pol004Get(t, client, cb, target); hits != 1 || status != http.StatusOK {
		t.Errorf("control, empty rulebase under default allow: status %d, backend hits %d; want 200 and 1", status, hits)
	}
}

func TestPOL004E2E_ReplaceAllUnknownActionNeverReachesBackend(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	pol004AssertBlocksAndControlsHold(t, client, cb, target, host, func(rules []PolicyRule) {
		policyStore.ReplaceAll(rules) // the CP→DP snapshot apply and replace-mode import door
	})
}

func TestPOL004E2E_LoadUnknownActionNeverReachesBackend(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	dir := t.TempDir()
	n := 0
	pol004AssertBlocksAndControlsHold(t, client, cb, target, host, func(rules []PolicyRule) {
		// A policy file as a newer release, a restored backup or an operator
		// would leave it: written by a store, then read by the live one.
		n++
		path := filepath.Join(dir, fmt.Sprintf("policy-%d.json", n))
		writer := &PolicyStore{}
		if err := writer.Load(path); err != nil {
			t.Fatalf("adopt %s: %v", path, err)
		}
		writer.ReplaceAll(rules)
		if err := writer.SaveErr(); err != nil {
			t.Fatalf("save %s: %v", path, err)
		}
		if err := policyStore.Load(path); err != nil { // the durable-load door
			t.Fatalf("Load %s: %v", path, err)
		}
	})
}

// TestPOL004_MixedVersionRoundTripKeepsTheOpaqueAction: an older node that
// loads a newer rulebase and saves it again must hand back the action it did
// not understand, byte for byte. Rewriting it — to "", to Block_Page, to
// anything — would change what the newer nodes enforce after the next sync.
func TestPOL004_MixedVersionRoundTripKeepsTheOpaqueAction(t *testing.T) {
	setupProxyTest(t)
	ps := loadIntoFreshStore(t, `[
		{"priority":1,"name":"future-restriction","destFQDN":"blocked.example.com","action":"Quarantine"},
		{"priority":2,"name":"known-allow","destFQDN":"allowed.example.com","action":"Allow"}
	]`)
	if err := ps.SaveErr(); err != nil {
		t.Fatalf("save: %v", err)
	}
	saved, err := os.ReadFile(ps.path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(saved), `"action": "Quarantine"`) && !strings.Contains(string(saved), `"action":"Quarantine"`) {
		t.Fatalf("the unknown action did not survive the save; file:\n%s", saved)
	}
	again := &PolicyStore{}
	if err := again.Load(ps.path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if n := len(again.List()); n != 2 {
		t.Fatalf("reloaded rulebase has %d rule(s), want 2", n)
	}
	assertUnknownActionBlockedFromStore(t, again, "blocked.example.com", "Quarantine")
	if m := again.Evaluate("203.0.113.9", "", "", "allowed.example.com", nil); m == nil || m.Action != ActionAllow {
		t.Errorf("the known Allow rule did not survive the round trip: %+v", m)
	}
}

// TestPOL004_OperatorIsWarnedOncePerRetainedRuleWithSanitizedValues: a retained
// unknown action blocks traffic the operator may not expect to be blocked, so
// each one is announced at both doors, and the rule name and action — which a
// policy file or a peer controls — cannot forge a log line.
func TestPOL004_OperatorIsWarnedOncePerRetainedRuleWithSanitizedValues(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	sink := captureLoggerForTest(t)

	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "future-a", DestFQDN: "a.example.com", Action: "Quarantine"},
		{Priority: 2, Name: "evil\nPolicy: forged line", DestFQDN: "b.example.com", Action: "Isolate\r\nFORGED"},
		{Priority: 3, Name: "known", DestFQDN: "c.example.com", Action: ActionAllow},
		{Priority: 4, Name: "empty-action", DestFQDN: "d.example.com", Action: ""}, // resolves to Allow: not unknown
	})
	out := sink.String()
	if n := strings.Count(out, "with unrecognized action"); n != 2 {
		t.Errorf("bulk replace announced %d retained unknown-action rule(s), want 2 (not the known or the empty one); log:\n%s", n, out)
	}
	if !strings.Contains(out, `"future-a"`) || !strings.Contains(out, `"Quarantine"`) {
		t.Errorf("the warning does not name the rule and its action; log:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(line, "Policy: forged line") || strings.HasPrefix(line, "FORGED") {
			t.Errorf("a rule name or action forged a log line: %q", line)
		}
	}

	sink2 := captureLoggerForTest(t)
	loadIntoFreshStore(t, `[
		{"priority":1,"name":"future-a","destFQDN":"a.example.com","action":"Quarantine"},
		{"priority":2,"name":"known","destFQDN":"c.example.com","action":"Allow"}
	]`)
	if n := strings.Count(sink2.String(), "with unrecognized action"); n != 1 {
		t.Errorf("load announced %d retained unknown-action rule(s), want 1; log:\n%s", n, sink2.String())
	}
}
