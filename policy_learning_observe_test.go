package main

// M2 — end-to-end observation transport tests: real proxy traffic produces
// server-derived observations; spoofed client input cannot enter them; a nil
// (disabled) engine is a zero-cost no-op.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// obsCollector gathers observations across goroutines.
type obsCollector struct {
	mu  sync.Mutex
	got []policylearn.Observation
}

func (c *obsCollector) sink(o policylearn.Observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, o)
}

func (c *obsCollector) all() []policylearn.Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]policylearn.Observation(nil), c.got...)
}

// swapPolicyLearnSink installs a memory-only engine with an active session and
// the given sink; restores the previous singleton on cleanup. Returns the
// engine so tests can Close (deterministic drain) before asserting.
func swapPolicyLearnSink(t *testing.T, sink func(policylearn.Observation)) *policylearn.Engine {
	t.Helper()
	eng, err := policylearn.New(policylearn.Config{Now: time.Now, Sink: sink})
	if err != nil {
		t.Fatalf("policylearn.New: %v", err)
	}
	if _, err := eng.StartSession("m2-test"); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(eng)
	t.Cleanup(func() {
		policyLearnEngine.Store(prev)
		_ = eng.Close()
	})
	return eng
}

func obsForHost(t *testing.T, col *obsCollector, host string) (policylearn.Observation, bool) {
	t.Helper()
	obs := col.all()
	for i := range obs { // index-based: Observation carries a groups slice (rangeValCopy)
		if obs[i].Host == host {
			return obs[i], true
		}
	}
	return policylearn.Observation{}, false
}

// TestObservationE2E_AuthenticatedAllow: an authenticated allowed request
// emits one observation carrying the resolved subject, verbatim provenance,
// groups, stable rule ID, action, status, and the resolved SSL action — all
// server-derived.
func TestObservationE2E_AuthenticatedAllow(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "alice", "eng-token", nil); got != http.StatusOK {
		t.Fatalf("GET: %d", got)
	}
	_ = eng.Close() // deterministic drain

	u, _ := url.Parse(backend.URL)
	hostOnly, _, _ := net.SplitHostPort(u.Host)
	o, ok := obsForHost(t, col, hostOnly)
	if !ok {
		t.Fatalf("no observation for %s (got %v)", hostOnly, col.all())
	}
	if o.Subject != "alice" || o.AuthSource != "test-idp" {
		t.Errorf("subject/source = %q/%q", o.Subject, o.AuthSource)
	}
	if len(o.Groups) != 1 || o.Groups[0] != "engineering" {
		t.Errorf("groups = %v", o.Groups)
	}
	if o.RuleID == "" || o.Action != string(ActionAllow) || o.Status != "OK" || o.Method != http.MethodGet {
		t.Errorf("decision fields: rule %q action %q status %q method %q", o.RuleID, o.Action, o.Status, o.Method)
	}
	if o.SSLAction != string(SSLBypass) && o.SSLAction != string(SSLInspect) {
		t.Errorf("SSLAction = %q, want a resolved value on the allowed branch", o.SSLAction)
	}
	if o.At == 0 {
		t.Error("At not stamped")
	}
}

// TestObservationE2E_SpoofCannotEnter: Exempt posture + spoofed
// X-User-Identity → the observation carries empty Subject, "unauth"
// provenance, and no groups. No client value crosses the boundary.
func TestObservationE2E_SpoofCannotEnter(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "any-allow", DestFQDN: "*", Action: ActionAllow}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	if got := spoofedGet(t, proxyURL, backend.URL+"/", "mallory"); got != http.StatusOK {
		t.Fatalf("GET: %d", got)
	}
	_ = eng.Close()

	u, _ := url.Parse(backend.URL)
	hostOnly, _, _ := net.SplitHostPort(u.Host)
	o, ok := obsForHost(t, col, hostOnly)
	if !ok {
		t.Fatal("no observation")
	}
	if o.Subject != "" || o.AuthSource != "unauth" || len(o.Groups) != 0 {
		t.Errorf("spoof leaked into the observation: subject %q source %q groups %v", o.Subject, o.AuthSource, o.Groups)
	}
}

// TestObservationE2E_HostCanonicalized (Codex round 9): spelling aliases like
// ExAmPle.COM. are ONE destination to policy and category resolution, so the
// observation must carry the canonical host from the ingress normalization
// gate — the raw spelling made aliases consume separate TopHosts budget
// entries and perturb evidence hashes.
func TestObservationE2E_HostCanonicalized(t *testing.T) {
	_, _ = startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), nil) // no rules; default deny — observed before any dial
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	if got := proxiedGet(t, proxyURL, "http://ExAmPle.COM./", "", "", nil); got != http.StatusForbidden {
		t.Fatalf("GET: %d, want 403 (default deny)", got)
	}
	_ = eng.Close()

	if _, raw := obsForHost(t, col, "ExAmPle.COM."); raw {
		t.Fatal("observation carries the RAW host spelling, not the canonical form")
	}
	if _, ok := obsForHost(t, col, "example.com"); !ok {
		t.Fatalf("no observation under the canonical host (got %v)", col.all())
	}
}

// TestObservationE2E_DefaultDenyBlocked: a default-denied request emits a
// blocked-branch observation (status POLICY_DEFAULT_DENY, action
// default:deny, empty rule/SSL) and no URL/path ever appears (host only).
func TestObservationE2E_DefaultDenyBlocked(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), nil) // no rules; default deny
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	if got := proxiedGet(t, proxyURL, backend.URL+"/some/path?secret=1", "", "", nil); got != http.StatusForbidden {
		t.Fatalf("GET: %d, want 403", got)
	}
	_ = eng.Close()

	u, _ := url.Parse(backend.URL)
	hostOnly, _, _ := net.SplitHostPort(u.Host)
	o, ok := obsForHost(t, col, hostOnly)
	if !ok {
		t.Fatal("no observation for the blocked request")
	}
	if o.Status != "POLICY_DEFAULT_DENY" || o.Action != "default:deny" || o.RuleID != "" || o.SSLAction != "" {
		t.Errorf("blocked-branch fields: %+v", o)
	}
	for _, other := range col.all() {
		if other.Host != hostOnly && other.Host != "" {
			continue
		}
		if containsSrc(other.Host, "/") || containsSrc(other.Host, "secret") {
			t.Errorf("observation leaked URL material: %q", other.Host)
		}
	}
}

// TestObservationE2E_CONNECTTunnel: a CONNECT bypass tunnel emits an
// observation with Method CONNECT and the resolved SSL action.
func TestObservationE2E_CONNECTTunnel(t *testing.T) {
	restore := ssrf.AllowLoopbackForTest()
	t.Cleanup(restore)
	setupProxyTest(t)
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })
	policyStore.Add(PolicyRule{Priority: 1, Name: "tunnel-allow", DestFQDN: "*", Action: ActionAllow})
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, _ := url.Parse(srv.URL)

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := ln.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target) //nolint:errcheck // test conn write; failure surfaces on the read below
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !containsHTTP200(line) {
		t.Fatalf("CONNECT: %q %v", line, err)
	}
	conn.Close()
	_ = eng.Close()

	hostOnly, _, _ := net.SplitHostPort(target)
	o, ok := obsForHost(t, col, hostOnly)
	if !ok {
		t.Fatalf("no CONNECT observation (got %v)", col.all())
	}
	if o.Method != http.MethodConnect || o.Status != "OK" || o.SSLAction == "" {
		t.Errorf("CONNECT observation: %+v", o)
	}
}

// TestObservation_ActionDerivedFromEnforcementStatus (Codex round 16): the
// default-action label must come from the ENFORCEMENT's own recorded status,
// never a fresh read of the defaultPolicyAction atomic — a default-action
// flip landing between applyPolicyDecision and the adapter callback mislabeled
// the observation against the decision that actually ran. Simulated here by
// pointing the atomic at "deny" while the recorded status says the request was
// allowed under default-allow: the observation must say default:allow.
func TestObservation_ActionDerivedFromEnforcementStatus(t *testing.T) {
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)
	prevAllow := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prevAllow) })

	// The enforcement decision ran under default-allow (status OK, no match);
	// the atomic has since flipped to deny before the adapter observed it.
	setDefaultPolicyAction("deny")
	learnObserveDecision(authOutcome{identity: "alice", source: "local"}, "flip-action.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	// And the mirror case: enforcement default-denied; atomic now says allow.
	setDefaultPolicyAction("allow")
	learnObserveDecision(authOutcome{identity: "alice", source: "local"}, "flip-deny.example", "GET", nil, "POLICY_DEFAULT_DENY", "", learnDecisionKey{}, false)
	_ = eng.Close()

	if o, ok := obsForHost(t, col, "flip-action.example"); !ok {
		t.Fatalf("no observation for the allowed request (got %v)", col.all())
	} else if o.Action != "default:allow" {
		t.Errorf("allowed-branch Action = %q, want default:allow (current atomic value must not leak in)", o.Action)
	}
	if o, ok := obsForHost(t, col, "flip-deny.example"); !ok {
		t.Fatalf("no observation for the denied request (got %v)", col.all())
	} else if o.Action != "default:deny" {
		t.Errorf("denied-branch Action = %q, want default:deny", o.Action)
	}
}

// TestObservation_DefaultDecisionCarriesDecisionTimeIdentity (Codex rounds
// 20/21): the observation's policy identity must be fenced against the FULL
// identity key captured before evaluation — a post-decision seam read let a
// change-and-restore inside the evaluation→stamp window pair transient
// evidence with the restored baseline identity, and the decision depends on
// the whole config (rulebase, groups, default action), not just the default-
// action word. Key unchanged ⇒ the memoized identity is the decision
// identity; ANY component moved ⇒ the stamp is a unique flip witness the
// churn latch cannot mistake for the baseline.
func TestObservation_DefaultDecisionCarriesDecisionTimeIdentity(t *testing.T) {
	plDurableDraftHarness(t)
	col := &obsCollector{}
	eng := swapPolicyLearnSink(t, col.sink)
	auth := authOutcome{identity: "alice", source: "local"}

	// Consistent case: the key at capture is still current — the stamp must
	// be the real (memoized) content identity.
	pk, ok := learnDecisionKeySnapshot()
	if !ok {
		t.Fatal("learnDecisionKeySnapshot refused with an active session")
	}
	steadyWant := policyContentIdentityCached() // identity at the steady call, before the later mutations
	learnObserveDecision(auth, "steady.example", "GET", nil, "OK", "Bypass", pk, true)

	// Default-action flip case: a set lands inside the bracket (round 20).
	prev := defaultPolicyAction()
	stale, _ := learnDecisionKeySnapshot()
	setDefaultPolicyAction(prev) // same value, new word: a completed round trip
	learnObserveDecision(auth, "flipped.example", "GET", nil, "OK", "Bypass", stale, true)

	// Rulebase round-trip case (round 21): a rule is removed and restored
	// inside the bracket — the default-action word never moves, but the
	// generation does, so the stamp must still be the witness, never the
	// restored baseline identity.
	enabled := true
	blocker := PolicyRule{ID: newRuleID(), Name: "transient-blocker", SourceGroup: "g",
		DestFQDN: "blocked.example", Action: ActionBlockPage, Enabled: &enabled}
	policyStore.ReplaceAll([]PolicyRule{blocker})
	stale2, _ := learnDecisionKeySnapshot() // captured while the blocker is REMOVED...
	policyStore.ReplaceAll([]PolicyRule{blocker, {ID: newRuleID(), Name: "extra",
		SourceGroup: "g", DestFQDN: "x.example", Action: ActionAllow, Enabled: &enabled}})
	policyStore.ReplaceAll([]PolicyRule{blocker}) // ...and the original policy restored
	learnObserveDecision(auth, "rulebase-flip.example", "GET", nil, "OK", "Bypass", stale2, true)

	// Taxonomy round-trip case (round 22): the admin category store is edited
	// and restored inside the bracket — the content fingerprint returns to
	// its baseline (ABA-blind), but the mutation counter moved, so the
	// CATEGORY stamp must be the witness, never the restored epoch.
	stale3, _ := learnDecisionKeySnapshot()
	if err := catStore.Set("transient-cat", []string{"transient.example"}, false); err != nil {
		t.Fatal(err)
	}
	if err := catStore.Delete("transient-cat"); err != nil {
		t.Fatal(err)
	}
	learnObserveDecision(auth, "taxonomy-flip.example", "GET", nil, "OK", "Bypass", stale3, true)
	_ = eng.Close()

	if o, ok := obsForHost(t, col, "steady.example"); !ok {
		t.Fatalf("no steady observation (got %v)", col.all())
	} else if o.PolicyID != steadyWant {
		t.Errorf("steady-key stamp = %q, want the memoized content identity at the decision", o.PolicyID)
	}
	if o, ok := obsForHost(t, col, "flipped.example"); !ok {
		t.Fatalf("no flipped observation (got %v)", col.all())
	} else if !strings.HasPrefix(o.PolicyID, "policy-flip@") {
		t.Errorf("stale-word stamp = %q, want a policy-flip witness — the restored identity would latch no churn", o.PolicyID)
	}
	if o, ok := obsForHost(t, col, "rulebase-flip.example"); !ok {
		t.Fatalf("no rulebase-flip observation (got %v)", col.all())
	} else if !strings.HasPrefix(o.PolicyID, "policy-flip@") {
		t.Errorf("rulebase round-trip stamp = %q, want a policy-flip witness — only the default-action word was fenced", o.PolicyID)
	}
	if o, ok := obsForHost(t, col, "taxonomy-flip.example"); !ok {
		t.Fatalf("no taxonomy-flip observation (got %v)", col.all())
	} else if !strings.HasPrefix(o.CatEpoch, "category-flip@") {
		t.Errorf("taxonomy round-trip stamp = %q, want a category-flip witness — the ABA-blind fingerprint restored to baseline", o.CatEpoch)
	} else if strings.HasPrefix(o.PolicyID, "policy-flip@") {
		t.Errorf("taxonomy-only mutation fabricated a POLICY witness (%q) — the fence halves must be independent", o.PolicyID)
	}
}

// TestObservationE2E_DisabledNilEngine: with the singleton nil the adapter is
// a no-op — the request flows and nothing panics.
func TestObservationE2E_DisabledNilEngine(t *testing.T) {
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(nil)
	t.Cleanup(func() { policyLearnEngine.Store(prev) })
	learnObserveDecision(authOutcome{identity: "x", source: "local"}, "h.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
}
