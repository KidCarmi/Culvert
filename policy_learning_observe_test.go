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

// TestObservationE2E_DisabledNilEngine: with the singleton nil the adapter is
// a no-op — the request flows and nothing panics.
func TestObservationE2E_DisabledNilEngine(t *testing.T) {
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(nil)
	t.Cleanup(func() { policyLearnEngine.Store(prev) })
	learnObserveDecision(authOutcome{identity: "x", source: "local"}, "h.example", "GET", nil, "OK", "Bypass")
}
