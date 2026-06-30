package main

// Policy-flow E2E through the REAL proxy socket. Complements the decision-layer
// security suite (policy_bypass_security_test.go) by proving the full customer
// chain: request → policy decision → upstream reached (or not) → matched-rule
// observability, over a real listener. Hermetic: loopback upstreams only.

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ruleHitCount returns the runtime hit counter for the named rule (matched-rule
// observability), or -1 if absent.
func ruleHitCount(name string) int64 {
	for _, r := range policyStore.List() {
		if r.Name == name {
			return r.HitCount
		}
	}
	return -1
}

// TestPolicyFlow_PriorityFirstMatchWins proves rules evaluate in priority order
// and the FIRST match wins — through the real proxy, asserting both the response
// and whether the upstream was reached, plus which rule recorded the hit.
func TestPolicyFlow_PriorityFirstMatchWins(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}

	// block (priority 1) ahead of allow (priority 2): first match (block) wins.
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "block-first", DestFQDN: "*", Action: ActionBlockPage})
	policyStore.Add(PolicyRule{Priority: 2, Name: "allow-second", DestFQDN: "*", Action: ActionAllow})

	resp, err := client.Get(backend.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("block-first: status %d, want 403", resp.StatusCode)
	}
	if cb.hitCount() != 0 {
		t.Errorf("block-first: upstream reached, want not reached")
	}
	if h := ruleHitCount("block-first"); h < 1 {
		t.Errorf("matched-rule observability: block-first HitCount=%d, want ≥1", h)
	}

	// Reverse priority: allow (priority 1) now wins.
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "allow-first", DestFQDN: "*", Action: ActionAllow})
	policyStore.Add(PolicyRule{Priority: 2, Name: "block-second", DestFQDN: "*", Action: ActionBlockPage})

	before := cb.hitCount()
	resp2, err := client.Get(backend.URL + "/")
	if err != nil {
		t.Fatalf("GET2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("allow-first: status %d, want 200", resp2.StatusCode)
	}
	if cb.hitCount() <= before {
		t.Errorf("allow-first: upstream not reached, want reached")
	}
	if h := ruleHitCount("allow-first"); h < 1 {
		t.Errorf("matched-rule observability: allow-first HitCount=%d, want ≥1", h)
	}
}

// TestPolicyFlow_RuleUpdateWhileTrafficFlows proves a live policy change takes
// effect on the very next request (hot reload) AND that flipping the rule while
// concurrent traffic flows never yields an inconsistent response (only 200/403,
// never a 5xx or a crash).
func TestPolicyFlow_RuleUpdateWhileTrafficFlows(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startTestProxy(t)
	allow := func() {
		policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "allow", DestFQDN: "*", Action: ActionAllow}})
	}
	block := func() {
		policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "block", DestFQDN: "*", Action: ActionBlockPage}})
	}

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	get := func() int {
		resp, err := client.Get(backend.URL + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Hot-reload: the decision changes immediately on the next request.
	allow()
	if s := get(); s != http.StatusOK {
		t.Errorf("after allow: %d, want 200", s)
	}
	block()
	if s := get(); s != http.StatusForbidden {
		t.Errorf("after live flip to block: %d, want 403 (hot reload)", s)
	}
	allow()
	if s := get(); s != http.StatusOK {
		t.Errorf("after live flip back to allow: %d, want 200", s)
	}

	// Churn under concurrent traffic: every response must be a clean 200 or 403.
	var unexpected int64
	stop := make(chan struct{})
	var churn sync.WaitGroup
	churn.Add(1)
	go func() {
		defer churn.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				allow()
			} else {
				block()
			}
			time.Sleep(time.Millisecond)
		}
	}()
	var wg sync.WaitGroup
	for c := 0; c < 12; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
			for r := 0; r < 25; r++ {
				resp, err := cl.Get(backend.URL + "/")
				if err != nil {
					atomic.AddInt64(&unexpected, 1)
					continue
				}
				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
					atomic.AddInt64(&unexpected, 1)
				}
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	close(stop)
	churn.Wait()
	if unexpected != 0 {
		t.Errorf("policy update under traffic produced %d inconsistent responses (want only 200/403)", unexpected)
	}
}

// TestPolicyFlow_IPLiterals proves policy matches IPv4 and IPv6 literal hosts
// through the real proxy (allow reaches, block does not).
func TestPolicyFlow_IPLiterals(t *testing.T) {
	t.Run("ipv4_literal", func(t *testing.T) {
		backend, cb := startCountingBackend(t) // 127.0.0.1
		proxyURL := startTestProxy(t)
		policyStore.rules = nil
		policyStore.Add(PolicyRule{Priority: 1, Name: "allow-v4", DestFQDN: "127.0.0.1", Action: ActionAllow})
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
		resp, err := client.Get(backend.URL + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || cb.hitCount() == 0 {
			t.Errorf("IPv4 literal allow: status %d reached=%v, want 200 reached", resp.StatusCode, cb.hitCount() > 0)
		}
	})

	t.Run("ipv6_literal", func(t *testing.T) {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		var hits int64
		srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&hits, 1)
			w.WriteHeader(http.StatusOK)
		})}}
		srv.Start()
		defer srv.Close()

		proxyURL := startTestProxy(t)
		policyStore.rules = nil
		policyStore.Add(PolicyRule{Priority: 1, Name: "block-v6", DestFQDN: "::1", Action: ActionBlockPage})
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
		resp, err := client.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("IPv6 literal block: status %d, want 403", resp.StatusCode)
		}
		if atomic.LoadInt64(&hits) != 0 {
			t.Errorf("IPv6 literal block: upstream reached, want not reached")
		}
	})
}

// TestPolicyFlow_MalformedConnectRejected proves a CONNECT with a malformed
// authority is cleanly rejected (non-2xx, no hang/crash) rather than tunneled.
func TestPolicyFlow_MalformedConnectRejected(t *testing.T) {
	proxyURL := startTestProxy(t) // default allow — so rejection is structural, not policy
	for _, authority := range []string{
		"not-a-host-without-port",
		"[::1",           // unterminated IPv6 bracket
		"host:99999",     // out-of-range port
		"a b.example:80", // space in host
	} {
		conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			continue // closed/rejected without a response is also acceptable
		}
		if resp.StatusCode == http.StatusOK {
			t.Errorf("malformed CONNECT %q established a tunnel (200) — must be rejected", authority)
		}
		resp.Body.Close()
		conn.Close()
	}
}
