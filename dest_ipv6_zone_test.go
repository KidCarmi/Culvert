package main

// Zoned IPv6 destinations are refused (see destIPv6Zoned).
//
// The defect: "[::1%25lo]" reached the handler as "[::1%lo]", no literal
// matcher canonicalized it, so a Block rule for "::1" did not match — and the
// dialer honoured the zone and connected to ::1 anyway. Measured on an
// IPv6-capable CI runner before this fix (PR #2049, shadow job on e1a3710):
//
//	"[::1]"       block-rule status=403 backend=not-reached
//	"[::1%25lo]"  no-rule    status=200 backend=REACHED
//
// The refusal tests below run on any host, because the refusal happens before
// any dial. The reachability test needs an IPv6 loopback, and on GitHub Actions
// its absence is a FAILURE, not a skip: a host without IPv6 cannot show that the
// backend stays unreached, and must not be counted as having shown it.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDestIPv6Zoned(t *testing.T) {
	zoned := []string{
		"[::1%lo]", "[::1%lo]:8080", "[fe80::1%eth0]:443", "[2001:db8::7%eth0]", "[::1%25lo]", // "25lo" is a zone too
		"[::1%]", "[::1%]:80", "[::1%a%b]:80", "[::ffff:192.0.2.7%lo]:80",
		"::1%lo", "fe80::1%eth0", // SOCKS5 DOMAIN form: no brackets
	}
	for _, a := range zoned {
		if !destIPv6Zoned(a) {
			t.Errorf("destIPv6Zoned(%q) = false, want true", a)
		}
	}
	clean := []string{
		"[::1]", "[::1]:8080", "[2001:db8::7]:443", "[::ffff:192.0.2.7]:80", "::1", "192.0.2.7:80", "example.com", "example.com:443",
		"bücher.de", "b%C3%BCcher.de", "xn--bcher-kva.de:443", // an encoded or decoded IDN is not an address
		"100%.example.com", "a%lo", "192.0.2.7%lo:80", // a "%" after something that is not an IPv6 address
		"", ":443", "[", "[]", "[%lo]",
	}
	for _, a := range clean {
		if destIPv6Zoned(a) {
			t.Errorf("destIPv6Zoned(%q) = true, want false", a)
		}
	}
}

// zoneWire sends one request line through a real socket and returns the status.
func zoneWire(t *testing.T, proxyAddr, method, authority string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if method == http.MethodConnect {
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	} else {
		fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority, authority)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	code := 0
	fmt.Sscanf(line, "HTTP/1.1 %d", &code)
	return code
}

// TestZonedIPv6Dest_RefusedBeforePolicyOnHTTPAndCONNECT needs no IPv6: the
// refusal precedes every matcher and every dial.
func TestZonedIPv6Dest_RefusedBeforePolicyOnHTTPAndCONNECT(t *testing.T) {
	proxyURL := startTestProxy(t) // restores rules and the default action on cleanup
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "v6", DestFQDN: "::1", Action: ActionBlockPage},
		{Priority: 2, Name: "idn", DestFQDN: "xn--bcher-kva.de", Action: ActionBlockPage},
	})
	hits := ruleHitCount

	for _, authority := range []string{
		"[::1%25lo]", "[::1%25lo]:8080", "[fe80::1%25eth0]:443", "[2001:db8::7%25eth0]:443",
		"[::1%2525lo]:80", // decoded once by the parser to the zone "25lo": still a zone, never decoded twice
	} {
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			rl = newRateLimiter()
			before := hits("v6")
			if code := zoneWire(t, proxyURL.Host, method, authority); code != http.StatusBadRequest {
				t.Errorf("%s %q: status %d, want 400", method, authority, code)
			}
			// The status is what separates fixed from unfixed here: before the fix
			// these were 403 from the default deny. The counter staying still only
			// shows the refusal did not come from the rule.
			if hits("v6") != before {
				t.Errorf("%s %q: rule v6 recorded a hit for a refused destination", method, authority)
			}
		}
	}

	// Not-vacuous controls. A gate that refused every bracket, every "%" or every
	// IPv6 literal would pass everything above.
	controls := []struct {
		authority, rule string
	}{
		{"[::1]:8080", "v6"},             // zone-free IPv6 still reaches policy and its rule
		{"[0:0:0:0:0:0:0:1]", "v6"},      // and still by address, not spelling
		{"b%C3%BCcher.de:443", "idn"},    // an encoded IDN is not a zone
		{"xn--bcher-kva.de:8443", "idn"}, //
	}
	for _, c := range controls {
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			rl = newRateLimiter()
			before := hits(c.rule)
			if code := zoneWire(t, proxyURL.Host, method, c.authority); code != http.StatusForbidden {
				t.Errorf("control %s %q: status %d, want 403 from rule %q", method, c.authority, code, c.rule)
			}
			if hits(c.rule) != before+1 {
				t.Errorf("control %s %q: rule %q did not decide", method, c.authority, c.rule)
			}
		}
	}
}

// TestZonedIPv6Dest_BackendIsNeverReached is the acceptance test for the
// defect: with a Block rule for ::1 and default ALLOW, a zoned spelling must be
// refused and the backend must see nothing, on plain HTTP and on CONNECT.
func TestZonedIPv6Dest_BackendIsNeverReached(t *testing.T) {
	ln, err := ctxListen("[::1]:0")
	if err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no IPv6 loopback on a CI runner (%v): this test is the qualification for the zoned-IPv6 fix and must run", err)
		}
		t.Skipf("no IPv6 loopback on this host (%v): the backend-unreached qualification did not run here", err)
	}
	var backendHits int64
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&backendHits, 1)
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	proxyURL := startTestProxy(t)
	setDefaultPolicyAction("allow")
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "block-v6-loopback", DestFQDN: "::1", Action: ActionBlockPage}})

	// The empty zone is refused by net/http itself before the handler; it is here
	// to show the backend stays unreached for it too, not as evidence of the fix.
	for _, zone := range []string{"lo", "lo0", "1", ""} {
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			rl = newRateLimiter()
			authority := "[::1%25" + zone + "]:" + port
			if code := zoneWire(t, proxyURL.Host, method, authority); code != http.StatusBadRequest {
				t.Errorf("%s %q: status %d, want 400", method, authority, code)
			}
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt64(&backendHits); n != 0 {
		t.Fatalf("backend was reached %d time(s) through a zoned spelling of a blocked address", n)
	}

	// The rule itself still works for the zone-free spelling...
	rl = newRateLimiter()
	if code := zoneWire(t, proxyURL.Host, http.MethodGet, "[::1]:"+port); code != http.StatusForbidden {
		t.Errorf("zone-free blocked address: status %d, want 403", code)
	}
	// ...and with the rule gone, a zone-free IPv6 destination is still served:
	// the fix refuses zones, not IPv6.
	policyStore.ReplaceAll(nil)
	rl = newRateLimiter()
	if code := zoneWire(t, proxyURL.Host, http.MethodGet, "[::1]:"+port); code != http.StatusOK {
		t.Errorf("zone-free IPv6 destination under default allow: status %d, want 200", code)
	}
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt64(&backendHits); n != 1 {
		t.Errorf("backend hits = %d, want exactly 1 (the zone-free positive control)", n)
	}
}

// TestZonedIPv6Dest_SOCKS5DomainFormRefused: ATYP 0x04 cannot carry a zone, but
// the DOMAIN form is free text and becomes a dial target through JoinHostPort.
func TestZonedIPv6Dest_SOCKS5DomainFormRefused(t *testing.T) {
	setupProxyTest(t)
	sink := captureLoggerForTest(t) // before the listener: see captureLoggerForTest
	ln := startSOCKS5Listener(t)

	socks5ConnectRaw(t, ln.Addr().String(), "::1%lo", 9)
	socks5ConnectRaw(t, ln.Addr().String(), "fe80::1%eth0", 443)
	// The handler replies to the client BEFORE it writes its log line, so the
	// client returning does not mean the line exists yet. Wait for it, bounded.
	deadline := time.Now().Add(3 * time.Second)
	for strings.Count(sink.String(), "source=ipv6-zone") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	out := sink.String()
	if n := strings.Count(out, "source=ipv6-zone"); n != 2 {
		t.Errorf("zoned SOCKS5 DOMAIN destinations refused with source=ipv6-zone %d time(s), want 2; log:\n%s", n, out)
	}
	if strings.Contains(out, "SOCKS5 OK") || strings.Contains(out, "SOCKS5 SSRF block") || strings.Contains(out, "SOCKS5 dial error") {
		t.Errorf("a zoned SOCKS5 destination got past the gate to the dial; log:\n%s", out)
	}
}

// TestZonedIPv6Dest_PolicyTesterRefuses keeps the simulator aligned: it must
// not report a policy answer for a destination the data path refuses.
func TestZonedIPv6Dest_PolicyTesterRefuses(t *testing.T) {
	startTestProxy(t)
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "v6", DestFQDN: "::1", Action: ActionBlockPage}})
	for _, host := range []string{"[::1%lo]", "[::1%25lo]:443", "[fe80::1%eth0]:80"} {
		w := httptest.NewRecorder()
		apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": host}))
		if w.Code != http.StatusBadRequest {
			t.Errorf("tester on %q: status %d, want 400: %s", host, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": "[::1]:443"}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"matched":true`) {
		t.Errorf("tester on zone-free [::1]: status %d body %s, want a match on rule v6", w.Code, w.Body.String())
	}
}

// TestZonedIPv6Dest_SourceGatesAnswerFirst pins the position of the refusal: a
// source the IP filter denies gets the IP filter's answer, not INVALID_HOST, so
// a blocked source is attributed correctly and cannot probe zoned spellings
// without passing the gates every other request passes.
func TestZonedIPv6Dest_SourceGatesAnswerFirst(t *testing.T) {
	proxyURL := startTestProxy(t) // setupProxyTest inside installs a fresh ipf for this test
	ipf.SetMode("block")
	if err := ipf.Add("127.0.0.1"); err != nil {
		t.Fatalf("ipf.Add: %v", err)
	}
	t.Cleanup(func() { ipf = newIPFilter() })
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		if code := zoneWire(t, proxyURL.Host, method, "[::1%25lo]:8080"); code != http.StatusForbidden {
			t.Errorf("%s from an IP-filter-blocked source to a zoned destination: status %d, want 403 (IP_BLOCKED)", method, code)
		}
	}
}
