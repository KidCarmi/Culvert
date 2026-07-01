package main

// Proxy edge-case / abuse security suite, end-to-end through the real socket.
// These target the classic forward-proxy attack surface: HTTP request
// smuggling, malformed Proxy-Authorization (auth confusion), the Drop action's
// silent-close contract, and open-redirect protection on the Redirect action.
// Every test asserts a customer-visible guarantee (no desync, no spurious auth,
// no unsafe redirect) and that the upstream is reached only when it should be.

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// startRawUpstream is a minimal keep-alive HTTP/1.1 upstream that records the
// RAW header block of every request it receives (so a test can inspect the
// exact framing the proxy emitted). It answers every request with 200 / no body.
func startRawUpstream(t *testing.T) (host string, recorded func() []string) {
	t.Helper()
	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("raw upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var blocks []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRawUpstream(c, &mu, &blocks)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), blocks...)
	}
}

// serveRawUpstream reads keep-alive request header blocks off conn, records each
// verbatim under mu, and answers 200 / no body. Extracted from startRawUpstream
// to keep cognitive complexity within bounds.
func serveRawUpstream(conn net.Conn, mu *sync.Mutex, blocks *[]string) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		block, ok := readHeaderBlock(br)
		if !ok {
			return
		}
		mu.Lock()
		*blocks = append(*blocks, block)
		mu.Unlock()
		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); err != nil {
			return
		}
	}
}

// readHeaderBlock reads lines up to and including the blank line that terminates
// an HTTP header block, returning the raw block and false on read error/EOF.
func readHeaderBlock(br *bufio.Reader) (string, bool) {
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", false
		}
		b.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return b.String(), true
		}
	}
}

// TestEdge_RequestSmugglingNoAmbiguousFramingUpstream proves the anti-smuggling
// invariant: no matter what ambiguous framing a client sends, the proxy never
// FORWARDS a request to the upstream that carries ambiguous framing (both
// Content-Length and Transfer-Encoding, or duplicate Content-Length). The proxy
// must normalize (it re-emits via the Go transport) or reject — so an upstream
// or downstream cache can never desync on message boundaries.
func TestEdge_RequestSmugglingNoAmbiguousFramingUpstream(t *testing.T) {
	host, recorded := startRawUpstream(t)
	proxyURL := startTestProxy(t)

	payloads := []string{
		// Duplicate, conflicting Content-Length.
		"POST http://" + host + "/a HTTP/1.1\r\nHost: " + host +
			"\r\nContent-Length: 0\r\nContent-Length: 44\r\n\r\n" +
			"GET http://" + host + "/smuggled HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		// Content-Length + Transfer-Encoding: chunked (CL.TE).
		"POST http://" + host + "/b HTTP/1.1\r\nHost: " + host +
			"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	}
	for _, p := range payloads {
		conn, err := dialTimeout(proxyURL.Host)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(p)) //nolint:errcheck // test I/O; error not actionable
		buf := make([]byte, 4096)
		conn.Read(buf) //nolint:errcheck // test I/O; error not actionable
		conn.Close()
	}
	time.Sleep(150 * time.Millisecond)

	for _, block := range recorded() {
		lower := strings.ToLower(block)
		hasCL := strings.Contains(lower, "content-length:")
		hasTE := strings.Contains(lower, "transfer-encoding:")
		if hasCL && hasTE {
			t.Errorf("REQUEST SMUGGLING: proxy forwarded a request with BOTH Content-Length and Transfer-Encoding (ambiguous framing):\n%s", block)
		}
		if strings.Count(lower, "content-length:") > 1 {
			t.Errorf("REQUEST SMUGGLING: proxy forwarded a request with DUPLICATE Content-Length:\n%s", block)
		}
	}
}

// TestEdge_MalformedProxyAuthNeverAuthenticates feeds malformed
// Proxy-Authorization headers and asserts none authenticate the client (407
// challenge, upstream never reached) and none crash the proxy.
func TestEdge_MalformedProxyAuthNeverAuthenticates(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule()) // auth enabled, default deny

	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	headers := []string{
		"Basic !!!not-base64!!!",                       // invalid base64
		"Basic " + b64("nocolon"),                      // no colon separator
		"Bearer sometoken",                             // wrong scheme
		"Basic ",                                       // empty credentials
		"basic " + b64("alice:eng-token"),              // lowercase scheme (must not match "Basic ")
		"Basic " + b64(strings.Repeat("a", 5000)+":x"), // oversized username
		"Basic " + b64(":onlypassword"),                // empty username
	}
	for _, h := range headers {
		p := *proxyURL
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&p)}, Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/", http.NoBody)
		req.Header.Set("Proxy-Authorization", h)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("malformed Proxy-Auth %q caused a transport error (proxy should answer cleanly): %v", h, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("AUTH CONFUSION: malformed Proxy-Authorization %q AUTHENTICATED (200)", h)
		}
	}
	if cb.hitCount() != 0 {
		t.Errorf("malformed Proxy-Auth reached upstream %d times, want 0", cb.hitCount())
	}
}

// TestEdge_DropActionSilentClose proves the Drop action drops the connection
// with NO HTTP response (silent RST) and never reaches the upstream — distinct
// from Block_Page which serves a 403.
func TestEdge_DropActionSilentClose(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t)
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "drop-all", DestFQDN: "*", Action: ActionDrop})

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := ctxGet(client, backend.URL+"/")
	if err == nil {
		resp.Body.Close()
		t.Errorf("Drop action returned an HTTP response (%d) — must silently close with no response", resp.StatusCode)
	}
	if cb.hitCount() != 0 {
		t.Errorf("Drop action reached upstream %d times, want 0", cb.hitCount())
	}
}

// TestEdge_RedirectOpenRedirectProtection proves the Redirect action issues a
// 302 to a SAFE absolute public URL but REFUSES unsafe targets (non-http(s)
// schemes and private/internal hosts) — open-redirect / SSRF-via-redirect
// protection.
func TestEdge_RedirectOpenRedirectProtection(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t)
	client := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	setRedirect := func(url string) {
		policyStore.rules = nil
		policyStore.Add(PolicyRule{Priority: 1, Name: "redir", DestFQDN: "*", Action: ActionRedirect, RedirectURL: url})
	}

	// Safe: absolute http(s) to a public host literal → 302 with Location.
	setRedirect("http://8.8.8.8/elsewhere")
	resp, err := ctxGet(client, backend.URL+"/")
	if err != nil {
		t.Fatalf("safe redirect GET: %v", err)
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "http://8.8.8.8/elsewhere" {
		t.Errorf("safe redirect: status %d location %q, want 302 to the URL", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	// Unsafe targets must be refused (not redirected to).
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html,xss",
		"http://10.0.0.1/internal", // private host → SSRF-via-redirect
		"http://127.0.0.1/loopback",
		"//evil.example/protorel", // scheme-relative (not absolute http(s))
		"ftp://evil.example/x",
	} {
		setRedirect(bad)
		r, err := ctxGet(client, backend.URL+"/")
		if err != nil {
			t.Fatalf("unsafe redirect GET (%q): %v", bad, err)
		}
		if r.StatusCode == http.StatusFound {
			t.Errorf("OPEN REDIRECT: unsafe target %q produced a 302 to %q", bad, r.Header.Get("Location"))
		}
		r.Body.Close()
	}
	if cb.hitCount() != 0 {
		t.Errorf("redirect rule reached upstream %d times, want 0 (redirect never forwards)", cb.hitCount())
	}
}

// TestEdge_DuplicateAndMissingHostHandled proves the proxy handles odd Host
// framing without crashing: a request with no resolvable authority fails closed
// rather than panicking or hanging.
func TestEdge_DuplicateAndMissingHostHandled(t *testing.T) {
	proxyURL := startTestProxy(t)
	// Authority-form GET (no scheme/host in the target, empty Host) — the proxy
	// must answer (some 4xx/5xx) and not hang or crash.
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: \r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return // connection closed without a response is acceptable (fail-closed)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("empty-Host request returned 200 — want a 4xx/5xx fail-closed")
	}
}
