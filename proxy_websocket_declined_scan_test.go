package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// A plain-HTTP download is file-blocked by URL extension, by response
// Content-Type and by response Content-Disposition. Adding
// "Upgrade: websocket" + "Connection: Upgrade" to the SAME request must not
// change that: an origin that ignores the upgrade answers 200 with the file,
// and that answer is an ordinary HTTP response, not a WebSocket.
//
// Pre-fix, isWebSocketUpgrade(r) exempted the request from the URL checks in
// preDispatchBlocked/applyPolicyDecision, and handleWebSocket's non-101 branch
// copied the origin's body to the client with none of handleHTTP's response
// checks — so the two headers alone delivered the blocked file.
//
// Each case runs the undressed request first as a control: if the plain path
// does not block, the case proves nothing about the dressed one.
func TestWebSocketUpgradeHeaders_DoNotBypassPlainHTTPFileBlock(t *testing.T) {
	const payload = "MZ-this-is-the-blocked-download"

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/by-content-type":
			w.Header().Set("Content-Type", "application/x-msdownload")
		case "/by-content-disposition":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="setup.exe"`)
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		// Deliberately ignores Upgrade, as a static file server does.
		_, _ = io.WriteString(w, payload)
	}))
	defer origin.Close()

	allowLoopbackTunnel(t)
	proxyURL := startTestProxy(t) // default-allow, real listener

	orig := fileBlocker
	fb := fileblock.NewBlocker()
	for _, ext := range fileblock.DefaultBlockedExts {
		fb.Add(ext)
	}
	fileBlocker = fb
	t.Cleanup(func() { fileBlocker = orig })

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
	}
	fetch := func(t *testing.T, path string, dressed bool) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if dressed {
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s (dressed=%v): %v", path, dressed, err)
		}
		defer resp.Body.Close() //nolint:errcheck // test cleanup
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	for _, path := range []string{"/setup.exe", "/by-content-type", "/by-content-disposition"} {
		t.Run(path, func(t *testing.T) {
			if code, body := fetch(t, path, false); strings.Contains(body, payload) {
				t.Fatalf("control: plain GET delivered the payload (status %d) — the case does not exercise a block", code)
			}
			code, body := fetch(t, path, true)
			if strings.Contains(body, payload) {
				t.Fatalf("Upgrade-dressed GET delivered the blocked payload (status %d): the two headers bypass file blocking", code)
			}
			if code != http.StatusForbidden {
				t.Fatalf("Upgrade-dressed GET status = %d, want 403 block page", code)
			}
		})
	}
}
