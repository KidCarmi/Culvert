package main

// F6 — typed identity plumbing (removal of the internal X-User-Identity
// transport). Invariant: identity and auth provenance used by policy, logging,
// inspection, and file/scanner attribution travel through typed server-side
// values (authOutcome / ProxyIdentity), never through an HTTP header.
//
// Before F6, handleHTTP's scanner/file-block rows read X-User-Identity AFTER
// scrubForwardedHeaders had already deleted it — those rows were permanently
// identity-empty (dead channel). F6 removes the channel and threads
// ProxyIdentity instead, so the rows now carry BOTH the authenticated identity
// and the server-derived AuthSource.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// newHeaderServingBackend serves 200 with the given Content-Disposition.
func newHeaderServingBackend(t *testing.T, contentDisposition string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", contentDisposition)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func containsSrc(src, pat string) bool { return strings.Contains(src, pat) }

// blockExeResponses swaps in a fileBlocker that blocks .exe (by response
// Content-Disposition / path), restoring the original on cleanup.
func blockExeResponses(t *testing.T) {
	t.Helper()
	orig := fileBlocker
	fb := fileblock.NewBlocker()
	fb.Add("exe")
	fileBlocker = fb
	t.Cleanup(func() { fileBlocker = orig })
}

// entryFor returns the newest log entry for host with the given status.
func entryFor(t *testing.T, destHost, status string) (LogEntry, bool) {
	t.Helper()
	entries := logGet()
	for i := range entries { // index-based: LogEntry is a large struct (rangeValCopy)
		if entries[i].Host == destHost && entries[i].Status == status {
			return entries[i], true
		}
	}
	return LogEntry{}, false
}

// TestTypedIdentity_HTTPFileBlockAttributed: an authenticated plain-HTTP
// download blocked by the response Content-Disposition carries the REAL
// identity and auth source — attribution the header channel could never
// deliver (it was scrubbed before those reads).
func TestTypedIdentity_HTTPFileBlockAttributed(t *testing.T) {
	blockExeResponses(t)
	backendSrv := newHeaderServingBackend(t, "attachment; filename=payload.exe")
	proxyURL := startAuthProxy(t, testProvider(), engRule())

	if got := proxiedGet(t, proxyURL, backendSrv.URL+"/", "alice", "eng-token", nil); got != http.StatusForbidden {
		t.Fatalf("blocked download: status %d, want 403", got)
	}
	u, _ := url.Parse(backendSrv.URL)
	e, ok := entryFor(t, u.Host, "FILE_BLOCKED")
	if !ok {
		t.Fatal("no FILE_BLOCKED entry")
	}
	if e.Identity != "alice" {
		t.Errorf("FILE_BLOCKED identity = %q, want alice (typed plumbing)", e.Identity)
	}
	if e.AuthSource != "test-idp" {
		t.Errorf("FILE_BLOCKED auth_source = %q, want test-idp", e.AuthSource)
	}
}

// TestTypedIdentity_HTTPFileBlockSpoofCannotInject: the same block under the
// Exempt posture with a spoofed X-User-Identity header — attribution must be
// empty identity + "unauth" provenance; the spoofed value must appear nowhere.
func TestTypedIdentity_HTTPFileBlockSpoofCannotInject(t *testing.T) {
	blockExeResponses(t)
	backendSrv := newHeaderServingBackend(t, "attachment; filename=payload.exe")
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "any-allow", DestFQDN: "*", Action: ActionAllow}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	if got := spoofedGet(t, proxyURL, backendSrv.URL+"/", "mallory"); got != http.StatusForbidden {
		t.Fatalf("blocked download: status %d, want 403", got)
	}
	u, _ := url.Parse(backendSrv.URL)
	e, ok := entryFor(t, u.Host, "FILE_BLOCKED")
	if !ok {
		t.Fatal("no FILE_BLOCKED entry")
	}
	if e.Identity != "" {
		t.Errorf("spoofed FILE_BLOCKED identity = %q, want empty", e.Identity)
	}
	if e.AuthSource != "unauth" {
		t.Errorf("spoofed FILE_BLOCKED auth_source = %q, want unauth", e.AuthSource)
	}
}

// TestTypedIdentity_InspectBlockRowAttributed: the SSL-inspect block-row
// recorder carries identity + provenance from the typed ProxyIdentity.
func TestTypedIdentity_InspectBlockRowAttributed(t *testing.T) {
	id := ProxyIdentity{ClientIP: "198.51.100.9", Identity: "carol", AuthSource: "oidc:okta"}
	recordInspectBlock(id, "SCAN_BLOCKED", "clam", "eicar", "typed-inspect.example", "/x", nil, nil)
	e, ok := entryFor(t, "typed-inspect.example", "SCAN_BLOCKED")
	if !ok {
		t.Fatal("no SCAN_BLOCKED entry")
	}
	if e.Identity != "carol" || e.AuthSource != "oidc:okta" || e.IP != "198.51.100.9" {
		t.Errorf("inspect row attribution = identity %q source %q ip %q", e.Identity, e.AuthSource, e.IP)
	}
}

// TestTypedIdentity_NoInternalHeaderTransport: nothing in the runtime request
// path stamps or reads X-User-Identity — the channel is gone, not merely
// unused. (The scrubs keep DELETING it as defense-in-depth; Del calls are
// allowed, Set/Get are not.)
func TestTypedIdentity_NoInternalHeaderTransport(t *testing.T) {
	forbidden := []string{
		`Header.Set("X-User-Identity"`,
		`Header.Get("X-User-Identity"`,
	}
	for _, file := range []string{"proxy.go", "proxy_http.go", "proxy_tunnel.go", "proxy_tunnel_h2.go", "proxy_portal.go", "socks5.go", "store.go", "cdr_proxy.go"} {
		raw := mustReadFile(t, file)
		for _, pat := range forbidden {
			if containsSrc(raw, pat) {
				t.Errorf("%s still uses the X-User-Identity header transport (%s) — identity must travel as typed values (F6)", file, pat)
			}
		}
	}
}
