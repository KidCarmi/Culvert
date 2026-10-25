//go:build linux

package applianceconsole

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the production probe argv with a real curl and a hostile local
// configuration. Only the destination changes to an isolated loopback server.
func TestHTTPProbesIgnoreLocalCurlConfiguration(t *testing.T) {
	home := t.TempDir()
	config := "request = DELETE\nheader = \"X-Console-Config: unexpected\"\n"
	if err := os.WriteFile(filepath.Join(home, ".curlrc"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + ":" + r.Header.Get("X-Console-Config")
		_, _ = w.Write([]byte(`{"needsSetup":false}`))
	}))
	defer server.Close()
	run := func(ctx context.Context, args []string) string {
		args = append([]string(nil), args...)
		args[len(args)-1] = server.URL
		// #nosec G204 -- fixed collector argv; test replaces only the loopback URL.
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=" + home, "CURL_HOME=" + home}
		data, err := cmd.Output()
		if err != nil {
			t.Errorf("curl fixture: %v", err)
		}
		return string(data)
	}
	// Prove the fixture changes curl behavior without the production guard.
	run(t.Context(), []string{"/usr/bin/curl", "--noproxy", "*", "--silent", "--max-time", "2", server.URL})
	if len(requests) != 1 {
		t.Fatal("configuration fixture did not make exactly one request")
	}
	if got := <-requests; got != "DELETE:unexpected" {
		t.Fatalf("configuration fixture was not effective: %q", got)
	}
	c, _ := fixture(t)
	c.sources.Probe = func(ctx context.Context, args []string) string {
		if args[0] == "/usr/bin/curl" {
			return run(ctx, args)
		}
		return ""
	}
	raw := c.observations(t.Context())
	if raw["health"] != "200" || !strings.HasSuffix(raw["setup"], "\n200") || !strings.HasSuffix(raw["ready"], "\n200") {
		t.Fatalf("HTTP probes did not complete: %v", raw)
	}
	if len(requests) != 3 {
		t.Fatalf("expected three HTTP probes, got %d", len(requests))
	}
	for range 3 {
		if got := <-requests; got != "GET:" {
			t.Errorf("local curl configuration changed a production probe: %q", got)
		}
	}
}
