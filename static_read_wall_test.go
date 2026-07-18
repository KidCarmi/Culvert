package main

import (
	"os"
	"strings"
	"testing"
)

// TestStaticIndexReadsAreCWDIndependent is an ANTI-REGRESSION WALL. Tests must read
// the SPA via staticIndexHTMLPath() (an absolute path anchored to the package source
// dir), NEVER via a CWD-relative os.ReadFile("static/index.html"). A relative read
// intermittently picks up the wrong file when a concurrent test changes the working
// directory (os.Chdir), which the determinism and -race gates catch as a flaky
// "static/index.html missing …" failure. That class cost real debugging time to
// track down; this wall keeps it from creeping back.
//
// The check scans every *_test.go file, ignoring comment lines so the helper's own
// doc comment does not trip it.
func TestStaticIndexReadsAreCWDIndependent(t *testing.T) {
	const forbidden = `ReadFile("static/index.html")`
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		// This wall file names the forbidden pattern in its own const/doc; skip it.
		if name == "static_read_wall_test.go" {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx] // drop the trailing comment
			}
			if strings.Contains(code, forbidden) {
				t.Errorf("%s:%d reads static/index.html via a CWD-relative path — use staticIndexHTMLPath() so a concurrent os.Chdir cannot flake the read", name, i+1)
			}
		}
	}
}
