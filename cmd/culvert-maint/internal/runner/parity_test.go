package runner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParity_TemplatesMatchSudoersAllowlist enforces the four-step
// contract from D1.6 plan § 4.6: every runner template MUST have a
// matching sudoers entry, and every sudoers entry MUST map to a known
// runner template. This catches drift in either direction:
//
//   - a template added in code without the sudoers line: production
//     would fail at exec time when the agent calls `sudo -n docker …`
//     and sudo refuses.
//   - a sudoers line added without the template: dead allowlist surface
//     that broadens privilege without any code path using it.
//
// The test reads packaging/sudoers/culvert-maint relative to the repo
// root.
func TestParity_TemplatesMatchSudoersAllowlist(t *testing.T) {
	sudoersPath := findSudoersFile(t)
	allowed := parseSudoersTemplates(t, sudoersPath)

	registered := make(map[string]struct{})
	for _, tmpl := range Registry() {
		registered[normalize(tmpl.Sudoers)] = struct{}{}
	}

	for k := range registered {
		if _, ok := allowed[k]; !ok {
			t.Errorf("runner template missing from %s:\n    template: %q\nadd a matching sudoers line per § 4.6 contract", sudoersPath, k)
		}
	}
	for k := range allowed {
		if _, ok := registered[k]; !ok {
			t.Errorf("sudoers entry has no matching runner template:\n    sudoers: %q\nremove the entry or add a Template that uses it", k)
		}
	}
}

// findSudoersFile walks up from this file's directory looking for
// packaging/sudoers/culvert-maint. The repo root is wherever that path
// first resolves.
func findSudoersFile(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 12; i++ { // bounded
		candidate := filepath.Join(dir, "packaging", "sudoers", "culvert-maint")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate packaging/sudoers/culvert-maint from %s", wd)
	return ""
}

// parseSudoersTemplates reads a sudoers file and returns the set of
// allowed command lines, normalised to match the form used by Template.Sudoers.
//
// Recognised line shape:
//
//	<user> ALL=(root) NOPASSWD: <command line>
//
// Comment and blank lines are ignored. Other shapes are flagged via
// t.Fatalf so unexpected directives are surfaced.
func parseSudoersTemplates(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	f, err := os.Open(path) //nolint:gosec // test reads packaging file by computed path
	if err != nil {
		t.Fatalf("open sudoers: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Expect:  <user> ALL=(root) NOPASSWD: <command line>
		idx := strings.Index(line, "NOPASSWD:")
		if idx == -1 {
			t.Fatalf("unexpected sudoers line shape: %q", line)
		}
		cmd := strings.TrimSpace(line[idx+len("NOPASSWD:"):])
		if cmd == "" {
			t.Fatalf("empty command in sudoers line: %q", line)
		}
		out[normalize(cmd)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan sudoers: %v", err)
	}
	return out
}

// normalize collapses whitespace so the parity check tolerates tab vs.
// single-space differences between the runner's Sudoers string and the
// on-disk file.
func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
