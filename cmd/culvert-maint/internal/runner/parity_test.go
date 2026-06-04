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
		for _, line := range tmpl.SudoersLines {
			registered[normalize(line)] = struct{}{}
		}
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

// TestParity_SudoersAreFullyPathBound rejects any registered template
// whose sudoers lines are NOT bound to the full compose path. This is
// the foot-gun the original review caught: a template with
// `-f {compose_file}` would let sudo accept the bare filename from
// any cwd the agent process could be coerced into.
func TestParity_SudoersAreFullyPathBound(t *testing.T) {
	for _, tmpl := range Registry() {
		for _, line := range tmpl.SudoersLines {
			// Templates that touch the compose project must reference
			// the full {compose_path} placeholder, never bare {compose_file}.
			if strings.Contains(line, "{compose_file}") &&
				!strings.Contains(line, "{compose_path}") {
				t.Errorf("template %q sudoers line uses bare {compose_file} — must use {compose_path} so the allowlist is path-bound: %q",
					tmpl.ID, line)
			}
			// Sudoers must never reference a relative path token.
			if strings.HasPrefix(line, "./") || strings.HasPrefix(line, "../") {
				t.Errorf("template %q sudoers line begins with a relative path: %q", tmpl.ID, line)
			}
		}
	}
}

// TestParity_D16bRegistryShape asserts the D1.6b registry contains
// exactly the templates the slice was scoped to add, and that each
// template carries SudoersLines (no template skips its allowlist
// contract).
func TestParity_D16bRegistryShape(t *testing.T) {
	wantIDs := map[TemplateID]struct{}{
		TemplateComposeStatus:               {},
		TemplateComposeCLIBackupEncrypted:   {},
		TemplateComposeCLIBackupUnencrypted: {},
		TemplateComposeCLIBackupList:        {},
		TemplateComposeCLIRestoreDryRun:     {},
		TemplateComposeCLIRestoreCommit:     {},
		TemplateComposeDown:                 {},
		TemplateComposeUp:                   {},
		TemplateComposeCLICleanupDryRun:     {},
		TemplateComposeCLICleanupCommit:     {},
		TemplateComposeImageInspect:         {},
		TemplateComposeManifestInspect:      {},
		TemplateComposeContainerInspect:     {},
		TemplateComposePull:                 {},
	}
	gotIDs := map[TemplateID]struct{}{}
	for _, tmpl := range Registry() {
		gotIDs[tmpl.ID] = struct{}{}
		if len(tmpl.SudoersLines) == 0 {
			t.Errorf("template %q has no SudoersLines — every template must declare its allowlist", tmpl.ID)
		}
	}
	for id := range wantIDs {
		if _, ok := gotIDs[id]; !ok {
			t.Errorf("registry missing expected template %q", id)
		}
	}
	for id := range gotIDs {
		if _, ok := wantIDs[id]; !ok {
			t.Errorf("registry has unexpected template %q (registry scope is closed)", id)
		}
	}
	// Restore templates MUST have exactly 12 lines each (3 modes ×
	// 4 flag combos). No fewer (would be incomplete coverage), no
	// more (would mean extra wildcard surface leaked through).
	for _, id := range []TemplateID{TemplateComposeCLIRestoreDryRun, TemplateComposeCLIRestoreCommit} {
		tmpl := templateByID(id)
		if tmpl == nil {
			t.Errorf("template %q missing from registry", id)
			continue
		}
		if got := len(tmpl.SudoersLines); got != 12 {
			t.Errorf("template %q must enumerate exactly 12 sudoers lines (3 modes × 4 flag combos); got %d", id, got)
		}
	}
}

// TestSudoers_EnvKeepPreservesOverlayVars asserts the env-preservation
// Defaults block is present. Under privilege_mode=sudoers the agent
// forwards CULVERT_PROXY_IMAGE (upgrade pin) and CULVERT_BACKUP_PASSPHRASE
// (encrypted backup) by overlay; sudo's env_reset would strip both before
// `docker compose` saw them without these env_keep lines.
func TestSudoers_EnvKeepPreservesOverlayVars(t *testing.T) {
	data, err := os.ReadFile(findSudoersFile(t)) //nolint:gosec // test reads packaging file by computed path
	if err != nil {
		t.Fatalf("read sudoers: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		`Defaults:culvert-maint env_keep += "CULVERT_PROXY_IMAGE"`,
		`Defaults:culvert-maint env_keep += "CULVERT_BACKUP_PASSPHRASE"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing env-preservation line:\n  %s", want)
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
		// `Defaults` directives (e.g. env_keep preservation) are policy,
		// not command allowlist entries — they have no NOPASSWD command
		// to match against a template, so skip them here. Their presence
		// is asserted separately (TestSudoers_EnvKeepPreservesOverlayVars).
		if strings.HasPrefix(line, "Defaults") {
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
