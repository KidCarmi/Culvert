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
		TemplateImagePullDigest:             {},
		TemplateImageTagPinned:              {},
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

// TestSudoers_EnvKeepIsCommandScoped asserts env preservation is
// COMMAND-SCOPED (D1.6c privilege hardening), not a blanket per-user
// default. After P1.4 the ONLY preserved var is CULVERT_BACKUP_PASSPHRASE
// (backup/restore); CULVERT_PROXY_IMAGE and its env_keep are GONE — the
// proxy image is now bound at the sudo boundary by the pull/tag entries.
func TestSudoers_EnvKeepIsCommandScoped(t *testing.T) {
	data, err := os.ReadFile(findSudoersFile(t)) //nolint:gosec // test reads packaging file by computed path
	if err != nil {
		t.Fatalf("read sudoers: %v", err)
	}
	content := string(data)

	// The remaining command-scoped preservation (passphrase) must be present.
	for _, want := range []string{
		`Cmnd_Alias CULVERT_MAINT_PASSPHRASE_CMNDS =`,
		`Defaults!CULVERT_MAINT_PASSPHRASE_CMNDS env_keep += "CULVERT_BACKUP_PASSPHRASE"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing command-scoped env-preservation:\n  %s", want)
		}
	}

	// P1.4: CULVERT_PROXY_IMAGE must NOT appear in any executable directive.
	// (It may only be MENTIONED in an explanatory comment.) No alias, no
	// env_keep, no NOPASSWD command — the image is no longer env-selected.
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // comments may reference the var by name
		}
		if strings.Contains(trimmed, "CULVERT_PROXY_IMAGE") {
			t.Errorf("P1.4: no executable sudoers directive may reference CULVERT_PROXY_IMAGE:\n  %s", trimmed)
		}
	}

	// The blanket per-user env_keep must NOT exist.
	for _, banned := range []string{
		`Defaults:culvert-maint env_keep += "CULVERT_PROXY_IMAGE"`,
		`Defaults:culvert-maint env_keep += "CULVERT_BACKUP_PASSPHRASE"`,
	} {
		if strings.Contains(content, banned) {
			t.Errorf("sudoers must NOT keep a blanket per-user env_keep:\n  %s", banned)
		}
	}

	// The passphrase alias must scope to the cli encrypt/restore commands
	// only — never the pull/tag/up image-selection commands.
	passAlias := aliasBody(content, "CULVERT_MAINT_PASSPHRASE_CMNDS")
	if !strings.Contains(passAlias, "--encrypt") || !strings.Contains(passAlias, "--restore") {
		t.Errorf("passphrase alias must cover --encrypt + --restore; got:\n%s", passAlias)
	}
	if strings.Contains(passAlias, "docker pull") || strings.Contains(passAlias, "docker tag") || strings.Contains(passAlias, "up -d") {
		t.Errorf("passphrase alias must NOT cover the image pull/tag/up commands:\n%s", passAlias)
	}
}

// TestSudoers_ImagePullTagAreRepoBound asserts the P1.4 boundary: the pull
// and tag entries bind a repo LITERAL ({proxy_repo}, no wildcard) + an exact
// 64-class hex digest, and the tag destination is the fixed pinned tag.
func TestSudoers_ImagePullTagAreRepoBound(t *testing.T) {
	data, err := os.ReadFile(findSudoersFile(t)) //nolint:gosec // test reads packaging file by computed path
	if err != nil {
		t.Fatalf("read sudoers: %v", err)
	}
	digest := "{proxy_repo}@sha256:" + strings.Repeat("[0-9a-f]", 64)
	wantPull := "/usr/bin/docker pull " + digest
	wantTag := "/usr/bin/docker tag " + digest + " culvert/proxy:pinned"
	content := normalize(string(data))
	if !strings.Contains(content, normalize(wantPull)) {
		t.Errorf("sudoers missing repo-bound pull entry:\n  %s", wantPull)
	}
	if !strings.Contains(content, normalize(wantTag)) {
		t.Errorf("sudoers missing repo-bound tag→pinned entry:\n  %s", wantTag)
	}
	// No `docker compose pull proxy` (the old env-selected path) may remain.
	if strings.Contains(content, "compose -f {compose_path} pull proxy") {
		t.Errorf("the old `docker compose pull proxy` entry must be removed (P1.4)")
	}
}

// aliasBody returns the text of a `Cmnd_Alias <name> = …` definition,
// following `\` line continuations, up to the first non-continued line.
func aliasBody(content, name string) string {
	lines := strings.Split(content, "\n")
	var body strings.Builder
	collecting := false
	for _, ln := range lines {
		if !collecting {
			if strings.HasPrefix(ln, "Cmnd_Alias "+name+" ") || strings.HasPrefix(ln, "Cmnd_Alias "+name+"=") {
				collecting = true
				body.WriteString(ln)
				body.WriteString("\n")
				if !strings.HasSuffix(strings.TrimRight(ln, " \t"), `\`) {
					break
				}
			}
			continue
		}
		body.WriteString(ln)
		body.WriteString("\n")
		if !strings.HasSuffix(strings.TrimRight(ln, " \t"), `\`) {
			break
		}
	}
	return body.String()
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
		// `Defaults` directives (e.g. command-scoped env_keep) and
		// `Cmnd_Alias` definitions (which group commands for those
		// Defaults) are policy, not command allowlist entries — they have
		// no NOPASSWD command to match against a template, so skip them
		// here. Their presence is asserted separately
		// (TestSudoers_EnvKeepPreservesOverlayVars). Alias-continuation
		// lines (leading whitespace, trailing `\`) are folded into the
		// Cmnd_Alias they belong to and likewise carry no NOPASSWD.
		if strings.HasPrefix(line, "Defaults") || strings.HasPrefix(line, "Cmnd_Alias") {
			continue
		}
		if !strings.Contains(line, "NOPASSWD:") && (strings.HasSuffix(line, `\`) || strings.HasPrefix(line, "/usr/bin/docker")) {
			// Cmnd_Alias continuation line (the alias body, comma/`\`
			// separated). No NOPASSWD grant.
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
