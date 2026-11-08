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
	// Restore templates used to enumerate 12 wildcarded sudoers lines
	// each (3 modes × 4 flag combos). They now run through the
	// compose-cli wrapper, so each MUST declare exactly the single
	// argument-less wrapper line: no fewer (no allowlist), no more (no
	// leftover wildcard surface). The 24 mode/flag combinations are
	// enforced by the wrapper itself (wrapper_test.go).
	for _, id := range []TemplateID{TemplateComposeCLIRestoreDryRun, TemplateComposeCLIRestoreCommit} {
		tmpl := templateByID(id)
		if tmpl == nil {
			t.Errorf("template %q missing from registry", id)
			continue
		}
		if len(tmpl.SudoersLines) != 1 || tmpl.SudoersLines[0] != ComposeCLIWrapperPath {
			t.Errorf("template %q must declare exactly the wrapper sudoers line %q; got %q", id, ComposeCLIWrapperPath, tmpl.SudoersLines)
		}
	}
}

// sudoersCommandSpecs returns every command spec the sudoers file grants or
// names: the command part of each NOPASSWD rule and each Cmnd_Alias member
// (continuation lines folded). Comments and Defaults lines are skipped.
func sudoersCommandSpecs(t *testing.T, content string) []string {
	t.Helper()
	var specs []string
	var alias strings.Builder
	inAlias := false
	flushAlias := func() {
		body := alias.String()
		alias.Reset()
		inAlias = false
		if i := strings.Index(body, "="); i >= 0 {
			for _, member := range strings.Split(body[i+1:], ",") {
				if m := strings.TrimSpace(member); m != "" {
					specs = append(specs, m)
				}
			}
		}
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if inAlias {
			alias.WriteString(" " + strings.TrimSuffix(line, `\`))
			if !strings.HasSuffix(line, `\`) {
				flushAlias()
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
			continue
		}
		if strings.HasPrefix(line, "Cmnd_Alias") {
			alias.WriteString(strings.TrimSuffix(line, `\`))
			inAlias = true
			if !strings.HasSuffix(line, `\`) {
				flushAlias()
			}
			continue
		}
		idx := strings.Index(line, "NOPASSWD:")
		if idx == -1 {
			t.Fatalf("unexpected sudoers line shape: %q", line)
		}
		specs = append(specs, strings.TrimSpace(line[idx+len("NOPASSWD:"):]))
	}
	if inAlias {
		t.Fatalf("unterminated Cmnd_Alias continuation in sudoers")
	}
	return specs
}

// sudoRsArgWildcardError mirrors sudo-rs's command-argument rule
// (src/sudoers/tokens.rs, Command::construct): split the spec on
// whitespace, drop a SOLE trailing `*` (the "any further arguments"
// form), and reject the spec if any remaining argument contains `*` or
// `?`. Returns "" when the spec is acceptable.
func sudoRsArgWildcardError(spec string) string {
	fields := strings.Fields(spec)
	if len(fields) < 2 {
		return ""
	}
	args := fields[1:]
	if args[len(args)-1] == "*" {
		args = args[:len(args)-1]
	}
	for _, a := range args {
		if strings.ContainsAny(a, "*?") {
			return "wildcards are not allowed in command arguments: " + a
		}
	}
	return ""
}

// TestSudoers_NoWildcardInCommandArguments is the Ubuntu 26.04 regression
// gate. sudo-rs, the default sudo there, refuses a sudoers file whose
// command arguments carry `*` or `?` anywhere except as a sole trailing
// `*`, and `visudo -c` then rejects the WHOLE file, so the agent cannot be
// installed at all. CI runs the real `visudo -c` only on whatever sudo the
// runner image ships; this static check applies the sudo-rs rule on every
// runner, to both the on-disk file and every template's SudoersLines.
func TestSudoers_NoWildcardInCommandArguments(t *testing.T) {
	data, err := os.ReadFile(findSudoersFile(t))
	if err != nil {
		t.Fatalf("read sudoers: %v", err)
	}
	specs := sudoersCommandSpecs(t, string(data))
	if len(specs) == 0 {
		t.Fatal("parsed no command specs from the sudoers file")
	}
	for _, spec := range specs {
		if msg := sudoRsArgWildcardError(spec); msg != "" {
			t.Errorf("sudoers spec would fail sudo-rs visudo (%s):\n  %s", msg, spec)
		}
	}
	for _, tmpl := range Registry() {
		for _, line := range tmpl.SudoersLines {
			if msg := sudoRsArgWildcardError(line); msg != "" {
				t.Errorf("template %q sudoers line would fail sudo-rs visudo (%s):\n  %s", tmpl.ID, msg, line)
			}
		}
	}

	// Negative controls: the rule must still catch the shapes that broke
	// main, and must still admit the sole-trailing form sudo-rs accepts.
	for _, bad := range []string{
		"/usr/bin/docker compose -f /srv/c.yml --profile cli run --rm cli --backup /backup/*",
		"/usr/bin/docker compose -f /srv/c.yml --profile cli run --rm cli --restore /backup/* --mode full",
		"/usr/bin/docker compose -f /srv/c.yml --profile cli run --rm cli --older-than * --keep-last *",
		"/usr/bin/docker image inspect a?b",
	} {
		if sudoRsArgWildcardError(bad) == "" {
			t.Errorf("negative control not caught: %q", bad)
		}
	}
	for _, good := range []string{
		"/usr/bin/docker image inspect *",
		ComposeCLIWrapperPath,
		"/usr/bin/docker compose -f /srv/c.yml down",
	} {
		if msg := sudoRsArgWildcardError(good); msg != "" {
			t.Errorf("positive control rejected (%s): %q", msg, good)
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

	// The passphrase alias must scope to the compose-cli wrapper ONLY —
	// never a docker command directly (in particular not the pull/tag/up
	// image-selection commands). The wrapper is the sole consumer: it
	// forwards the var with `-e` for backup-encrypted/restore and unsets
	// it for backup/cleanup (pinned by wrapper_test.go).
	passAlias := aliasBody(content, "CULVERT_MAINT_PASSPHRASE_CMNDS")
	wantAlias := "Cmnd_Alias CULVERT_MAINT_PASSPHRASE_CMNDS = " + ComposeCLIWrapperPath
	if normalize(passAlias) != wantAlias {
		t.Errorf("passphrase alias must be exactly %q; got:\n%s", wantAlias, passAlias)
	}
	if strings.Contains(passAlias, "docker") {
		t.Errorf("passphrase alias must NOT name any docker command directly:\n%s", passAlias)
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
	// Colons are escaped (`\:`) for sudoers grammar.
	digest := `{proxy_repo}@sha256\:` + strings.Repeat("[0-9a-f]", 64)
	wantPull := "/usr/bin/docker pull " + digest
	wantTag := "/usr/bin/docker tag " + digest + ` culvert/proxy\:pinned`
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
