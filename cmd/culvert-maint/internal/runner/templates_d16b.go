// D1.6b runner templates: backup / restore / cleanup orchestration of
// the D1.5 Compose `cli` profile + the bare compose lifecycle commands
// (down, up).
//
// CONTRACT (non-negotiable, mirrors D1.6 plan § 4.1, § 4.6):
//
//   - One template = one method on *Runner with explicit, typed args.
//     The method validates inputs, builds argv in the canonical order,
//     and calls runWithEnv. There is no generic dispatch — handlers
//     cannot bypass the validators by passing argv directly.
//   - Canonical argv ordering for restore (mandatory):
//     --restore <path>
//     --mode <mode>
//     --accept-dp-reenrollment   (only when true)
//     --allow-counter-rollback   (only when true)
//     --confirm                  (commit only, last position)
//   - Backup paths must live directly under /backup; the agent passes
//     `/backup/<filename>` and the filename must be a bare basename.
//   - The encrypted-backup template forwards CULVERT_BACKUP_PASSPHRASE
//     into the cli container via `-e NAME` (no =VALUE form). The
//     unencrypted template does NOT include `-e`. Restore templates
//     ALWAYS forward `-e CULVERT_BACKUP_PASSPHRASE` because the cli
//     container detects encrypted vs unencrypted from the file's
//     magic bytes — passing the env var when the archive is plaintext
//     is harmless (the cli ignores it).
//   - Sudoers is the privilege boundary; the agent's validation is
//     defense-in-depth. Every template registered here has matching
//     sudoers entries enumerated in packaging/sudoers/culvert-maint;
//     the parity test asserts the bidirectional match.
package runner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnvCulvertBackupPassphrase is the env-var name the cli container
// reads for backup encryption / restore decryption. Exported so the
// agent's main can include it in EnvAllow.
const EnvCulvertBackupPassphrase = "CULVERT_BACKUP_PASSPHRASE"

// RestoreMode is the validated enum value for `--mode`.
type RestoreMode string

// RestoreMode values are the closed enum the agent will accept on
// /v1/restores/dryrun and /v1/restores/commit. The cli container
// rejects anything outside this set; the agent rejects up-front so
// sudo is never invoked with a bogus mode.
const (
	RestoreModeFull          RestoreMode = "full"
	RestoreModeTrustRootOnly RestoreMode = "trust-root-only"
	RestoreModeStateOnly     RestoreMode = "state-only"
)

// validRestoreModes is the closed set used by the validator.
var validRestoreModes = map[RestoreMode]struct{}{
	RestoreModeFull:          {},
	RestoreModeTrustRootOnly: {},
	RestoreModeStateOnly:     {},
}

// IsValid reports whether the mode is one of the closed enum values.
func (m RestoreMode) IsValid() bool {
	_, ok := validRestoreModes[m]
	return ok
}

// backupFilenameRE bounds the filename shape: alphanumerics, dot,
// underscore, hyphen. No path separators, no shell metas, no spaces.
// Length 1..255.
var backupFilenameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

// ValidateBackupFilename is the canonical filename validator. Returns
// an error if the filename has a path separator, traversal sequence,
// shell metacharacter, or otherwise fails the bounded regex. Exported
// so handlers can validate before attempting to call a runner method.
func ValidateBackupFilename(filename string) error {
	return validateBackupFilename(filename)
}

// validateBackupFilename is the unexported implementation kept for
// internal callers that don't need the exported wrapper.
func validateBackupFilename(filename string) error {
	if filename == "" {
		return errors.New("backup filename: empty")
	}
	if filename == "." || filename == ".." {
		return errors.New("backup filename: must not be '.' or '..'")
	}
	if strings.ContainsAny(filename, "/\\") {
		return fmt.Errorf("backup filename: must be a bare basename (no '/' or '\\'), got %q", filename)
	}
	if !backupFilenameRE.MatchString(filename) {
		return fmt.Errorf("backup filename: must match [a-zA-Z0-9._-]{1,255}, got %q", filename)
	}
	if strings.HasPrefix(filename, ".") {
		return fmt.Errorf("backup filename: must not start with '.', got %q", filename)
	}
	return nil
}

// ValidateOlderThan is the exported wrapper around validateOlderThan.
func ValidateOlderThan(dur string) error { return validateOlderThan(dur) }

// ValidateKeepLast is the exported wrapper around validateKeepLast.
func ValidateKeepLast(n int) error { return validateKeepLast(n) }

// olderThanRE bounds the on-the-wire older_than string shape. The
// sudoers entry uses `--older-than *` (one bounded wildcard token),
// so the agent's validator is the only barrier between operator
// input and a sudo argv. We accept ONLY the time.ParseDuration
// alphabet — digits, optional decimal, and one of the unit suffixes
// — with no surrounding whitespace, control characters, or shell
// metacharacters. time.ParseDuration alone tolerates nothing weird,
// but we belt-and-braces with this regex so an upstream bug that
// builds the string differently still fails loudly.
var olderThanRE = regexp.MustCompile(`^\d+(\.\d+)?(ns|us|µs|ms|s|m|h)$`)

// validateOlderThan parses dur and bounds its range. The cleanup CLI
// also parses with time.ParseDuration; the agent enforces the same
// strictness up-front so an invalid request never reaches sudo. The
// surface area is tightened further by olderThanRE which rejects
// whitespace, control chars, and shell metacharacters before we even
// hand the string to time.ParseDuration.
func validateOlderThan(dur string) error {
	if dur == "" {
		return errors.New("older_than: empty")
	}
	if !olderThanRE.MatchString(dur) {
		return fmt.Errorf("older_than: must match ^[0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h)$ with no whitespace, control chars, or shell metacharacters; got %q", dur)
	}
	d, err := time.ParseDuration(dur)
	if err != nil {
		return fmt.Errorf("older_than: %w", err)
	}
	if d < time.Hour {
		return fmt.Errorf("older_than: must be at least 1h, got %s", d)
	}
	if d > 8760*time.Hour { // 1 year
		return fmt.Errorf("older_than: must be at most 1y (8760h), got %s", d)
	}
	return nil
}

// validateKeepLast bounds the keep_last integer.
func validateKeepLast(n int) error {
	if n < 0 {
		return fmt.Errorf("keep_last: must be >= 0, got %d", n)
	}
	if n > 100 {
		return fmt.Errorf("keep_last: must be <= 100, got %d", n)
	}
	return nil
}

// backupPath builds the canonical `/backup/<filename>` path used in
// every backup/restore template's argv.
func backupPath(filename string) string {
	return "/backup/" + filename
}

// ─── Template registrations (appended to Registry below) ────────────

// d16bTemplates returns the closed list of D1.6b templates. Each
// template's BaseArgv contains the {compose_path} placeholder; the
// runner expands it at exec time.
//
// Sudoers strings are documentation-of-record; the parity test
// cross-checks them against the on-disk sudoers file. The strings
// here use literal spaces between argv tokens — they are NOT regexes
// or globs.
func d16bTemplates() []Template {
	return []Template{
		{
			ID:       TemplateComposeCLIBackupEncrypted,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "-e", EnvCulvertBackupPassphrase, "cli", "--encrypt", "--backup"},
			SudoersLines: []string{
				"/usr/bin/docker compose -f {compose_path} --profile cli run --rm -e " + EnvCulvertBackupPassphrase + " cli --encrypt --backup /backup/*",
			},
			StateChanging: true,
		},
		{
			ID:       TemplateComposeCLIBackupUnencrypted,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "cli", "--backup"},
			SudoersLines: []string{
				"/usr/bin/docker compose -f {compose_path} --profile cli run --rm cli --backup /backup/*",
			},
			StateChanging: true,
		},
		{
			ID:       TemplateComposeCLIBackupList,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "cli", "--list-backups", "--backup-dir", "/backup"},
			SudoersLines: []string{
				"/usr/bin/docker compose -f {compose_path} --profile cli run --rm cli --list-backups --backup-dir /backup",
			},
			StateChanging: false,
		},
		{
			ID:            TemplateComposeCLIRestoreDryRun,
			BaseArgv:      []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "-e", EnvCulvertBackupPassphrase, "cli", "--restore"},
			SudoersLines:  enumerateRestoreSudoersLines(restoreSudoersPrefix, false),
			StateChanging: false,
		},
		{
			ID:            TemplateComposeCLIRestoreCommit,
			BaseArgv:      []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "-e", EnvCulvertBackupPassphrase, "cli", "--restore"},
			SudoersLines:  enumerateRestoreSudoersLines(restoreSudoersPrefix, true),
			StateChanging: true,
		},
		{
			ID:       TemplateComposeDown,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "down"},
			SudoersLines: []string{
				"/usr/bin/docker compose -f {compose_path} down",
			},
			StateChanging: true,
		},
		{
			ID:       TemplateComposeUp,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "up", "-d"},
			SudoersLines: []string{
				"/usr/bin/docker compose -f {compose_path} up -d",
			},
			StateChanging: true,
		},
		{
			ID:       TemplateComposeCLICleanupDryRun,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "cli", "--cleanup-restore-leftovers", "--older-than"},
			SudoersLines: []string{
				// `*` matches one argv token; agent enforces strict
				// time.ParseDuration shape and integer keep_last via
				// validateOlderThan + validateKeepLast before sudo is
				// even invoked. Single bounded wildcard per variable
				// position is acceptable per the user's directive
				// ("only bounded backup path wildcard where unavoidable").
				"/usr/bin/docker compose -f {compose_path} --profile cli run --rm cli --cleanup-restore-leftovers --older-than * --keep-last *",
			},
			StateChanging: false,
		},
		{
			ID:       TemplateComposeCLICleanupCommit,
			BaseArgv: []string{"docker", "compose", "-f", "{compose_path}", "--profile", "cli", "run", "--rm", "cli", "--cleanup-restore-leftovers", "--older-than"},
			SudoersLines: []string{
				"/usr/bin/docker compose -f {compose_path} --profile cli run --rm cli --cleanup-restore-leftovers --older-than * --keep-last * --confirm",
			},
			StateChanging: true,
		},
	}
}

// restoreSudoersPrefix is the fixed prefix shared by every restore
// allowlist entry. Suffix varies by mode and optional flags.
const restoreSudoersPrefix = "/usr/bin/docker compose -f {compose_path} --profile cli run --rm -e " + EnvCulvertBackupPassphrase + " cli --restore /backup/*"

// enumerateRestoreSudoersLines produces every legal restore allowlist
// line. The product is:
//
//	prefix --mode <mode> [<flags-in-canonical-order>] [--confirm]
//
// where mode is one of {full, trust-root-only, state-only} and the
// optional flag set has 4 combinations (none, accept-dp-reenrollment,
// allow-counter-rollback, both — in that fixed order so sudoers
// matching is deterministic). withConfirm controls whether each line
// gets a trailing --confirm (commit template) or not (dryrun
// template).
//
// Result: 12 lines per template (3 modes × 4 flag combos).
func enumerateRestoreSudoersLines(prefix string, withConfirm bool) []string {
	out := make([]string, 0, 12)
	confirm := ""
	if withConfirm {
		confirm = " --confirm"
	}
	for _, mode := range []string{"full", "trust-root-only", "state-only"} {
		for _, flags := range []string{
			"",
			" --accept-dp-reenrollment",
			" --allow-counter-rollback",
			" --accept-dp-reenrollment --allow-counter-rollback",
		} {
			out = append(out, prefix+" --mode "+mode+flags+confirm)
		}
	}
	return out
}

// ─── Typed methods on *Runner ───────────────────────────────────────

// ComposeBackupEncrypted runs the encrypted-backup template with the
// passphrase forwarded into the cli container via env var. The
// resolvedPassphrase is set in the runner-child env via overlay (NOT
// in argv); the cli container reads it from $CULVERT_BACKUP_PASSPHRASE.
func (r *Runner) ComposeBackupEncrypted(ctx context.Context, filename, resolvedPassphrase string) (*Result, error) {
	if err := validateBackupFilename(filename); err != nil {
		return nil, err
	}
	if resolvedPassphrase == "" {
		return nil, errors.New("encrypted backup: resolved passphrase is empty")
	}
	tmpl := templateByID(TemplateComposeCLIBackupEncrypted)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeCLIBackupEncrypted not registered")
	}
	argv := r.buildArgv(tmpl)
	argv = append(argv, backupPath(filename))
	overlay := map[string]string{EnvCulvertBackupPassphrase: resolvedPassphrase}
	return r.runWithEnv(ctx, argv, overlay)
}

// ComposeBackupUnencrypted runs the unencrypted-backup template. No
// passphrase is forwarded; the runner explicitly suppresses
// CULVERT_BACKUP_PASSPHRASE in the child env so the cli container
// cannot accidentally pick up a host-side value.
func (r *Runner) ComposeBackupUnencrypted(ctx context.Context, filename string) (*Result, error) {
	if err := validateBackupFilename(filename); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateComposeCLIBackupUnencrypted)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeCLIBackupUnencrypted not registered")
	}
	argv := r.buildArgv(tmpl)
	argv = append(argv, backupPath(filename))
	overlay := map[string]string{EnvCulvertBackupPassphrase: ""} // explicit unset
	return r.runWithEnv(ctx, argv, overlay)
}

// ComposeBackupList runs the list-backups template. Emits a JSON
// array on stdout (parsed by the agent's GET /v1/backups handler).
func (r *Runner) ComposeBackupList(ctx context.Context) (*Result, error) {
	tmpl := templateByID(TemplateComposeCLIBackupList)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeCLIBackupList not registered")
	}
	argv := r.buildArgv(tmpl)
	// Listing does not need any passphrase. Suppress.
	overlay := map[string]string{EnvCulvertBackupPassphrase: ""}
	return r.runWithEnv(ctx, argv, overlay)
}

// ComposeRestoreDryRun runs the restore dry-run template (no
// `--confirm`). resolvedPassphrase may be empty when the archive is
// not encrypted; the cli container detects from magic bytes.
//
// Canonical argv tail (after BaseArgv expansion):
//
//	/backup/<filename> --mode <mode> [--accept-dp-reenrollment] [--allow-counter-rollback]
func (r *Runner) ComposeRestoreDryRun(ctx context.Context, filename string, mode RestoreMode, acceptDP, allowCounter bool, resolvedPassphrase string) (*Result, error) {
	argv, err := r.buildRestoreArgv(TemplateComposeCLIRestoreDryRun, filename, mode, acceptDP, allowCounter, false)
	if err != nil {
		return nil, err
	}
	return r.runWithEnv(ctx, argv, restorePassphraseOverlay(resolvedPassphrase))
}

// ComposeRestoreCommit runs the restore commit template. Same argv
// tail as dry-run plus a trailing `--confirm`. State-changing.
func (r *Runner) ComposeRestoreCommit(ctx context.Context, filename string, mode RestoreMode, acceptDP, allowCounter bool, resolvedPassphrase string) (*Result, error) {
	argv, err := r.buildRestoreArgv(TemplateComposeCLIRestoreCommit, filename, mode, acceptDP, allowCounter, true)
	if err != nil {
		return nil, err
	}
	return r.runWithEnv(ctx, argv, restorePassphraseOverlay(resolvedPassphrase))
}

// buildRestoreArgv assembles the canonical-order argv for both
// restore.dryrun and restore.commit. The withConfirm flag controls
// the trailing --confirm token.
func (r *Runner) buildRestoreArgv(id TemplateID, filename string, mode RestoreMode, acceptDP, allowCounter, withConfirm bool) ([]string, error) {
	if err := validateBackupFilename(filename); err != nil {
		return nil, err
	}
	if !mode.IsValid() {
		return nil, fmt.Errorf("restore: mode must be one of full|trust-root-only|state-only, got %q", mode)
	}
	tmpl := templateByID(id)
	if tmpl == nil {
		return nil, fmt.Errorf("runner: template %s not registered", id)
	}
	argv := r.buildArgv(tmpl)
	argv = append(argv, backupPath(filename), "--mode", string(mode))
	// Optional flags in fixed canonical order: --accept-dp-reenrollment,
	// then --allow-counter-rollback. Position matters for sudoers
	// matching — every enumerated entry assumes this order.
	if acceptDP {
		argv = append(argv, "--accept-dp-reenrollment")
	}
	if allowCounter {
		argv = append(argv, "--allow-counter-rollback")
	}
	if withConfirm {
		argv = append(argv, "--confirm")
	}
	return argv, nil
}

// restorePassphraseOverlay builds the env overlay for restore calls.
// An empty resolvedPassphrase means "the archive is unencrypted; do
// not pass a value into the child env" — encoded as overlay value "",
// which the runner interprets as "unset for this call".
func restorePassphraseOverlay(resolvedPassphrase string) map[string]string {
	return map[string]string{EnvCulvertBackupPassphrase: resolvedPassphrase}
}

// ComposeDown runs `docker compose -f <p> down`. State-changing.
func (r *Runner) ComposeDown(ctx context.Context) (*Result, error) {
	tmpl := templateByID(TemplateComposeDown)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeDown not registered")
	}
	return r.runWithEnv(ctx, r.buildArgv(tmpl), nil)
}

// ComposeUp runs `docker compose -f <p> up -d`. State-changing.
func (r *Runner) ComposeUp(ctx context.Context) (*Result, error) {
	tmpl := templateByID(TemplateComposeUp)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeUp not registered")
	}
	return r.runWithEnv(ctx, r.buildArgv(tmpl), nil)
}

// ComposeCleanupDryRun runs the cleanup template without --confirm.
//
// Canonical argv tail: --older-than <dur> --keep-last <n>
func (r *Runner) ComposeCleanupDryRun(ctx context.Context, olderThan string, keepLast int) (*Result, error) {
	argv, err := r.buildCleanupArgv(TemplateComposeCLICleanupDryRun, olderThan, keepLast, false)
	if err != nil {
		return nil, err
	}
	return r.runWithEnv(ctx, argv, nil)
}

// ComposeCleanupCommit runs the cleanup template with --confirm.
// State-changing.
func (r *Runner) ComposeCleanupCommit(ctx context.Context, olderThan string, keepLast int) (*Result, error) {
	argv, err := r.buildCleanupArgv(TemplateComposeCLICleanupCommit, olderThan, keepLast, true)
	if err != nil {
		return nil, err
	}
	return r.runWithEnv(ctx, argv, nil)
}

func (r *Runner) buildCleanupArgv(id TemplateID, olderThan string, keepLast int, withConfirm bool) ([]string, error) {
	if err := validateOlderThan(olderThan); err != nil {
		return nil, err
	}
	if err := validateKeepLast(keepLast); err != nil {
		return nil, err
	}
	tmpl := templateByID(id)
	if tmpl == nil {
		return nil, fmt.Errorf("runner: template %s not registered", id)
	}
	argv := r.buildArgv(tmpl)
	// BaseArgv ends at "--older-than"; append <dur>, --keep-last, <n>,
	// and optionally --confirm. Canonical order is fixed for sudoers.
	argv = append(argv, olderThan, "--keep-last", strconv.Itoa(keepLast))
	if withConfirm {
		argv = append(argv, "--confirm")
	}
	return argv, nil
}
