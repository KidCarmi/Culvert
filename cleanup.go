package main

// D1.3c — restore leftover cleanup.
//
// Operator-only one-shot CLI for safely removing /data.bak.<ts>-<pid> and
// /data.staging.<ts>-<pid> directories left behind by D1.3b.2b restore
// commits or killed restores. Two commands:
//
//	--list-restore-leftovers          read-only inventory
//	--cleanup-restore-leftovers       delete plan / execute (with --confirm)
//
// Safety contract (non-negotiable):
//  1. dataDir is never a deletion candidate.
//  2. Only direct siblings of dataDir are even considered.
//  3. Only directories matching the exact regex are eligible.
//  4. Lstat at admission AND Lstat at deletion (TOCTOU re-check).
//  5. Symlinks are never followed and never deleted.
//  6. Files are never deleted (only directories).
//  7. Dry-run is the default; --confirm is required for destruction.
//  8. Two-tier admission: names that don't match the leftover regex at
//     all are silently ignored (we don't warn on every unrelated sibling
//     next to dataDir). Regex-shaped candidates that fail any safety
//     check (symlink, non-directory, parent mismatch, bad timestamp, bad
//     pid, lstat error, size walk error) emit a WARN on stderr and are
//     never silently hidden.
//  9. Fail closed on any ambiguity.
//  10. Sort order is deterministic (timestamp asc, pid asc, name asc).

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// cleanupOpts captures the CLI flags for cleanup-restore-leftovers.
type cleanupOpts struct {
	Confirm   bool
	OlderThan time.Duration // 0 = no filter
	KeepLast  int           // <= 0 = no filter; applies to .bak only
}

type leftoverKind string

const (
	leftoverBak     leftoverKind = "bak"
	leftoverStaging leftoverKind = "staging"
)

// leftover is an admitted candidate.
type leftover struct {
	Path      string
	Kind      leftoverKind
	Timestamp time.Time
	PID       int
	SizeBytes int64
}

// skipReason describes a regex-shaped candidate that was rejected by an
// admission safety check (symlink, non-directory, parent mismatch, bad
// timestamp, bad pid, lstat error, size walk error). Surfaced as WARN
// lines on stderr so regex-shaped candidates that fail safety checks
// are never silently hidden. Note: directory entries whose names do not
// match the leftover regex at all are silently ignored — they're not
// near-misses, just unrelated siblings of dataDir.
type skipReason struct {
	Path   string
	Reason string
}

// preDeleteHook is a test-only hook invoked between admission Lstat and
// the deletion-time Lstat. Production: nil.
var preDeleteHook func(path string)

// compileLeftoverNameRE builds the regex matching restore leftover
// directory names exactly:
//
//	<base>.bak.<YYYYMMDDTHHMMSSZ>-<pid>
//	<base>.staging.<YYYYMMDDTHHMMSSZ>-<pid>
//
// <base> is the basename of dataDir and is dynamic, so the regex is
// compiled per discovery.
func compileLeftoverNameRE(base string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(base)
	return regexp.MustCompile(`^` + quoted + `\.(bak|staging)\.([0-9]{8}T[0-9]{6}Z)-([0-9]+)$`)
}

// resolveDataDirRoots normalizes dataDir into (parent, base, abs) and
// refuses paths that have no usable parent (root, "."). All admission
// uses these absolute roots so relative-path tricks cannot escape.
func resolveDataDirRoots(dataDir string) (parent, base, abs string, err error) {
	if dataDir == "" {
		return "", "", "", fmt.Errorf("cleanup: data dir is empty")
	}
	abs, err = filepath.Abs(dataDir)
	if err != nil {
		return "", "", "", fmt.Errorf("cleanup: resolve data dir: %w", err)
	}
	abs = filepath.Clean(abs)
	parent = filepath.Dir(abs)
	base = filepath.Base(abs)
	if parent == abs || base == "" || base == "." || base == "/" || base == string(filepath.Separator) {
		return "", "", "", fmt.Errorf("cleanup: refusing to operate with data dir %q (no usable parent)", abs)
	}
	if parent == "" || parent == "." {
		return "", "", "", fmt.Errorf("cleanup: refusing to operate with data dir %q (empty parent)", abs)
	}
	return parent, base, abs, nil
}

// admitEntry runs the per-entry admission rules used by discoverLeftovers.
// Returns (lo, nil) for an admitted candidate, (nil, &skipReason) for a
// regex-match that failed a safety rule, (lo, &skipReason) for an
// admitted candidate whose size walk failed (informational warning),
// and (nil, nil) for entries whose name does not match the leftover
// regex at all (silent ignore — not a near-miss).
func admitEntry(entry os.DirEntry, parent, abs string, re *regexp.Regexp) (*leftover, *skipReason) {
	name := entry.Name()
	m := re.FindStringSubmatch(name)
	if m == nil {
		return nil, nil
	}
	full := filepath.Join(parent, name)
	if filepath.Dir(full) != parent {
		return nil, &skipReason{Path: full, Reason: "candidate parent mismatch"}
	}
	if filepath.Clean(full) == abs {
		// Cannot happen because regex requires a "<base>.bak." or
		// "<base>.staging." prefix, but defense-in-depth.
		return nil, &skipReason{Path: full, Reason: "candidate equals data dir"}
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, &skipReason{Path: full, Reason: fmt.Sprintf("lstat: %v", err)}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &skipReason{Path: full, Reason: "symlink (refusing to follow)"}
	}
	if !info.IsDir() {
		return nil, &skipReason{Path: full, Reason: "not a directory"}
	}
	ts, terr := time.ParseInLocation("20060102T150405Z", m[2], time.UTC)
	if terr != nil {
		return nil, &skipReason{Path: full, Reason: fmt.Sprintf("invalid timestamp: %v", terr)}
	}
	pid, perr := strconv.Atoi(m[3])
	if perr != nil || pid < 0 {
		return nil, &skipReason{Path: full, Reason: "invalid pid component"}
	}
	kind := leftoverBak
	if m[1] == "staging" {
		kind = leftoverStaging
	}
	size, sizeErr := dirSizeBytes(full)
	lo := &leftover{Path: full, Kind: kind, Timestamp: ts, PID: pid, SizeBytes: size}
	if sizeErr != nil {
		// Size is informational; admit but warn.
		return lo, &skipReason{Path: full, Reason: fmt.Sprintf("size walk failed: %v", sizeErr)}
	}
	return lo, nil
}

// discoverLeftovers reads the parent of dataDir and returns admitted
// leftovers and a list of warnings about regex-near-misses or
// non-directory / symlink candidates. Discovery is non-recursive and
// uses Lstat exclusively.
func discoverLeftovers(dataDir string) ([]leftover, []skipReason, error) {
	parent, base, abs, err := resolveDataDirRoots(dataDir)
	if err != nil {
		return nil, nil, err
	}
	re := compileLeftoverNameRE(base)

	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, nil, fmt.Errorf("cleanup: read parent dir %q: %w", parent, err)
	}

	var (
		valid   []leftover
		skipped []skipReason
	)
	for _, entry := range entries {
		lo, skip := admitEntry(entry, parent, abs, re)
		if skip != nil {
			skipped = append(skipped, *skip)
		}
		if lo != nil {
			valid = append(valid, *lo)
		}
	}

	sort.Slice(valid, func(i, j int) bool {
		if !valid[i].Timestamp.Equal(valid[j].Timestamp) {
			return valid[i].Timestamp.Before(valid[j].Timestamp)
		}
		if valid[i].PID != valid[j].PID {
			return valid[i].PID < valid[j].PID
		}
		return valid[i].Path < valid[j].Path
	})
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	return valid, skipped, nil
}

// dirSizeBytes walks dir using Lstat-based traversal; symlinks contribute
// 0 bytes (we never follow them). filepath.Walk uses Lstat internally.
func dirSizeBytes(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return total, err
	}
	return total, nil
}

// applyCleanupFilters applies --older-than and --keep-last to a sorted
// list of leftovers and returns the candidates selected for deletion.
//
// --older-than: candidate Timestamp must be strictly before now - OlderThan.
// --keep-last:  applies to leftoverBak only; the N newest .bak entries
//
//	are preserved regardless of --older-than.
func applyCleanupFilters(in []leftover, opts cleanupOpts, now time.Time) []leftover {
	if len(in) == 0 {
		return nil
	}
	cutoff := time.Time{}
	if opts.OlderThan > 0 {
		cutoff = now.Add(-opts.OlderThan)
	}

	var baks []leftover
	for i := range in {
		if in[i].Kind == leftoverBak {
			baks = append(baks, in[i])
		}
	}

	keep := map[string]bool{}
	if opts.KeepLast > 0 {
		// baks is sorted oldest-first; preserve the tail.
		startIdx := len(baks) - opts.KeepLast
		if startIdx < 0 {
			startIdx = 0
		}
		for i := startIdx; i < len(baks); i++ {
			keep[baks[i].Path] = true
		}
	}

	var out []leftover
	for i := range in {
		lo := in[i]
		if keep[lo.Path] {
			continue
		}
		if !cutoff.IsZero() && !lo.Timestamp.Before(cutoff) {
			continue
		}
		out = append(out, lo)
	}
	return out
}

// runListLeftovers prints all admitted leftovers to stdout; skipped
// candidates are surfaced as WARN lines on stderr. Read-only.
func runListLeftovers(dataDir string) error {
	valid, skipped, err := discoverLeftovers(dataDir)
	if err != nil {
		return err
	}
	return writeLeftoverList(os.Stdout, os.Stderr, valid, skipped, time.Now().UTC())
}

func writeLeftoverList(stdout, stderr io.Writer, valid []leftover, skipped []skipReason, now time.Time) error {
	if len(valid) == 0 {
		_, _ = fmt.Fprintln(stdout, "No restore leftovers found.")
	} else {
		_, _ = fmt.Fprintf(stdout, "%-60s %-8s %-12s %s\n", "PATH", "TYPE", "AGE", "SIZE")
		for i := range valid {
			lo := valid[i]
			_, _ = fmt.Fprintf(stdout, "%-60s %-8s %-12s %s\n",
				lo.Path, string(lo.Kind), formatAge(now.Sub(lo.Timestamp)), formatBytes(lo.SizeBytes))
		}
	}
	for i := range skipped {
		_, _ = fmt.Fprintf(stderr, "WARN: skipping %s: %s\n", skipped[i].Path, skipped[i].Reason)
	}
	return nil
}

// runCleanupLeftovers plans and (with Confirm) executes deletion.
//
// Without --confirm: prints "WILL DELETE" plan; no filesystem mutation.
// With --confirm:    deletes selected leftovers in deterministic order;
// re-Lstats each candidate immediately before delete (TOCTOU); surfaces
// per-candidate failures on stderr and continues; returns a non-nil
// error if any candidate failed to delete.
func runCleanupLeftovers(dataDir string, opts cleanupOpts) error {
	valid, skipped, err := discoverLeftovers(dataDir)
	if err != nil {
		return err
	}
	for i := range skipped {
		_, _ = fmt.Fprintf(os.Stderr, "WARN: skipping %s: %s\n", skipped[i].Path, skipped[i].Reason)
	}
	now := time.Now().UTC()
	plan := applyCleanupFilters(valid, opts, now)
	if len(plan) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No candidates match the given filters.")
		return nil
	}

	parent, base, abs, err := resolveDataDirRoots(dataDir)
	if err != nil {
		return err
	}
	re := compileLeftoverNameRE(base)

	if !opts.Confirm {
		_, _ = fmt.Fprintln(os.Stdout, "Cleanup plan (dry-run — no changes will be made):")
		var totalBytes int64
		for i := range plan {
			lo := plan[i]
			_, _ = fmt.Fprintf(os.Stdout, "  WILL DELETE  %s   (%s, %s, %s)\n",
				lo.Path, formatBytes(lo.SizeBytes), formatAge(now.Sub(lo.Timestamp)), string(lo.Kind))
			totalBytes += lo.SizeBytes
		}
		_, _ = fmt.Fprintf(os.Stdout, "\nTotal: %d directories, %s\n", len(plan), formatBytes(totalBytes))
		_, _ = fmt.Fprintln(os.Stdout, "Re-run with --confirm to execute deletion.")
		return nil
	}

	_, _ = fmt.Fprintln(os.Stdout, "Cleanup (DESTRUCTIVE — deleting now):")
	var (
		deleted      int
		deletedBytes int64
		failed       int
	)
	for i := range plan {
		lo := plan[i]
		if derr := deleteOneLeftover(lo, parent, abs, re); derr != nil {
			failed++
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", lo.Path, derr)
			pathSafe := lo.Path
			logger.Printf("cleanup: failed to delete %q: %v", sanitizeLog(pathSafe), derr)
			continue
		}
		deleted++
		deletedBytes += lo.SizeBytes
		_, _ = fmt.Fprintf(os.Stdout, "  DELETED      %s   (%s)\n", lo.Path, formatBytes(lo.SizeBytes))
		logger.Printf("cleanup: deleted %q (%d bytes)", sanitizeLog(lo.Path), lo.SizeBytes)
	}
	_, _ = fmt.Fprintf(os.Stdout, "\nTotal deleted: %d directories, %s\n", deleted, formatBytes(deletedBytes))
	if failed > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Errors: %d candidate(s) could not be deleted; rerun to retry.\n", failed)
		return fmt.Errorf("cleanup: %d failure(s)", failed)
	}
	return nil
}

// deleteOneLeftover re-Lstats the candidate, re-verifies all admission
// invariants, and removes it. The re-check is the TOCTOU guard against
// symlink-swap attacks between discovery and deletion.
func deleteOneLeftover(lo leftover, parent, dataDirAbs string, re *regexp.Regexp) error {
	if preDeleteHook != nil {
		preDeleteHook(lo.Path)
	}
	name := filepath.Base(lo.Path)
	if !re.MatchString(name) {
		return fmt.Errorf("name no longer matches leftover pattern")
	}
	if filepath.Dir(lo.Path) != parent {
		return fmt.Errorf("parent mismatch")
	}
	if filepath.Clean(lo.Path) == dataDirAbs {
		return fmt.Errorf("candidate equals data dir")
	}
	info, err := os.Lstat(lo.Path)
	if err != nil {
		return fmt.Errorf("re-lstat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("became a symlink between discovery and deletion (refusing)")
	}
	if !info.IsDir() {
		return fmt.Errorf("no longer a directory (refusing)")
	}
	if err := os.RemoveAll(lo.Path); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

// formatBytes renders a byte count in 1024-based units with one decimal
// place, e.g. "412.3 MB".
func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	f := float64(n) / 1024
	idx := 0
	for f >= 1024 && idx < len(units)-1 {
		f /= 1024
		idx++
	}
	return fmt.Sprintf("%.1f %s", f, units[idx])
}

// formatAge renders a duration as "<N>d <H>h", "<N>h", or "<N>m".
func formatAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d / time.Hour)
	if h < 24 {
		return fmt.Sprintf("%dh", h)
	}
	days := h / 24
	rem := h - days*24
	return fmt.Sprintf("%dd %dh", days, rem)
}
