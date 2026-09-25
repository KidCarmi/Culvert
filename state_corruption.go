package main

// state_corruption.go — CHAOS-05/07: quarantine-don't-overwrite for
// present-but-corrupt security-critical state files.
//
// ui_users.json (admin roster + TOTP enrollments, CHAOS-05) and
// cluster.json (enrolled-node roster + revoked-cert list, CHAOS-07) were
// loaded with a log-and-continue posture: a corrupt file left an EMPTY
// in-memory store, and the next save atomically OVERWROTE the corrupt
// file. Admin accounts, TOTP secrets, and the revocation list (revoked
// DP certs validate again — the security-relevant half) were destroyed
// permanently, with one startup log line as the only trace.
//
// The F4 fix (fsynced atomic writes) removed the main CAUSE of torn
// files; this file is the RESPONSE to one. On a parse failure the loader
// now:
//  1. renames the corrupt file to <path>.corrupt.<unixnano> in the same
//     directory (same filesystem, so the rename is atomic and never a
//     copy) — no later save can destroy the evidence, and the operator
//     can inspect/repair/restore it;
//  2. fires a state_file_corrupt alert through deferStartupAlert — both
//     loads run before loadPersistentAdminState populates the webhook
//     store (the CHAOS-06 lesson);
//  3. records the failure for /readyz as a report-only fail row (the
//     CHAOS-06 posture): boot still proceeds with an empty store, since
//     both degradations are survivable (env fallback creds / node
//     re-enrollment) and refusing to boot could take down a fleet on a
//     single bad sector. Refuse-to-boot for cluster.json specifically is
//     a posture decision recorded as the CHAOS-05/07 remainder.
//
// Read errors (EACCES, EIO) deliberately do NOT quarantine: the content
// may be intact, and os.Rename needs only directory permissions, so
// quarantining could move a healthy file aside on a transient permission
// problem. Only a file we READ and could not PARSE is treated as corrupt.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	stateCorruptionMu     sync.Mutex
	stateCorruptionByKind = map[string]string{} // kind → detail, for /readyz
	// stateCorruptionRecordByKind mirrors stateCorruptionByKind but holds only
	// the SAFE subset of the evidence — no absolute file path or quarantine
	// filename — for the authenticated /api/diagnostics operator-contract row
	// (checkStateFileIntegrity), which is viewer-role and documented as never
	// returning raw paths (apiDiagnostics, diagnostics.go). The full detail,
	// including the path, stays log/alert-only as before.
	stateCorruptionRecordByKind = map[string]stateCorruptionRecord{}
)

// stateCorruptionRecord is the path-free view of one recorded corruption.
type stateCorruptionRecord struct {
	ParseErr         string // parseErr.Error(); "" for a residual-only record
	QuarantineFailed bool   // true when this boot's rename-aside attempt itself failed
	Residual         bool   // true when detected via a prior boot's leftover quarantine file(s)
	ResidualCount    int    // number of unreconciled quarantine siblings, when Residual
}

// stateCorruptionRecordsSnapshot returns a copy of the recorded (path-free)
// corruption evidence, keyed by kind. Empty when every state file on this
// node loaded cleanly.
func stateCorruptionRecordsSnapshot() map[string]stateCorruptionRecord {
	stateCorruptionMu.Lock()
	defer stateCorruptionMu.Unlock()
	out := make(map[string]stateCorruptionRecord, len(stateCorruptionRecordByKind))
	for k, v := range stateCorruptionRecordByKind {
		out[k] = v
	}
	return out
}

// stateCorruptionSnapshot returns a copy of the recorded state-file
// corruptions (kind → human-readable detail). Empty when every state
// file parsed cleanly.
func stateCorruptionSnapshot() map[string]string {
	stateCorruptionMu.Lock()
	defer stateCorruptionMu.Unlock()
	out := make(map[string]string, len(stateCorruptionByKind))
	for k, v := range stateCorruptionByKind {
		out[k] = v
	}
	return out
}

// resetStateCorruption clears the recorded corruptions. Test isolation
// only — production never un-records a corruption (the quarantine file
// persisting on disk is the durable signal).
func resetStateCorruption() {
	stateCorruptionMu.Lock()
	defer stateCorruptionMu.Unlock()
	stateCorruptionByKind = map[string]string{}
	stateCorruptionRecordByKind = map[string]stateCorruptionRecord{}
}

// quarantineCorruptStateFile moves a corrupt state file aside, fires the
// state_file_corrupt alert, and records the failure for /readyz. Returns
// the quarantine path, or "" when the rename itself failed (the loud log,
// alert, and /readyz row still happen — with an explicit warning that the
// evidence is still in the save path's line of fire).
func quarantineCorruptStateFile(kind, path string, parseErr error) string {
	qpath := fmt.Sprintf("%s.corrupt.%d", path, time.Now().UnixNano())
	var detail string
	if err := os.Rename(path, qpath); err != nil {
		qpath = ""
		detail = fmt.Sprintf("%s state file %s is corrupt (%v) and could not be quarantined (%v) — the next save WILL OVERWRITE it; copy it elsewhere now, then restore it or a backup and restart", kind, path, parseErr, err)
	} else {
		detail = fmt.Sprintf("%s state file %s is corrupt (%v) — quarantined to %s; running with an EMPTY %s store until the quarantined file or a backup is repaired, moved back, and the node restarted", kind, path, parseErr, qpath, kind)
	}
	logger.Printf("StateCorruption: %q", sanitizeLog(detail))

	stateCorruptionMu.Lock()
	stateCorruptionByKind[kind] = detail
	stateCorruptionRecordByKind[kind] = stateCorruptionRecord{
		ParseErr:         parseErr.Error(),
		QuarantineFailed: qpath == "",
	}
	stateCorruptionMu.Unlock()

	deferStartupAlert("state_file_corrupt", AlertPayload{Detail: detail, Source: "storage"})
	return qpath
}

// noteResidualQuarantine re-surfaces an UNRECONCILED corruption from a
// PRIOR boot. The in-memory record is process-local, so without this the
// /readyz row and alert vanish on the next restart even though the problem
// persists: a corrupt cluster.json is quarantined, the node keeps running
// and later saves a fresh EMPTY cluster.json, and on reboot that
// replacement parses cleanly — probes go green while the node still runs
// with the lost roster/revocation state and the .corrupt.* evidence sits
// unreconciled on disk. Called at load time (before the parse attempt, so
// a still-present quarantine surfaces whether or not the current file
// parses); the signal persists until the operator repairs/restores or
// removes the quarantined file. Fires at most once per boot, and never
// clobbers a richer same-boot record from quarantineCorruptStateFile.
func noteResidualQuarantine(kind, path string) {
	noteResidualQuarantinePaths(kind, path)
}

// noteResidualQuarantinePaths is noteResidualQuarantine for a kind whose
// state lives in more than one file (the per-capability MCP journals share
// one kind): the leftover quarantine siblings of every path are counted
// together into ONE record, so the second capability's residual is never
// dropped by the once-per-kind guard. Empty paths are ignored.
func noteResidualQuarantinePaths(kind string, paths ...string) {
	var matches []string
	path := "" // the first path that has leftover siblings, named in the detail
	for _, p := range paths {
		if p == "" {
			continue
		}
		m, err := filepath.Glob(globEscapeLiteral(p) + ".corrupt.*")
		if err != nil || len(m) == 0 {
			continue
		}
		if path == "" {
			path = p
		}
		matches = append(matches, m...)
	}
	if len(matches) == 0 {
		return
	}

	stateCorruptionMu.Lock()
	_, already := stateCorruptionByKind[kind]
	stateCorruptionMu.Unlock()
	if already {
		// A fresh quarantine this boot already recorded the richer detail.
		return
	}

	detail := fmt.Sprintf("%s state file %s has %d unreconciled quarantined sibling(s) from a prior corrupt load (e.g. %s) — the node may be running with an EMPTY %s store; repair/restore the quarantined file or remove it once reconciled, then restart", kind, path, len(matches), matches[0], kind)
	logger.Printf("StateCorruption: %q", sanitizeLog(detail))

	stateCorruptionMu.Lock()
	stateCorruptionByKind[kind] = detail
	stateCorruptionRecordByKind[kind] = stateCorruptionRecord{Residual: true, ResidualCount: len(matches)}
	stateCorruptionMu.Unlock()

	deferStartupAlert("state_file_corrupt", AlertPayload{Detail: detail, Source: "storage"})
}

// globEscapeLiteral escapes the filepath.Match metacharacters in a LITERAL
// path so it can prefix a glob pattern: CULVERT_DATA_DIR may be any absolute
// path, and an unescaped `[` (or `*`, `?`, `\`) in it would either fail the
// glob with ErrBadPattern or silently search a different path, dropping the
// residual-quarantine record after a restart.
func globEscapeLiteral(p string) string {
	var b strings.Builder
	b.Grow(len(p) + 8)
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '*' || c == '?' || c == '[':
			// A one-byte character class matches the byte literally on every
			// platform (Windows disables backslash escaping in Match).
			b.WriteByte('[')
			b.WriteByte(c)
			b.WriteByte(']')
		case c == '\\' && runtime.GOOS != "windows":
			b.WriteString(`\\`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// checkStateFileIntegrity is the `state_file_<kind>` authenticated
// operator-contract row: every recorded CHAOS-05/07 state-file quarantine,
// viewer-safe. It closes a gap /ready's appendStateFileChecks documents but
// does not itself provide — that row is deliberately generic ("see server
// logs") because /ready is unauthenticated on the proxy port, so an admin
// with no log/SSH access and no alert webhook configured had no way to learn
// WHICH state file was quarantined, why, or whether the situation is a fresh
// quarantine, an unreconciled leftover from a prior boot, or (most urgent) a
// quarantine attempt that itself failed — without reading the process log.
//
// Deliberately path-free: apiDiagnostics is viewer-role and documented as
// never returning raw file paths or filesystem layout; the recovery action
// (restore a backup, then restart) does not require the exact path, and the
// process log / state_file_corrupt alert payload still carry it in full.
// Read-only — reads the cached record only, never touches disk. Contributes
// nothing when every state file on this node loaded cleanly.
func checkStateFileIntegrity() []OperatorContractCheck {
	recs := stateCorruptionRecordsSnapshot()
	if len(recs) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(recs))
	for k := range recs {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	checks := make([]OperatorContractCheck, 0, len(kinds))
	for _, kind := range kinds {
		rec := recs[kind]
		switch {
		case rec.Residual:
			checks = append(checks, OperatorContractCheck{
				Code:   "state_file_" + kind,
				Status: diagWarn,
				Message: fmt.Sprintf("%s: %d unreconciled quarantined copy/copies remain from a prior corrupt load; the node may still be running with an empty %s store",
					kind, rec.ResidualCount, kind),
				OperatorAction: "Restore the quarantined copy or a backup on this node's data volume, then restart; once reconciled, remove the leftover quarantine file(s) to clear this row.",
			})
		case rec.QuarantineFailed:
			checks = append(checks, OperatorContractCheck{
				Code:   "state_file_" + kind,
				Status: diagFail,
				Message: fmt.Sprintf("%s state file is corrupt (%s) and could not be quarantined — the next save will overwrite it",
					kind, rec.ParseErr),
				OperatorAction: "Copy the state file aside by hand immediately, then restore it or a backup and restart.",
			})
		default:
			checks = append(checks, OperatorContractCheck{
				Code:   "state_file_" + kind,
				Status: diagWarn,
				Message: fmt.Sprintf("%s state file was corrupt (%s) and has been quarantined at startup; the node is running with an empty %s store",
					kind, rec.ParseErr, kind),
				OperatorAction: "Restore the quarantined copy or a backup on this node's data volume, then restart.",
			})
		}
	}
	return checks
}
