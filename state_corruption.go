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
	"sync"
	"time"
)

var (
	stateCorruptionMu     sync.Mutex
	stateCorruptionByKind = map[string]string{} // kind → detail, for /readyz
)

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
	stateCorruptionMu.Unlock()

	deferStartupAlert("state_file_corrupt", AlertPayload{Detail: detail, Source: "storage"})
	return qpath
}
