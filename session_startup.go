package main

// session_startup.go — startup-time loader for the session slice (PR3
// expansion, Batch 2). Seeds the HMAC secret, optionally loads persisted
// revocations, and applies the session TTL.

import (
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// loadSession applies cfg: seed the random session secret, override it
// from config if provided, attach the revocations file (if any) and load
// existing entries, then apply the TTL. Returns a non-fatal error only
// for the revocations-load path; callers typically log and continue.
func loadSession(cfg sessionStartupConfig) error {
	// Only fall through to the config-file secret when CULVERT_SESSION_SECRET
	// did not already supply the key — an explicit env value must win over
	// config.yaml's session_secret, not the other way around (session.go's
	// documented priority: env > config file > random).
	if envSet := initSessionSecret(); !envSet {
		initSessionSecretFromConfig(cfg.Secret)
	}

	if cfg.RevocationsFile != "" {
		session.SetRevocationsPath(cfg.RevocationsFile)
		noteRevocationPersistenceConfigured(cfg.RevocationsFile)
		// Surface an UNRECONCILED quarantine from a prior boot before the parse
		// attempt: this boot's file may parse cleanly precisely because a later
		// save replaced the corrupt one with a fresh EMPTY list, and probes
		// going green over a lost revocation list is the failure being closed.
		noteResidualQuarantine("session_revocations", cfg.RevocationsFile)
		if err := sessionRevoked.LoadRevocations(); err != nil {
			// CHAOS-68: a revocations file that was READ and could not be
			// PARSED is corrupt, and the pre-existing posture — log it, boot
			// with an empty list — is fail-OPEN on the one control that can
			// withdraw an already-issued session: every revoked cookie and
			// every deleted account's session works again for the rest of its
			// TTL, and the next SaveRevocations atomically OVERWRITES the
			// evidence. Quarantine it (move aside, never delete), fire the
			// existing state_file_corrupt alert, and record the /readyz row —
			// the same response ui_users.json and cluster.json already get,
			// with no new operator vocabulary.
			//
			// A READ failure is deliberately NOT quarantined: the content may
			// be intact behind a transient permission or I/O fault, and moving
			// a healthy security-critical file aside is the worse error. Same
			// rule, and the same reasoning, as state_corruption.go's.
			//
			// revocationLoadIsCorrupt is the SHARED predicate: the same call
			// decides whether to quarantine here and which remedy the
			// session_revocation contract row advertises. Classifying the
			// error separately in either place is how the action taken and
			// the action advertised drift apart — which is exactly what the
			// row did before, sending an operator after a .corrupt.* file
			// that an unreadable (never-quarantined) file does not have.
			//
			// AU-38: the corrupt branch does NOT fence writes because the
			// quarantine moves the file aside, freeing the path — but that is
			// only true when the rename SUCCEEDS. quarantineCorruptStateFile
			// returns "" when it fails, and its own log line says "the next
			// save WILL OVERWRITE it", so discarding that return left the only
			// copy of the corrupt evidence exposed to the first logout after
			// boot. Reproduced: a basename long enough that `.corrupt.<ns>`
			// exceeds the 255-byte filename limit while AtomicWrite's shorter
			// `.tmp.*` still fits, so the quarantine fails and the save
			// succeeds — destroying the file.
			if revocationLoadIsCorrupt(err) {
				if quarantineCorruptStateFile("session_revocations", cfg.RevocationsFile, err) == "" {
					sessionRevoked.FenceWritesUnquarantined()
					noteRevocationQuarantineFailed()
				}
			}
			noteRevocationLoadDegraded(err)
			return fmt.Errorf("load revocations: %w", err)
		}
	}

	if cfg.TimeoutHours > 0 {
		SetSessionTTL(time.Duration(cfg.TimeoutHours) * time.Hour)
		logger.Printf("Session: timeout %dh", cfg.TimeoutHours)
	}
	return nil
}
