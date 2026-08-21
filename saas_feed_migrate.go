package main

// saas_feed_migrate.go — F3a-1 pre-GA schema migration for the SaaS feed store
// (roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §A.5). Culvert is pre-GA (no
// customers), so this is a one-time, deterministic, idempotent initialization of
// the new feed-config schema boundary — NOT a provenance-reconstruction engine.
//
// Safety contract (all enforced here + pinned by saas_feed_migrate_test.go):
//   - runs only on an EXISTING settings file; a fresh install has nothing to migrate;
//   - idempotent via a durable schema marker (saas_store_schema_version);
//   - a file from a NEWER binary (marker > current) is REFUSED (fail-closed
//     downgrade guard) and never mutated;
//   - the existing file is BACKED UP (atomic) before the first persisted mutation;
//   - the migrated settings are committed ATOMICALLY (marker + fields together),
//     so no failure can partially expose new settings as committed;
//   - on ANY failure (backup/marshal/write) the in-memory struct is REVERTED, so
//     this boot behaves exactly as pre-migration and the migration retries next boot;
//   - it touches ONLY the feed schema fields — no unrelated AdminSettings field is
//     reset or rewritten;
//   - it does NOT reconstruct provenance from old values, and (in F3a-1) it does
//     NOT rewrite the persisted URL that the still-live legacy syncer reads — the
//     URL matrix is applied read-only by ResolveSaaSFeedConfig.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// saasStoreSchemaVersion is the current feed-store schema this binary writes and
// is the highest it can safely interpret.
const saasStoreSchemaVersion = 1

// ErrSaaSSchemaTooNew is returned when the persisted settings carry a feed-store
// schema newer than this binary supports (a downgrade). Fail closed; the file is
// left untouched.
var ErrSaaSSchemaTooNew = errors.New("saas feed store: settings schema is newer than this binary supports")

// SaaSMigrationReport is the observable result of a migration attempt.
type SaaSMigrationReport struct {
	Outcome       string // "already_current" | "migrated" | "downgrade_refused" | "failed"
	FromSchema    int
	ToSchema      int
	URLClass      string // "unset" | "historical" | "official" | "unsupported" (informational; URL not rewritten)
	ProtocolReset bool
	BackupPath    string
	Err           string // short, sanitized failure note (empty on success)
}

// classifyFeedURL reports how the persisted URL is classified by the §A.5.3
// matrix WITHOUT mutating it (informational for the migration report).
func classifyFeedURL(persisted string) string {
	p := strings.TrimSpace(persisted)
	if p == "" {
		return "unset"
	}
	for _, h := range historicalSaaSFeedURLs {
		if p == h {
			return "historical"
		}
	}
	if validateOfficialManifestURL(p) == nil {
		return "official"
	}
	return "unsupported"
}

// migrateSaaSFeedStore initializes the feed-config schema boundary on s in place
// and, when a migration is performed, backs up rawFile and atomically persists the
// migrated settings to path. rawFile is the exact pre-migration on-disk content
// (the caller already read it), preserved verbatim in the backup. now supplies the
// backup timestamp (injectable for deterministic tests).
func migrateSaaSFeedStore(s *AdminSettings, path string, rawFile []byte, now func() time.Time) (SaaSMigrationReport, error) {
	rep := SaaSMigrationReport{FromSchema: s.SaaSStoreSchemaVersion, ToSchema: saasStoreSchemaVersion}

	if s.SaaSStoreSchemaVersion > saasStoreSchemaVersion {
		rep.Outcome = "downgrade_refused"
		rep.Err = "schema newer than supported"
		return rep, fmt.Errorf("%w: file=%d supported=%d", ErrSaaSSchemaTooNew, s.SaaSStoreSchemaVersion, saasStoreSchemaVersion)
	}
	if s.SaaSStoreSchemaVersion == saasStoreSchemaVersion {
		rep.Outcome = "already_current" // idempotent
		return rep, nil
	}

	// Pre-F3a file (schema 0/absent). Capture pre-migration values for revert.
	prevSchema := s.SaaSStoreSchemaVersion
	prevProto := s.SaaSFeedProtocol
	revert := func() {
		s.SaaSStoreSchemaVersion = prevSchema
		s.SaaSFeedProtocol = prevProto
	}

	rep.URLClass = classifyFeedURL(s.SaaSFeedURL)

	// Canonicalize the protocol in-memory (inert in F3a-1). An unsupported value is
	// reset to the only legal protocol and reported; empty canonicalizes silently.
	if norm, err := resolveFeedProtocol(s.SaaSFeedProtocol); err != nil {
		rep.ProtocolReset = true
		s.SaaSFeedProtocol = saasFeedProtocolV1
	} else if norm != s.SaaSFeedProtocol {
		if prevProto != "" {
			rep.ProtocolReset = true
		}
		s.SaaSFeedProtocol = norm
	}
	s.SaaSStoreSchemaVersion = saasStoreSchemaVersion

	// Backup BEFORE the first persisted mutation. AtomicWrite gives temp+fsync+
	// rename+parent-fsync, so a crash never leaves a torn backup.
	bak := fmt.Sprintf("%s.pre-f3a-%d.bak", path, now().UTC().UnixNano())
	if err := fileutil.AtomicWrite(bak, rawFile, 0o600); err != nil {
		revert()
		rep.Outcome = "failed"
		rep.Err = "backup write failed"
		return rep, fmt.Errorf("saas migration: backup %s: %w", bak, err)
	}
	rep.BackupPath = bak

	// Commit the migrated settings atomically: marker + fields in one write.
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		revert()
		rep.Outcome = "failed"
		rep.Err = "marshal failed"
		return rep, fmt.Errorf("saas migration: marshal: %w", err)
	}
	if err := fileutil.AtomicWrite(path, data, 0o600); err != nil {
		revert()
		rep.Outcome = "failed"
		rep.Err = "settings write failed"
		return rep, fmt.Errorf("saas migration: persist %s: %w", path, err)
	}

	rep.Outcome = "migrated"
	return rep, nil
}
