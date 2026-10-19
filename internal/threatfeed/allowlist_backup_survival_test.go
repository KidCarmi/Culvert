package threatfeed

// allowlist_backup_survival_test.go — the admin-managed domain allowlist must
// survive an encrypted backup restored onto a FRESH appliance, independently of
// the disposable threat-feed DB (owner P1 review, PR #1528). backup.go omits the
// feed DB (a re-downloadable cache) by design; the allowlist is persisted to a
// SEPARATE file (threat_domain_allowlist.json) that IS backed up. These tests
// model "fresh recovery" as a new Feed whose feed-DB path is ABSENT (the cache
// is gone on a fresh volume) while the standalone allowlist file is present
// (carried over by the restore). Re-adding the entry is NOT what is tested —
// survival of the ORIGINAL configuration is.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// freshFeedDBPath returns a path inside a brand-new temp dir — a feed DB that
// does NOT exist, modelling the disposable cache missing after a restore onto a
// fresh volume.
func freshFeedDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "feed.json")
}

// TestAllowlist_CustomEntriesSurviveFreshRecovery: an admin sets a custom
// allowlist; a fresh appliance (feed DB absent) that restored only the
// standalone allowlist file must come up with exactly that list — not defaults.
func TestAllowlist_CustomEntriesSurviveFreshRecovery(t *testing.T) {
	allowlistPath := filepath.Join(t.TempDir(), "threat_domain_allowlist.json")

	orig := New()
	orig.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)
	if err := orig.SetDomainAllowlist([]string{"marker-survives.example", "github.com"}); err != nil {
		t.Fatalf("SetDomainAllowlist: %v", err)
	}

	// Fresh recovery: feed DB gone (new absent path), allowlist file restored.
	recovered := New()
	recovered.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)

	got := recovered.DomainAllowlist()
	want := []string{"github.com", "marker-survives.example"} // DomainAllowlist sorts
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("admin allowlist did not survive fresh recovery: got %v; want %v", got, want)
	}
}

// TestAllowlist_ExplicitClearSurvivesFreshRecovery: an explicit full clear is a
// deliberate security posture and must survive fresh recovery as EMPTY — the
// seeded defaults must NOT silently come back (the absent-vs-empty contract).
func TestAllowlist_ExplicitClearSurvivesFreshRecovery(t *testing.T) {
	allowlistPath := filepath.Join(t.TempDir(), "threat_domain_allowlist.json")

	orig := New()
	orig.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)
	if n := len(orig.DomainAllowlist()); n != len(defaultDomainAllowlist) {
		t.Fatalf("Init did not seed defaults: got %d, want %d", n, len(defaultDomainAllowlist))
	}
	if err := orig.SetDomainAllowlist([]string{}); err != nil { // explicit clear
		t.Fatalf("clear: %v", err)
	}

	recovered := New()
	recovered.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)

	if got := recovered.DomainAllowlist(); len(got) != 0 {
		t.Fatalf("explicit clear did not survive fresh recovery — defaults returned: %v", got)
	}
}

// TestAllowlist_AbsentFileSeedsDefaultsAndWritesIt: a fresh install (no feed DB,
// no allowlist file) seeds defaults AND writes the standalone file, so the very
// first backup already captures the admin-managed surface.
func TestAllowlist_AbsentFileSeedsDefaultsAndWritesIt(t *testing.T) {
	allowlistPath := filepath.Join(t.TempDir(), "threat_domain_allowlist.json")

	tf := New()
	tf.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)

	if n := len(tf.DomainAllowlist()); n != len(defaultDomainAllowlist) {
		t.Fatalf("fresh install should seed defaults: got %d, want %d", n, len(defaultDomainAllowlist))
	}
	if _, err := os.Stat(allowlistPath); err != nil {
		t.Fatalf("Init should have written the standalone allowlist file for backup: %v", err)
	}
	// And a backup/restore of that file reproduces the defaults on a fresh node.
	recovered := New()
	recovered.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)
	if n := len(recovered.DomainAllowlist()); n != len(defaultDomainAllowlist) {
		t.Fatalf("defaults did not round-trip through the standalone file: got %d", n)
	}
}

// TestAllowlist_MigratesLegacyFeedDBOnFirstBoot: an appliance upgraded from a
// pre-fix binary has the admin allowlist ONLY in the feed DB. First boot with
// the fix must migrate it into the standalone (backed-up) file, so the next
// backup preserves it even though the admin never re-edited it.
func TestAllowlist_MigratesLegacyFeedDBOnFirstBoot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "feed.json")
	allowlistPath := filepath.Join(t.TempDir(), "threat_domain_allowlist.json")

	// Pre-fix: allowlist lives in the feed DB only (allowlistPath "").
	legacy := New()
	legacy.Init(dbPath, time.Hour)
	if err := legacy.SetDomainAllowlist([]string{"legacy-custom.example"}); err != nil {
		t.Fatalf("legacy set: %v", err)
	}
	if _, err := os.Stat(allowlistPath); !os.IsNotExist(err) {
		t.Fatalf("precondition: standalone file must not exist yet (err=%v)", err)
	}

	// First boot WITH the fix: feed DB present, standalone file absent → migrate.
	upgraded := New()
	upgraded.InitWithAllowlist(dbPath, allowlistPath, time.Hour)
	if _, err := os.Stat(allowlistPath); err != nil {
		t.Fatalf("first boot did not migrate the legacy allowlist into the backed-up file: %v", err)
	}
	if got, want := upgraded.DomainAllowlist(), []string{"legacy-custom.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("migrated allowlist wrong: got %v; want %v", got, want)
	}

	// Now a fresh recovery with ONLY the migrated file (feed DB gone) preserves it.
	recovered := New()
	recovered.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)
	if got, want := recovered.DomainAllowlist(), []string{"legacy-custom.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("migrated allowlist did not survive fresh recovery: got %v; want %v", got, want)
	}
}

// TestAllowlist_StandaloneFileIsAuthoritativeOverFeedDB: when both the feed DB
// and the standalone file carry an allowlist, the standalone file wins (it is
// the source of truth and the only copy a backup carries).
func TestAllowlist_StandaloneFileIsAuthoritativeOverFeedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "feed.json")
	allowlistPath := filepath.Join(t.TempDir(), "threat_domain_allowlist.json")

	// Seed the feed DB with one list (pre-fix style), then write a DIFFERENT
	// standalone file (as a restore would place).
	legacy := New()
	legacy.Init(dbPath, time.Hour)
	if err := legacy.SetDomainAllowlist([]string{"from-feed-db.example"}); err != nil {
		t.Fatalf("seed feed db: %v", err)
	}
	fileList := []string{"from-standalone.example"}
	writeAllowlistFile(t, allowlistPath, &fileList)

	tf := New()
	tf.InitWithAllowlist(dbPath, allowlistPath, time.Hour)
	if got, want := tf.DomainAllowlist(), []string{"from-standalone.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("standalone file should win: got %v; want %v", got, want)
	}
}

// TestAllowlist_FileFormat_AbsentVsEmpty pins the on-disk contract: a cleared
// allowlist writes an explicit empty array (not an absent field), which is what
// lets fresh recovery tell "admin cleared" from "never configured".
func TestAllowlist_FileFormat_AbsentVsEmpty(t *testing.T) {
	allowlistPath := filepath.Join(t.TempDir(), "threat_domain_allowlist.json")
	tf := New()
	tf.InitWithAllowlist(freshFeedDBPath(t), allowlistPath, time.Hour)
	if err := tf.SetDomainAllowlist([]string{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	data, err := os.ReadFile(allowlistPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f domainAllowlistFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.DomainAllowlist == nil {
		t.Fatalf("cleared allowlist must serialize the field (empty array), not omit it: %s", data)
	}
	if len(*f.DomainAllowlist) != 0 {
		t.Fatalf("cleared allowlist must be empty, got %v", *f.DomainAllowlist)
	}
	// A present-but-no-field file is NOT authoritative (keeps current state).
	noField := filepath.Join(t.TempDir(), "nofield.json")
	if err := os.WriteFile(noField, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	tf2 := New()
	tf2.allowlistPath = noField
	if auth, err := tf2.loadAllowlistFromDisk(); err != nil || auth {
		t.Fatalf("present-but-no-field file must be non-authoritative: auth=%v err=%v", auth, err)
	}
}

func writeAllowlistFile(t *testing.T, path string, list *[]string) {
	t.Helper()
	data, err := json.MarshalIndent(domainAllowlistFile{Version: 1, DomainAllowlist: list}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
