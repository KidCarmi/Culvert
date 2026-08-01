package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) }
}

// writeSettings marshals s to a temp settings file and returns (path, rawBytes).
func writeSettings(t *testing.T, s AdminSettings) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, raw
}

// A pre-F3 settings file (no schema marker) migrates: marker set, backup created,
// legacy URL left UNTOUCHED (no live-behavior change), report accurate.
func TestMigrate_FromPreF3State(t *testing.T) {
	legacy := AdminSettings{SaaSFeedURL: historicalSaaSFeedURLs[0]}
	path, raw := writeSettings(t, legacy)

	s := legacy // in-memory struct as LoadAdminSettings would have it
	rep, err := migrateSaaSFeedStore(&s, path, raw, fixedClock())
	if err != nil {
		t.Fatalf("migration should succeed: %v", err)
	}
	if rep.Outcome != "migrated" || rep.ToSchema != saasStoreSchemaVersion {
		t.Fatalf("bad report: %+v", rep)
	}
	if rep.URLClass != "historical" {
		t.Errorf("url_class = %q; want historical", rep.URLClass)
	}
	if s.SaaSStoreSchemaVersion != saasStoreSchemaVersion {
		t.Errorf("in-memory marker not set: %d", s.SaaSStoreSchemaVersion)
	}
	if s.SaaSFeedURL != historicalSaaSFeedURLs[0] {
		t.Errorf("F3a-1 migration must NOT rewrite the persisted URL; got %q", s.SaaSFeedURL)
	}
	// Persisted file now carries the marker.
	var onDisk AdminSettings
	b, _ := os.ReadFile(path)
	_ = json.Unmarshal(b, &onDisk)
	if onDisk.SaaSStoreSchemaVersion != saasStoreSchemaVersion {
		t.Errorf("persisted marker not committed: %d", onDisk.SaaSStoreSchemaVersion)
	}
	// Backup exists and equals the ORIGINAL bytes.
	if rep.BackupPath == "" {
		t.Fatal("no backup path reported")
	}
	bak, err := os.ReadFile(rep.BackupPath)
	if err != nil {
		t.Fatalf("backup unreadable: %v", err)
	}
	if string(bak) != string(raw) {
		t.Errorf("backup does not equal the pre-migration bytes")
	}
}

// Migration is idempotent: a file already at the current schema is a no-op and is
// not rewritten.
func TestMigrate_Idempotent(t *testing.T) {
	s := AdminSettings{SaaSStoreSchemaVersion: saasStoreSchemaVersion}
	path, raw := writeSettings(t, s)
	before, _ := os.Stat(path)

	rep, err := migrateSaaSFeedStore(&s, path, raw, fixedClock())
	if err != nil || rep.Outcome != "already_current" {
		t.Fatalf("idempotent no-op expected; got outcome=%s err=%v", rep.Outcome, err)
	}
	// No backup should have been created (glob for .bak siblings).
	matches, _ := filepath.Glob(path + ".pre-f3a-*.bak")
	if len(matches) != 0 {
		t.Errorf("idempotent run must not create a backup; found %v", matches)
	}
	after, _ := os.Stat(path)
	if before.ModTime() != after.ModTime() || before.Size() != after.Size() {
		t.Errorf("idempotent run must not rewrite the file")
	}

	// Second run through migrate again is still a no-op (double idempotency).
	rep2, _ := migrateSaaSFeedStore(&s, path, raw, fixedClock())
	if rep2.Outcome != "already_current" {
		t.Errorf("second run not idempotent: %+v", rep2)
	}
}

// A file from a newer binary is refused (fail-closed downgrade guard); nothing is
// written and the in-memory struct is not advanced.
func TestMigrate_DowngradeRefused(t *testing.T) {
	s := AdminSettings{SaaSStoreSchemaVersion: saasStoreSchemaVersion + 1}
	path, raw := writeSettings(t, s)

	rep, err := migrateSaaSFeedStore(&s, path, raw, fixedClock())
	if !errors.Is(err, ErrSaaSSchemaTooNew) {
		t.Fatalf("want ErrSaaSSchemaTooNew; got %v", err)
	}
	if rep.Outcome != "downgrade_refused" {
		t.Errorf("outcome = %q; want downgrade_refused", rep.Outcome)
	}
	matches, _ := filepath.Glob(path + ".pre-f3a-*.bak")
	if len(matches) != 0 {
		t.Errorf("downgrade must not create a backup; found %v", matches)
	}
}

// An unsupported persisted protocol is reset to signed_manifest_v1 and reported;
// an unsupported URL is classified (not rewritten in F3a-1).
func TestMigrate_ResetsUnsupportedProtocol(t *testing.T) {
	s := AdminSettings{SaaSFeedProtocol: "legacy_raw_json_v0", SaaSFeedURL: "https://mirror.example.com/x.json"}
	path, raw := writeSettings(t, s)
	rep, err := migrateSaaSFeedStore(&s, path, raw, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ProtocolReset || s.SaaSFeedProtocol != saasFeedProtocolV1 {
		t.Errorf("unsupported protocol must reset to v1; report=%+v proto=%q", rep, s.SaaSFeedProtocol)
	}
	if rep.URLClass != "unsupported" {
		t.Errorf("url_class = %q; want unsupported", rep.URLClass)
	}
	if s.SaaSFeedURL != "https://mirror.example.com/x.json" {
		t.Errorf("F3a-1 migration must not rewrite the persisted URL")
	}
}

// Backup failure (unwritable parent) fails safely: error returned, outcome=failed,
// the in-memory marker is REVERTED, and the original file is untouched. Uses a
// regular file as the settings' parent directory so os.CreateTemp fails even for
// root (ENOTDIR) — no chmod races.
func TestMigrate_BackupFailure_RevertsAndFailsSafe(t *testing.T) {
	tmp := t.TempDir()
	fileAsParent := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fileAsParent, "admin_settings.json") // parent is a FILE
	s := AdminSettings{SaaSFeedURL: "https://x"}
	raw, _ := json.MarshalIndent(s, "", "  ")

	rep, err := migrateSaaSFeedStore(&s, path, raw, fixedClock())
	if err == nil {
		t.Fatalf("expected backup failure")
	}
	if rep.Outcome != "failed" {
		t.Errorf("outcome = %q; want failed", rep.Outcome)
	}
	// Fail-safe: in-memory schema reverted to pre-migration (0), so this boot
	// behaves exactly as un-migrated and retries next boot.
	if s.SaaSStoreSchemaVersion != 0 {
		t.Errorf("failed migration must revert the in-memory marker; got %d", s.SaaSStoreSchemaVersion)
	}
}

// Migration touches ONLY the feed schema fields — unrelated AdminSettings are
// preserved semantically.
func TestMigrate_UnrelatedSettingsUnchanged(t *testing.T) {
	orig := AdminSettings{
		BlocklistFeedURL: "https://blocklist.example/list.txt",
		YARATimeoutSecs:  42,
		SaaSFeedURL:      historicalSaaSFeedURLs[0],
	}
	path, raw := writeSettings(t, orig)

	s := orig
	if _, err := migrateSaaSFeedStore(&s, path, raw, fixedClock()); err != nil {
		t.Fatal(err)
	}
	var after AdminSettings
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &after); err != nil {
		t.Fatal(err)
	}
	if after.BlocklistFeedURL != orig.BlocklistFeedURL {
		t.Errorf("unrelated BlocklistFeedURL changed: %q → %q", orig.BlocklistFeedURL, after.BlocklistFeedURL)
	}
	if after.YARATimeoutSecs != orig.YARATimeoutSecs {
		t.Errorf("unrelated YARATimeoutSecs changed: %d → %d", orig.YARATimeoutSecs, after.YARATimeoutSecs)
	}
	if after.SaaSFeedURL != orig.SaaSFeedURL {
		t.Errorf("persisted SaaSFeedURL changed: %q → %q", orig.SaaSFeedURL, after.SaaSFeedURL)
	}
	if after.SaaSStoreSchemaVersion != saasStoreSchemaVersion {
		t.Errorf("marker not set on disk")
	}
}
