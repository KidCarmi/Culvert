package threatfeed

// allowlist_persist_test.go — regression coverage for the domain-allowlist
// empty-clear persistence quirk (moved in-package from package main's
// threatfeed_allowlist_persist_test.go at extraction, ADR-0002).
//
// Pre-fix shape: feedDB.DomainAllowlist had json:"domain_allowlist,omitempty"
// AND loadFromDisk gated restore on `len(db.DomainAllowlist) > 0`. So:
//   1. Admin clears the allowlist via SetDomainAllowlist([]).
//   2. saveToDisk marshals feedDB; the empty allowlist + omitempty drops
//      the field entirely.
//   3. On restart, loadFromDisk decodes db.DomainAllowlist as nil; the
//      `len > 0` guard skips the restore branch; Init's seeded defaults
//      (26 popular hosting platforms) silently come back.
// The admin's clear was reverted on every restart, with no signal.
//
// Fix shape: remove omitempty AND switch the load guard from `len > 0` to
// `!= nil`. Empty allowlist now serializes as `"domain_allowlist": []`, the
// load branch fires for the explicit empty case (wipe), and absent-field
// (legacy save / pre-allowlist DB) still falls through to "keep seeded
// defaults" — backward compatible.

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// TestThreatFeed_DomainAllowlist_PopulatedRoundTrip is the baseline:
// a populated admin allowlist must save and reload faithfully. Passes
// before and after the fix; pins that we didn't regress the working
// case while fixing the broken one.
func TestThreatFeed_DomainAllowlist_PopulatedRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "feed.json")

	tf1 := New()
	tf1.Init(dbPath, time.Hour) // seeds 26 defaults; load is a no-op (file missing)

	tf1.SetDomainAllowlist([]string{"example.com", "test.example"})

	tf2 := New()
	tf2.Init(dbPath, time.Hour) // seeds defaults, then loads from disk → replaces

	got := tf2.DomainAllowlist()
	want := []string{"example.com", "test.example"} // DomainAllowlist sorts
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("populated round-trip lost entries: got %v; want %v", got, want)
	}
}

// TestThreatFeed_DomainAllowlist_EmptyClearPersists is the regression-
// catch: an admin clear (SetDomainAllowlist([])) must survive restart.
// Without the fix, the empty save drops the field via omitempty and
// loadFromDisk's `len > 0` guard keeps the just-seeded 26 defaults —
// the admin's intent is silently reverted.
func TestThreatFeed_DomainAllowlist_EmptyClearPersists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "feed.json")

	tf1 := New()
	tf1.Init(dbPath, time.Hour)
	// Sanity: defaults were seeded.
	if n := len(tf1.DomainAllowlist()); n != len(defaultDomainAllowlist) {
		t.Fatalf("Init did not seed defaults: got %d entries, want %d", n, len(defaultDomainAllowlist))
	}

	tf1.SetDomainAllowlist([]string{}) // explicit clear → saves

	tf2 := New()
	tf2.Init(dbPath, time.Hour) // seeds defaults, then loads from disk

	got := tf2.DomainAllowlist()
	if len(got) != 0 {
		t.Fatalf("admin clear did not survive restart — got %d entries: %v (the empty-allowlist persistence quirk regressed)", len(got), got)
	}
}

// TestThreatFeed_DomainAllowlist_LegacyAbsentFieldKeepsDefaults pins
// the backward-compat half of the fix: a JSON file that does NOT
// contain a `domain_allowlist` field at all (a legacy save from before
// the omitempty fix, or any pre-allowlist DB shape) must still leave
// the Init-seeded defaults in place. The `!= nil` guard distinguishes
// "field absent" (keep defaults) from "field present but empty" (wipe).
func TestThreatFeed_DomainAllowlist_LegacyAbsentFieldKeepsDefaults(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "feed.json")

	// Hand-craft a legacy feedDB JSON with NO domain_allowlist field —
	// exactly what the pre-fix omitempty path produced when the
	// in-memory allowlist was empty.
	legacy := `{"last_sync":"0001-01-01T00:00:00Z","urls":{},"domains":{}}`
	if err := os.WriteFile(dbPath, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy DB: %v", err)
	}

	tf := New()
	tf.Init(dbPath, time.Hour) // seeds defaults, loads → field absent → keep defaults

	got := tf.DomainAllowlist()
	if len(got) != len(defaultDomainAllowlist) {
		t.Fatalf("legacy save (allowlist field absent) should preserve the %d seeded defaults; got %d: %v",
			len(defaultDomainAllowlist), len(got), got)
	}
}
