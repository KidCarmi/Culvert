package main

// configversion_rate_limit_exempt_test.go — regression coverage for the
// RateLimitExempt rollback-surface completion (Finding 10.3 PR-2). Per
// roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md.
//
// Before this extension, captureConfigBackup recorded RateLimitRPM but NOT
// the exemption list, and applyConfigBackup/diffConfigs ignored exemptions
// entirely — so a config version created by the security.update handler
// reverted the RPM on rollback but silently dropped the exemption changes
// (rollback "lied"). These tests pin the corrected round-trip plus the
// nil-skip / explicit-[] semantics shared with CategoryGroups/URLCategories.
//
// findChange / assertNameInList / assertNoChange are defined in
// configversion_category_groups_test.go (same package).

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// snapshotRateLimiter captures and restores rl's exemption whitelist AND
// configured RPM so these tests do not pollute siblings under
// -shuffle=on / -count=N. Uses the new ReplaceExemptions primitive for the
// whitelist restore.
func snapshotRateLimiter(t *testing.T) {
	t.Helper()
	origExempt := rl.ListExemptions()
	origLimit := rl.Limit()
	t.Cleanup(func() {
		rl.ReplaceExemptions(origExempt)
		rl.Configure(origLimit, time.Minute)
	})
}

func sortedExemptions(t *testing.T) []string {
	t.Helper()
	out := rl.ListExemptions()
	sort.Strings(out)
	return out
}

// ─── Test 1: round-trip (RPM + exemptions together) ───────────────────

// TestConfigVersion_RateLimitExempt_RoundTrip is the regression-catch for
// the core fix: a v1 snapshot must restore BOTH the RPM and the exemption
// list on rollback. Without the capture/apply additions, exemptions would
// stay at the mutated v2 value while RPM reverted — the intra-subsystem
// inconsistency this PR closes.
func TestConfigVersion_RateLimitExempt_RoundTrip(t *testing.T) {
	snapshotRateLimiter(t)
	tmp := snapshotConfigVersionsDir(t)

	// Seed v1: known RPM + an IP and a CIDR exemption.
	rl.Configure(120, time.Minute)
	rl.ReplaceExemptions([]string{"203.0.113.7", "198.51.100.0/24"})

	saveConfigVersion("rate-exempt-round-trip", "v1")

	// Mutate to v2: different RPM + a different exemption.
	rl.Configure(60, time.Minute)
	rl.ReplaceExemptions([]string{"192.0.2.1"})

	loadAndApplyV1Envelope(t, tmp)

	got := sortedExemptions(t)
	want := []string{"198.51.100.0/24", "203.0.113.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("exemptions after rollback = %v; want %v — rollback dropped the exemption restore", got, want)
	}
	if rl.Limit() != 120 {
		t.Errorf("RPM after rollback = %d; want 120 (RPM/exempt must roll back together)", rl.Limit())
	}
}

// ─── Test 2: nil snapshot is a no-op ──────────────────────────────────

// TestConfigVersion_RateLimitExempt_NilSnapshotIsNoOp pins the backward-
// compat contract: a configBackup whose RateLimitExempt is nil (an old
// pre-extension snapshot) leaves the live whitelist untouched.
func TestConfigVersion_RateLimitExempt_NilSnapshotIsNoOp(t *testing.T) {
	snapshotRateLimiter(t)
	rl.ReplaceExemptions([]string{"203.0.113.9"})
	pre := sortedExemptions(t)

	backup := configBackup{
		Version:    1,
		ExportedAt: "test",
		// RateLimitExempt: nil — pre-extension shape.
	}
	applyConfigBackup(&backup)

	post := sortedExemptions(t)
	if !reflect.DeepEqual(pre, post) {
		t.Errorf("nil-snapshot apply mutated exemptions: pre=%v post=%v", pre, post)
	}
}

// ─── Test 3: explicit [] wipes ────────────────────────────────────────

// TestConfigVersion_RateLimitExempt_EmptySnapshotWipes pins the wipe
// half: a snapshot recorded at zero exemptions (non-nil []string{}) clears
// the live whitelist on rollback. The nil-skip guard must key on nil, not
// len()==0, or this wipe would be silently dropped.
func TestConfigVersion_RateLimitExempt_EmptySnapshotWipes(t *testing.T) {
	snapshotRateLimiter(t)
	rl.ReplaceExemptions([]string{"203.0.113.10"})

	backup := configBackup{
		Version:         1,
		ExportedAt:      "test",
		RateLimitExempt: []string{}, // explicit empty
	}
	applyConfigBackup(&backup)

	if got := rl.ListExemptions(); len(got) != 0 {
		t.Errorf("empty-snapshot apply did NOT wipe exemptions: got %v", got)
	}
}

// ─── Test 4: diffConfigs reports add/remove ───────────────────────────

// TestConfigVersion_RateLimitExempt_DiffReportsChanges pins the dry-run
// preflight accuracy: diffConfigs must surface rate_limit_exempt so a
// rollback preview reflects the actual exemption delta. Without the
// diffStringList call, dry-run would claim "no change" while apply mutates
// the whitelist — the rollback "lie" this PR also closes.
func TestConfigVersion_RateLimitExempt_DiffReportsChanges(t *testing.T) {
	a := &configBackup{RateLimitExempt: []string{"203.0.113.1", "203.0.113.2"}}
	b := &configBackup{RateLimitExempt: []string{"203.0.113.1", "203.0.113.3"}}

	change := findChange(t, diffConfigs(a, b), "rate_limit_exempt")
	assertNameInList(t, change.To, "added", "203.0.113.3")
	assertNameInList(t, change.From, "removed", "203.0.113.2")
}

// ─── Test 5: diff nil-skip mirrors apply ──────────────────────────────

// TestConfigVersion_RateLimitExempt_DiffNilSkipsField pins the diff
// nil-skip: a nil target (pre-extension snapshot) must produce no
// rate_limit_exempt diff, mirroring applyConfigBackup's no-op — otherwise
// rolling back to an old snapshot would report every live exemption as
// removed while apply leaves them untouched.
func TestConfigVersion_RateLimitExempt_DiffNilSkipsField(t *testing.T) {
	a := &configBackup{RateLimitExempt: []string{"203.0.113.1"}}
	b := &configBackup{ /* RateLimitExempt nil */ }

	assertNoChange(t, diffConfigs(a, b), "rate_limit_exempt")
}

// ─── Test 6: empty marshals as [] not null ────────────────────────────

// TestConfigVersion_RateLimitExempt_EmptyMarshalsAsArray pins the JSON
// shape contract: a snapshot with zero exemptions must serialize as
// "rateLimitExempt":[] (NOT omitted, NOT null), so a zero-exemption v1
// round-trips as a wipe rather than a nil-skip. Guards the omitempty
// removal AND the non-nil-empty ListExemptions contract.
func TestConfigVersion_RateLimitExempt_EmptyMarshalsAsArray(t *testing.T) {
	snapshotRateLimiter(t)
	rl.ReplaceExemptions(nil) // zero exemptions

	backup := captureConfigBackup()
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"rateLimitExempt":[]`) {
		t.Errorf(`expected "rateLimitExempt":[] in marshaled snapshot; got: %s`, js)
	}
	if strings.Contains(js, `"rateLimitExempt":null`) {
		t.Errorf(`marshaled snapshot has "rateLimitExempt":null — omitempty must be absent AND ListExemptions must return non-nil empty: %s`, js)
	}
}
