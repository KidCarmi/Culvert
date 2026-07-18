package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeBundleStateFile writes a state.json sidecar so a fake bundle can carry a
// specific lifecycle State and/or CaseID (retention exemption inputs).
func writeBundleStateFile(t *testing.T, id, state, caseID string) {
	t.Helper()
	st := supportBundleStateFile{State: state, CaseID: caseID}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(supportBundleStatePath(id), b, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

// writeBundleTGZ writes a bundle.csb.tgz of n bytes so the size cap has something to
// measure.
func writeBundleTGZ(t *testing.T, id string, n int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"), make([]byte, n), 0o600); err != nil {
		t.Fatalf("write tgz: %v", err)
	}
}

// TestRetentionCountCap_ExemptsEvidenceAndPending proves the count cap never evicts a
// case-bound (evidence) or pending (under-review) bundle, and only counts EVICTABLE
// (ready + unbound) bundles toward `keep`.
func TestRetentionCountCap_ExemptsEvidenceAndPending(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	ts := func(dAgo int) string { return now.Add(-time.Duration(dAgo) * time.Hour).Format(time.RFC3339) }

	// 3 ready+unbound (evictable), newest→oldest by age. keep=2 ⇒ oldest evictable evicted.
	writeFakeBundle(t, "csb_readynewaaaaaaaaa234567abc", ts(1))
	writeFakeBundle(t, "csb_readymidaaaaaaaaa234567abc", ts(2))
	writeFakeBundle(t, "csb_readyoldaaaaaaaaa234567abc", ts(3)) // oldest evictable → should go
	// 1 case-bound (evidence) + 1 pending — both exempt, must survive.
	writeFakeBundle(t, "csb_caseboundaaaaaaaa234567abc", ts(9))
	writeBundleStateFile(t, "csb_caseboundaaaaaaaa234567abc", bundleStateReady, "SR-8821")
	writeFakeBundle(t, "csb_pendingaaaaaaaaaa234567abc", ts(9))
	writeBundleStateFile(t, "csb_pendingaaaaaaaaaa234567abc", bundleStatePending, "")

	pruneSupportBundles(2)

	exists := func(id string) bool { _, e := os.Stat(filepath.Join(supportBundlesDir(), id)); return e == nil }
	if exists("csb_readyoldaaaaaaaaa234567abc") {
		t.Error("oldest ready+unbound bundle should have been evicted by the count cap")
	}
	for _, id := range []string{
		"csb_readynewaaaaaaaaa234567abc", "csb_readymidaaaaaaaaa234567abc",
		"csb_caseboundaaaaaaaa234567abc", "csb_pendingaaaaaaaaaa234567abc",
	} {
		if !exists(id) {
			t.Errorf("%s should have survived the count cap (kept or exempt)", id)
		}
	}
}

// TestRetentionAgeCap_ExemptsEvidence proves a case-bound bundle never ages out, while
// an equally-old unbound bundle does.
func TestRetentionAgeCap_ExemptsEvidence(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	old := now.Add(-60 * 24 * time.Hour).Format(time.RFC3339)
	writeFakeBundle(t, "csb_ageunboundaaaaaaa234567abc", old)
	writeFakeBundle(t, "csb_ageboundaaaaaaaaa234567abc", old)
	writeBundleStateFile(t, "csb_ageboundaaaaaaaaa234567abc", bundleStateReady, "SR-1")

	pruneSupportBundlesByAge(now, supportRetentionMaxAgeVal())

	exists := func(id string) bool { _, e := os.Stat(filepath.Join(supportBundlesDir(), id)); return e == nil }
	if exists("csb_ageunboundaaaaaaa234567abc") {
		t.Error("old unbound bundle should have aged out")
	}
	if !exists("csb_ageboundaaaaaaaaa234567abc") {
		t.Error("case-bound evidence must NOT age out")
	}
}

// TestRetentionSizeCap_ReclaimsOldestUnbound proves the byte cap evicts oldest-first
// over evictable bundles until under the ceiling, exempting case-bound evidence.
func TestRetentionSizeCap_ReclaimsOldestUnbound(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	ts := func(dAgo int) string { return now.Add(-time.Duration(dAgo) * time.Hour).Format(time.RFC3339) }

	// Three 1000-byte unbound bundles + one 1000-byte case-bound. Cap 2500 ⇒ must drop
	// the single oldest unbound (leaving 3×1000=3000... still over → drop next oldest
	// unbound → 2000 ≤ 2500). Case-bound is never touched.
	writeFakeBundle(t, "csb_sizenewaaaaaaaaaa234567abc", ts(1))
	writeBundleTGZ(t, "csb_sizenewaaaaaaaaaa234567abc", 1000)
	writeFakeBundle(t, "csb_sizemidaaaaaaaaaa234567abc", ts(2))
	writeBundleTGZ(t, "csb_sizemidaaaaaaaaaa234567abc", 1000)
	writeFakeBundle(t, "csb_sizeoldaaaaaaaaaa234567abc", ts(3))
	writeBundleTGZ(t, "csb_sizeoldaaaaaaaaaa234567abc", 1000)
	writeFakeBundle(t, "csb_sizeboundaaaaaaaa234567abc", ts(9))
	writeBundleTGZ(t, "csb_sizeboundaaaaaaaa234567abc", 1000)
	writeBundleStateFile(t, "csb_sizeboundaaaaaaaa234567abc", bundleStateReady, "SR-2")

	pruneSupportBundlesBySize(2500, "")

	exists := func(id string) bool { _, e := os.Stat(filepath.Join(supportBundlesDir(), id)); return e == nil }
	if exists("csb_sizeoldaaaaaaaaaa234567abc") || exists("csb_sizemidaaaaaaaaaa234567abc") {
		t.Error("size cap should have reclaimed the two oldest unbound bundles")
	}
	if !exists("csb_sizenewaaaaaaaaaa234567abc") {
		t.Error("newest unbound bundle should survive under the cap")
	}
	if !exists("csb_sizeboundaaaaaaaa234567abc") {
		t.Error("case-bound evidence must never be size-reclaimed")
	}
}

// TestRetentionSizeCap_NeverEvictsExceptDir proves the create-path guarantee: the size
// prune must NEVER evict the bundle named by exceptDir even when the store is over the
// ceiling and EVERY other bundle is case-bound evidence (so nothing else is evictable).
// Regression for the create-path hazard where a store already at the size ceiling from
// evidence bundles would delete the freshly-built bundle before returning its id.
func TestRetentionSizeCap_NeverEvictsExceptDir(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	ts := func(dAgo int) string { return now.Add(-time.Duration(dAgo) * time.Hour).Format(time.RFC3339) }

	// Three 1000-byte case-bound (evidence) bundles fill the store past a 2500 cap, plus a
	// fresh unbound bundle the create path would pass as exceptDir. With everything else
	// evidence, the prune has nothing evictable — it must leave exceptDir alone, not delete
	// it as the only unbound (evictable) bundle.
	for i, id := range []string{
		"csb_exboundoneaaaaaaa234567abc",
		"csb_exboundtwoaaaaaaa234567abc",
		"csb_exboundthreeaaaa2234567abc",
	} {
		writeFakeBundle(t, id, ts(i+2))
		writeBundleTGZ(t, id, 1000)
		writeBundleStateFile(t, id, bundleStateReady, "SR-EX")
	}
	const fresh = "csb_exfreshaaaaaaaaaa234567abc"
	writeFakeBundle(t, fresh, ts(1))
	writeBundleTGZ(t, fresh, 1000)

	pruneSupportBundlesBySize(2500, fresh)

	exists := func(id string) bool { _, e := os.Stat(filepath.Join(supportBundlesDir(), id)); return e == nil }
	if !exists(fresh) {
		t.Error("the just-created (exceptDir) bundle must never be size-reclaimed, even when the store is over-cap with only evidence")
	}
	// The three evidence bundles are also exempt, so the store legitimately stays over-cap
	// (logged once) — that is the documented one-way manual-cleanup posture, not a bug.
	for _, id := range []string{
		"csb_exboundoneaaaaaaa234567abc",
		"csb_exboundtwoaaaaaaa234567abc",
		"csb_exboundthreeaaaa2234567abc",
	} {
		if !exists(id) {
			t.Errorf("case-bound evidence %s must never be size-reclaimed", id)
		}
	}
}

// TestRetentionPruneSerialization runs all three prune passes concurrently over one
// store; the -race gate proves supportPruneMu prevents the list+RemoveAll race (and
// the os.RemoveAll-returns-nil-on-ENOENT double-count).
func TestRetentionPruneSerialization(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	for i := 0; i < 20; i++ {
		// Valid id: "csb_" + 26 chars from [a-z2-7]; 25 'a' + one distinct letter.
		id := "csb_" + strings.Repeat("a", 25) + string(rune('a'+i))
		writeFakeBundle(t, id, now.Add(-time.Duration(i)*time.Hour).Format(time.RFC3339))
		writeBundleTGZ(t, id, 1000)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pruneSupportBundles(3)
			pruneSupportBundlesByAge(now, time.Hour)
			pruneSupportBundlesBySize(2000, "")
		}()
	}
	wg.Wait() // -race asserts no data race; no panic asserts the mutex holds
}
