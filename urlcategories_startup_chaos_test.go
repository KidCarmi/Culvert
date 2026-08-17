package main

// urlcategories_startup_chaos_test.go — CHAOS-50 gates for the boot posture of
// the Layer-2 community category store.
//
// The defect these pin: a damaged store directory used to call logFatalf, so an
// unclean container kill turned an OPTIONAL, DERIVED cache into a permanent
// refusal to boot — no proxy, no admin UI, no health endpoint, and (with the
// shipped docker-compose.yml, which sets both `-cat-feed-db /data/catfeeddb`
// and `restart: unless-stopped`) an unattended crash-loop.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// swapCommunityDBGlobals isolates the process-wide store singletons so a
// degradation test cannot leak a nil (or a live handle) into another test.
func swapCommunityDBGlobals(t *testing.T) {
	t.Helper()
	prevDB, prevSyncer := communityDB, globalUT1FeedSyncer
	resetCatFeedDBHealthForTest()
	t.Cleanup(func() {
		if communityDB != nil && communityDB != prevDB {
			_ = communityDB.Close()
		}
		communityDB, globalUT1FeedSyncer = prevDB, prevSyncer
		resetCatFeedDBHealthForTest()
	})
	communityDB, globalUT1FeedSyncer = nil, nil
}

func seedCorruptStore(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	if err := db.BulkWrite(map[string]string{"example.com": "Social"}); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	mf := filepath.Join(dir, "MANIFEST")
	b, err := os.ReadFile(mf)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	for i := 8; i < len(b); i++ {
		b[i] ^= 0xFF
	}
	if err := os.WriteFile(mf, b, 0o600); err != nil {
		t.Fatalf("corrupt manifest: %v", err)
	}
	return dir
}

// THE gate. loadCommunityFeedDB must RETURN on a damaged store. Run in a child
// process so a regression to logFatalf is observed as the process exit it
// actually is, rather than silently taking the whole test binary down.
func TestLoadCommunityFeedDB_DamagedStoreDoesNotKillTheProcess(t *testing.T) {
	if dir := os.Getenv("CULVERT_CATFEEDDB_BOOT_CHILD"); dir != "" {
		cfg := urlCategoriesStartupConfig{FeedDBPath: dir}
		syncer := loadCommunityFeedDB(cfg, t.Context())
		_ = syncer
		if communityDB != nil {
			_ = communityDB.Close()
		}
		os.Stdout.WriteString("child: boot completed\n")
		return
	}

	dir := seedCorruptStore(t)
	cmd := exec.Command(os.Args[0], "-test.run", "TestLoadCommunityFeedDB_DamagedStoreDoesNotKillTheProcess")
	cmd.Env = append(os.Environ(), "CULVERT_CATFEEDDB_BOOT_CHILD="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "child: boot completed") {
		t.Fatalf("boot did not survive a damaged community store (exit %v). A category CACHE must never be able to stop an in-line gateway from starting.\n%s", err, out)
	}
}

// An ENVIRONMENTAL failure (missing volume, wrong mount, no permission) is not
// recoverable by quarantine, so the store simply goes away and the node keeps
// serving on Layer 1 — byte-identical to running without `-cat-feed-db`.
func TestLoadCommunityFeedDB_EnvironmentalFailureDegradesToLayer1(t *testing.T) {
	swapCommunityDBGlobals(t)

	base := t.TempDir()
	notADir := filepath.Join(base, "catfeeddb")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	syncer := loadCommunityFeedDB(urlCategoriesStartupConfig{FeedDBPath: notADir}, t.Context())
	if syncer != nil {
		t.Error("a feed syncer was started against a store that never opened")
	}
	if communityDB != nil {
		t.Error("communityDB must stay nil so every Layer-2 consumer's nil guard applies")
	}
	h := catFeedDBState()
	if !h.Configured || h.Available {
		t.Errorf("health = %+v, want configured and unavailable", h)
	}
	if h.Quarantines != 0 {
		t.Errorf("environmental failure quarantined %d copies — a rename fixes none of these faults", h.Quarantines)
	}
	if got := checkCategoryFeedDB(); got.Status != diagWarn {
		t.Errorf("diagnostics status = %q, want warn (the gateway is serving; a fail row would misreport it)", got.Status)
	}
}

// A CORRUPT store self-heals: quarantined, re-created empty, and the syncer is
// started so the feed refills it.
func TestLoadCommunityFeedDB_CorruptStoreSelfHealsAndKeepsServing(t *testing.T) {
	swapCommunityDBGlobals(t)
	dir := seedCorruptStore(t)

	syncer := loadCommunityFeedDB(urlCategoriesStartupConfig{FeedDBPath: dir}, t.Context())
	if syncer == nil || communityDB == nil {
		t.Fatal("a recoverable store did not come up")
	}
	h := catFeedDBState()
	if !h.Available || !h.Recovered {
		t.Errorf("health = %+v, want available and recovered", h)
	}
	if h.ResidualCopies != 1 {
		t.Errorf("ResidualCopies = %d, want 1 (the evidence must be kept, not deleted)", h.ResidualCopies)
	}
	if got := checkCategoryFeedDB(); got.Status != diagWarn || got.OperatorAction == "" {
		t.Errorf("recovery row = %+v, want a warn carrying an operator action", got)
	}
	if q := catdb.QuarantinedCopies(dir); len(q) != 1 {
		t.Errorf("quarantined copies on disk = %v, want 1", q)
	}
}

// A healthy store with no history is unremarkable — no warn, no noise.
func TestLoadCommunityFeedDB_HealthyStoreIsQuiet(t *testing.T) {
	swapCommunityDBGlobals(t)
	dir := filepath.Join(t.TempDir(), "catfeeddb")

	if syncer := loadCommunityFeedDB(urlCategoriesStartupConfig{FeedDBPath: dir}, t.Context()); syncer == nil {
		t.Fatal("healthy store did not come up")
	}
	if got := checkCategoryFeedDB(); got.Status != diagOK {
		t.Errorf("healthy store row = %+v, want ok", got)
	}
}

// An unconfigured feed must not produce a diagnostics row that looks like a
// problem — most deployments never enable Layer 2.
func TestCheckCategoryFeedDB_UnconfiguredIsOK(t *testing.T) {
	resetCatFeedDBHealthForTest()
	t.Cleanup(resetCatFeedDBHealthForTest)
	got := checkCategoryFeedDB()
	if got.Status != diagOK || got.Code != "category_feed_db" {
		t.Errorf("unconfigured row = %+v, want an ok category_feed_db row", got)
	}
}

// Evidence from an earlier incident stays visible after the store itself is
// healthy again: the in-memory record does not survive a restart, but the
// `.corrupt.*` directory on the volume does, and it is disk the operator has
// not reclaimed.
func TestCheckCategoryFeedDB_UnreconciledQuarantineStaysVisible(t *testing.T) {
	resetCatFeedDBHealthForTest()
	t.Cleanup(resetCatFeedDBHealthForTest)
	noteCatFeedDBState(catFeedDBHealth{
		Configured: true, Available: true, Path: "/data/catfeeddb", ResidualCopies: 1,
	})
	got := checkCategoryFeedDB()
	if got.Status != diagWarn {
		t.Errorf("status = %q, want warn", got.Status)
	}
	if !strings.Contains(got.Message, "quarantined") {
		t.Errorf("message does not mention the quarantine: %q", got.Message)
	}
}

// The viewer-role diagnostics surface must not leak the raw store path or the
// raw badger error. Both go to the logs and the alert instead — the same
// guardrail the root_ca row carries (CHAOS-28).
func TestCheckCategoryFeedDB_RowCarriesNoRawCause(t *testing.T) {
	resetCatFeedDBHealthForTest()
	t.Cleanup(resetCatFeedDBHealthForTest)
	noteCatFeedDBState(catFeedDBHealth{
		Configured: true,
		Available:  false,
		Path:       "/srv/culvert/data/catfeeddb",
		Detail:     `Buffer length: 4294967295 greater than file size: 30. Manifest file might be corrupted`,
	})
	got := checkCategoryFeedDB()
	for _, leak := range []string{"/srv/culvert", "Buffer length", "Manifest file"} {
		if strings.Contains(got.Message+got.OperatorAction, leak) {
			t.Errorf("diagnostics row leaks %q: %+v", leak, got)
		}
	}
}

// Structural guard against a regression to the fatal posture. The Layer-1
// catStore load in the same file is deliberately still fatal (it IS the
// policy-load-bearing tier); this pins only the Layer-2 loader.
func TestLoadCommunityFeedDB_SourceHasNoFatalExit(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "urlcategories_startup.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	start := strings.Index(string(src), "func loadCommunityFeedDB(")
	if start < 0 {
		t.Fatal("loadCommunityFeedDB not found — update this guard alongside the rename")
	}
	body := string(src)[start:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	for _, banned := range []string{"logFatalf(", "log.Fatal", "os.Exit("} {
		if strings.Contains(body, banned) {
			t.Errorf("loadCommunityFeedDB contains %q — a Layer-2 CACHE must never stop an in-line gateway from booting", banned)
		}
	}
}

// The three exposition series. Pinned because they are the only signal an
// operator has that a node quietly dropped to Layer-1-only categorisation, and
// `available 0` must be emitted (not omitted) so an alerting rule can key on it.
func TestMetrics_CatFeedDBSeries(t *testing.T) {
	resetCatFeedDBHealthForTest()
	t.Cleanup(resetCatFeedDBHealthForTest)

	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_catfeeddb_available 0",
		"culvert_catfeeddb_recovered 0",
		"culvert_catfeeddb_quarantined_copies 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q missing from /metrics on an unconfigured node", want)
		}
	}

	noteCatFeedDBState(catFeedDBHealth{
		Configured: true, Available: true, Recovered: true, Quarantines: 1, ResidualCopies: 2,
	})
	body = renderMetrics(t)
	for _, want := range []string{
		"culvert_catfeeddb_available 1",
		"culvert_catfeeddb_recovered 1",
		"culvert_catfeeddb_quarantined_copies 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q missing from /metrics after a recovery", want)
		}
	}
}
