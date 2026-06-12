package main

// blocklist_normalize_test.go — coverage for normalizeBlocklistLine, the
// /etc/hosts-format feed parsing fix, per-feed attribution, and the
// load-time repair of entries stored verbatim by pre-normalization imports
// ("0.0.0.0 ads.example" rows that could never match a request host).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeBlocklistLine(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		// Plain domain lists.
		{"example.com", "example.com", true},
		{"  spaces.net  ", "spaces.net", true},
		{"UPPER.COM", "upper.com", true},
		{"*.wild.org", "*.wild.org", true},
		{"https://stripped.com/path?q=1", "stripped.com", true},
		{"host.com:8080", "host.com", true},
		// Comments and blanks.
		{"", "", false},
		{"# comment", "", false},
		{"ads.example # inline comment", "ads.example", true},
		// /etc/hosts format (StevenBlack et al).
		{"0.0.0.0 ads.example", "ads.example", true},
		{"127.0.0.1 tracker.example", "tracker.example", true},
		{"0.0.0.0 ads.example # comment", "ads.example", true},
		{"0.0.0.0\tads.tabbed.example", "ads.tabbed.example", true},
		// Hosts-file boilerplate must be skipped, not blocked.
		{"127.0.0.1 localhost", "", false},
		{"127.0.0.1 localhost.localdomain", "", false},
		{"255.255.255.255 broadcasthost", "", false},
		{"::1 ip6-localhost", "", false},
		{"ff02::1 ip6-allnodes", "", false},
		// Unblockable IP targets.
		{"0.0.0.0 0.0.0.0", "", false},
		{"0.0.0.0", "", false},
		{"127.0.0.1", "", false},
		// A public IP entry is a legitimate block target.
		{"203.0.113.7", "203.0.113.7", true},
		{"0.0.0.0 203.0.113.7", "203.0.113.7", true},
		// FQDN trailing dot canonicalized away.
		{"example.com.", "example.com", true},
		{"0.0.0.0 ads.example.", "ads.example", true},
		{".", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeBlocklistLine(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("normalizeBlocklistLine(%q) = (%q, %v); want (%q, %v)",
				tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestMergeFromLines_HostsFileFormat(t *testing.T) {
	b := newBlocklist()
	added := b.MergeFromLines([]string{
		"# StevenBlack-style header",
		"127.0.0.1 localhost",
		"0.0.0.0 0.0.0.0",
		"0.0.0.0 ads.hosts-format.invalid",
		"0.0.0.0 tracker.hosts-format.invalid",
		"plain.domain.invalid",
	}, "")
	if added != 3 {
		t.Errorf("added = %d; want 3 (two hosts-format + one plain)", added)
	}
	if !b.isListed("ads.hosts-format.invalid") {
		t.Error("ads.hosts-format.invalid should be blockable after hosts-format normalization")
	}
	if b.isListed("0.0.0.0 ads.hosts-format.invalid") {
		t.Error("verbatim hosts-format line must NOT be stored as an entry")
	}
	if b.isListed("localhost") {
		t.Error("hosts-file boilerplate (localhost) must not be imported")
	}
}

func TestMergeFromLines_FeedAttribution(t *testing.T) {
	b := newBlocklist()
	b.manual = map[string]bool{}
	b.AddManual("manual.attr.invalid")

	const feed = "https://feeds.example/attr.txt"
	b.MergeFromLines([]string{"fed.attr.invalid", "manual.attr.invalid", "*.wild.attr.invalid"}, feed)

	entries := b.ListWithSource()
	byHost := map[string]BlocklistEntry{}
	for _, e := range entries {
		byHost[e.Host] = e
	}
	if e := byHost["fed.attr.invalid"]; e.Source != "feed" || e.Feed != feed {
		t.Errorf("fed.attr.invalid = %+v; want source=feed, feed=%s", e, feed)
	}
	if e := byHost["*.wild.attr.invalid"]; e.Source != "feed" || e.Feed != feed {
		t.Errorf("*.wild.attr.invalid = %+v; want source=feed, feed=%s", e, feed)
	}
	// Admin-added entries keep their badge and never gain feed attribution.
	if e := byHost["manual.attr.invalid"]; e.Source != "manual" || e.Feed != "" {
		t.Errorf("manual.attr.invalid = %+v; want source=manual, no feed", e)
	}
}

// TestBlocklistLoad_RepairsPreNormalizationEntries: a main file written by
// the pre-fix importer contains verbatim "0.0.0.0 domain" rows and junk
// "0.0.0.0 0.0.0.0" rows. Load must repair the former into blockable
// hostnames and drop the latter.
func TestBlocklistLoad_RepairsPreNormalizationEntries(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	old := "0.0.0.0 broken-a.invalid\n" +
		"0.0.0.0 broken-b.invalid\n" +
		"0.0.0.0 0.0.0.0\n" +
		"127.0.0.1 localhost\n" +
		"clean.invalid\n" +
		"*.wild.invalid\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatalf("write old-format blocklist: %v", err)
	}

	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !b.isListed("broken-a.invalid") || !b.isListed("broken-b.invalid") {
		t.Error("hosts-format rows must be repaired into blockable hostnames")
	}
	if b.isListed("0.0.0.0 broken-a.invalid") {
		t.Error("verbatim hosts-format row must not survive Load")
	}
	if b.isListed("localhost") || b.isListed("0.0.0.0") {
		t.Error("boilerplate/unspecified rows must be dropped on Load")
	}
	if !b.isListed("clean.invalid") || !b.isListed("sub.wild.invalid") {
		t.Error("clean rows must load unchanged")
	}
	if got := b.Count(); got != 4 {
		t.Errorf("Count = %d; want 4 (broken-a, broken-b, clean, *.wild)", got)
	}

	// Save rewrites the file clean; a fresh Load needs no repairs.
	b.Save()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved blocklist: %v", err)
	}
	for _, bad := range []string{"0.0.0.0", "localhost"} {
		if containsLine(string(data), bad) {
			t.Errorf("saved file still contains %q:\n%s", bad, data)
		}
	}
}

// containsLine reports whether any line equals needle or starts with
// "needle " (a verbatim hosts-format row). splitLines lives in
// blocklist_addmanual_persist_test.go (same package).
func containsLine(data, needle string) bool {
	for _, l := range splitLines(data) {
		if l == needle || (len(l) > len(needle) && l[:len(needle)+1] == needle+" ") {
			return true
		}
	}
	return false
}

// TestMergeFromLines_AttributionOnlySyncPersists: a re-sync that adds no
// new hosts but stamps attribution on already-listed entries (repaired by
// Load, or imported before the .sources sidecar existed) must still write
// the sidecar — attribution may not be memory-only (Codex P2, PR #438).
// The follow-up no-change sync must NOT rewrite the files.
func TestMergeFromLines_AttributionOnlySyncPersists(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	// Pre-existing entry with no attribution (pre-sidecar import).
	if err := os.WriteFile(path, []byte("preexisting.attr.invalid\n"), 0o600); err != nil {
		t.Fatalf("seed blocklist: %v", err)
	}

	const feed = "https://feeds.example/retro.txt"
	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Re-sync: same host, nothing new — only attribution changes.
	if added := b.MergeFromLines([]string{"preexisting.attr.invalid"}, feed); added != 0 {
		t.Fatalf("added = %d; want 0 (host already listed)", added)
	}
	data, err := os.ReadFile(path + ".sources")
	if err != nil {
		t.Fatalf(".sources not written on attribution-only sync: %v", err)
	}
	var sources map[string]string
	if err := json.Unmarshal(data, &sources); err != nil {
		t.Fatalf("unmarshal .sources: %v", err)
	}
	if sources["preexisting.attr.invalid"] != feed {
		t.Errorf(".sources = %v; want preexisting.attr.invalid → %s", sources, feed)
	}

	// Steady state: re-sync with identical content must not rewrite.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat main file: %v", err)
	}
	if added := b.MergeFromLines([]string{"preexisting.attr.invalid"}, feed); added != 0 {
		t.Fatalf("steady-state added = %d; want 0", added)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("re-stat main file: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("steady-state re-sync rewrote the main file; expected no save when nothing changed")
	}
}

// TestBlocklistSources_PersistRoundTrip: feed attribution survives a
// Save + Load cycle via the .sources sidecar, and removed hosts are
// pruned from it.
func TestBlocklistSources_PersistRoundTrip(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("seed empty blocklist: %v", err)
	}

	const feed = "https://feeds.example/persist.txt"
	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	b.MergeFromLines([]string{"keep.persist.invalid", "gone.persist.invalid"}, feed)
	b.Remove("gone.persist.invalid")
	b.Save()

	b2 := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b2.Load(path); err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	entries := b2.ListWithSource()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v; want only keep.persist.invalid", entries)
	}
	if entries[0].Host != "keep.persist.invalid" || entries[0].Feed != feed {
		t.Errorf("entry = %+v; want keep.persist.invalid attributed to %s", entries[0], feed)
	}
}

// ─── Cascade delete + legacy cleanup (PR: feed-source management) ────

func newAttributedBlocklist(t *testing.T) *Blocklist {
	t.Helper()
	ensureBlocklistStartupTestLogger(t)
	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	b.MergeFromLines([]string{"a.feed-one.invalid", "*.w.feed-one.invalid"}, "https://feeds.example/one.txt")
	b.MergeFromLines([]string{"b.feed-two.invalid"}, "https://feeds.example/two.txt")
	b.MergeFromLines([]string{"legacy.orphan.invalid"}, "") // pre-attribution import
	b.AddManual("keep.manual.invalid")
	return b
}

func TestRemoveByFeedSource_CascadeDeletesOnlyThatFeed(t *testing.T) {
	b := newAttributedBlocklist(t)

	if got := b.CountByFeedSource("https://feeds.example/one.txt"); got != 2 {
		t.Errorf("CountByFeedSource(one) = %d; want 2", got)
	}
	removed := b.RemoveByFeedSource("https://feeds.example/one.txt")
	if removed != 2 {
		t.Errorf("RemoveByFeedSource(one) = %d; want 2", removed)
	}
	if b.isListed("a.feed-one.invalid") || b.isListed("x.w.feed-one.invalid") {
		t.Error("feed-one entries must be gone after cascade delete")
	}
	if !b.isListed("b.feed-two.invalid") {
		t.Error("feed-two entry must survive a feed-one cascade delete")
	}
	if !b.isListed("legacy.orphan.invalid") || !b.isListed("keep.manual.invalid") {
		t.Error("orphan and manual entries must survive a cascade delete")
	}
	if got := b.CountByFeedSource("https://feeds.example/one.txt"); got != 0 {
		t.Errorf("CountByFeedSource(one) after delete = %d; want 0", got)
	}
}

func TestRemoveByFeedSource_ManualOverlapSurvives(t *testing.T) {
	b := newAttributedBlocklist(t)
	// Host both admin-added AND present in feed-one content: manual wins.
	b.AddManual("a.feed-one.invalid")
	if removed := b.RemoveByFeedSource("https://feeds.example/one.txt"); removed != 1 {
		t.Errorf("removed = %d; want 1 (only the wildcard; manual-overlap host kept)", removed)
	}
	if !b.isListed("a.feed-one.invalid") {
		t.Error("admin-added host must survive cascade delete of its feed")
	}
}

func TestRemoveUnattributedFeedEntries_OnlyOrphans(t *testing.T) {
	b := newAttributedBlocklist(t)
	removed := b.RemoveUnattributedFeedEntries()
	if removed != 1 {
		t.Errorf("removed = %d; want 1 (only legacy.orphan.invalid)", removed)
	}
	if b.isListed("legacy.orphan.invalid") {
		t.Error("orphan must be removed")
	}
	if !b.isListed("a.feed-one.invalid") || !b.isListed("b.feed-two.invalid") {
		t.Error("attributed entries must survive orphan cleanup")
	}
	if !b.isListed("keep.manual.invalid") {
		t.Error("manual entries must survive orphan cleanup")
	}
}

// TestRestoreFeedSources_SurvivesRebuild pins the Codex P1 (PR #447) fix:
// a config-rollback-style rebuild (Remove all + Add) must not strand feed
// entries as unattributed — attribution is snapshotted and re-stamped for
// hosts that survive the rebuild.
func TestRestoreFeedSources_SurvivesRebuild(t *testing.T) {
	b := newAttributedBlocklist(t)

	snap := b.SnapshotFeedSources()
	for _, h := range b.List() {
		b.Remove(h)
	}
	// Re-add a subset, the way applyConfigBackup does (plain Add).
	b.Add("a.feed-one.invalid")
	b.Add("b.feed-two.invalid")
	b.RestoreFeedSources(snap)

	byHost := map[string]BlocklistEntry{}
	for _, e := range b.ListWithSource() {
		byHost[e.Host] = e
	}
	if e := byHost["a.feed-one.invalid"]; e.Feed != "https://feeds.example/one.txt" {
		t.Errorf("a.feed-one.invalid attribution after rebuild = %+v; want feed-one", e)
	}
	if e := byHost["b.feed-two.invalid"]; e.Feed != "https://feeds.example/two.txt" {
		t.Errorf("b.feed-two.invalid attribution after rebuild = %+v; want feed-two", e)
	}
	// Hosts NOT re-added must not be resurrected into feedSrc.
	if got := b.CountByFeedSource("https://feeds.example/one.txt"); got != 1 {
		t.Errorf("CountByFeedSource(one) = %d; want 1 (wildcard not re-added)", got)
	}
}

// TestCleanupUnattributed_RefusedWithoutFeeds pins the server-side gate:
// with zero configured feeds, unattributed entries are likely static-file
// or config-restored operator data, so the purge must be refused.
func TestCleanupUnattributed_RefusedWithoutFeeds(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t)) // zero feeds
	origBL := bl
	bl = newAttributedBlocklist(t)
	t.Cleanup(func() { bl = origBL })

	r := adminCtx(httptest.NewRequestWithContext(context.Background(),
		http.MethodDelete, "/api/blocklist?scope=unattributed", http.NoBody))
	w := httptest.NewRecorder()
	apiBlocklist(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("cleanup without feeds: status = %d; want 409 (%s)", w.Code, w.Body.String())
	}
	if !bl.isListed("legacy.orphan.invalid") {
		t.Error("orphan must NOT be removed when the gate refuses")
	}

	// With a feed configured the same call succeeds.
	blFeedSyncer.SetFeed("https://feeds.example/gate.txt", 0)
	w = httptest.NewRecorder()
	r = adminCtx(httptest.NewRequestWithContext(context.Background(),
		http.MethodDelete, "/api/blocklist?scope=unattributed", http.NoBody))
	apiBlocklist(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("cleanup with feeds: status = %d; want 200 (%s)", w.Code, w.Body.String())
	}
	if bl.isListed("legacy.orphan.invalid") {
		t.Error("orphan should be removed once the gate passes")
	}
}
