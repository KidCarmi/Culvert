package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// ─── normaliseFeedURL ─────────────────────────────────────────────────────────

func TestNormaliseFeedURL_Valid(t *testing.T) {
	norm, host := normaliseFeedURL("http://malware.example.com/bad/path?query=1")
	if norm == "" {
		t.Error("normaliseFeedURL: expected non-empty norm")
	}
	if host != "malware.example.com" {
		t.Errorf("normaliseFeedURL host = %q, want malware.example.com", host)
	}
	// query stripped
	if norm != "http://malware.example.com/bad/path" {
		t.Errorf("normaliseFeedURL norm = %q, want path only (no query)", norm)
	}
}

func TestNormaliseFeedURL_NoScheme(t *testing.T) {
	norm, host := normaliseFeedURL("evil.example.com/malware")
	if norm == "" {
		t.Error("normaliseFeedURL: no-scheme URL should still parse")
	}
	if host != "evil.example.com" {
		t.Errorf("normaliseFeedURL host = %q, want evil.example.com", host)
	}
}

func TestNormaliseFeedURL_InvalidURL(t *testing.T) {
	norm, host := normaliseFeedURL("://bad")
	if norm != "" || host != "" {
		t.Errorf("normaliseFeedURL invalid URL should return empty, got norm=%q host=%q", norm, host)
	}
}

func TestNormaliseFeedURL_PrivateIP(t *testing.T) {
	norm, host := normaliseFeedURL("http://192.168.1.1/malware")
	if norm != "" || host != "" {
		t.Errorf("normaliseFeedURL private IP should return empty, got norm=%q host=%q", norm, host)
	}
}

func TestNormaliseFeedURL_TrailingSlash(t *testing.T) {
	norm, _ := normaliseFeedURL("http://evil.example.com/")
	if norm == "" {
		t.Fatal("expected non-empty norm")
	}
	// trailing slash should be trimmed
	if norm[len(norm)-1] == '/' {
		t.Errorf("normaliseFeedURL should trim trailing slash, got %q", norm)
	}
}

// ─── ThreatFeed CheckURL / CheckDomain ────────────────────────────────────────

func newEnabledFeed() *ThreatFeed {
	tf := &ThreatFeed{
		urls:            make(map[string]feedEntry),
		domains:         make(map[string]feedEntry),
		domainAllowlist: make(map[string]bool),
		enabled:         true,
	}
	tf.totalEntries.Store(0)
	return tf
}

func TestThreatFeed_CheckURL_Hit(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["http://malware.example.com/evil"] = feedEntry{Source: "urlhaus", AddedAt: time.Now()}

	hit, src := tf.CheckURL("http://malware.example.com/evil")
	if !hit {
		t.Error("CheckURL should detect known malicious URL")
	}
	if src != "urlhaus" {
		t.Errorf("CheckURL source = %q, want urlhaus", src)
	}
}

func TestThreatFeed_CheckURL_Miss(t *testing.T) {
	tf := newEnabledFeed()
	hit, _ := tf.CheckURL("http://clean.example.com/page")
	if hit {
		t.Error("CheckURL should not flag unknown URL")
	}
}

func TestThreatFeed_CheckURL_DomainFallback(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.com"] = feedEntry{Source: "openphish", AddedAt: time.Now()}

	// URL not in urls map but domain is in domains map
	hit, src := tf.CheckURL("http://malware.example.com/some/path")
	if !hit {
		t.Error("CheckURL should fall back to domain lookup")
	}
	if src != "openphish" {
		t.Errorf("CheckURL domain fallback source = %q, want openphish", src)
	}
}

func TestThreatFeed_DomainAllowlistClearsDomainButKeepsURLBlock(t *testing.T) {
	tf := newEnabledFeed()
	now := time.Now()
	tf.urls["https://www.google.com/malware"] = feedEntry{Source: "urlhaus", AddedAt: now}
	tf.domains["www.google.com"] = feedEntry{Source: "openphish", AddedAt: now}

	if hit, _ := tf.CheckDomain("www.google.com"); !hit {
		t.Fatal("setup failed: domain should be blocked before allowlist")
	}

	tf.AddDomainAllowlist("www.google.com")

	if hit, _ := tf.CheckDomain("www.google.com"); hit {
		t.Error("allowlisted domain should stop domain-level threat blocks immediately")
	}
	if hit, _ := tf.CheckURL("https://www.google.com/safe"); hit {
		t.Error("allowlisted domain should not be blocked through URL domain fallback")
	}
	if _, ok := tf.domains["www.google.com"]; ok {
		t.Error("allowlisting should prune the stale domain entry from the in-memory domain map")
	}

	hit, src := tf.CheckURL("https://www.google.com/malware?ignored=true")
	if !hit {
		t.Fatal("exact malicious URL must remain blocked after domain allowlist")
	}
	if src != "urlhaus" {
		t.Errorf("exact URL block source = %q, want urlhaus", src)
	}
}

func TestThreatFeed_CheckDomainAllowlistDefendsAgainstStaleDomainMap(t *testing.T) {
	tf := newEnabledFeed()
	tf.domainAllowlist["www.google.com"] = true
	tf.domains["www.google.com"] = feedEntry{Source: "openphish", AddedAt: time.Now()}

	if hit, _ := tf.CheckDomain("www.google.com"); hit {
		t.Error("allowlist should suppress stale domain-map entries on the hot path")
	}
	if hit, _ := tf.CheckURL("https://www.google.com/clean"); hit {
		t.Error("allowlist should suppress stale domain fallback in CheckURL")
	}
}

func TestThreatFeed_DomainAllowlistNormalizesOperatorInputs(t *testing.T) {
	tf := newEnabledFeed()

	tf.SetDomainAllowlist([]string{
		"WWW.GOOGLE.COM.",
		"www.google.com:443",
		"https://www.google.com/",
		"www.google.com/safe/path",
	})

	got := tf.DomainAllowlist()
	if len(got) != 1 || got[0] != "www.google.com" {
		t.Fatalf("DomainAllowlist normalized entries = %v, want [www.google.com]", got)
	}
	tf.domains["www.google.com"] = feedEntry{Source: "openphish", AddedAt: time.Now()}
	if hit, _ := tf.CheckDomain("www.google.com:443"); hit {
		t.Error("normalized allowlist should match host:port lookup")
	}
}

func TestThreatFeed_CheckURL_Disabled(t *testing.T) {
	tf := &ThreatFeed{
		urls:    make(map[string]feedEntry),
		domains: make(map[string]feedEntry),
		enabled: false,
	}
	hit, _ := tf.CheckURL("http://malware.example.com/evil")
	if hit {
		t.Error("CheckURL should return false when feed is disabled")
	}
}

func TestThreatFeed_CheckDomain_Hit(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["phishing.example.com"] = feedEntry{Source: "openphish", AddedAt: time.Now()}

	hit, src := tf.CheckDomain("phishing.example.com")
	if !hit {
		t.Error("CheckDomain should detect known malicious domain")
	}
	if src != "openphish" {
		t.Errorf("CheckDomain source = %q, want openphish", src)
	}
}

func TestThreatFeed_CheckDomain_CaseInsensitive(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.com"] = feedEntry{Source: "urlhaus", AddedAt: time.Now()}

	hit, _ := tf.CheckDomain("MALWARE.EXAMPLE.COM")
	if !hit {
		t.Error("CheckDomain should be case-insensitive")
	}
}

func TestThreatFeed_CheckDomain_TrailingDot(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.com"] = feedEntry{Source: "urlhaus", AddedAt: time.Now()}

	hit, _ := tf.CheckDomain("malware.example.com.")
	if !hit {
		t.Error("CheckDomain should strip trailing dot")
	}
}

func TestThreatFeed_CheckDomain_Miss(t *testing.T) {
	tf := newEnabledFeed()
	hit, _ := tf.CheckDomain("clean.example.com")
	if hit {
		t.Error("CheckDomain should not flag unknown domain")
	}
}

func TestThreatFeed_CheckDomain_Disabled(t *testing.T) {
	tf := &ThreatFeed{
		urls:    make(map[string]feedEntry),
		domains: make(map[string]feedEntry),
		enabled: false,
	}
	hit, _ := tf.CheckDomain("evil.example.com")
	if hit {
		t.Error("CheckDomain should return false when feed is disabled")
	}
}

// ─── ThreatFeed.loadFromDisk ───────────────────────────────────────────────────

func TestThreatFeed_LoadFromDisk_NonExistent(t *testing.T) {
	tf := newEnabledFeed()
	err := tf.loadFromDisk("/tmp/nonexistent_feed_test_xyz.json")
	if err != nil {
		t.Errorf("loadFromDisk on nonexistent file should return nil, got %v", err)
	}
}

func TestThreatFeed_LoadFromDisk_Valid(t *testing.T) {
	db := feedDB{
		LastSync: time.Now(),
		URLs:     map[string]feedEntry{"http://evil.com/bad": {Source: "urlhaus", AddedAt: time.Now()}},
		Domains:  map[string]feedEntry{"evil.com": {Source: "urlhaus", AddedAt: time.Now()}},
	}
	data, _ := json.Marshal(db)
	f, err := os.CreateTemp("", "feeddb*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.Write(data)
	f.Close()

	tf := newEnabledFeed()
	if err := tf.loadFromDisk(f.Name()); err != nil {
		t.Fatalf("loadFromDisk error: %v", err)
	}
	if _, ok := tf.urls["http://evil.com/bad"]; !ok {
		t.Error("loadFromDisk should populate URLs map")
	}
}

func TestThreatFeed_LoadFromDisk_BadJSON(t *testing.T) {
	f, _ := os.CreateTemp("", "badfeed*.json")
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("not json")
	f.Close()

	tf := newEnabledFeed()
	err := tf.loadFromDisk(f.Name())
	if err == nil {
		t.Error("loadFromDisk with bad JSON should return error")
	}
}

// ─── ThreatFeed.Stats ─────────────────────────────────────────────────────────

func TestThreatFeed_Stats(t *testing.T) {
	tf := newEnabledFeed()
	tf.totalEntries.Store(42)
	count, _, _ := tf.Stats()
	if count != 42 {
		t.Errorf("Stats count = %d, want 42", count)
	}
}

func TestThreatFeed_ExportURLs(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["http://evil.com/payload"] = feedEntry{Source: "urlhaus", AddedAt: time.Unix(1700000000, 0)}
	tf.urls["http://bad.com/malware"] = feedEntry{Source: "openphish", AddedAt: time.Unix(1700000001, 0)}

	exported := tf.ExportURLs()
	if len(exported) != 2 {
		t.Fatalf("ExportURLs len = %d, want 2", len(exported))
	}
	if exported["http://evil.com/payload"] != 1700000000 {
		t.Errorf("evil.com timestamp = %d", exported["http://evil.com/payload"])
	}
}

func TestThreatFeed_ExportDomains(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["evil.com"] = feedEntry{Source: "urlhaus", AddedAt: time.Unix(1700000000, 0)}

	exported := tf.ExportDomains()
	if len(exported) != 1 {
		t.Fatalf("ExportDomains len = %d, want 1", len(exported))
	}
	if exported["evil.com"] != 1700000000 {
		t.Errorf("evil.com timestamp = %d", exported["evil.com"])
	}
}

func TestThreatFeed_ImportFeedData(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["old.com/page"] = feedEntry{Source: "urlhaus", AddedAt: time.Unix(1600000000, 0)}

	urls := map[string]int64{
		"http://new.com/bad": 1700000000,
	}
	domains := map[string]int64{
		"new-domain.com": 1700000001,
	}

	tf.ImportFeedData(urls, domains)

	if len(tf.urls) != 1 {
		t.Errorf("after import, urls len = %d, want 1", len(tf.urls))
	}
	if _, ok := tf.urls["http://new.com/bad"]; !ok {
		t.Error("expected new URL to be present")
	}
	if _, ok := tf.urls["old.com/page"]; ok {
		t.Error("old URL should have been replaced")
	}
	if len(tf.domains) != 1 {
		t.Errorf("after import, domains len = %d, want 1", len(tf.domains))
	}
	if tf.domains["new-domain.com"].Source != "cluster-sync" {
		t.Errorf("source = %q, want cluster-sync", tf.domains["new-domain.com"].Source)
	}
}

func TestThreatFeed_ImportFeedDataPreservesDomainAllowlistAndURLBlocks(t *testing.T) {
	tf := newEnabledFeed()
	tf.SetDomainAllowlist([]string{"www.google.com"})

	urls := map[string]int64{
		"https://www.google.com/malware": 1700000000,
	}
	domains := map[string]int64{
		"www.google.com": 1700000001,
	}

	tf.ImportFeedData(urls, domains)

	if hit, _ := tf.CheckDomain("www.google.com"); hit {
		t.Error("cluster import should not reintroduce allowlisted domain blocks")
	}
	if _, ok := tf.domains["www.google.com"]; ok {
		t.Error("cluster import should prune allowlisted domains from the domain map")
	}
	if hit, src := tf.CheckURL("https://www.google.com/malware"); !hit || src != "cluster-sync" {
		t.Errorf("exact malicious URL should remain blocked after cluster import; hit=%v src=%q", hit, src)
	}
}
