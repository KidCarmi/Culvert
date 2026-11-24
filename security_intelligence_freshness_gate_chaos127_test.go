package main

// security_intelligence_freshness_gate_chaos127_test.go — the class-ending
// gate for the security-intelligence freshness family (CHAOS-127).
//
// # What this gate is and why it exists
//
// Five consecutive rounds found the SAME defect in a different body of
// security intelligence, one at a time:
//
//	WK-5/CHAOS-59  the threat feed had a last-good value and no recency
//	CHAOS-108      a feed loop whose enumeration the feedsched doc did not cover
//	CHAOS-123      culvert_blocklist_size held through a dead feed
//	CHAOS-124      the ClamAV signature database had no age anywhere
//	CHAOS-127      the GeoIP database's only staleness judgement was in a browser
//
// Each round closed its own body and handed the CLASS forward. CHAOS-123 §9.4
// proposed ending it and CHAOS-124 §9.1 stated the remedy and left it Open:
//
//	A gate that enumerates every body of security intelligence and asserts
//	each has a freshness surface. […] A test over the intelligence inputs
//	(feeds, AV definitions, GeoIP database, YARA rule set, category DB)
//	asserting each exports an age or a last-success would end the class
//	instead of retiring it one input at a time. Open.
//
// This is that test. Every body below declares EXACTLY ONE of two things: the
// freshness series it exports, or a stated reason it is exempt. There is no
// third column and no default, so a body cannot sit in this table without a
// decision having been made about it.
//
// # What it can and cannot catch — read this before trusting it
//
// It CATCHES: a declared freshness series being renamed, deleted or moved out
// of the emitters (every name below is checked against the tree, so a series
// that stops existing fails here rather than silently stopping being scraped);
// an exemption with no reason; and a body being moved between the two columns
// without a human looking at it.
//
// It CANNOT discover a SEVENTH body on its own. There is no machine-readable
// registry of "things this gateway enforces with externally-sourced data" to
// diff against — supportMetricRegistry is a deliberately narrow
// support-health scope that must not grow, and internal/feedsched's own
// enumeration is the one CHAOS-123 found to be already incomplete ("The doc
// counts THREE loops; the tree has more"). So adding a new intelligence input
// without a freshness surface AND without a row here still passes, and that is
// this gate's residual risk, recorded as such in the CHAOS-127 review rather
// than papered over. What the gate changes is that the question is now asked
// in one place, with the answer for every known body written down.
//
// A count is deliberately NOT asserted: a count tells a reader that something
// moved without telling them what, which is the failure AGENTS.md records for
// the eager-import allowlist ("an exact allowlist, never a count").

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// intelligenceBody is one body of security intelligence this gateway enforces
// with data it did not author.
type intelligenceBody struct {
	// Name is how the review and the operator docs refer to this body.
	Name string
	// Owner is where the data lives, for a reader following this table.
	Owner string
	// FreshnessSeries are the /metrics series that answer "how current is
	// this data". Every name must exist in the tree. Mutually exclusive with
	// ExemptBecause.
	FreshnessSeries []string
	// ExemptBecause is the stated reason this body needs no freshness series.
	// An exemption is a decision on the record, not an omission. Mutually
	// exclusive with FreshnessSeries.
	ExemptBecause string
	// ClosedBy names the round that gave this body its surface, so a reader
	// can find the reasoning rather than re-deriving it.
	ClosedBy string
}

// securityIntelligenceBodies is the inventory. Adding a body here with
// neither column filled fails the gate.
var securityIntelligenceBodies = []intelligenceBody{
	{
		Name:  "Category/URL classification feed (and the Layer-2 community store it fills)",
		Owner: "internal/feedsync → internal/catdb, internal/urlcat",
		// The store's own row (catfeeddb_health.go) covers AVAILABILITY and
		// corruption; the feed's last-sync covers AGE. They are two questions
		// about one body and the age one is what this family is about.
		FreshnessSeries: []string{"culvert_category_feed_last_sync_timestamp_seconds"},
		ClosedBy:        "CHAOS-50 / the category-feed observability work",
	},
	{
		Name:            "Threat-intelligence feed",
		Owner:           "internal/threatfeed",
		FreshnessSeries: []string{"culvert_threat_feed_last_success_timestamp_seconds"},
		ClosedBy:        "WK-5 / CHAOS-59",
	},
	{
		Name:  "Signed SaaS feed",
		Owner: "internal/saasfeed",
		// This body uses the STRONGEST primitive in the family and it is
		// worth naming, because it is not the shape the other rows use: the
		// publisher stamps an expiry into the signed snapshot, so staleness
		// is a fact the origin asserts rather than a threshold the consumer
		// guesses. culvert_saasfeed_expires_in_seconds goes NEGATIVE once the
		// active snapshot is past its expiry. It is emitted only while a
		// version is active, so the never-activated and failing shapes are
		// carried by consecutive_failures beside it.
		//
		// Note for anyone grepping: culvert_saas_feed_last_sync_timestamp_seconds
		// (with the underscore) is a RETIRED legacy series that
		// urlcat_metrics_test.go asserts is absent. This gate's first draft
		// declared it, and this gate is what caught that.
		FreshnessSeries: []string{
			"culvert_saasfeed_expires_in_seconds",
			"culvert_saasfeed_consecutive_failures",
		},
		ClosedBy: "F3b-4 signed-feed observability",
	},
	{
		Name:  "Operator-configured remote blocklist feeds",
		Owner: "internal/blocklistfeed",
		FreshnessSeries: []string{
			"culvert_blocklist_feed_oldest_success_timestamp_seconds",
			"culvert_blocklist_feed_stale_seconds",
			"culvert_blocklist_feed_stale",
		},
		ClosedBy: "CHAOS-123",
	},
	{
		Name:  "ClamAV signature database",
		Owner: "the clamav container, observed over clamd VERSION",
		FreshnessSeries: []string{
			"culvert_clamav_signature_age_seconds",
			"culvert_clamav_signature_age_unknown",
		},
		ClosedBy: "CHAOS-124",
	},
	{
		Name:  "GeoIP country database",
		Owner: "a MaxMind GeoLite2 .mmdb on disk, via internal/geoip",
		FreshnessSeries: []string{
			"culvert_geoip_database_age_seconds",
			"culvert_geoip_database_age_unknown",
			"culvert_geoip_database_stale",
		},
		ClosedBy: "CHAOS-127",
	},
	{
		Name:  "YARA rule set",
		Owner: "internal/yara, rules in the configured rules directory",
		// CHAOS-124 §9.3 assessed this and placed it below the others, and
		// the reasoning is recorded rather than restated: the rules change
		// ONLY through Culvert's own admin paths (the rules CRUD API and the
		// reload endpoint, ui_security.go), so there is no out-of-process
		// updater that can die unnoticed — which is the mechanism every other
		// body on this list fails by. An "age" here would measure how long
		// since an operator last edited their own detection content, which is
		// a different and much weaker signal, and roadmap/
		// CHAOS-REVIEW-2026-10-31.md:528 already recorded it as lower
		// priority for exactly this reason. It stays open and correctly lower;
		// the decision is on the record here so a future round finds it
		// instead of rediscovering the gap.
		ExemptBecause: "no out-of-process updater exists: rules change only through Culvert's own admin API, so there is no third-party refresh loop whose death would be invisible (CHAOS-124 §9.3, still open and correctly lower priority)",
	},
	{
		Name:  "Operator-entered static blocklist",
		Owner: "internal/blocklist",
		// Not externally sourced. Its entries are typed in by an operator and
		// persisted; there is no origin that can go stale behind their back,
		// which is the whole mechanism this family tracks. culvert_blocklist_size
		// exists and is a SIZE, and CHAOS-123's finding was precisely that a
		// size is not a freshness proxy — for the FEED. For the hand-entered
		// list there is nothing to be fresh relative to.
		ExemptBecause: "not externally sourced: entries are operator-authored and persisted, so no upstream exists that could silently stop publishing (CHAOS-123 established that culvert_blocklist_size is a size, not a freshness signal, and that distinction is why this row is an exemption rather than a surface)",
	},
}

// TestCHAOS127EveryIntelligenceBodyIsClassified is the gate's first half: no
// body may sit in the inventory undecided.
func TestCHAOS127EveryIntelligenceBodyIsClassified(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range securityIntelligenceBodies {
		if b.Name == "" {
			t.Error("a body with no Name — it cannot be discussed in a review or a runbook")
			continue
		}
		if seen[b.Name] {
			t.Errorf("%s: declared twice", b.Name)
		}
		seen[b.Name] = true

		if b.Owner == "" {
			t.Errorf("%s: no Owner, so a reader cannot find the data this row is about", b.Name)
		}

		hasSeries := len(b.FreshnessSeries) > 0
		hasExemption := strings.TrimSpace(b.ExemptBecause) != ""

		switch {
		case hasSeries && hasExemption:
			t.Errorf("%s: declares BOTH freshness series and an exemption. Pick one: a body with a surface is not exempt, and an exempt body must not claim a surface it does not have.", b.Name)
		case !hasSeries && !hasExemption:
			t.Errorf("%s: declares NEITHER a freshness series nor a reason to be exempt. This is the gap five rounds found one body at a time — decide it here.", b.Name)
		case hasSeries && b.ClosedBy == "":
			t.Errorf("%s: exports a freshness surface but names no round that reasoned about it; a future reader needs the reference", b.Name)
		case hasExemption && len(b.ExemptBecause) < 60:
			// A short exemption is how this class comes back: "N/A" passes a
			// gate and tells the next reader nothing.
			t.Errorf("%s: exemption reason is %d characters (%q). State the MECHANISM that makes a freshness surface unnecessary, not a label.",
				b.Name, len(b.ExemptBecause), b.ExemptBecause)
		}
	}
}

// TestCHAOS127DeclaredFreshnessSeriesAllExist is the gate's second half, and
// the part that reacts to the tree rather than to this file.
//
// A declared series that has been renamed, deleted, or moved out of the
// emitters stops being scraped silently: every dashboard and every
// Alertmanager rule keyed on it goes quiet, which reads exactly like a healthy
// fleet. This asserts each name still exists in non-test Go source.
func TestCHAOS127DeclaredFreshnessSeriesAllExist(t *testing.T) {
	src := nonTestGoSources(t)

	for _, b := range securityIntelligenceBodies {
		for _, series := range b.FreshnessSeries {
			if !strings.Contains(src, series) {
				t.Errorf("%s: declared freshness series %s is not present in any non-test Go source. If it was renamed, update this row — a silently unscraped series is indistinguishable from a healthy fleet.",
					b.Name, series)
			}
		}
	}
}

// TestCHAOS127GeoIPIsNoLongerExempt is the narrow regression this round earns.
// It pins the inventory's verdict for the body CHAOS-127 closed, so a future
// change that drops the GeoIP series has to argue with a named test rather
// than quietly re-opening the gap.
func TestCHAOS127GeoIPIsNoLongerExempt(t *testing.T) {
	for _, b := range securityIntelligenceBodies {
		if !strings.Contains(b.Name, "GeoIP") {
			continue
		}
		if b.ExemptBecause != "" {
			t.Fatalf("the GeoIP country database is marked exempt (%q). CHAOS-127 measured the gap: a 1096-day-old database loaded and serving, with zero lines on /metrics about it.", b.ExemptBecause)
		}
		if len(b.FreshnessSeries) == 0 {
			t.Fatal("the GeoIP country database declares no freshness series")
		}
		return
	}
	t.Fatal("the GeoIP country database is absent from the inventory entirely")
}

// nonTestGoSources concatenates the repository root's non-test Go sources,
// where the /metrics emitters live. Tests run with the working directory set
// to the package directory, which is the repository root for package main.
func nonTestGoSources(t *testing.T) string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no Go sources found in the working directory; this gate reads the tree and cannot run blind")
	}
	var b strings.Builder
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}
