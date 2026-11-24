package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// geoip_database_freshness.go — the GeoIP country-database freshness plane
// (CHAOS-127).
//
// # Why this file exists
//
// CHAOS-124 closed the ClamAV signature database's freshness gap and then
// handed the CLASS forward in its §9.1, in these words:
//
//	A gate that enumerates every body of security intelligence and asserts
//	each has a freshness surface. […] A test over the intelligence inputs
//	(feeds, AV definitions, GeoIP database, YARA rule set, category DB)
//	asserting each exports an age or a last-success would end the class
//	instead of retiring it one input at a time. Open.
//
// This file is the GeoIP half of that ask; the gate itself is
// security_intelligence_freshness_gate_chaos127_test.go.
//
// The GeoIP database is the SIXTH body of security intelligence this gateway
// enforces, and it is the one where Culvert has no updater at all. The four
// periodic feeds (internal/feedsync, internal/threatfeed, internal/saasfeed,
// internal/blocklistfeed) each export a last-success timestamp or an age, and
// CHAOS-124 added the fifth for ClamAV. Here there is no loop to fail:
// internal/geoip's own doc says "Culvert never auto-refreshes this file", so
// decay is the DEFAULT STATE rather than a failure mode. A GeoLite2-Country
// file installed once at deployment is simply older every day, forever, and
// MaxMind republishes it twice a week.
//
// # The gap, measured at the claim revision
//
// The node already LEARNS the answer. readerBuildTime
// (internal/geoip/geoip.go) parses the .mmdb's own BuildEpoch at load, and
// BuildTime() is documented "callers use this to surface staleness to the
// operator (there is otherwise no signal that the loaded database predates a
// country's IP allocations)". That is exactly right about the need. It had
// exactly ONE consumer — apiGeoIPConfig in ui_security.go, which emits
// dbAgeDays — and the only staleness JUDGEMENT anywhere in the product was a
// line of browser JavaScript:
//
//	const stale = g.dbAgeDays > 90;            // static/index.html
//
// which paints a label amber inside a panel a human has to open. Measured on
// the production path with a database built 1096 days ago: /metrics carried
// 888 lines and not one of them was about the database, readiness reported
// `geoip: ok`, and /api/diagnostics produced no row. An enterprise SWG is
// watched by Prometheus and Alertmanager, and that path could not see GeoIP
// currency in any form.
//
// # Why the existing surfaces cannot cover it
//
// **The metric family that looks like it covers this is the one that hides
// it.** /metrics does carry six culvert_geo_* series — culvert_geo_warm_total,
// _warm_dropped_total, _warm_failed_total, _warm_saturated, _warm_inflight and
// culvert_geo_policy_unresolved_total — so a reviewer grepping for GeoIP
// instrumentation finds hits and concludes the plane is instrumented. Every
// one of them measures how BUSY the resolution path is, or how often it failed
// to resolve. None measures whether the data it resolved against is still
// TRUE. This is the shape WK-5/CHAOS-59 closed for the threat feed and
// CHAOS-123 for culvert_blocklist_size, with a new twist: here the misleading
// series are not a stale last-good value, they are a different question
// answered well.
//
// culvert_geo_policy_unresolved_total is the sharpest instance. It counts
// country-scoped rule evaluations that did not match because the country was
// UNKNOWN — the failure mode of a MISSING database. A stale database is not
// unknown, it resolves briskly and confidently to whatever country owned that
// prefix three years ago, so this counter stays at zero through the entire
// degradation it looks like it would catch.
//
// **Every liveness surface stays green by construction.** healthcheck.go
// reports checks["geoip"] = ok on geoip.Enabled(), which is a nil-pointer
// check on the loaded reader: a database from 2023 passes it forever.
// geoip_database_health.go's geoip_database_for_rules row — the one row this
// plane already had — fires only when NO database is loaded, and says so in
// its own comment ("if geoip.Enabled() { return nil }"). The two conditions
// are complements: that row covers "the rules cannot match", this one covers
// "the rules match, against the wrong answer".
//
// # Why it is reachable by ordinary operations, and what degrades
//
// No attacker and no fault are required — only time, and the absence of a
// habit. There is no updater to break, no credential to expire and no egress
// to block, which is why this is the one body where nothing in the product
// ever moved. GeoLite2 also requires a (free) MaxMind licence key and an
// operator-run download, so the file commonly arrives once, by hand, at
// deployment.
//
// What degrades is a SECURITY CONTROL, in the fail-open direction. A
// destCountry BLOCK rule is an enforcement decision, and IP allocations move
// between countries continuously — transfers between regional registries,
// reassignments inside them, and the ordinary churn of cloud providers' pools.
// Every prefix that changed hands since the build date is now classified by
// this gateway as the country that used to own it, so traffic an operator
// configured to be blocked is allowed (and traffic they configured to be
// allowed is blocked). Both directions are silent: the request log records the
// country Culvert believes, the per-rule hit counters move normally, and the
// verdict is internally consistent with a world that no longer exists.
//
// # What this file adds
//
// The shape threatfeed_health.go, blocklist_feed_health.go and
// clamav_signature_freshness.go use:
//
//   - /metrics — the culvert_geoip_database_* family, emitted only when a
//     database is actually loaded.
//   - /api/diagnostics — a `geoip_database_age` row for the stale shape, and
//     for the two UNMEASURABLE shapes (an unreadable build epoch, a
//     future-dated database), neither of which may be reported as fresh.
//   - a `geoip_database_pending_restart` row, which is the finding's second
//     half: see below.
//
// # The second half — the remedy the product advised could not take effect
//
// The GUI's existing warning says "stale, consider updating". An operator who
// does exactly that, dropping a current .mmdb at the configured path, sees
// nothing change: InitGeoDB is startup-only, and TryDeferredLoad publishes
// only while no reader is loaded, so on a working node it is a no-op by
// construction. Measured: with a fresh file written to the same path,
// ArmDeferredLoad returned false, TryDeferredLoad loaded nothing, and the
// reported build date stayed at the three-year-old value. Nothing anywhere
// said a restart was required.
//
// A live reload is NOT the fix and is deliberately not attempted here: GEO-1
// (CHAOS-64, internal/geoip/geoip.go) records that Close() munmaps a buffer an
// in-flight lookup may still hold — a SIGSEGV recover() cannot catch, with no
// log line and no crash record. Making the reader lifetime safe first is an
// owner decision with a real design (hold the read lock across db.Country,
// reference-count, or never close), not a rider on an observability round.
//
// So this plane reports the state instead of changing it: when the file on
// disk carries a NEWER build than the reader being served, the operator has
// already done their half and the node is waiting on a restart. That is a
// different row, a different action, and an actively useful one — it closes
// the loop on the advice the product was already giving.
//
// # What it deliberately does NOT add
//
// **No file I/O at scrape time.** Every series below reads the build
// timestamp the loaded reader already holds in memory. The pending-restart
// comparison needs to open the file on disk, so it lives ONLY in the
// diagnostics path, whose documented side-effect contract already permits
// bounded read-only file access and which is role-gated and human-driven.
// /metrics is commonly unauthenticated when metricsToken is unset, and a
// scrape that opened and mmapped a ~9 MB database would let any scraper drive
// file I/O at this process once per scrape. This is the posture
// support_collectors_posture_b.go records and clamav_signature_freshness.go
// restates: "cached health snapshot + atomic gauges, never the live dial".
//
// **No alert.** ClamAV's staleness got one because malware definitions are
// hours-critical and because there is an EVENT to clear the episode on: an
// observed newer database. Neither holds here. Age is a monotone function of
// wall-clock time with no event to key an episode on, so a fire-once alert
// could only ever be cleared by the operator replacing the file — and a
// condition that clears solely on human action is a ticket, not a page. The
// gauges below let an operator set their own threshold in Alertmanager, which
// is the surface that was actually missing. Recorded in the review's §7.
//
// **No readiness change and no fail-closed toggle.** A node with an old GeoIP
// database is a fully serving gateway. Refusing traffic, or ejecting the node
// from a load balancer, because a file an operator maintains by hand is behind
// would convert a slow degradation into the customer's outage — the judgement
// threatfeed_health.go, catfeeddb_health.go, blocklist_feed_health.go and
// clamav_signature_freshness.go all record for their own planes.
//
// **No new operator setting for the threshold.** 90 days is kept, not chosen:
// it is the threshold static/index.html has used since the GUI panel was
// written, and the point of this round is that the judgement was in the wrong
// PROCESS, not that it was the wrong number. A new setting would need admin
// API and GUI parity for a value an operator can already threshold themselves
// off culvert_geoip_database_age_seconds. The two surfaces are held together
// by a divergence gate rather than by a comment: see
// TestCHAOS127GUIThresholdMatchesBackend.

// geoipDBStaleAfterDays is the age at which a loaded GeoIP database is
// reported stale.
//
// This value is NOT independent: static/index.html's loadGeoIPStatus has
// judged staleness at `g.dbAgeDays > 90` since that panel was written, and
// this round moves that judgement into the process without changing it. The
// two must agree or an operator gets one answer from the GUI and another from
// Prometheus. TestCHAOS127GUIThresholdMatchesBackend reads the JavaScript and
// fails if they diverge, so this constant cannot be changed alone.
const geoipDBStaleAfterDays = 90

// geoipDBStaleAfter is geoipDBStaleAfterDays as a duration.
const geoipDBStaleAfter = geoipDBStaleAfterDays * 24 * time.Hour

// geoipDBFutureSkew is how far ahead of now a build timestamp may sit before
// it is treated as unmeasurable rather than as "very fresh".
//
// A build epoch in the future cannot be an age, and the fail-safe direction is
// to report it as unmeasurable: a corrupt or hand-edited metadata block must
// not be able to manufacture an arbitrarily LOW age and so silence the plane
// permanently. The tolerance exists because the honest cause of a few minutes
// of skew is this node's clock, not the file — CHAOS-84 covers clock rollback
// as its own domain — and MaxMind's own build timestamp is only
// second-granular.
const geoipDBFutureSkew = 5 * time.Minute

// geoipDBNow is the clock seam. Tests replace it; production never does.
var geoipDBNow = time.Now

// geoipDBBuildTimeFn and geoipDBFileBuildTimeFn are the seams onto the owner
// package, so the gates can drive every shape without a real .mmdb where the
// shape is not about the file (and with one where it is).
var (
	geoipDBBuildTimeFn     = geoip.BuildTime
	geoipDBFileBuildTimeFn = geoip.FileBuildTime
	geoipDBPathFn          = func() string { return uiCfgGeoIPDB }
)

// geoipDBFreshnessSnapshot is one coherent read of the loaded database's
// freshness. It is derived entirely from in-memory state: no file I/O.
type geoipDBFreshnessSnapshot struct {
	// Loaded reports whether a reader is installed. When false every other
	// field is zero and this plane emits nothing at all.
	Loaded bool
	// Built is the loaded database's embedded MaxMind build timestamp.
	Built time.Time
	// Age is now - Built, floored at zero. Only meaningful when Measurable.
	Age time.Duration
	// Measurable is false for the two shapes that have no age: a zero or
	// absent build epoch, and a build timestamp in the future beyond
	// geoipDBFutureSkew. Neither is ever reported as fresh.
	Measurable bool
	// FutureDated distinguishes the two unmeasurable shapes for the row's
	// wording; both are unmeasurable.
	FutureDated bool
	// Stale is true only when Measurable and Age exceeds the threshold. An
	// unmeasurable database is NOT stale — it is unmeasurable, which is a
	// separate row and a separate series.
	Stale bool
}

// geoipDBFreshness takes one coherent snapshot. Safe on any path: it reads the
// owner's RLock-protected build timestamp and this file's clock seam, and
// touches no file.
func geoipDBFreshness() geoipDBFreshnessSnapshot {
	built, ok := geoipDBBuildTimeFn()
	if !ok {
		return geoipDBFreshnessSnapshot{}
	}
	snap := geoipDBFreshnessSnapshot{Loaded: true, Built: built}
	// A zero build epoch is a .mmdb whose metadata carried no build_epoch (or
	// carried zero). time.Unix(0,0) is 1970, which as an "age" would be ~56
	// years and would read as the most alarming possible staleness — a number
	// the product cannot stand behind. Report it as unmeasurable instead.
	if built.IsZero() || built.Unix() <= 0 {
		return snap
	}
	now := geoipDBNow()
	if built.After(now.Add(geoipDBFutureSkew)) {
		snap.FutureDated = true
		return snap
	}
	snap.Measurable = true
	if age := now.Sub(built); age > 0 {
		snap.Age = age
	}
	snap.Stale = snap.Age > geoipDBStaleAfter
	return snap
}

// geoipDBWritePrometheus appends the culvert_geoip_database_* family.
//
// Emitted only when a database is loaded. A node with GeoIP disabled — the
// default, and the common case — publishes no series at all rather than a
// zero, for the reason clamav_signature_freshness.go records for its own
// family: a zero age on a node with no database is indistinguishable from a
// perfectly current one, and a fleet-wide alert on `age > X` must not be
// silently satisfied by the nodes that have no database to be current about.
// culvert_geoip_database_loaded is the series that answers "is there one",
// and it is emitted as 1 so that `absent()` means disabled, not broken.
func geoipDBWritePrometheus(w *strings.Builder) {
	snap := geoipDBFreshness()
	if !snap.Loaded {
		return
	}

	w.WriteString("\n# HELP culvert_geoip_database_loaded 1 when a MaxMind GeoLite2 country database is loaded and serving destination-country lookups (absent when GeoIP is not configured)\n")
	w.WriteString("# TYPE culvert_geoip_database_loaded gauge\n")
	w.WriteString("culvert_geoip_database_loaded 1\n")

	// The age and the build timestamp are both exported, for the reason
	// blocklist_feed_health.go records: the unmeasurable case has no
	// timestamp to subtract from, and that is precisely the case an operator
	// most needs to see rather than silently treat as zero.
	w.WriteString("\n# HELP culvert_geoip_database_age_seconds Age of the loaded GeoIP database, from the MaxMind build timestamp embedded in the .mmdb (not the file's mtime); 0 when the age cannot be measured — read culvert_geoip_database_age_unknown alongside it\n")
	w.WriteString("# TYPE culvert_geoip_database_age_seconds gauge\n")
	fmt.Fprintf(w, "culvert_geoip_database_age_seconds %d\n", int64(snap.Age.Seconds()))

	w.WriteString("\n# HELP culvert_geoip_database_build_timestamp_seconds Unix time of the loaded GeoIP database's embedded MaxMind build timestamp (0 when it is absent or unreadable)\n")
	w.WriteString("# TYPE culvert_geoip_database_build_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_geoip_database_build_timestamp_seconds %d\n", geoipDBBuildUnix(snap))

	w.WriteString("\n# HELP culvert_geoip_database_age_unknown 1 when the loaded GeoIP database carries no readable build timestamp, or one in the future, so its age cannot be measured and must not be read as fresh\n")
	w.WriteString("# TYPE culvert_geoip_database_age_unknown gauge\n")
	fmt.Fprintf(w, "culvert_geoip_database_age_unknown %d\n", boolGauge(!snap.Measurable))

	fmt.Fprintf(w, "\n# HELP culvert_geoip_database_stale 1 when the loaded GeoIP database's build timestamp is more than %d days old, so destination-country rules are enforcing against outdated IP allocations\n", geoipDBStaleAfterDays)
	w.WriteString("# TYPE culvert_geoip_database_stale gauge\n")
	fmt.Fprintf(w, "culvert_geoip_database_stale %d\n", boolGauge(snap.Stale))
}

// geoipDBBuildUnix renders the build timestamp for the scrape surface, as 0
// for the shapes that have none. A negative or pre-epoch value is reported as
// 0 rather than passed through: the series is documented as a Unix time, and a
// negative one would be read by every dashboard as a date in 1969.
func geoipDBBuildUnix(snap geoipDBFreshnessSnapshot) int64 {
	if snap.Built.IsZero() || snap.Built.Unix() <= 0 {
		return 0
	}
	return snap.Built.Unix()
}

// checkGeoDatabaseAge returns the operator-contract rows for a LOADED GeoIP
// database's freshness.
//
// Complement of checkGeoDatabaseForRules (geoip_database_health.go), which
// covers the opposite condition — rules that cannot match because no database
// is loaded. Nothing here fires when no database is loaded, so the two never
// both speak about the same node.
//
// Report-only: no rule, matcher, lookup or loader behaviour changes.
func checkGeoDatabaseAge() []OperatorContractCheck {
	snap := geoipDBFreshness()
	if !snap.Loaded {
		return nil
	}
	var rows []OperatorContractCheck

	switch {
	case snap.FutureDated:
		rows = append(rows, OperatorContractCheck{
			Code:   "geoip_database_age",
			Status: diagWarn,
			Message: fmt.Sprintf("The loaded GeoIP database reports a build timestamp in the future (%s), so its age cannot be measured and staleness is not being checked on this node",
				snap.Built.UTC().Format(time.RFC3339)),
			OperatorAction: "Check this node's clock (and NTP) first, since a node running behind real time reports every database as future-dated. If the clock is right, the .mmdb's metadata is wrong — re-download it from MaxMind.",
		})
	case !snap.Measurable:
		rows = append(rows, OperatorContractCheck{
			Code:           "geoip_database_age",
			Status:         diagWarn,
			Message:        "The loaded GeoIP database carries no readable MaxMind build timestamp, so its age cannot be measured and staleness is not being checked on this node",
			OperatorAction: "Re-download the GeoLite2-Country database from MaxMind and restart. A .mmdb with no build_epoch in its metadata is not a file MaxMind publishes; check for a truncated or hand-assembled download.",
		})
	case snap.Stale:
		days := int(snap.Age.Hours() / 24)
		rows = append(rows, OperatorContractCheck{
			Code:   "geoip_database_age",
			Status: diagWarn,
			Message: fmt.Sprintf("The loaded GeoIP database was built %d days ago (%s), over the %d-day threshold. Culvert never refreshes this file, so destination-country rules are enforcing against IP allocations that are %d days out of date — traffic may be allowed or blocked as the wrong country.",
				days, snap.Built.UTC().Format("2006-01-02"), geoipDBStaleAfterDays, days),
			OperatorAction: fmt.Sprintf("Download a current GeoLite2-Country.mmdb from MaxMind, replace the file at the configured path, and RESTART the proxy — a loaded database is never re-read (see the %s row once the file is in place).", "geoip_database_pending_restart"),
		})
	}

	return append(rows, checkGeoDatabasePendingRestart(snap)...)
}

// checkGeoDatabasePendingRestart reports the state in which the operator has
// already done their half: a newer database is on disk at the configured path
// and this process is still serving the older one.
//
// This is the row that closes the loop on the advice the GUI was already
// giving. Without it, replacing the file produces no observable change
// anywhere in the product — measured at the claim revision — and an operator
// has no way to tell "my update did not take" from "my update was not needed".
//
// Bounded read-only file I/O, in the diagnostics path only. It opens the
// configured path, reads the metadata build epoch and closes it, publishing
// nothing: geoip.FileBuildTime documents the lifetime argument. Deliberately
// NOT on /metrics — see the file comment.
//
// Silent (no row) on every inconclusive shape: no path configured, the file
// unreadable or not a .mmdb, or either build timestamp unmeasurable. A failure
// to READ the file is already the business of geoip_database_for_rules and of
// /api/geoip's lastError, and inventing a second voice for it here would
// report an unopenable file as a pending restart, which is the opposite of
// true.
func checkGeoDatabasePendingRestart(snap geoipDBFreshnessSnapshot) []OperatorContractCheck {
	if !snap.Loaded || snap.Built.IsZero() || snap.Built.Unix() <= 0 {
		return nil
	}
	path := geoipDBPathFn()
	if path == "" {
		return nil
	}
	onDisk, err := geoipDBFileBuildTimeFn(path)
	if err != nil || onDisk.IsZero() || onDisk.Unix() <= 0 {
		return nil
	}
	if !onDisk.After(snap.Built) {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "geoip_database_pending_restart",
		Status: diagWarn,
		Message: fmt.Sprintf("The GeoIP database file on disk was built %s, newer than the %s database this process loaded at startup. Culvert never re-reads a loaded database, so destination-country rules are still being enforced against the older one.",
			onDisk.UTC().Format("2006-01-02"), snap.Built.UTC().Format("2006-01-02")),
		OperatorAction: "Restart the proxy to pick up the newer database. The file is already in place and no further download is needed; a rolling restart across the fleet is enough.",
	}}
}
