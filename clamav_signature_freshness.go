package main

// clamav_signature_freshness.go — the ClamAV signature-database freshness
// plane (CHAOS-124).
//
// # Why this file exists
//
// The 2026-11-18 round (CHAOS-123) closed the operator-configured blocklist
// feed's freshness gap and then handed the CLASS forward, in these words:
//
//	Apply the same audit to the remaining optional feeds. This round and
//	CHAOS-108 have now each found the same class in a feed loop that the
//	internal/feedsched doc's enumeration did not cover. The doc counts THREE
//	loops; the tree has more.
//
// This file is the loop that audit found, and it is not a feed at all — which
// is why four freshness rounds walked past it. Culvert's four periodic
// intelligence feeds (internal/feedsync, internal/threatfeed,
// internal/saasfeed, internal/blocklistfeed) now each export a last-success
// timestamp or an age. The fifth body of security intelligence this gateway
// enforces is the ClamAV signature database, and Culvert does not fetch it:
// freshclam does, OUT OF PROCESS, in a container Culvert does not supervise
// (docker-compose.yml runs clamav/clamav with CLAMAV_NO_FRESHCLAMD=false).
// Because there is no loop in this repository, there was no freshness surface
// in this repository either.
//
// # The gap, measured at the claim revision
//
// The node already LEARNS the signature set's build date. clamd's VERSION
// reply is "ClamAV 1.4.1/27456/Mon Nov 03 09:21:33 2025";
// internal/clamav.parseClamVersion splits out that third field as DBDate, and
// scan_signature_watch.go asks for it every five minutes (CHAOS-107, so a
// definition change flushes the verdict cache). The date was then DISCARDED:
// its only consumer was secscan.go's cache key,
//
//	key := v.Engine + "/" + v.DBVersion + "/" + v.DBDate
//
// an opaque change detector. Nothing parsed DBDate into a time, so nothing in
// the product could compare it to now. There was no metric, no alert and no
// health row for signature AGE.
//
// The one surface that existed is the role-gated /api/security-scan/status,
// which carries clamav_version as a raw string, with this recorded intent
// (ENGINEERING_LOG.md): "AV currency is a first-order security signal.
// Surfacing engine + definition date lets an operator confirm freshclam is
// working without shelling into the container." That intent is right and the
// delivery stops one step short: a date string on an admin panel requires a
// human to notice it, read it, and do the subtraction. An enterprise SWG is
// watched by Prometheus and Alertmanager, and that path could not see AV
// currency in any form.
//
// # Why the existing surfaces cannot cover it
//
// **The metric that looks like it covers this is the one that hides it.**
// culvert_scan_sigdb_invalidations_total counts verdict-cache flushes forced by
// an observed signature CHANGE. It moves only when the definitions move, so a
// node whose freshclam died three weeks ago and a node that is perfectly
// current but has had no update in the last hour export a byte-identical
// value. That is the same mechanism WK-5/CHAOS-59 closed for the threat feed
// and CHAOS-123 closed for culvert_blocklist_size: a last-good value that
// holds is not a freshness proxy, it is the thing that makes the outage
// invisible.
//
// **Every liveness surface stays green by construction.** checks["clamav"] in
// healthcheck.go is ClamAVStatus() == "connected", a PING. The diagnostics row
// in diagnostics_clamav_scan.go and the scan_clam_error alert both key on
// UNREACHABILITY. docker-compose.yml's own healthcheck is
// `clamdscan --ping 3`. A daemon with six-month-old definitions is reachable,
// answers PING, answers VERSION, scans every body it is handed and returns
// CLEAN — so it passes all four, forever. restart: unless-stopped and the
// persistent clamav-db volume mean a restart reloads the same stale database,
// so not even a reboot moves any of it. This is the state CHAOS-123 described
// for the blocklist feed — "a restart reloads the same entries from disk, so
// not even a reboot moves it" — reached by a different route.
//
// # Why it is reachable by ordinary operations
//
// No attacker is required. freshclam lives in a container Culvert neither
// starts nor watches, and it stops updating for mundane reasons: egress to
// database.clamav.net blocked by the very network policy the gateway is
// deployed to enforce, a DNS failure inside that container, a full
// /var/lib/clamav, or an operator setting CLAMAV_NO_FRESHCLAMD=true, which
// disables the updater entirely while leaving a daemon that answers every
// probe. ClamAV's distribution has also historically refused updates to
// end-of-life engine versions, so a pinned image that ages out of support
// stops receiving definitions while remaining healthy by every measure this
// product took.
//
// What degrades is specific and is not a cache: the malware signatures
// published since the database stopped moving are exactly the ones this
// gateway now fails to detect, and it reports those bodies to users as clean.
//
// # What this file adds
//
// The shape blocklist_feed_health.go and threatfeed_health.go use:
//
//   - /metrics — the culvert_clamav_signature_* family, emitted only when
//     local ClamAV scanning is configured and an observation has landed.
//   - /api/diagnostics — a `clamav_signatures` row for the stale and
//     unmeasurable shapes.
//   - alerts — `clamav_signature_stale`, fire-once per episode, cleared on
//     OBSERVED evidence of a fresh database, never on elapsed time.
//
// # What it deliberately does NOT add
//
// **No dial at scrape time.** Every surface here reads a snapshot recorded by
// the five-minute signature watcher that already runs. /metrics is commonly
// unauthenticated when metricsToken is unset, and a scrape that could trigger
// a VERSION dial would let any scraper drive traffic at the daemon — and, on a
// DOWN daemon, one dial per scrape. This is the posture
// support_collectors_posture_b.go records: "cached health snapshot + atomic
// gauges, never the live client.Health() dial".
//
// **No fail-closed toggle, and no readiness change.** A node with stale
// definitions is a fully serving gateway: policy, categories, DPI, YARA, CDR,
// the threat feed and the blocklist all apply, and ClamAV still catches
// everything its database knows. Blocking traffic, or ejecting the node from a
// load balancer, because a third-party updater is behind would convert a
// degradation into the customer's outage — the judgement threatfeed_health.go,
// catfeeddb_health.go and blocklist_feed_health.go all record. The row is
// report-only for the same reason.
//
// **No engine or database-version LABEL on any series.** Both are on the
// role-gated status API already. As metric labels they would churn cardinality
// on every definition update — which is several times a day on a HEALTHY node,
// so the cost would fall entirely on the operators who have nothing wrong.
//
// **No page for an UNMEASURABLE date.** See clamavSigUnknown below.

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/clamav"
)

const (
	// clamavSigStaleAfter is how old a signature database must be before this
	// plane calls it stale.
	//
	// Unlike CHAOS-123's blocklist feeds and CHAOS-59's threat feed, there is
	// no configured interval here to take a multiple of: freshclam's cadence
	// lives in another container's configuration and this process cannot read
	// it. So this is an absolute bound, and it is chosen against what upstream
	// actually does rather than against a Culvert setting. ClamAV publishes
	// daily updates (freshclam's own default is 12 checks a day), so a database
	// that has not moved for 48 hours has missed roughly two dozen
	// opportunities and is not a quiet patch window.
	//
	// Two days, not one: a single missed day is reachable by an upstream
	// publishing pause or a long maintenance window, and this plane pages. The
	// same factor-of-two discipline as threatFeedStaleFactor and
	// blocklistFeedStaleFactor, applied to upstream's nominal daily cadence
	// instead of to a local interval. An operator who wants tighter alerts on
	// culvert_clamav_signature_age_seconds directly, which the runbook says.
	clamavSigStaleAfter = 48 * time.Hour

	// clamavSigLogInterval rate-limits the staleness log line: the onset
	// immediately, then at most one line per interval, then one recovery line
	// naming the suppressed count. Same discipline as blocklist_feed_health.go
	// and storage_health.go.
	clamavSigLogInterval = 6 * time.Hour
)

// clamavSigRecord holds the last observation the signature watcher made, plus
// the edge-triggered alert and log gates.
//
// The observation is CACHED here rather than re-read from the scanner at
// surface time, for the no-dial-at-scrape reason in the file header. It is
// written by one caller (noteClamAVSignatureObservation, from the five-minute
// watcher) and read by the metrics writer, the diagnostics row and the admin
// API, so the mutex is doing real work rather than guarding a single word.
type clamavSigRecord struct {
	mu sync.Mutex

	// observed is false until a VERSION reply has been parsed at all. Every
	// surface reports the plane as absent then, rather than exporting a zero
	// that cannot be told apart from "the database was built at the epoch" —
	// the CHAOS-54 rule.
	observed bool

	// dbTime is the signature database's build time, and dbTimeKnown is
	// whether the reply carried one this process could parse. The pair is
	// never collapsed: see clamavSigUnknown.
	dbTime      time.Time
	dbTimeKnown bool

	// observedAt is when that reply landed, so a surface can say how current
	// the OBSERVATION is as distinct from how current the DATABASE is. A
	// daemon that went unreachable an hour ago leaves a database age that is
	// an hour behind the truth, and an operator reading a stale row deserves
	// to know which of the two is the problem.
	observedAt time.Time

	// alerted latches the stale alert for one episode so a node that stays
	// stale does not re-page every five minutes. Cleared only by an OBSERVED
	// fresh database, never by elapsed time — a daemon that stopped answering
	// looks identical to a healthy one otherwise, the mistake ca_health.go and
	// storage_health.go both call out by name.
	alerted bool

	// sawStale records that this episode was OBSERVED stale at least once,
	// whether or not anything was paged for it — the same split the two feed
	// planes carry in latchOncePerEpisodeOnDelivery. alerted is set only by a
	// DISPATCHED alert, so with no webhook configured (the default posture) it
	// stays false for the whole episode; the "current again" line below is
	// gated on this instead. Cleared wherever alerted is.
	sawStale bool

	logAt      time.Time
	suppressed int64
}

var clamavSigHealth clamavSigRecord

// clamavSigNow is the clock seam. Tests drive a 48-hour threshold
// deterministically instead of sleeping past it.
var clamavSigNow = time.Now

// clamavSigSnapshot is the computed view every surface renders.
type clamavSigSnapshot struct {
	// Armed is true once an observation has landed, so the plane has something
	// to report.
	Armed bool

	// DBTime / Age describe the signature database. AgeKnown is false when the
	// daemon answered but its reply carried no parseable build date; Age is
	// then meaningless and must not be rendered.
	DBTime   time.Time
	Age      time.Duration
	AgeKnown bool

	// Stale is AgeKnown and past clamavSigStaleAfter. It is the only condition
	// that pages.
	Stale bool

	// Unknown is the measurable-gap state: a daemon that answers VERSION with
	// no build date this process can parse.
	Unknown bool

	// FutureDated reports a build date AHEAD of this node's clock, which is
	// clock skew between this process and whatever host built or reported the
	// database, not a fresh database. Age is clamped to zero in that case, so
	// without this flag the skew would present as a perfectly current
	// signature set and never be questioned.
	FutureDated bool

	// ObservedAt / ObservationAge describe how current the OBSERVATION is.
	ObservedAt     time.Time
	ObservationAge time.Duration
}

// clamavSigState computes the snapshot from the recorded observation.
func clamavSigState() clamavSigSnapshot {
	clamavSigHealth.mu.Lock()
	defer clamavSigHealth.mu.Unlock()
	return clamavSigStateLocked()
}

func clamavSigStateLocked() clamavSigSnapshot {
	if !clamavSigHealth.observed {
		return clamavSigSnapshot{}
	}
	now := clamavSigNow()
	snap := clamavSigSnapshot{
		Armed:          true,
		ObservedAt:     clamavSigHealth.observedAt,
		ObservationAge: now.Sub(clamavSigHealth.observedAt),
	}
	if snap.ObservationAge < 0 {
		snap.ObservationAge = 0
	}
	if !clamavSigHealth.dbTimeKnown {
		snap.Unknown = true
		return snap
	}
	snap.DBTime = clamavSigHealth.dbTime
	snap.AgeKnown = true
	snap.Age = now.Sub(clamavSigHealth.dbTime)
	if snap.Age < 0 {
		// A database dated in this node's future. Clamp rather than report a
		// negative age: a negative duration would render as a nonsense gauge
		// and would compare below every threshold, silently passing the
		// staleness check for as long as the skew lasts.
		snap.Age = 0
		snap.FutureDated = true
	}
	snap.Stale = snap.Age > clamavSigStaleAfter
	return snap
}

// fireClamAVSignatureStaleAlert delivers the `clamav_signature_stale` alert.
//
// Package-level seam so tests observe transitions synchronously rather than
// racing the process-global alerts sink. HasSubscriber-gated because with no
// webhook configured — the default posture, and the state of every test binary
// — this must not spawn a goroutine at all.
//
// The Detail carries an age and a build date, both computed here. It carries no
// engine string and no raw reply: Dispatch dedups on event+Detail, and the raw
// reply changes on every engine upgrade, so putting it in the Detail would
// weaken the dedup window for no operator benefit.
//
// It reports whether the alert was DISPATCHED, and the caller consumes the
// once-per-episode latch only on a true return
// (SEC-CLAMSIG-STALE-LATCH-1, see noteClamAVSignatureObservation).
var fireClamAVSignatureStaleAlert = func(detail string) bool {
	if !alertStore().HasSubscriber("clamav_signature_stale") {
		return false
	}
	go fireAlert("clamav_signature_stale", AlertPayload{
		Detail: detail,
		Source: "clamav",
	})
	return true
}

// noteClamAVSignatureObservation records one VERSION observation and evaluates
// staleness. Called from the signature watcher (scan_signature_watch.go) on
// every poll, including the immediate one at startup.
//
// A FAILED observation (ok false — daemon down, no VERSION capability, ClamAV
// not configured) deliberately records NOTHING and clears nothing. The
// unreachable daemon is already a failing readiness row, a diagnostics row and
// a scan_clam_error alert; re-reporting it here as a freshness problem would
// double-page one fault under two names. Keeping the last observation also
// keeps the honest answer available: the database was this old when we could
// last see it, and ObservationAge says how long ago that was.
func noteClamAVSignatureObservation(v clamav.Version, ok bool) {
	if !ok {
		return
	}
	dbTime, known := v.DBTime()

	clamavSigHealth.mu.Lock()
	clamavSigHealth.observed = true
	clamavSigHealth.dbTime = dbTime
	clamavSigHealth.dbTimeKnown = known
	clamavSigHealth.observedAt = clamavSigNow()
	snap := clamavSigStateLocked()

	var (
		shouldLog  bool
		recovered  bool
		suppressed int64
	)
	switch {
	case snap.Stale:
		clamavSigHealth.sawStale = true
		if !clamavSigHealth.alerted {
			// SEC-CLAMSIG-STALE-LATCH-1 (the sibling of
			// SEC-BLFEED-STALE-LATCH-1 and SEC-TFEED-STALE-LATCH-1, the rule
			// latchOncePerEpisodeOnDelivery carries for the two feed planes):
			// the episode is consumed only by a DISPATCHED alert.
			//
			// Latching first and firing afterwards burned the episode whenever
			// nothing subscribed — the DEFAULT posture, no webhooks configured
			// — and this latch clears only on an OBSERVED newer database,
			// never on elapsed time. Worse, the watcher's immediate poll
			// (startScanSignatureWatch) runs from initBackgroundServices,
			// BEFORE initPersistentAdminState loads the webhook store, so even
			// a node with the webhook configured on disk had no subscriber yet
			// at its first observation. A node that booted with month-old
			// definitions therefore spent its one page on nobody and never
			// paged again, while clamd stayed reachable and went on returning
			// CLEAN for malware published since the database was built.
			//
			// Not dispatching leaves the episode OPEN, so the next poll (five
			// minutes) re-attempts: that is what makes this plane need no
			// startup-alert queue and no episode generation. The verdict
			// (snap) is computed in this same critical section rather than
			// outside it, which is the window the feed planes' generation
			// counter exists to close; the sink is safe to call under the lock
			// for the same reason their delivered() is — it only probes the
			// lock-free subscription index and hands delivery to a goroutine.
			detail := fmt.Sprintf("ClamAV signature database is %s old (built %s); freshclam is not updating it",
				clamavSigRoundAge(snap.Age), snap.DBTime.UTC().Format(time.RFC3339))
			if fireClamAVSignatureStaleAlert(detail) {
				clamavSigHealth.alerted = true
			}
		}
		now := clamavSigNow()
		if clamavSigHealth.logAt.IsZero() || now.Sub(clamavSigHealth.logAt) >= clamavSigLogInterval {
			clamavSigHealth.logAt = now
			shouldLog = true
		} else {
			clamavSigHealth.suppressed++
		}
	case snap.AgeKnown && !snap.FutureDated:
		// OBSERVED evidence of a fresh database is the only thing that ends an
		// episode.
		//
		// FutureDated is excluded deliberately, and it is not a hypothetical:
		// a future-dated reading has its age CLAMPED to zero, so without this
		// exclusion a clock jump on the ClamAV host would present a stale
		// database as perfectly current, clear the episode, and log a recovery
		// that did not happen. Skew is an inability to measure, exactly like
		// Unknown, and neither clears nor fires. The episode survives until
		// the clocks agree and a real age can be read.
		recovered = clamavSigHealth.sawStale
		suppressed = clamavSigHealth.suppressed
		clamavSigHealth.alerted = false
		clamavSigHealth.sawStale = false
		clamavSigHealth.logAt = time.Time{}
		clamavSigHealth.suppressed = 0
	}
	age := snap.Age
	clamavSigHealth.mu.Unlock()

	if shouldLog && logger != nil {
		logger.Printf("SecurityScan: ClamAV signature database is %s old — the daemon is healthy and scanning, but malware published since it was built is NOT being detected; check freshclam in the ClamAV container",
			clamavSigRoundAge(age))
	}
	if recovered && logger != nil {
		logger.Printf("SecurityScan: ClamAV signature database is current again (%d suppressed staleness log lines during the episode)", suppressed)
	}
}

// clamavSigRoundAge renders a duration for an operator: whole hours up to two
// days, whole days beyond. Avoids "1178h21m14.3s" in a page body.
func clamavSigRoundAge(d time.Duration) string {
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh", int64(d.Hours()))
	}
	return fmt.Sprintf("%dd", int64(d.Hours())/24)
}

// clamAVSignaturesCode is the diagnostics code of the signature-freshness row.
const clamAVSignaturesCode = "clamav_signatures"

// checkClamAVSignatures returns zero or one row for a signature database that
// is stale, unmeasurable, or dated in this node's future.
//
// Report-only, and a pure memory read of the cached observation — it never
// dials the daemon, so it adds nothing to the diagnostics report's cost
// profile (see the concurrency notes at the top of diagnostics.go).
//
// Contributes nothing when ClamAV is not configured, scanning is off, body
// scanning is delegated to the remote scan service, no observation has landed
// yet, or the database is current. The message is a fixed string plus
// timings: the row is readable by the viewer role, and the engine string and
// raw reply stay on the role-gated Security Scanning status.
func checkClamAVSignatures() []OperatorContractCheck {
	if globalSecScanner == nil || !globalSecScanner.Enabled() {
		return nil
	}
	// In sidecar mode this process holds no local daemon to ask, and the
	// remote /scan protocol does not carry the sidecar's signature identity.
	// Reporting "unknown" for that deployment would be a row an operator
	// cannot act on; the gap is recorded in the review's residual risk.
	if globalRemoteScanner != nil && globalRemoteScanner.Enabled() {
		return nil
	}
	return clamavSignatureRows(clamavSigState())
}

// clamavSignatureRows builds the row from a snapshot, with no global reads.
//
// Split from checkClamAVSignatures so the operator-facing contract — which
// shape produces which message, and that the action names freshclam rather
// than sending the operator to restart Culvert — is testable without standing
// up a configured scanner and a live daemon in the test binary.
func clamavSignatureRows(snap clamavSigSnapshot) []OperatorContractCheck {
	if !snap.Armed {
		return nil
	}

	switch {
	case snap.Stale:
		msg := fmt.Sprintf("ClamAV virus definitions are %s old (built %s) — the daemon is healthy and scanning, but malware published since then is NOT being detected and those downloads are reported to users as clean",
			clamavSigRoundAge(snap.Age), snap.DBTime.UTC().Format("2006-01-02 15:04 UTC"))
		if snap.ObservationAge > clamavSigStaleAfter {
			msg += fmt.Sprintf("; this reading is itself %s old because the daemon has not answered since",
				clamavSigRoundAge(snap.ObservationAge))
		}
		return []OperatorContractCheck{{
			Code:           clamAVSignaturesCode,
			Status:         diagWarn,
			Message:        msg,
			OperatorAction: "Virus definitions are updated by freshclam inside the ClamAV container, not by Culvert. Check that the updater is running (CLAMAV_NO_FRESHCLAMD must not be true), that the container can reach database.clamav.net, that /var/lib/clamav has free space, and that the ClamAV engine version is still supported — end-of-life engines are refused updates. The row clears within about five minutes of the daemon reporting a newer database, with no restart.",
		}}
	case snap.Unknown:
		return []OperatorContractCheck{{
			Code:           clamAVSignaturesCode,
			Status:         diagWarn,
			Message:        "ClamAV answers but reports no virus-definition build date this node can read, so definition age cannot be checked on this node — a database that stops updating would not be detected",
			OperatorAction: "Confirm the ClamAV daemon has a signature database loaded and reports it: `clamdscan --version` should print three /-separated fields (engine, database counter, build date). A reply with no build date usually means no database is loaded, or that a non-clamd service is answering on the configured address.",
		}}
	case snap.FutureDated:
		return []OperatorContractCheck{{
			Code:   clamAVSignaturesCode,
			Status: diagWarn,
			Message: fmt.Sprintf("ClamAV reports a virus-definition build date in this node's future (%s) — the two clocks disagree, so definition age cannot be trusted and a stale database would not be detected",
				snap.DBTime.UTC().Format("2006-01-02 15:04 UTC")),
			OperatorAction: "Reconcile the clocks: this node's time and the ClamAV host's time should both come from NTP. Definition-age checking resumes automatically once the reported build date is no longer ahead of this node's clock.",
		}}
	}
	return nil
}

// clamavSigWritePrometheus appends the culvert_clamav_signature_* family.
//
// Emitted only when an observation has landed, so a node with no local ClamAV
// exports nothing here rather than a row of zeros an alert rule would read as a
// 1970-vintage signature database.
func clamavSigWritePrometheus(w *strings.Builder) {
	snap := clamavSigState()
	if !snap.Armed {
		return
	}

	w.WriteString("\n# HELP culvert_clamav_signature_timestamp_seconds Unix time the ClamAV virus-definition database in use was built (0 = the daemon reports no readable build date)\n")
	w.WriteString("# TYPE culvert_clamav_signature_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_clamav_signature_timestamp_seconds %d\n", unixOrZero(snap.DBTime))

	// The age is exported as well as the timestamp, for the reason
	// blocklist_feed_health.go records: an operator should not have to express
	// a freshness rule as time() minus a gauge that can legitimately be 0.
	w.WriteString("\n# HELP culvert_clamav_signature_age_seconds Age of the ClamAV virus-definition database in use (0 when the build date is unreadable or ahead of this node's clock — check culvert_clamav_signature_age_unknown and _future_dated)\n")
	w.WriteString("# TYPE culvert_clamav_signature_age_seconds gauge\n")
	fmt.Fprintf(w, "culvert_clamav_signature_age_seconds %d\n", int64(snap.Age.Seconds()))

	w.WriteString("\n# HELP culvert_clamav_signature_stale 1 when the ClamAV virus-definition database in use is older than 48h, 0 otherwise\n")
	w.WriteString("# TYPE culvert_clamav_signature_stale gauge\n")
	fmt.Fprintf(w, "culvert_clamav_signature_stale %d\n", boolGauge(snap.Stale))

	w.WriteString("\n# HELP culvert_clamav_signature_age_unknown 1 when ClamAV answers but reports no readable definition build date, so staleness cannot be evaluated on this node\n")
	w.WriteString("# TYPE culvert_clamav_signature_age_unknown gauge\n")
	fmt.Fprintf(w, "culvert_clamav_signature_age_unknown %d\n", boolGauge(snap.Unknown))

	w.WriteString("\n# HELP culvert_clamav_signature_future_dated 1 when ClamAV reports a definition build date ahead of this node's clock (clock skew; age is reported as 0 and staleness cannot be trusted)\n")
	w.WriteString("# TYPE culvert_clamav_signature_future_dated gauge\n")
	fmt.Fprintf(w, "culvert_clamav_signature_future_dated %d\n", boolGauge(snap.FutureDated))

	// How current the OBSERVATION is, which is a different question from how
	// current the DATABASE is. A daemon that stopped answering freezes the
	// age above; this is the series that says so, and it is why a stale row
	// cannot be mistaken for a fresh reading of an old database.
	w.WriteString("\n# HELP culvert_clamav_signature_observation_age_seconds Seconds since this node last read the ClamAV definition identity (grows without bound while the daemon is unreachable, freezing the other series in this family)\n")
	w.WriteString("# TYPE culvert_clamav_signature_observation_age_seconds gauge\n")
	fmt.Fprintf(w, "culvert_clamav_signature_observation_age_seconds %d\n", int64(snap.ObservationAge.Seconds()))
}

// resetClamAVSigHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so replacing it wholesale under the lock
// would swap the held mutex for an unlocked zero value — the fault
// resetScanSvcHealthForTest records in scan_svc_listener.go.
func resetClamAVSigHealthForTest() {
	clamavSigHealth.mu.Lock()
	clamavSigHealth.observed = false
	clamavSigHealth.dbTime = time.Time{}
	clamavSigHealth.dbTimeKnown = false
	clamavSigHealth.observedAt = time.Time{}
	clamavSigHealth.alerted = false
	clamavSigHealth.sawStale = false
	clamavSigHealth.logAt = time.Time{}
	clamavSigHealth.suppressed = 0
	clamavSigHealth.mu.Unlock()
	clamavSigNow = time.Now
}
