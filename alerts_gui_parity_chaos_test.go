package main

// alerts_gui_parity_chaos_test.go — CHAOS-113's third finding: the alert
// vocabulary the CODE fires and the alert vocabulary an OPERATOR can SUBSCRIBE
// to from the product's own UI had drifted apart, in one direction, silently.
//
// Why this is a chaos finding and not a docs nit. Several producers gate on a
// subscriber before they do any work:
//
//	if !alerts.HasSubscriber("scan_svc_down") { return }
//
// That gate is correct and deliberate (it removes a goroutine, a payload build
// and a dedup-mutex round trip from every response of a node already having a
// bad day — the contract fireDNSFailureAlert documents). Its consequence is
// that an event with NO WAY TO SUBSCRIBE is an event that never fires. The
// admin API does not validate event names, so an operator who already knows
// the string can POST it to /api/alerts/webhooks by hand — but the Alerts
// panel's checkbox list is the only place the vocabulary is discoverable, and
// nothing told them the string exists.
//
// Measured at this round's claim point: 13 production events were fired with
// no checkbox. Four of them were the SCANNING plane — scan_svc_down (the
// fail-open sidecar fault), scan_timeout (fail-closed), scan_skipped
// (fail-open) — while scan_clam_error was the only scanning event an operator
// could tick. So the deployment the CHAOS-52 runbook RECOMMENDS as the remedy
// for a slow scanner (the process-isolated sidecar) was the one deployment
// whose scanning faults could not be alerted on from the UI at all.
//
// This round closes the scanning plane's gap and adds the new
// scan_svc_listener_down beside it. The other nine are recorded in
// scanAlertGUIKnownGaps: this gate exists so the list can only ever get
// SHORTER, and so a new event cannot join it by accident.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// alertFireRe finds an alert event name at a production call site. The four
// forms are the whole surface: main's fireAlert, the package's own
// alerts.Fire, the store method, and the HasSubscriber gate (which names an
// event even where the Fire is built elsewhere).
var alertFireRe = regexp.MustCompile(`(?:fireAlert|alerts\.Fire|globalAlertStore\.Fire|HasSubscriber)\(\s*"([a-z0-9_]+)"`)

// guiEventRe finds a subscribable event in the Alerts panel.
var guiEventRe = regexp.MustCompile(`class="wh-event" value="([a-z0-9_]+)"`)

// scanAlertGUIKnownGaps are the events this round found fired with no GUI
// checkbox and deliberately did NOT fix.
//
// Every one of them belongs to a plane this round does not own, and each needs
// its own owner decision about wording and severity in the panel — an alert
// checkbox is an operator-facing contract, not a string. Fixing nine panels
// from a scan-sidecar round is exactly the "change wider than a chaos round
// should make unreviewed" the 2026-10-13 backlog's preamble describes. They
// are recorded here, in executable form, rather than in prose that nothing
// reads.
//
// REMOVING an entry from this list is the fix. Adding one requires explaining
// why a new event ships unsubscribable.
var scanAlertGUIKnownGaps = map[string]string{
	"admin_ui_unavailable":        "CHAOS-57 admin UI listener plane",
	"cdr_unavailable":             "CDR sanitisation plane",
	"disk_critical":               "log-disk guard plane",
	"dns_failure":                 "destination-DNS resolution plane",
	"ha_lease_reacquired":         "HA lease plane",
	"ha_manual_failover_required": "HA lease plane",
	"ha_resume_unfenced":          "HA lease plane",
	"ha_self_fenced":              "HA lease plane",
	"pac_profile_degraded":        "PAC profile plane",
	"yara_degraded":               "YARA engine plane",
}

// TestChaos113_EveryFiredAlertIsSubscribableInTheGUI is the differential
// oracle. It reads the two sides out of the tree rather than restating either,
// so neither can drift without this failing.
func TestChaos113_EveryFiredAlertIsSubscribableInTheGUI(t *testing.T) {
	fired, scanned := firedAlertEvents(t)
	// A broken regex must not make this gate vacuously green — the same
	// guard the SOCKS5 restart-guidance scan uses.
	if scanned < 400 {
		t.Fatalf("the alert scan only examined %d source files — it is not reading the tree", scanned)
	}
	if len(fired) < 25 {
		t.Fatalf("the alert scan found only %d events — the call-site pattern has drifted", len(fired))
	}

	gui := guiSubscribableEvents(t)
	if len(gui) < 20 {
		t.Fatalf("the Alerts panel scan found only %d checkboxes — the markup has drifted", len(gui))
	}

	var missing []string
	for _, ev := range fired {
		if gui[ev] {
			continue
		}
		if _, known := scanAlertGUIKnownGaps[ev]; known {
			continue
		}
		missing = append(missing, ev)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these alert events are fired by production code but cannot be subscribed to from the Alerts panel, and are not recorded in scanAlertGUIKnownGaps: %s\n"+
			"A producer that gates on alerts.HasSubscriber will therefore never fire it. Add a checkbox in static/index.html, or record the gap with its reason.",
			strings.Join(missing, ", "))
	}

	// The scanning plane is this round's own fix: it must be subscribable,
	// not merely absent from the missing list.
	for _, ev := range []string{"scan_svc_listener_down", "scan_svc_down", "scan_timeout", "scan_skipped", "scan_clam_error"} {
		if !gui[ev] {
			t.Errorf("scanning-plane event %q has no Alerts-panel checkbox", ev)
		}
	}
}

// TestChaos113_KnownAlertGUIGapsAreStillGaps keeps the recorded debt honest in
// the other direction: an entry that has since been fixed must be DELETED, or
// the list silently becomes a list of things that are fine.
func TestChaos113_KnownAlertGUIGapsAreStillGaps(t *testing.T) {
	fired, _ := firedAlertEvents(t)
	firedSet := map[string]bool{}
	for _, ev := range fired {
		firedSet[ev] = true
	}
	gui := guiSubscribableEvents(t)

	for ev, plane := range scanAlertGUIKnownGaps {
		switch {
		case gui[ev]:
			t.Errorf("%q (%s) now HAS an Alerts-panel checkbox — delete it from scanAlertGUIKnownGaps", ev, plane)
		case !firedSet[ev]:
			t.Errorf("%q (%s) is no longer fired by production code — delete it from scanAlertGUIKnownGaps", ev, plane)
		}
	}
}

// firedAlertEvents returns the sorted set of alert event names at production
// call sites, and how many source files were examined.
func firedAlertEvents(t *testing.T) (events []string, filesScanned int) {
	t.Helper()
	set := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable corner of the tree is not this gate's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- walking this repository's own sources
		if rerr != nil {
			return nil
		}
		filesScanned++
		for _, m := range alertFireRe.FindAllStringSubmatch(string(b), -1) {
			set[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for ev := range set {
		events = append(events, ev)
	}
	sort.Strings(events)
	return events, filesScanned
}

// guiSubscribableEvents returns the events the Alerts panel offers.
func guiSubscribableEvents(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	set := map[string]bool{}
	for _, m := range guiEventRe.FindAllStringSubmatch(string(b), -1) {
		set[m[1]] = true
	}
	return set
}
