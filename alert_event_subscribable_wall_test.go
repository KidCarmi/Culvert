package main

// alert_event_subscribable_wall_test.go — SEC-ALERTSUB-1.
//
// THE FINDING. `internal/alerts.Store` matches a webhook's subscription
// against an alert's event name EXACTLY, or against the wildcard `"*"`
// (store.go `HasSubscriber` / `Dispatch`). An empty `Events` list means
// NOTHING — there is deliberately no empty-means-all rule. And the admin UI
// builds that list from ONE source:
//
//	const events = [...document.querySelectorAll('.wh-event:checked')].map(cb=>cb.value);
//
// — the checked checkboxes, with no `"*"` option anywhere in the page. So an
// event name that has no checkbox is UNSUBSCRIBABLE through the product's own
// UI: an operator who opens the webhook modal and ticks EVERY box still never
// receives it.
//
// Measured on the tree before the fix: 18 of 40 production alert events had no
// checkbox, among them `ha_manual_failover_required` — the one event whose
// entire purpose is to say a human must intervene — plus `ha_self_fenced` and
// `ha_resume_unfenced` (CHAOS-55's split-brain signals), `disk_critical`,
// `dns_failure`, `cdr_unavailable`, the whole scan plane (`scan_timeout`,
// `scan_skipped`, `scan_svc_down`, `yara_degraded`), the whole
// `saas_feed_*` family, and `admin_ui_unavailable` — CHAOS-57's own alert,
// which has been undeliverable to a GUI-managed webhook since the day it
// shipped.
//
// This is a MONITORING-VISIBILITY silent failure of the alerting plane
// itself: nothing errors, nothing is logged, `Dispatch` still takes the dedup
// key and still fans out — to zero hooks. The appliance is quiet in exactly
// the way a healthy one is.
//
// WHY A WALL AND NOT JUST THE 19 CHECKBOXES. The checkboxes are the fix for
// today's gap; this test is the fix for the CLASS. Every one of those 18 was
// added by somebody who wired a complete Go-side alert — seam, HasSubscriber
// gate, bounded Detail, runbook — and had no way to discover that one HTML
// edit was still outstanding. There is no compiler relationship between a Go
// string literal and an HTML attribute, so the only thing that can hold them
// together is an assertion. The repo already learned this lesson once, in the
// other direction: static/index.html carries a comment at the release-catalog
// rows recording that events missing from the list "would be silently filtered
// for GUI-managed webhooks (Codex review on PR #639)" — the hazard was known,
// written down next to the list, and still recurred 18 times, because a
// comment cannot fail a build.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// alertEmitterRe matches the event-name literal in every production path that
// can reach Store.Dispatch:
//
//   - fireAlert("x", ...)            — the root seam
//   - deferStartupAlert("x", ...)    — the boot-time deferred fire
//   - alerts.Fire("x", ...)          — the internal/* package seam
//   - Event: "x"                     — a payload built literally and dispatched
//
// Enumerating from the EMITTERS rather than from one call shape is deliberate.
// A wall scoped to a single syntactic form proves less than it looks: SOCKS5's
// log-injection wall (SEC-SOCKS5-LOG-1 round 2) was written against direct
// `logger.*` calls and missed the identical taint arriving through
// `plugin.Decide` → `obs.Printf`. Nine of the events in this tree are fired
// through something other than `fireAlert`, so a `fireAlert`-only wall would
// have passed while `ha_manual_failover_required` stayed unsubscribable.
var alertEmitterRe = regexp.MustCompile(
	`(?:fireAlert|deferStartupAlert|alerts\.Fire)\("([a-z0-9_]+)"|Event:\s*"([a-z0-9_]+)"`)

// whEventRe matches a subscribable event checkbox in the admin UI.
var whEventRe = regexp.MustCompile(`class="wh-event"\s+value="([a-z0-9_*]+)"`)

// alertEventWallExempt lists event names the scan finds that are NOT operator
// alert events, with the reason each is exempt. Keep this list tiny and
// justified: every entry is an assertion that an operator never needs to
// subscribe to that name.
var alertEventWallExempt = map[string]string{
	// The webhook "send test event" button's own payload. It is delivered to
	// the ONE hook being tested by id, never matched against a subscription,
	// so a checkbox for it would subscribe an operator to nothing.
	"test": "the webhook test-delivery payload; targeted by hook id, never event-matched",
}

// collectFiredAlertEvents scans every production .go file in the module for
// event names reaching an alert emitter.
func collectFiredAlertEvents(t *testing.T) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	root := pkgSourceDir()

	// The walk only ENUMERATES; every file is read afterwards, outside the
	// callback. gosec G122 flags a filesystem operation performed inside a
	// Walk callback, because the path the callback is handed was resolved by
	// an earlier lstat and a symlink swapped in between the two is a TOCTOU
	// traversal. Collecting first and reading after keeps discovery and
	// reading separate, which is the clearer shape here anyway.
	var sources []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// frontend/ is TypeScript and node_modules is enormous; neither
			// can call a Go emitter.
			switch info.Name() {
			case "node_modules", "frontend", ".git", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only: a symlink or device node is never a source file
		// this wall needs to read, and skipping them here means the read loop
		// below is handed nothing but ordinary files.
		if !info.Mode().IsRegular() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		sources = append(sources, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	for _, path := range sources {
		b, rerr := os.ReadFile(path) // #nosec G304 -- enumerated from our own module source tree
		if rerr != nil {
			t.Fatalf("reading %s: %v", path, rerr)
		}
		for _, m := range alertEmitterRe.FindAllStringSubmatch(string(b), -1) {
			ev := m[1]
			if ev == "" {
				ev = m[2]
			}
			if ev == "" {
				continue
			}
			rel, rerr2 := filepath.Rel(root, path)
			if rerr2 != nil {
				rel = path
			}
			found[ev] = append(found[ev], rel)
		}
	}
	return found
}

// collectSubscribableEvents reads the admin UI's checkbox list.
func collectSubscribableEvents(t *testing.T) map[string]bool {
	t.Helper()
	// Anchored to the package source dir, not the CWD: a concurrent os.Chdir
	// in another test would otherwise flake this read (the repo's
	// TestTestFileReadsAreCWDIndependent wall enforces it).
	b, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("reading %s: %v", staticIndexHTMLPath(), err)
	}
	out := map[string]bool{}
	for _, m := range whEventRe.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = true
	}
	return out
}

// TestWall_EveryFiredAlertEventIsSubscribable is the wall.
//
// An alert an operator cannot subscribe to through the product's own UI is an
// alert that does not exist for most deployments. Adding a new event therefore
// means TWO edits, and this test is what makes the second one unforgettable.
func TestWall_EveryFiredAlertEventIsSubscribable(t *testing.T) {
	fired := collectFiredAlertEvents(t)
	listed := collectSubscribableEvents(t)

	// NOT-VACUOUS: a regex that stopped matching, or a walk that found no
	// files, would make this test pass forever while proving nothing. The
	// bounds are deliberately well below the real counts (40 fired / 42
	// listed at the time of writing) so ordinary growth does not churn them,
	// but far above zero.
	if len(fired) < 20 {
		t.Fatalf("not-vacuous check failed: found only %d fired alert events; the emitter "+
			"regex or the module walk has stopped matching, so this wall proves nothing", len(fired))
	}
	if len(listed) < 20 {
		t.Fatalf("not-vacuous check failed: found only %d subscribable events in "+
			"static/index.html; the checkbox regex has stopped matching", len(listed))
	}

	var missing []string
	for ev := range fired {
		if _, exempt := alertEventWallExempt[ev]; exempt {
			continue
		}
		if !listed[ev] {
			missing = append(missing, ev+" (fired from "+strings.Join(dedupe(fired[ev]), ", ")+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d production alert event(s) have no subscribable checkbox in static/index.html, "+
			"so NO GUI-managed webhook can ever receive them (the store matches event names exactly, "+
			"and the webhook modal has no \"*\" option):\n  %s\n\n"+
			"Fix: add one `<label ...><input type=\"checkbox\" class=\"wh-event\" value=\"<event>\"> "+
			"<Human label></label>` row to the event list in static/index.html, in the SAME commit as "+
			"the Go-side alert. If an event genuinely is not operator-subscribable, add it to "+
			"alertEventWallExempt with the reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestWall_AlertEventWallDetectsAMissingCheckbox is the CONTROL.
//
// Without it, a regex typo that matched nothing, or an exemption map that
// swallowed everything, would leave the wall green forever — the vacuous-gate
// failure mode this repo has hit repeatedly (CHAOS-69's unreachable SOCKS5
// bound, CHAOS-70's structural wall whose match count dropped to zero). It
// drives the SAME comparison the wall performs against a synthetic event that
// is deliberately absent from the HTML, and requires it to be reported.
func TestWall_AlertEventWallDetectsAMissingCheckbox(t *testing.T) {
	listed := collectSubscribableEvents(t)

	const synthetic = "culvert_synthetic_unsubscribable_event"
	if listed[synthetic] {
		t.Fatalf("control is invalid: %q is actually present in static/index.html", synthetic)
	}

	fired := map[string][]string{synthetic: {"synthetic_test.go"}}
	var missing []string
	for ev := range fired {
		if _, exempt := alertEventWallExempt[ev]; exempt {
			continue
		}
		if !listed[ev] {
			missing = append(missing, ev)
		}
	}
	if len(missing) != 1 || missing[0] != synthetic {
		t.Fatalf("control failed: the wall's own comparison did not flag a missing checkbox; got %v", missing)
	}
}

// TestWall_ExemptAlertEventsAreStillFired keeps the exemption map honest: an
// exemption for an event nothing fires any more is dead weight that makes the
// wall look narrower than it is.
func TestWall_ExemptAlertEventsAreStillFired(t *testing.T) {
	fired := collectFiredAlertEvents(t)
	for ev, reason := range alertEventWallExempt {
		if _, ok := fired[ev]; !ok {
			t.Errorf("alertEventWallExempt carries %q (%q) but nothing fires it any more — remove the exemption", ev, reason)
		}
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
