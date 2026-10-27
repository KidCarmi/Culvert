package main

// Tests for the evaluation-scoped schedule memo (scheduleClock): the Stage-2
// access scan resolves a scheduled rule's timezone and derives the clock fields
// ONCE per (instant, timezone) instead of once per RULE.
//
// The load-bearing property is DECISION EQUIVALENCE. A memo is only a legitimate
// optimization if a scan that shares one cannot reach a different verdict from a
// scan that resolves every rule from scratch, so the oracle below is the
// pre-memo logic spelled out independently (resolve the location, convert the
// instant, compare day then window) rather than a second call into the
// production path. The riskiest shape — a rulebase whose consecutive rules carry
// DIFFERENT timezones, where a stale single-entry memo would silently judge one
// rule in another's zone — gets its own direct test.

import (
	"fmt"
	"testing"
	"time"
)

// scheduleOracle is the pre-memo decision, written out independently: load the
// location, convert the instant, then day-then-window on the converted value.
// It deliberately does not call scheduleClock, matchScheduleMemo or the shared
// day/window helpers — a differential oracle that shares the code under test
// proves nothing.
func scheduleOracle(t *testing.T, s *PolicySchedule, now time.Time) bool {
	t.Helper()
	loc := time.UTC
	if s.Timezone != "" {
		if l, err := time.LoadLocation(s.Timezone); err == nil {
			loc = l
		}
	}
	local := now.In(loc)
	if len(s.Days) > 0 {
		want := local.Weekday().String()[:3]
		hit := false
		for _, d := range s.Days {
			if len(d) == len(want) && equalFoldASCII(d, want) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if s.TimeStart == "" || s.TimeEnd == "" {
		return true
	}
	cur := fmt.Sprintf("%02d:%02d", local.Hour(), local.Minute())
	if s.TimeStart <= s.TimeEnd {
		return cur >= s.TimeStart && cur < s.TimeEnd
	}
	return cur >= s.TimeStart || cur < s.TimeEnd
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// scheduleMatrix is the (timezone x days x window) cross product the tests below
// drive. Timezones span a positive offset, a negative offset, a half-hour offset
// and a DST-observing zone, because the memo caches a CONVERTED instant and an
// offset error would otherwise hide behind UTC.
func scheduleMatrix() []*PolicySchedule {
	zones := []string{"", "UTC", "America/New_York", "Europe/London", "Asia/Kolkata", "Australia/Sydney"}
	dayLists := [][]string{nil, {"Mon"}, {"mon", "TUE"}, {"Sat", "Sun"}, {"Mon", "Tue", "Wed", "Thu", "Fri"}}
	windows := [][2]string{
		{"", ""},
		{"00:00", "24:00"},
		{"09:00", "17:00"},
		{"22:00", "06:00"}, // overnight
		{"12:00", "12:00"}, // empty window (end-exclusive)
		{"9:00", "17:00"},  // malformed start — legacy string comparison owns it
		{"09:00", "bogus"}, // malformed end — legacy path
	}
	var out []*PolicySchedule
	for _, z := range zones {
		for _, d := range dayLists {
			for _, w := range windows {
				out = append(out, &PolicySchedule{Days: d, TimeStart: w[0], TimeEnd: w[1], Timezone: z})
			}
		}
	}
	return out
}

// scheduleInstants spans weekday/weekend, both sides of every window bound, and
// both sides of a US and an EU DST transition.
func scheduleInstants() []time.Time {
	var out []time.Time
	for _, d := range []time.Time{
		time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),  // Monday, winter
		time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), // Saturday, winter
		time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC),  // US DST spring-forward
		time.Date(2026, 3, 29, 0, 0, 0, 0, time.UTC), // EU DST spring-forward
		time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC), // Wednesday, summer
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), // US DST fall-back
	} {
		for _, hm := range [][2]int{{0, 0}, {5, 59}, {6, 0}, {8, 59}, {9, 0}, {11, 59}, {12, 0}, {16, 59}, {17, 0}, {21, 59}, {22, 0}, {23, 59}} {
			out = append(out, d.Add(time.Duration(hm[0])*time.Hour+time.Duration(hm[1])*time.Minute))
		}
	}
	return out
}

// TestScheduleClock_MemoMatchesOracle is the differential oracle: one memo
// shared across the whole schedule matrix (the scan's reuse pattern) must agree
// with the independently written pre-memo decision for every instant.
func TestScheduleClock_MemoMatchesOracle(t *testing.T) {
	scheds := scheduleMatrix()
	for _, now := range scheduleInstants() {
		// ONE memo for all schedules at this instant — exactly how the Stage-2
		// scan reuses it across a rulebase.
		c := scheduleClock{now: now}
		for _, s := range scheds {
			got := matchScheduleMemo(s, &c)
			want := scheduleOracle(t, s, now)
			if got != want {
				t.Fatalf("memo disagreed with oracle: now=%s tz=%q days=%v window=%q-%q: got %v want %v",
					now.Format(time.RFC3339), s.Timezone, s.Days, s.TimeStart, s.TimeEnd, got, want)
			}
		}
	}
}

// TestScheduleClock_MatchScheduleAtUnchanged pins the public one-shot entry
// point to the same oracle, so the refactor that routed it through the memo did
// not move its behavior for the Stage-1 auth gate, CDR policy or the simulator.
func TestScheduleClock_MatchScheduleAtUnchanged(t *testing.T) {
	for _, now := range scheduleInstants() {
		for _, s := range scheduleMatrix() {
			if got, want := matchScheduleAt(s, now), scheduleOracle(t, s, now); got != want {
				t.Fatalf("matchScheduleAt: now=%s tz=%q days=%v window=%q-%q: got %v want %v",
					now.Format(time.RFC3339), s.Timezone, s.Days, s.TimeStart, s.TimeEnd, got, want)
			}
		}
	}
}

// TestScheduleClock_AlternatingTimezonesReDerive is the single-entry memo's
// sharpest failure mode: consecutive rules in DIFFERENT zones. A memo that
// answered rule 2 from rule 1's cached fields would judge it in the wrong zone,
// and because both verdicts are plausible booleans the error would be silent.
//
// The instant is chosen so the two zones fall on different sides of the window:
// 2026-01-05 21:00 UTC is Mon 16:00 in New York (inside 09:00-17:00) and Tue
// 08:00 in Sydney (outside it). Alternating must therefore alternate verdicts.
func TestScheduleClock_AlternatingTimezonesReDerive(t *testing.T) {
	now := time.Date(2026, 1, 5, 21, 0, 0, 0, time.UTC)
	ny := &PolicySchedule{Days: []string{"Mon"}, TimeStart: "09:00", TimeEnd: "17:00", Timezone: "America/New_York"}
	syd := &PolicySchedule{Days: []string{"Mon"}, TimeStart: "09:00", TimeEnd: "17:00", Timezone: "Australia/Sydney"}

	if want := scheduleOracle(t, ny, now); !want {
		t.Fatalf("test premise broken: NY rule should match at %s", now)
	}
	if want := scheduleOracle(t, syd, now); want {
		t.Fatalf("test premise broken: Sydney rule should not match at %s", now)
	}

	c := scheduleClock{now: now}
	// Alternate repeatedly: every switch must evict and re-derive, in both
	// directions, however many times the memo has already been filled.
	for i := 0; i < 8; i++ {
		if !matchScheduleMemo(ny, &c) {
			t.Fatalf("iteration %d: New_York rule should match (memo served a stale zone)", i)
		}
		if matchScheduleMemo(syd, &c) {
			t.Fatalf("iteration %d: Sydney rule should not match (memo served a stale zone)", i)
		}
	}
}

// TestScheduleClock_EmptyAndUTCAreDistinctKeys guards the memo key itself. ""
// and "UTC" resolve to the same location but are different strings; the memo
// must not treat a key change as a hit or a miss incorrectly.
func TestScheduleClock_EmptyAndUTCAreDistinctKeys(t *testing.T) {
	now := time.Date(2026, 1, 5, 10, 30, 0, 0, time.UTC)
	c := scheduleClock{now: now}
	empty := &PolicySchedule{TimeStart: "09:00", TimeEnd: "17:00"}
	utc := &PolicySchedule{TimeStart: "09:00", TimeEnd: "17:00", Timezone: "UTC"}
	for i := 0; i < 4; i++ {
		if !matchScheduleMemo(empty, &c) {
			t.Fatalf("iteration %d: empty timezone (UTC) should match 10:30 in 09:00-17:00", i)
		}
		if !matchScheduleMemo(utc, &c) {
			t.Fatalf("iteration %d: explicit UTC should match 10:30 in 09:00-17:00", i)
		}
	}
	if _, _, mins := c.at("UTC"); mins != 10*60+30 {
		t.Errorf("memoised minutes = %d, want %d", mins, 10*60+30)
	}
}

// TestScheduleClock_InvalidTimezoneStillFallsBackToUTC keeps the documented
// lenient Stage-2 posture: an unparseable zone evaluates in UTC (the Stage-1
// auth gate adds its own strict fail-closed pre-check, which is unaffected).
func TestScheduleClock_InvalidTimezoneStillFallsBackToUTC(t *testing.T) {
	now := time.Date(2026, 1, 5, 10, 30, 0, 0, time.UTC)
	s := &PolicySchedule{TimeStart: "09:00", TimeEnd: "17:00", Timezone: "Not/AZone"}
	c := scheduleClock{now: now}
	if !matchScheduleMemo(s, &c) {
		t.Error("invalid timezone should fall back to UTC and match 10:30 in 09:00-17:00")
	}
	if !matchScheduleAt(s, now) {
		t.Error("matchScheduleAt should agree on the UTC fallback")
	}
}

// TestEvaluate_ScheduledScanIsAllocationFree pins the scan's zero-allocation
// contract through the memo: scheduleClock lives on the caller's stack and must
// not escape. A regression here (a pointer retained, a value boxed into an
// interface) would put O(rules) garbage back on the proxy hot path.
func TestEvaluate_ScheduledScanIsAllocationFree(t *testing.T) {
	ps := buildScheduledPolicyStore(200)
	// Warm every lazily-filled cache (tzdata memo, rule snapshot) first, so the
	// measurement sees only steady-state per-request work.
	for i := 0; i < 50; i++ {
		ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
	}
	allocs := testing.AllocsPerRun(200, func() {
		ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
	})
	if allocs != 0 {
		t.Errorf("scheduled-rule evaluation allocated %.1f times per scan, want 0", allocs)
	}
}

// TestScheduleClock_MemoDoesNotReadTheClock pins the lazy-clock contract the
// memo inherited: scheduleClock derives from the instant it was GIVEN and never
// calls time.Now() itself, so a rulebase with no scheduled rule keeps paying no
// clock read and a scan cannot straddle a minute boundary mid-rulebase.
func TestScheduleClock_MemoDoesNotReadTheClock(t *testing.T) {
	// An instant far in the past: if anything under matchScheduleMemo consulted
	// the real clock, a Monday-only rule evaluated at this Monday instant would
	// start failing on most real days.
	now := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC) // Monday
	s := &PolicySchedule{Days: []string{"Mon"}, TimeStart: "09:00", TimeEnd: "17:00", Timezone: "UTC"}
	c := scheduleClock{now: now}
	for i := 0; i < 3; i++ {
		if !matchScheduleMemo(s, &c) {
			t.Fatalf("iteration %d: memo must decide against the supplied instant, not the wall clock", i)
		}
	}
	if !c.local.Equal(now) {
		t.Errorf("memoised local = %s, want the supplied instant %s", c.local, now)
	}
}
