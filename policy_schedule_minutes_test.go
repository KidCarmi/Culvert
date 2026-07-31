package main

// Tests for the allocation-free schedule time-of-day comparison (minutes-of-day
// integers instead of the previous per-rule fmt.Sprintf lexicographic string
// compare). The load-bearing property is ORDER EQUIVALENCE: on the strict
// zero-padded "HH:MM" format (plus the "24:00" end-of-day sentinel) the numeric
// comparison must reproduce the legacy string comparison decision bit-for-bit,
// and anything outside that format must stay on the legacy path unchanged.

import (
	"testing"
	"time"
)

func TestParseClockMinutes(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"00:00", 0, true},
		{"09:00", 540, true},
		{"17:30", 1050, true},
		{"23:59", 1439, true},
		{"24:00", 1440, true}, // accepted end-of-day sentinel (full-day windows)
		{"", 0, false},
		{"9:00", 0, false}, // unpadded — legacy comparison keeps ownership
		{"09:0", 0, false},
		{"009:00", 0, false},
		{"24:01", 0, false},
		{"25:00", 0, false},
		{"23:60", 0, false},
		{"aa:bb", 0, false},
		{"09-00", 0, false},
		{"09:00 ", 0, false},
	}
	for _, c := range cases {
		got, ok := parseClockMinutes(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseClockMinutes(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestScheduleTimeMatch_OrderEquivalence sweeps well-formed bound pairs (normal
// and overnight ranges, including the 24:00 sentinel) against instants across
// the day and asserts the numeric comparison agrees with the legacy string
// comparison on every combination. scheduleTimeMatchLegacy IS the pre-change
// implementation, so it serves as the oracle.
func TestScheduleTimeMatch_OrderEquivalence(t *testing.T) {
	var bounds []string
	for h := 0; h < 24; h++ {
		for _, m := range []int{0, 29, 59} {
			bounds = append(bounds, clockString(h, m))
		}
	}
	bounds = append(bounds, "24:00")

	checked := 0
	for _, start := range bounds {
		for _, end := range bounds {
			for cur := 0; cur < 24*60; cur += 17 { // prime stride hits varied minutes
				now := time.Date(2026, 1, 5, cur/60, cur%60, 30, 0, time.UTC)
				got := scheduleTimeMatch(start, end, now)
				want := scheduleTimeMatchLegacy(start, end, now)
				if got != want {
					t.Fatalf("scheduleTimeMatch(%q, %q) at %02d:%02d = %v, legacy comparison says %v",
						start, end, cur/60, cur%60, got, want)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("equivalence sweep ran no cases")
	}
}

// TestScheduleTimeMatch_MalformedBoundsKeepLegacyBehavior pins the fallback:
// bounds the strict parser rejects must produce exactly the legacy
// lexicographic decision — including its historical quirk that an unpadded
// "9:00" start lexicographically EXCEEDS "17:00", flipping the window into an
// overnight wrap (matching everything before 17:00, even 08:30 outside the
// admin's 9-to-5 intent, and rejecting everything at/after 17:00). Whatever
// such a schedule matched before this optimization, it matches now.
func TestScheduleTimeMatch_MalformedBoundsKeepLegacyBehavior(t *testing.T) {
	at0830 := time.Date(2026, 1, 5, 8, 30, 0, 0, time.UTC)
	if !scheduleTimeMatch("9:00", "17:00", at0830) {
		t.Error(`unpadded "9:00"-"17:00" at 08:30 did not match; legacy overnight-wrap semantics accept it ("08:30" < "17:00")`)
	}
	at1830 := time.Date(2026, 1, 5, 18, 30, 0, 0, time.UTC)
	if scheduleTimeMatch("9:00", "17:00", at1830) {
		t.Error(`unpadded "9:00"-"17:00" at 18:30 matched; legacy string comparison rejects it ("18:30" >= "17:00" and "18:30" < "9:00")`)
	}
}

// TestMatchScheduleAt_SharedInstant verifies the Evaluate-scan entry point
// honors the caller-supplied instant (the one-clock-read-per-scan contract)
// rather than re-reading the wall clock.
func TestMatchScheduleAt_SharedInstant(t *testing.T) {
	s := &PolicySchedule{Days: []string{"Mon"}, TimeStart: "09:00", TimeEnd: "17:00"}
	monday10 := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC) // a Monday
	if !matchScheduleAt(s, monday10) {
		t.Error("Mon 10:00 inside Mon 09:00-17:00 should match")
	}
	sunday10 := time.Date(2026, 1, 4, 10, 0, 0, 0, time.UTC) // a Sunday
	if matchScheduleAt(s, sunday10) {
		t.Error("Sun 10:00 against a Mon-only schedule should not match")
	}
	monday8 := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)
	if matchScheduleAt(s, monday8) {
		t.Error("Mon 08:00 before the 09:00 window should not match")
	}
}

// TestEvaluate_ScheduledRuleDeniedByWindow verifies the Evaluate loop's lazy
// shared-clock path still gates on the time-of-day window end to end (the loop
// no longer routes through the matchSchedule wrapper).
func TestEvaluate_ScheduledRuleDeniedByWindow(t *testing.T) {
	// A one-minute window that cannot contain "now" (whatever now is): pick the
	// minute two hours ago in UTC; end-exclusive, so only that exact minute
	// matches, and now is never inside it.
	past := time.Now().UTC().Add(-2 * time.Hour)
	start := clockString(past.Hour(), past.Minute())
	end := clockString(past.Hour(), past.Minute()+1)
	if past.Minute() == 59 {
		start = clockString(past.Hour(), 58)
		end = clockString(past.Hour(), 59)
	}
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "narrow-window", DestFQDN: "*",
		Schedule: &PolicySchedule{TimeStart: start, TimeEnd: end, Timezone: "UTC"},
		Action:   ActionAllow,
	}})
	if m := ps.Evaluate("203.0.113.7", "", "unauth", "example.com", nil); m != nil {
		t.Errorf("rule scheduled for a past one-minute window matched now, got rule %q", m.Rule.Name)
	}
}

func clockString(h, m int) string {
	const digits = "0123456789"
	return string([]byte{digits[h/10], digits[h%10], ':', digits[m/10], digits[m%10]})
}
