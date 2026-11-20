package clamav

// CHAOS-124: the signature-database build date must become a TIME, because an
// age is the only form in which "freshclam stopped working" is observable. The
// string was already parsed out of the VERSION reply and then discarded into a
// cache key; these cases pin the shapes a real daemon emits and, more
// importantly, pin the two ways an unknown date must NOT be reported.

import (
	"testing"
	"time"
)

func TestDBTimeParsesObservedLayouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want time.Time
	}{
		{
			// clamd's own strftime("%a %b %d ...") — zero-padded day.
			name: "zero padded day",
			raw:  "ClamAV 1.4.1/27456/Mon Nov 03 09:21:33 2025",
			want: time.Date(2025, time.November, 3, 9, 21, 33, 0, time.UTC),
		},
		{
			name: "two digit day",
			raw:  "ClamAV 0.103.8/26982/Wed Apr 12 09:30:00 2023",
			want: time.Date(2023, time.April, 12, 9, 30, 0, 0, time.UTC),
		},
		{
			name: "space padded day",
			raw:  "ClamAV 1.4.1/27456/Mon Nov  3 09:21:33 2025",
			want: time.Date(2025, time.November, 3, 9, 21, 33, 0, time.UTC),
		},
		{
			name: "unpadded day",
			raw:  "ClamAV 1.4.1/27456/Mon Nov 3 09:21:33 2025",
			want: time.Date(2025, time.November, 3, 9, 21, 33, 0, time.UTC),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := parseClamVersion(tc.raw)
			got, ok := v.DBTime()
			if !ok {
				t.Fatalf("DBTime reported no date for %q (DBDate=%q) — a layout a real daemon emits must parse, or the freshness plane reports every such node as unknown", tc.raw, v.DBDate)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("DBTime = %v, want %v (DBDate=%q)", got, tc.want, v.DBDate)
			}
		})
	}
}

// TestDBTimeZonedReplyKeepsItsZone pins that a reply carrying a zone
// abbreviation parses to the correct instant rather than being rejected.
//
// It is NOT an ordering assertion: an unzoned layout fails outright on a zoned
// value (the year cannot match once "MST" is in the way), so the loop falls
// through to a zoned layout whatever the order. What this guards is the
// presence of a zoned layout at all — drop both and every daemon that reports
// a zone becomes permanently "unknown age", which is the silent failure this
// round exists to remove.
func TestDBTimeZonedReplyKeepsItsZone(t *testing.T) {
	v := parseClamVersion("ClamAV 1.4.1/27456/Mon Nov 03 09:21:33 UTC 2025")
	got, ok := v.DBTime()
	if !ok {
		t.Fatalf("DBTime reported no date for a zoned reply (DBDate=%q)", v.DBDate)
	}
	want := time.Date(2025, time.November, 3, 9, 21, 33, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("zoned reply parsed to %v, want %v — a zone-less layout matched first and dropped the year/zone", got, want)
	}
}

// TestDBTimeUnknownIsNotZeroAndNotNow is the case the whole freshness plane
// rests on. An absent or unintelligible date must report ok=false so the
// caller can say "unknown". If it instead returned a zero Time with ok=true,
// every such daemon would read as the oldest possible signature set; if it
// returned time.Now(), every one would read as permanently current. Both are
// silent failures, which is the class CHAOS-124 exists to remove.
func TestDBTimeUnknownIsNotZeroAndNotNow(t *testing.T) {
	for _, raw := range []string{
		"ClamAV 0.103.8",                            // engine only, no "/" fields
		"ClamAV 0.103.8/26982",                      // counter but no date
		"ClamAV 0.103.8/26982/",                     // empty date field
		"ClamAV 0.103.8/26982/not a date at all",    // unintelligible
		"ClamAV 0.103.8/26982/2023-04-12T09:30:00Z", // a plausible but unsupported shape
	} {
		v := parseClamVersion(raw)
		if got, ok := v.DBTime(); ok {
			t.Fatalf("DBTime(%q) reported a date %v — an absent or unparseable build date must be UNKNOWN, never a usable instant", raw, got)
		}
	}
}
