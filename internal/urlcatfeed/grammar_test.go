package urlcatfeed

import (
	"strings"
	"testing"
	"time"
)

// Differential oracles: verbatim copies of the root F3 field validators that
// package main kept beside the floor record (saas_feed_floor.go) before it
// bound to ParseCanonicalRFC3339 / IsSHA256Hex. They are frozen here so a later
// edit to the exported rules cannot silently diverge from the grammar the
// node-local floor, activation and checkpoint records were written under.
func oracleCanonicalUTCSecond(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	if t.UTC().Format(time.RFC3339) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func oracleValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func TestParseCanonicalRFC3339_MatchesRootOracle(t *testing.T) {
	cases := []string{
		"2026-11-19T00:00:00Z",
		"1970-01-01T00:00:00Z",
		"9999-12-31T23:59:59Z",
		"2026-11-19T00:00:00.5Z",    // fractional second
		"2026-11-19T00:00:00.000Z",  // zero fraction is still non-canonical
		"2026-11-19T02:00:00+02:00", // same instant, numeric offset
		"2026-11-19T00:00:00+00:00", // +00:00 instead of Z
		"2026-11-19t00:00:00z",      // lowercase designators
		"2026-11-19 00:00:00Z",      // space separator
		"2026-02-30T00:00:00Z",      // impossible date
		"",                          // empty
		" 2026-11-19T00:00:00Z",     // leading space
		"2026-11-19T00:00:00Z\n",    // trailing newline
		"2026-11-19T24:00:00Z",      // hour out of range
		"0000-01-01T00:00:00Z",      // year zero
		"2026-11-19T00:00:60Z",      // leap second form
	}
	for _, in := range cases {
		wantT, wantOK := oracleCanonicalUTCSecond(in)
		gotT, err := ParseCanonicalRFC3339(in)
		if gotOK := err == nil; gotOK != wantOK {
			t.Fatalf("%q: accepted=%v, root oracle accepted=%v (err=%v)", in, gotOK, wantOK, err)
		}
		if wantOK {
			if !gotT.Equal(wantT) || gotT.Location() != time.UTC {
				t.Fatalf("%q: got %v (%v), root oracle %v", in, gotT, gotT.Location(), wantT)
			}
		} else if !gotT.IsZero() {
			t.Fatalf("%q: rejected input returned non-zero time %v", in, gotT)
		}
	}
}

func TestIsSHA256Hex_MatchesRootOracle(t *testing.T) {
	ok := strings.Repeat("0123456789abcdef", 4)
	cases := []string{
		ok,
		strings.Repeat("f", 64),
		strings.ToUpper(ok),      // uppercase rejected
		ok[:63],                  // short
		ok + "0",                 // long
		"",                       // empty
		ok[:62] + "g0",           // non-hex ASCII
		ok[:62] + "é",            // 2-byte rune makes len 64
		ok[:61] + "\xff\xfe\xfd", // invalid UTF-8, len 64
		ok[:63] + "\x00",         // NUL
		strings.Repeat(" ", 64),  // spaces
	}
	for _, in := range cases {
		if got, want := IsSHA256Hex(in), oracleValidSHA256Hex(in); got != want {
			t.Fatalf("%q: IsSHA256Hex=%v, root oracle=%v", in, got, want)
		}
	}
}
