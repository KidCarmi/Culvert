package admission

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The 2026-10-08 package-isolation security review records, as a table, which
// zero-value engine calls panic and which do not. That table was WRONG when it
// was first written — it claimed `(&RateLimiter{}).Allow(...)` panics, which it
// does not, because Allow short-circuits on !enabled before it reaches the
// uninitialised shard maps. A security record that overstates a residual
// invites hardening the request path for a fault it cannot have. (The two
// write rows that DID panic were since made safe by PR #1563's lazy
// initialization; the table records both outcomes, re-measured.)
//
// Prose cannot be unit-tested, but an example can (the CHAOS-69 runbook-example
// precedent). This gate drives every row of that table against the shipped code
// and requires the document to agree. It pins the CONTRACT, not the layout: how
// the table is worded or how many rows it carries stays the author's call, but
// every row it does carry must name a call this gate knows how to run, and the
// outcome must match. A row naming an unknown call FAILS rather than skipping —
// a skip is how a future wrong claim would slip in unchecked.
const zeroValueDocPath = "../../docs/engineering/security-reviews/2026-10-08-admission-package-isolation-window.md"

// zeroValueCalls maps a normalised table cell to the call it describes. Each
// closure performs exactly the call the document shows, on a zero value.
func zeroValueCalls() map[string]func() {
	return map[string]func(){
		"(&admission.IPFilter{}).Allowed(ip)": func() { (&IPFilter{}).Allowed("203.0.113.7") },
		"(&admission.IPFilter{}).Add(ip)":     func() { _ = (&IPFilter{}).Add("203.0.113.7") },

		"(&admission.RateLimiter{}).Allow(ip)":             func() { (&RateLimiter{}).Allow("203.0.113.7") },
		"(&admission.RateLimiter{}).AllowAuto(ip)":         func() { (&RateLimiter{}).AllowAuto("203.0.113.7") },
		"(&admission.RateLimiter{}).AllowClusterAware(ip)": func() { (&RateLimiter{}).AllowClusterAware("203.0.113.7") },
		"(&admission.RateLimiter{}).AddExemption(ip)":      func() { _ = (&RateLimiter{}).AddExemption("203.0.113.7") },

		"Configure(10, time.Minute) then Allow(ip)": func() {
			r := &RateLimiter{}
			r.Configure(10, time.Minute)
			r.Allow("203.0.113.7")
		},
	}
}

type zeroValueRow struct {
	call        string
	expectPanic bool
	line        int
}

// normaliseCell strips the markdown the table uses for emphasis so the cell
// text can be matched against a call name.
func normaliseCell(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "**", "")
	return strings.Join(strings.Fields(s), " ")
}

// parseZeroValueTable returns the rows of the review document's zero-value
// table, located by its header rather than by line number.
func parseZeroValueTable(t *testing.T) []zeroValueRow {
	t.Helper()
	raw, err := os.ReadFile(zeroValueDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", zeroValueDocPath, err)
	}
	lines := strings.Split(string(raw), "\n")

	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "|") &&
			strings.Contains(normaliseCell(ln), "zero-value call") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: the zero-value table header was not found; if the table was "+
			"renamed or removed, this gate must be updated or retired deliberately", zeroValueDocPath)
	}

	var rows []zeroValueRow
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "|") {
			break // end of the table
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) < 2 {
			continue
		}
		call := normaliseCell(cells[0])
		result := strings.ToLower(normaliseCell(cells[1]))
		if call == "" || strings.HasPrefix(call, "---") {
			continue // separator row
		}
		// "no panic" also contains "panic", so the negative is tested first.
		expect := !strings.Contains(result, "no panic") && strings.Contains(result, "panic")
		rows = append(rows, zeroValueRow{call: call, expectPanic: expect, line: i + 1})
	}
	return rows
}

func panics(f func()) (did bool) {
	defer func() {
		if recover() != nil {
			did = true
		}
	}()
	f()
	return false
}

func TestZeroValueResidual_DocumentMatchesTheEngine(t *testing.T) {
	rows := parseZeroValueTable(t)
	known := zeroValueCalls()

	// Not vacuous: a table that parsed to nothing would pass every assertion.
	if len(rows) < len(known) {
		t.Fatalf("parsed %d table rows but know how to drive %d calls — the table "+
			"shrank or the parser stopped matching it", len(rows), len(known))
	}

	// Control: the gate must distinguish the two outcomes. A dispatcher that
	// reported "no panic" for everything would satisfy a table whose rows all
	// say "no panic" — which the table now does, because PR #1563 made the zero
	// value safe at both write sites that used to panic. So the detector is
	// proved against a call known to panic (the nil-map write those rows used
	// to reach: a bucket stored into a zero shard's map) and one known not to,
	// rather than against the table.
	if !panics(func() {
		var shard rlShard
		shard.clients["203.0.113.7"] = &clientBucket{}
	}) {
		t.Fatal("control: panics() did not detect a nil-map write — every " +
			"\"no panic\" row below would pass vacuously")
	}
	if panics(func() {}) {
		t.Fatal("control: panics() reported a panic for a call that cannot panic")
	}
	var sawSafe bool
	for _, r := range rows {
		if !r.expectPanic {
			sawSafe = true
		}
	}
	if !sawSafe {
		t.Fatalf("the table carries no \"no panic\" row; the record lists the " +
			"zero-value calls that are safe, and losing them all means the parser " +
			"stopped matching it")
	}

	driven := make(map[string]bool, len(rows))
	for _, r := range rows {
		call, ok := known[r.call]
		if !ok {
			t.Errorf("%s:%d: the document claims an outcome for %q, which this gate "+
				"cannot run. Add it to zeroValueCalls so the claim is measured, or "+
				"remove the row — an unmeasured claim is how the wrong one got in.",
				zeroValueDocPath, r.line, r.call)
			continue
		}
		driven[r.call] = true
		got := panics(call)
		if got != r.expectPanic {
			t.Errorf("%s:%d: %q — document says panic=%v, engine says panic=%v",
				zeroValueDocPath, r.line, r.call, r.expectPanic, got)
		}
	}

	for name := range known {
		if !driven[name] {
			t.Errorf("%s: this gate can run %q but the table no longer lists it; "+
				"the record must keep stating the outcome it depends on", zeroValueDocPath, name)
		}
	}
}
