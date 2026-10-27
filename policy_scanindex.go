package main

import (
	"strings"
	"sync/atomic"
)

// ─── Stage-2 packed destination prefilter ────────────────────────────────────
//
// What this addresses is recorded in sortLocked's own note: the Stage-2 scan
// scales SUPERLINEARLY above ~1 000 rules (7.6 ns/rule at 1 000 → 29.3 ns/rule
// at 10 000, BenchmarkPolicyEvaluate_NoMatch) because the touched working set
// of 568-byte definitions (~5.7 MB at 10 000 rules) leaves L2 — not because of
// heap scatter, which was measured and ruled out there. That note names the
// only remedy and declines to attempt it: "shrinking what the scan streams per
// rule is the only thing that can address it". This is that change.
//
// A rule's destination FQDN is the FIRST thing matchDestNorm tests and the most
// common access-rule scope in a gateway rulebase, so it is the discriminator
// worth packing. Each rule contributes one 16-byte row in ONE contiguous array
// (four rows per cache line, hardware-prefetchable), carrying the two facts a
// mismatch can be proven from without dereferencing the definition at all: the
// shortest host that can match, and the pattern's trailing bytes.
//
// ── The safety property ──────────────────────────────────────────────────────
//
// The index is ONE-DIRECTIONAL and never authoritative. A row can only make the
// scan REJECT a rule the full predicate would also have rejected; nothing is
// ever admitted, matched or skipped on a row's word, and every rule that
// survives the prefilter runs the complete unmodified check sequence
// (ruleIsEnabled → ruleTypeOf → matchSourceAddr → schedule → matchDestNorm).
// So the index cannot change an access decision unless the implication below
// fails, and TestPolicyScanIndex_DifferentialOracle pins that implication
// against the real evaluator over a randomized rule × host matrix.
//
// ── Why the implication holds ────────────────────────────────────────────────
//
// hostutil.MatchFQDNNorm(pattern, host) is suffix-anchored in every branch:
//
//	pattern == "*"            → matches every host          (no prefilter)
//	pattern == "*."+suffix    → HasSuffix(host, "."+suffix) || host == suffix
//	otherwise                 → host == pattern || host ends in "."+pattern
//
// Let cmp be the bytes a match requires the host to END with — the pattern
// itself, or pattern[2:] for the "*." form. Every matching branch implies both
//
//	len(host) >= len(cmp), and
//	the last min(8, len(cmp)) bytes of host equal those of cmp
//
// (for the "*." form, HasSuffix(host, "."+cmp) gives len(host) >= len(cmp)+1
// and the shared trailing bytes; host == cmp gives equality outright). The
// contrapositive is the prefilter: a host that is too SHORT, or whose packed
// trailing bytes differ, cannot match — provable from the row alone.
//
// ── Measured and rejected ───────────────────────────────────────────────────
//
// Two shapes of this change were measured and backed out, both because they
// charged rulebases the index cannot help:
//
//   - Indexing per-width host tails out of a [9]uint64 carried in the per-scan
//     struct. The inlined comparison takes that array's address, and the
//     72 bytes displaced the scan's other per-rule state: +22% on
//     BenchmarkPolicyEvaluate_CategoryRules/rules=200. The masked single-word
//     comparison in rejects() is the fix.
//   - Folding the scan's two eligibility checks (ruleIsEnabled, ruleTypeOf)
//     into one helper returning the skip REASON, to pay for the prefilter's
//     cyclop budget. It inlines, but it materializes a string header per rule:
//     +26% on the same benchmark, ~9 ns per rule. The budget is paid in the
//     schedule path (scheduleClock.armNow) instead, which runs only for rules
//     that carry a Schedule.
//
// ── Deliberately NOT done ───────────────────────────────────────────────────
//
// A rule scoped only by category, category group, country, source or schedule
// gets minLen == 0 and no prefilter: its predicates are not suffix-anchored and
// are already amortized to O(1) per rule by their own per-scan scratch
// (hostCatScratch, clientSource). Widening the row to cover them is a separate
// concern and a separate measurement, not a free extension of this one.

// policyScanTailMax is how many trailing pattern bytes a row packs. Eight is
// the widest that fits one register-sized field, and long enough that the
// shared ".com" / ".co.uk" tails of a real rulebase still discriminate on the
// label in front of them.
const policyScanTailMax = 8

// policyScanRow is one rule's packed destination prefilter — 16 bytes, versus
// the 568-byte definition it lets the scan not touch. Both fields are machine
// words, so the row needs no numeric conversion anywhere and no padding.
type policyScanRow struct {
	// tail packs the last min(minLen, policyScanTailMax) bytes of the rule's
	// cmp bytes (see the file comment), the final byte in the low bits. Read
	// only when minLen > 0.
	tail uint64
	// minLen is the shortest normalized host that CAN match this rule's FQDN
	// pattern, and doubles as the significant width of tail (capped at
	// policyScanTailMax). Zero means this rule has no destination prefilter —
	// the scan must run its full predicate — and is the fail-safe default for
	// every shape not handled below.
	minLen int
}

// policyScanIndex is one published revision's prefilter, bound to the exact
// rule slice it describes. The binding is the point: a reader pairs rows with
// rules by SLICE IDENTITY, so an index published for another revision is
// discarded rather than applied, and the index can never become a second
// source of truth for what the evaluator sees. Published lock-free under
// ps.mu (single writer) and read without any lock, like the category-group and
// urlcat published views.
type policyScanIndex struct {
	rules []*PolicyRule
	rows  []policyScanRow
}

// scanIndexFor returns the rows published for exactly this rule slice, or nil
// when there are none to apply: a store that has never published, a revision
// installed without passing through publication, or one no row can prefilter
// (see buildPolicyScanRows). All three mean the same thing to the caller — run
// the full per-rule predicate — so they deliberately share one answer.
func scanIndexFor(p *atomic.Pointer[policyScanIndex], rules []*PolicyRule) []policyScanRow {
	idx := p.Load()
	if idx == nil || !sameRuleSlice(idx.rules, rules) || len(idx.rows) != len(rules) {
		return nil
	}
	return idx.rows
}

// buildPolicyScanRows packs one row per rule, in scan order, or returns nil
// when NO rule in the revision can be prefiltered at all.
//
// The nil is a measured decision, not tidiness. A category-, country- or
// source-only rulebase has minLen == 0 in every row, so an armed prefilter
// would stream 16 bytes per rule and pack one host tail per evaluation to
// reject nothing: +4.4% on BenchmarkPolicyEvaluate_CategoryRules/rules=200 and
// +32.7% on rules=1, where the fixed arming cost is the whole measurement.
// Publishing no rows leaves those rulebases on exactly the pre-change path.
func buildPolicyScanRows(rules []*PolicyRule) []policyScanRow {
	rows := make([]policyScanRow, len(rules))
	prefilterable := false
	for i, rule := range rules {
		rows[i] = policyScanRowFor(rule)
		if rows[i].minLen != 0 {
			prefilterable = true
		}
	}
	if !prefilterable {
		return nil
	}
	return rows
}

// policyScanRowFor derives one rule's row. Every shape it does not prove a
// suffix anchor for returns the zero row (no prefilter).
func policyScanRowFor(rule *PolicyRule) policyScanRow {
	var row policyScanRow
	// A rule whose DestFQDN is set but whose normFQDN was NOT precomputed takes
	// matchDestNorm's allocating matchFQDN fallback, which is a different
	// predicate over the raw pattern. It gets no prefilter.
	if rule.DestFQDN == "" || rule.normFQDN == "" {
		return row
	}
	pattern := rule.normFQDN
	cmp := pattern
	switch {
	case pattern == "*":
		return row // matches every host
	case strings.HasPrefix(pattern, "*."):
		cmp = pattern[2:]
	}
	if cmp == "" {
		return row // "*." alone — no trailing bytes to anchor on
	}
	row.minLen = len(cmp)
	row.tail = packTrailingBytes(cmp, min(len(cmp), policyScanTailMax))
	return row
}

// packTrailingBytes packs the last n bytes of s into a uint64, the final byte
// in the low bits. Callers guarantee 1 <= n <= policyScanTailMax && n <= len(s).
func packTrailingBytes(s string, n int) uint64 {
	var v uint64
	for i := len(s) - n; i < len(s); i++ {
		v = v<<8 | uint64(s[i])
	}
	return v
}

// destPrefilter is ONE evaluation's view of a published index: the rows, and
// the probe host's trailing word packed once for the whole scan instead of once
// per rule. It carries the on/off decision so the scan's loop body gains a
// single predicted-not-taken branch and nothing else.
type destPrefilter struct {
	rows     []policyScanRow
	hostTail uint64
	hostLen  int
	on       bool
}

// newDestPrefilter arms the prefilter for a scan, or returns an inert one. It
// is inert unless the caller supplied rows for exactly this revision (ruleCount
// is the length the rows must describe) and the scan is untraced.
func newDestPrefilter(rows []policyScanRow, ruleCount int, normHost string, traced bool) destPrefilter {
	if traced || len(rows) != ruleCount {
		return destPrefilter{}
	}
	return destPrefilter{rows: rows, hostTail: packHostTail(normHost), hostLen: len(normHost), on: true}
}

// rejectsAt reports whether the row for rules[i] proves a destination mismatch,
// so the scan can skip that rule without dereferencing its definition. An inert
// prefilter always answers false and the scan runs unchanged.
func (p *destPrefilter) rejectsAt(i int) bool {
	return p.on && p.rows[i].rejects(p.hostLen, p.hostTail)
}

// packHostTail packs the last min(len(host), policyScanTailMax) bytes of ONE
// evaluation's normalized host into a word, the final byte in the low bits —
// the same layout a row packs its pattern with. Shorter hosts leave the high
// bytes zero, which is unreachable: a row comparing k bytes also has
// minLen >= k, so the length check rejects it before the word is compared.
func packHostTail(host string) uint64 {
	var v uint64
	for k := 1; k <= min(len(host), policyScanTailMax); k++ {
		v |= uint64(host[len(host)-k]) << (8 * (k - 1))
	}
	return v
}

// rejects reports whether this row PROVES the rule cannot match a host of
// hostLen bytes whose packed trailing word is hostTail. False means "not proven
// here" — the scan then runs the rule's full predicate, so a false is never a
// match.
//
// The comparison is masked rather than width-indexed on purpose: a table of
// per-width host tails would have to live in the per-scan struct, and a 72-byte
// array whose address the inlined comparison takes measurably displaced the
// scan's other per-rule state (+22% on BenchmarkPolicyEvaluate_CategoryRules/
// rules=200, a rulebase this index cannot help at all). One word plus a shift
// keeps the per-scan state in registers.
func (row *policyScanRow) rejects(hostLen int, hostTail uint64) bool {
	if row.minLen == 0 {
		return false
	}
	if hostLen < row.minLen {
		return true
	}
	// The row packed min(minLen, policyScanTailMax) bytes; compare exactly
	// those. minLen >= 1 here, so the shift is at most 56.
	mask := ^uint64(0) >> (64 - 8*min(row.minLen, policyScanTailMax))
	return row.tail != hostTail&mask
}

// publishScanIndexLocked packs and publishes the prefilter for the store's
// current revision. Callers MUST hold ps.mu for writing: that is what makes the
// atomic store a single-writer publication. It is called from exactly the two
// places that establish ps.verified, so an indexed revision and a verified one
// are always the same revision.
func (ps *PolicyStore) publishScanIndexLocked() {
	rules := ps.rules
	ps.scanIndex.Store(&policyScanIndex{rules: rules, rows: buildPolicyScanRows(rules)})
}
