package policy

import "strings"

// glob is a compiled, anchored, bounded glob matcher. It supports '*' (any run,
// including empty) and '?' (exactly one byte). It is WHOLE-VALUE anchored, rejects
// '**' and pathological shapes at compile time, and matches with a linear
// two-pointer algorithm (no recursion, no catastrophic backtracking). Byte-wise
// only — no Unicode normalization of opaque identifiers.
type glob struct {
	pattern string
}

// compileGlob validates and compiles p under the limits. It rejects an empty
// pattern, an over-limit length/segment count, '**', and a run of more than one
// consecutive '*'.
func compileGlob(p string, lim Limits) (glob, error) {
	if p == "" {
		return glob{}, condErr("empty glob pattern")
	}
	if len(p) > lim.MaxPatternBytes() {
		return glob{}, condErr("glob pattern exceeds the byte bound")
	}
	if strings.Contains(p, "**") {
		return glob{}, condErr("'**' is not permitted in a glob pattern")
	}
	if segs := strings.Count(p, "/") + 1; segs > lim.MaxPatternSegments() {
		return glob{}, condErr("glob pattern has too many segments")
	}
	return glob{pattern: p}, nil
}

// match reports whether s matches the whole (anchored) pattern. The algorithm is
// the classic iterative glob matcher: O(len(s) * number-of-stars) worst case,
// bounded by the compiled pattern/value lengths — no exponential backtracking.
func (g glob) match(s string) bool {
	p := g.pattern
	var si, pi int
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == s[si] || p[pi] == '?'):
			si++
			pi++
		case pi < len(p) && p[pi] == '*':
			star = pi
			mark = si
			pi++
		case star != -1:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
