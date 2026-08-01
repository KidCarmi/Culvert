package dlp

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// RedactLeaf redacts one string leaf, removing ONLY the classifications in want.
// It reuses the existing bounded deterministic scrubber for secret shapes and the
// PII corpus for PII/financial spans, replacing matched content with the
// scrubber's "[redacted:…]" tokens. It returns the redacted string, the sorted
// unique classifications actually removed, and the redaction count. The raw
// matched value is never returned. Redaction is idempotent (running it again over
// the output changes nothing).
func RedactLeaf(s string, want map[Classification]struct{}) (out string, removed []Classification, n int) {
	out = s
	seen := map[Classification]struct{}{}
	// 1. secret shapes — scrub whole leaf if any secret class is wanted.
	if scrubbed, cnt, ok := redactSecrets(out, want, seen); ok {
		out = scrubbed
		n += cnt
	}
	// 2. PII/financial spans — replace matched spans for wanted classes.
	for i := range piiDetectors {
		d := &piiDetectors[i]
		if _, ok := want[d.class]; !ok {
			continue
		}
		replaced := 0
		out = d.re.ReplaceAllStringFunc(out, func(m string) string {
			if d.skip != nil && d.skip(m) {
				return m
			}
			replaced++
			return "[redacted:" + d.id + "]"
		})
		if replaced > 0 {
			n += replaced
			mark(seen, d.class)
		}
	}
	for c := range seen {
		removed = append(removed, c)
	}
	sortClasses(removed)
	return out, removed, n
}

// redactSecrets scrubs secret shapes from s when the profile wants at least one
// secret class, returning the scrubbed string, the redaction count, and whether the
// scrub was kept (only kept when a detected class is in want). Detected wanted
// classes are recorded in seen.
func redactSecrets(s string, want map[Classification]struct{}, seen map[Classification]struct{}) (out string, count int, kept bool) {
	if !wantsAnySecret(want) {
		return s, 0, false
	}
	scrubbed, names, cnt := redaction.ScrubDetailDefault(s)
	if cnt == 0 {
		return s, 0, false
	}
	keep := false
	for _, name := range names {
		cl, _ := classifySecretName(name)
		if _, ok := want[cl]; ok {
			keep = true
			mark(seen, cl)
		}
	}
	if !keep {
		return s, 0, false
	}
	return scrubbed, cnt, true
}

func wantsAnySecret(want map[Classification]struct{}) bool {
	for c := range want {
		if c.IsSecret() {
			return true
		}
	}
	return false
}

func mark(m map[Classification]struct{}, c Classification) { m[c] = struct{}{} }

func sortClasses(cs []Classification) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j-1] > cs[j]; j-- {
			cs[j-1], cs[j] = cs[j], cs[j-1]
		}
	}
}

// ContainsRedactionToken reports whether s already carries a scrubber redaction
// token (used by the transform to assert idempotence / no residual).
func ContainsRedactionToken(s string) bool { return strings.Contains(s, "[redacted:") }
