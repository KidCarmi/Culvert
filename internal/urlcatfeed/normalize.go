package urlcatfeed

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/unicode/norm"
)

// Normalization + integrity rejection (F0 §7.4, §7.5). Every rule fails CLOSED:
// an input that cannot be reduced to a safe, unambiguous DNS A-label host is
// REJECTED, never coerced into acceptance. The producer runs these at generation
// time and the client re-runs the collision checks on a downloaded artifact
// (verify.go), so an integrity-violating signed artifact is rejected as a WHOLE
// candidate on both sides — no winner is ever picked.

// Rejection sentinels — tests assert the exact class via errors.Is.
var (
	ErrEmptyHost         = errors.New("urlcatfeed: empty host")
	ErrBadChars          = errors.New("urlcatfeed: host contains scheme/port/path/userinfo or illegal characters")
	ErrWildcard          = errors.New("urlcatfeed: wildcard host not allowed")
	ErrIPLiteral         = errors.New("urlcatfeed: IP literal not allowed (DNS names only)")
	ErrEmptyLabel        = errors.New("urlcatfeed: empty DNS label")
	ErrLabelLength       = errors.New("urlcatfeed: DNS label length out of range (1..63)")
	ErrHostLength        = errors.New("urlcatfeed: host length exceeds 253 octets")
	ErrIDNA              = errors.New("urlcatfeed: host failed IDNA/UTS-46 normalization")
	ErrPublicSuffix      = errors.New("urlcatfeed: bare public-suffix host not allowed")
	ErrEmptyCategory     = errors.New("urlcatfeed: empty category name")
	ErrCategoryCase      = errors.New("urlcatfeed: category names collide case-insensitively")
	ErrMultiCategory     = errors.New("urlcatfeed: host assigned to more than one category")
	ErrSuffixConflict    = errors.New("urlcatfeed: ancestor/descendant hosts in different categories")
	ErrCategoryUTF8      = errors.New("urlcatfeed: category name is not valid UTF-8")
	ErrCategoryChar      = errors.New("urlcatfeed: category name has control/format/separator characters")
	ErrCategoryLength    = errors.New("urlcatfeed: category name exceeds length bound")
	ErrEmptyCategoryHost = errors.New("urlcatfeed: category has no hosts")
)

const (
	maxHostOctets = 253
	maxLabelLen   = 63
)

// CanonicalCategoryName returns the canonical category name for raw, or an error
// if raw cannot be a valid category name (Finding 4). Canonical form is: valid
// UTF-8, NFC-normalized, surrounding whitespace trimmed, no control/format/line-
// separator/paragraph-separator characters, non-empty, and within the length
// bounds. The producer applies this to source names; the verifier requires an
// artifact's name to ALREADY equal its canonical form.
func CanonicalCategoryName(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", ErrCategoryUTF8
	}
	name := norm.NFC.String(strings.TrimSpace(raw))
	if name == "" {
		return "", ErrEmptyCategory
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return "", fmt.Errorf("%w: %q", ErrCategoryChar, raw)
		}
	}
	if utf8.RuneCountInString(name) > MaxCategoryNameCodePoints || len(name) > MaxCategoryNameBytes {
		return "", fmt.Errorf("%w: %q", ErrCategoryLength, raw)
	}
	return name, nil
}

// NormalizeHost reduces raw to a canonical DNS A-label host or rejects it. The
// result is parity-equal in spirit to the policy engine's hostutil.NormalizeHost
// (lowercase, trailing-dot stripped) but STRICTER: it additionally IDNA-folds to
// an A-label and rejects wildcards, IP literals, ports/schemes/paths, empty
// labels, over-length names, and bare public suffixes.
func NormalizeHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	h = strings.ToLower(h)
	if h == "" {
		return "", ErrEmptyHost
	}
	// Reject anything that is not a bare hostname: scheme, path, query, fragment,
	// userinfo, or a port/IPv6 colon. (A single trailing dot is allowed and
	// stripped below.)
	if strings.ContainsAny(h, "/\\@?#: \t") || strings.Contains(h, "://") {
		return "", fmt.Errorf("%w: %q", ErrBadChars, raw)
	}
	if strings.ContainsAny(h, "*") {
		return "", fmt.Errorf("%w: %q", ErrWildcard, raw)
	}
	// Strip exactly one trailing dot (FQDN form); a doubled trailing dot leaves
	// an empty final label and is rejected by the label check below.
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", ErrEmptyHost
	}
	// Reject IP literals (v4 and v6) — feed hosts are DNS names only. IPv6 is
	// already excluded by the colon check; this catches dotted-quad IPv4.
	if net.ParseIP(h) != nil {
		return "", fmt.Errorf("%w: %q", ErrIPLiteral, raw)
	}
	// IDNA / UTS-46 (non-transitional, STD3 rules via the Lookup profile):
	// convert U-labels to A-labels and validate. A name that cannot be converted
	// (invalid Unicode, disallowed code points, underscores under STD3, …) is
	// rejected.
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrIDNA, raw, err)
	}
	if len(ascii) > maxHostOctets {
		return "", fmt.Errorf("%w: %q", ErrHostLength, raw)
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", fmt.Errorf("%w: %q", ErrEmptyLabel, raw)
		}
		if len(label) > maxLabelLen {
			return "", fmt.Errorf("%w: %q", ErrLabelLength, raw)
		}
	}
	// Reject a bare public suffix (e.g. "com", "co.uk"): under the engine's
	// per-category suffix walk a bare suffix would match essentially every host.
	// EffectiveTLDPlusOne errors exactly when the host IS a public suffix (or is
	// otherwise not a registrable domain), which is the rejection signal.
	if _, err := publicsuffix.EffectiveTLDPlusOne(ascii); err != nil {
		return "", fmt.Errorf("%w: %q", ErrPublicSuffix, raw)
	}
	return ascii, nil
}

// hostAssignments is the deterministic host→category map built while normalizing
// a dataset. It enforces exact-duplicate single-category and ancestor/descendant
// cross-category rejection.
type hostAssignments struct {
	// catOf maps a normalized host to its category display name.
	catOf map[string]string
}

// assignHosts normalizes every (category, host) pair, rejecting exact multi-
// category duplicates. Same host in the SAME category is deduplicated silently.
func assignHosts(cats []SourceCategory) (*hostAssignments, error) {
	ha := &hostAssignments{catOf: make(map[string]string)}
	// Case-insensitive category-name collision guard (the engine indexes
	// lowercase(name), so "AI" and "ai" would fuse).
	seenCat := make(map[string]string)
	for _, c := range cats {
		name, err := CanonicalCategoryName(c.Name)
		if err != nil {
			return nil, err
		}
		lc := strings.ToLower(name)
		if prev, ok := seenCat[lc]; ok && prev != name {
			return nil, fmt.Errorf("%w: %q vs %q", ErrCategoryCase, prev, name)
		}
		seenCat[lc] = name
		hostsInCat := 0
		for _, raw := range c.Hosts {
			host, err := NormalizeHost(raw)
			if err != nil {
				return nil, err
			}
			hostsInCat++
			if prev, ok := ha.catOf[host]; ok && prev != name {
				return nil, fmt.Errorf("%w: %q in %q and %q", ErrMultiCategory, host, prev, name)
			}
			ha.catOf[host] = name
		}
		// A category that contributes zero hosts is rejected rather than silently
		// dropped (Finding 4).
		if hostsInCat == 0 {
			return nil, fmt.Errorf("%w: %q", ErrEmptyCategoryHost, name)
		}
	}
	if err := ha.checkSuffixConflicts(); err != nil {
		return nil, err
	}
	return ha, nil
}

// checkSuffixConflicts rejects any pair where one host is a proper DNS suffix of
// another and they belong to DIFFERENT categories (F0 §7.4). Walking each host's
// ancestor suffixes catches both directions: a descendant always finds its
// ancestor. Same-category ancestry is permitted (redundant but unambiguous).
func (ha *hostAssignments) checkSuffixConflicts() error {
	for host, cat := range ha.catOf {
		// Walk proper suffixes: for "a.b.c" → "b.c", "c".
		rest := host
		for {
			i := strings.IndexByte(rest, '.')
			if i < 0 {
				break
			}
			rest = rest[i+1:]
			if rest == "" {
				break
			}
			if ancCat, ok := ha.catOf[rest]; ok && ancCat != cat {
				return fmt.Errorf("%w: %q(%s) under %q(%s)", ErrSuffixConflict, host, cat, rest, ancCat)
			}
		}
	}
	return nil
}
