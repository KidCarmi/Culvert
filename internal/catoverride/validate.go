package catoverride

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// Override validation + normalization boundary (F3a-1). Every host is reduced to
// a canonical DNS A-label via urlcatfeed.NormalizeHost (which already rejects
// wildcards, IP literals, ports/schemes/paths, empty labels, over-length names,
// and bare public suffixes) and every category to canonical form via
// urlcatfeed.CanonicalCategoryName, so the override grammar is byte-identical to
// the feed producer/verifier. On top of that, Validate enforces the override
// MODEL: single category per host, no case-colliding categories, no
// ancestor/descendant cross-category ambiguity, no duplicate host across the
// added/recategorized maps, and no host that is both suppressed (tombstoned) and
// asserted (added/recategorized).

// Validation error sentinels — tests assert the exact class via errors.Is.
var (
	ErrDuplicateHost   = errors.New("catoverride: host appears in more than one override map")
	ErrTombstoneClash  = errors.New("catoverride: host is both tombstoned and added/recategorized")
	ErrCategoryCase    = errors.New("catoverride: category names collide case-insensitively")
	ErrMultiCategory   = errors.New("catoverride: host assigned to more than one category")
	ErrSuffixConflict  = errors.New("catoverride: ancestor/descendant hosts in different categories")
	ErrInvalidHost     = errors.New("catoverride: invalid override host")
	ErrInvalidCategory = errors.New("catoverride: invalid override category name")
)

// Normalize returns a canonicalized, validated copy of o: every host is
// NormalizeHost-reduced, every category CanonicalCategoryName-reduced, and the
// whole set is run through Validate. Any violation rejects the WHOLE set
// (all-or-nothing) — it never returns a partially-normalized value.
func Normalize(o Overrides) (Overrides, error) {
	out := Overrides{}
	var err error
	if out.Added, err = normalizeMap(o.Added); err != nil {
		return Overrides{}, err
	}
	if out.Recategorized, err = normalizeMap(o.Recategorized); err != nil {
		return Overrides{}, err
	}
	if out.Tombstones, err = normalizeHosts(o.Tombstones); err != nil {
		return Overrides{}, err
	}
	if err := Validate(out); err != nil {
		return Overrides{}, err
	}
	return out, nil
}

// normalizeMap canonicalizes a host→category map's keys and values.
func normalizeMap(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for rawHost, rawCat := range in {
		host, err := urlcatfeed.NormalizeHost(rawHost)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidHost, rawHost, err)
		}
		cat, err := urlcatfeed.CanonicalCategoryName(rawCat)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidCategory, rawCat, err)
		}
		if prev, ok := out[host]; ok && prev != cat {
			// Two raw keys normalized to the same host with different categories.
			return nil, fmt.Errorf("%w: %q → %q and %q", ErrMultiCategory, host, prev, cat)
		}
		out[host] = cat
	}
	return out, nil
}

// normalizeHosts canonicalizes and deduplicates a host list.
func normalizeHosts(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		host, err := urlcatfeed.NormalizeHost(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidHost, raw, err)
		}
		if _, dup := seen[host]; dup {
			continue // idempotent dedup within tombstones
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out, nil
}

// Validate enforces the override model on an ALREADY-normalized set. It assumes
// hosts/categories are canonical (Normalize guarantees this) and checks the
// cross-field invariants. Deterministic: it walks maps in sorted host order so a
// rejection message is stable.
func Validate(o Overrides) error {
	// A host may not appear in both added and recategorized (ambiguous role).
	for _, h := range sortedHosts(o.Added) {
		if _, dup := o.Recategorized[h]; dup {
			return fmt.Errorf("%w: %q in added and recategorized", ErrDuplicateHost, h)
		}
	}
	// A tombstoned host may not also be asserted (contradiction).
	asserted := make(map[string]struct{}, len(o.Added)+len(o.Recategorized))
	for h := range o.Added {
		asserted[h] = struct{}{}
	}
	for h := range o.Recategorized {
		asserted[h] = struct{}{}
	}
	for _, t := range o.Tombstones {
		if _, clash := asserted[t]; clash {
			return fmt.Errorf("%w: %q", ErrTombstoneClash, t)
		}
	}
	// Build the combined host→category assignment (added ∪ recategorized) and
	// enforce single-category-per-host, category-case-consistency, and no
	// ancestor/descendant cross-category ambiguity — the same integrity model the
	// feed artifact obeys (F0 §7.4).
	assign := make(map[string]string, len(asserted))
	seenCat := make(map[string]string) // lower(name) → canonical
	if err := foldAssign(assign, seenCat, o.Added); err != nil {
		return err
	}
	if err := foldAssign(assign, seenCat, o.Recategorized); err != nil {
		return err
	}
	return checkSuffixConflicts(assign)
}

// foldAssign folds one host→category map into the combined assignment, rejecting
// a host reassigned to a different category and a case-colliding category name.
func foldAssign(assign, seenCat, in map[string]string) error {
	for _, host := range sortedHosts(in) {
		cat := in[host]
		lc := strings.ToLower(cat)
		if prev, ok := seenCat[lc]; ok && prev != cat {
			return fmt.Errorf("%w: %q vs %q", ErrCategoryCase, prev, cat)
		}
		seenCat[lc] = cat
		if prev, ok := assign[host]; ok && prev != cat {
			return fmt.Errorf("%w: %q → %q and %q", ErrMultiCategory, host, prev, cat)
		}
		assign[host] = cat
	}
	return nil
}

// checkSuffixConflicts rejects any host that is a proper DNS suffix of another in
// the assignment where their categories differ (F0 §7.4). Walks each host's
// ancestor suffixes; a descendant always finds its ancestor.
func checkSuffixConflicts(assign map[string]string) error {
	// Deterministic ordering for a stable first-violation message.
	for _, host := range sortedHosts(assign) {
		cat := assign[host]
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
			if ancCat, ok := assign[rest]; ok && ancCat != cat {
				return fmt.Errorf("%w: %q(%s) under %q(%s)", ErrSuffixConflict, host, cat, rest, ancCat)
			}
		}
	}
	return nil
}
