package catoverride

// Differential oracle for the suppression fast path.
//
// covers() replaced a per-host linear scan over the override key list with an
// ancestor-suffix walk against a key SET. That is a pure performance change, so
// the obligation is equivalence, not behavior: this file keeps the ORIGINAL
// predicate frozen in-tree and asserts the two agree on every input, including
// the degenerate shapes the live callers never produce (empty keys, trailing
// dots, consecutive dots, bare labels) — because ComposeView/ComposeMembership
// are documented PURE exported functions, so nothing stops a caller or a future
// test from handing them a non-normalized set.
//
// suffixSuppressedLegacy is a verbatim copy of the removed helper. It is not
// called by production and must NOT be "kept in sync" with covers() — its whole
// value is that it does not move.

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// suffixSuppressedLegacy is the FROZEN pre-change predicate.
func suffixSuppressedLegacy(host string, tombstones []string) bool {
	for _, t := range tombstones {
		if host == t || strings.HasSuffix(host, "."+t) {
			return true
		}
	}
	return false
}

// legacyAssertKeys is the frozen pre-change assert-key construction, HOISTED out
// of the per-host loop exactly as ComposeView/ComposeMembership hoisted it. Build
// fidelity matters here: moving this inside the per-host predicate would add one
// slice allocation per feed host and make the frozen baseline look far worse than
// the code that actually shipped.
func legacyAssertKeys(o Overrides) []string {
	assertKeys := make([]string, 0, len(o.Recategorized)+len(o.Added))
	for h := range o.Recategorized {
		assertKeys = append(assertKeys, h)
	}
	for h := range o.Added {
		assertKeys = append(assertKeys, h)
	}
	return assertKeys
}

// legacyCovers is the frozen CALL SHAPE from ComposeView/ComposeMembership: the
// tombstones and the assert keys probed as two separate lists, OR'd. covers()
// probes their union, so this is the oracle for that merge as well.
//
// CORRECTNESS ORACLE ONLY — it rebuilds the assert keys on every call, so it must
// never be used as a performance baseline. The benchmarks call the faithful
// legacyComposeView/legacyComposeMembership below instead.
func legacyCovers(host string, o Overrides) bool {
	return suffixSuppressedLegacy(host, o.Tombstones) || suffixSuppressedLegacy(host, legacyAssertKeys(o))
}

// equivHosts are the adversarial host spellings. Normalization rejects most of
// them, which is exactly why they belong here: the pure functions do not
// normalize their input.
var equivHosts = []string{
	"", ".", "..", "com", ".com", "com.",
	"example.com", "example.com.", ".example.com",
	"a.example.com", "b.a.example.com", "xample.com", "notexample.com",
	"a..b", "a.b.", "example.co", "example.comm",
	"covered.example", "sub.covered.example", "deep.sub.covered.example",
	"tomb0.override.example", "added0.override.example", "recat1.override.example",
}

// equivKeySets are the override sets probed against every host above. The keys
// deliberately include ancestors, descendants, exact matches, near-misses and
// the degenerate empty key.
var equivKeySets = []Overrides{
	{},
	{Tombstones: []string{""}},
	{Tombstones: []string{"."}},
	{Tombstones: []string{"com"}},
	{Tombstones: []string{"example.com"}},
	{Tombstones: []string{"example.com."}},
	{Tombstones: []string{"a.example.com", "com."}},
	{Added: map[string]string{"example.com": "Business"}},
	{Recategorized: map[string]string{"covered.example": "Finance"}},
	{
		Added:         map[string]string{"added0.override.example": "Business", "b": "Business"},
		Recategorized: map[string]string{"recat1.override.example": "Finance", "example.co": "Finance"},
		Tombstones:    []string{"tomb0.override.example", "covered.example", ""},
	},
}

func TestSuppress_EquivalentToLegacy_Table(t *testing.T) {
	for si, o := range equivKeySets {
		sup := newSuffixSuppressor(o)
		for _, host := range equivHosts {
			want := legacyCovers(host, o)
			if got := sup.covers(host); got != want {
				t.Errorf("set#%d host=%q: covers=%v, legacy=%v", si, host, got, want)
			}
		}
	}
}

// TestSuppress_EquivalentToLegacy_Random fuzzes the label alphabet so ancestor,
// descendant, sibling and exact-match relationships all arise, then asserts the
// two predicates never diverge.
func TestSuppress_EquivalentToLegacy_Random(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE)) //nolint:gosec // deterministic test corpus, not crypto
	labels := []string{"a", "b", "com", "example", "co", "", "x"}
	randName := func() string {
		n := 1 + rng.Intn(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = labels[rng.Intn(len(labels))]
		}
		return strings.Join(parts, ".")
	}
	for iter := 0; iter < 4000; iter++ {
		o := Overrides{}
		for i := 0; i < rng.Intn(4); i++ {
			o.Tombstones = append(o.Tombstones, randName())
		}
		if k := rng.Intn(3); k > 0 {
			o.Added = make(map[string]string, k)
			for i := 0; i < k; i++ {
				o.Added[randName()] = "Business"
			}
		}
		if k := rng.Intn(3); k > 0 {
			o.Recategorized = make(map[string]string, k)
			for i := 0; i < k; i++ {
				o.Recategorized[randName()] = "Finance"
			}
		}
		sup := newSuffixSuppressor(o)
		for probe := 0; probe < 8; probe++ {
			host := randName()
			want := legacyCovers(host, o)
			if got := sup.covers(host); got != want {
				t.Fatalf("iter=%d host=%q overrides=%+v: covers=%v, legacy=%v", iter, host, o, got, want)
			}
		}
	}
}

// TestCompose_EquivalentToLegacy_WholeMaps lifts the equivalence from the
// predicate to the two exported compositions: a frozen reimplementation of the
// OLD ComposeView/ComposeMembership must produce identical maps.
func TestCompose_EquivalentToLegacy_WholeMaps(t *testing.T) {
	feed := map[string]string{}
	members := map[string][]string{}
	for i := 0; i < 200; i++ {
		h := fmt.Sprintf("host%d.tenant%d.example.com", i, i%7)
		feed[h] = "Social Media"
		members[h] = []string{"Social Media", "Collaboration"}
	}
	// Hosts the override keys actually cover, so the suppression arms fire.
	for _, h := range []string{"covered.example", "sub.covered.example", "example.com", "a.example.com"} {
		feed[h] = "Baseline"
		members[h] = []string{"Baseline", "Other"}
	}
	for si, o := range equivKeySets {
		gotView := ComposeView(feed, o)
		wantView := legacyComposeView(feed, o)
		if len(gotView) != len(wantView) {
			t.Fatalf("set#%d: view size %d, legacy %d", si, len(gotView), len(wantView))
		}
		for h, c := range wantView {
			if gotView[h] != c {
				t.Errorf("set#%d: view[%q]=%q, legacy %q", si, h, gotView[h], c)
			}
		}
		gotMem := ComposeMembership(members, o)
		wantMem := legacyComposeMembership(members, o)
		if len(gotMem) != len(wantMem) {
			t.Fatalf("set#%d: membership size %d, legacy %d", si, len(gotMem), len(wantMem))
		}
		for h, cats := range wantMem {
			if strings.Join(gotMem[h], "\x00") != strings.Join(cats, "\x00") {
				t.Errorf("set#%d: membership[%q]=%v, legacy %v", si, h, gotMem[h], cats)
			}
		}
	}
}

// legacyComposeView / legacyComposeMembership are the FROZEN pre-change bodies,
// verbatim including the hoisted assert-key slice and the two separate
// suffixSuppressedLegacy probes per host. These are what the benchmarks measure
// as "legacy"; they are not kept in sync with the current implementation.
func legacyComposeView(feed map[string]string, o Overrides) map[string]string {
	assertKeys := legacyAssertKeys(o)
	out := make(map[string]string, len(feed))
	for host, cat := range feed {
		if suffixSuppressedLegacy(host, o.Tombstones) || suffixSuppressedLegacy(host, assertKeys) {
			continue
		}
		out[host] = cat
	}
	for host, cat := range o.Recategorized {
		out[host] = cat
	}
	for host, cat := range o.Added {
		out[host] = cat
	}
	return out
}

func legacyComposeMembership(feed map[string][]string, o Overrides) map[string][]string {
	assertKeys := legacyAssertKeys(o)
	out := make(map[string][]string, len(feed))
	for host, cats := range feed {
		if suffixSuppressedLegacy(host, o.Tombstones) || suffixSuppressedLegacy(host, assertKeys) {
			continue
		}
		cp := make([]string, len(cats))
		copy(cp, cats)
		out[host] = cp
	}
	for host, cat := range o.Recategorized {
		out[host] = []string{cat}
	}
	for host, cat := range o.Added {
		out[host] = []string{cat}
	}
	return out
}
