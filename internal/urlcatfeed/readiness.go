package urlcatfeed

import (
	"fmt"
	"sort"
	"strings"
)

// Source-dataset readiness evaluator (Finding 7). Unlike Generate (which fails
// fast on the first violation), EvaluateReadiness walks the WHOLE dataset and
// returns a deterministic, complete inventory of every reason it is not yet
// publishable under the signed_manifest_v1 single-category / suffix-safe model.
// F5 MUST refuse to publish unless Ready is true.

// ReadinessConflict is one deterministic reason the dataset is not publishable.
type ReadinessConflict struct {
	Kind   string // "invalid_host" | "multi_category" | "suffix_conflict" | "category_name"
	Host   string // normalized host (or raw for invalid_host / "" for category_name)
	Detail string // human-readable specifics (sorted, deterministic)
}

// ReadinessReport is the complete, deterministically-ordered evaluation result.
type ReadinessReport struct {
	Ready            bool
	TotalRawHosts    int
	UniqueHosts      int
	InvalidHosts     []ReadinessConflict
	MultiCategory    []ReadinessConflict
	SuffixConflict   []ReadinessConflict
	CategoryName     []ReadinessConflict
	StructuralIssues []ReadinessConflict // generator-parity invariants (empty dataset, zero-host category, case collision)
}

// EvaluateReadiness produces the full inventory. It is pure and deterministic:
// every list is sorted, so the same dataset always yields identical output.
func EvaluateReadiness(ds SourceDataset) *ReadinessReport {
	r := &ReadinessReport{}
	catsOf := r.collectAssignments(ds)
	r.UniqueHosts = len(catsOf)
	r.MultiCategory = detectMultiCategory(catsOf)
	r.SuffixConflict = detectSuffixConflicts(catsOf)
	r.StructuralIssues = detectStructuralIssues(ds, catsOf)

	sortConflicts(r.InvalidHosts)
	sortConflicts(r.MultiCategory)
	sortConflicts(r.SuffixConflict)
	sortConflicts(r.CategoryName)
	sortConflicts(r.StructuralIssues)

	// Ready ⇔ Generate would succeed: every conflict list AND the generator-parity
	// structural invariants must be clear (Codex P2 — Ready is the F5 publish gate,
	// so it must reject any dataset Generate rejects).
	r.Ready = len(r.InvalidHosts) == 0 && len(r.MultiCategory) == 0 &&
		len(r.SuffixConflict) == 0 && len(r.CategoryName) == 0 &&
		len(r.StructuralIssues) == 0
	return r
}

// detectStructuralIssues mirrors the generator's non-conflict structural
// rejections so Ready cannot approve a dataset Generate would reject: a
// case-insensitive category-name collision (ErrCategoryCase), a category with no
// valid hosts (ErrEmptyCategoryHost), and an empty dataset (ErrNoCats).
func detectStructuralIssues(ds SourceDataset, catsOf map[string]map[string]struct{}) []ReadinessConflict {
	var out []ReadinessConflict
	seen := map[string]string{} // lowercase(canonical) -> canonical
	for _, c := range ds.Categories {
		name, err := CanonicalCategoryName(c.Name)
		if err != nil {
			continue // name-format issue already recorded under CategoryName
		}
		lc := strings.ToLower(name)
		if prev, ok := seen[lc]; ok && prev != name {
			out = append(out, ReadinessConflict{
				Kind: "category_case", Detail: fmt.Sprintf("%q vs %q", prev, name),
			})
		}
		seen[lc] = name
		if countValidHosts(c.Hosts) == 0 {
			out = append(out, ReadinessConflict{Kind: "empty_category", Detail: name})
		}
	}
	if len(catsOf) == 0 {
		out = append(out, ReadinessConflict{Kind: "empty_dataset", Detail: "no valid hosts in any category"})
	}
	return out
}

// countValidHosts counts how many of hosts normalize successfully.
func countValidHosts(hosts []string) int {
	n := 0
	for _, h := range hosts {
		if _, err := NormalizeHost(h); err == nil {
			n++
		}
	}
	return n
}

// collectAssignments normalizes every (category, host) pair into a host→category-
// set map, recording category-name and invalid-host conflicts as it goes.
func (r *ReadinessReport) collectAssignments(ds SourceDataset) map[string]map[string]struct{} {
	catsOf := map[string]map[string]struct{}{}
	for _, c := range ds.Categories {
		name, err := CanonicalCategoryName(c.Name)
		if err != nil {
			r.CategoryName = append(r.CategoryName, ReadinessConflict{
				Kind: "category_name", Detail: fmt.Sprintf("%q: %v", c.Name, err),
			})
			// Still evaluate its hosts under the raw (trimmed) name for coverage.
			name = strings.TrimSpace(c.Name)
		}
		for _, raw := range c.Hosts {
			r.TotalRawHosts++
			host, err := NormalizeHost(raw)
			if err != nil {
				r.InvalidHosts = append(r.InvalidHosts, ReadinessConflict{
					Kind: "invalid_host", Host: raw, Detail: err.Error(),
				})
				continue
			}
			if catsOf[host] == nil {
				catsOf[host] = map[string]struct{}{}
			}
			catsOf[host][name] = struct{}{}
		}
	}
	return catsOf
}

// detectMultiCategory reports any host assigned to more than one category.
func detectMultiCategory(catsOf map[string]map[string]struct{}) []ReadinessConflict {
	var out []ReadinessConflict
	for host, set := range catsOf {
		if len(set) > 1 {
			out = append(out, ReadinessConflict{
				Kind: "multi_category", Host: host, Detail: strings.Join(sortedKeys(set), " | "),
			})
		}
	}
	return out
}

// detectSuffixConflicts reports any host that is a proper DNS suffix of another
// where their category SETS differ. Walks each host's ancestor suffixes.
func detectSuffixConflicts(catsOf map[string]map[string]struct{}) []ReadinessConflict {
	var out []ReadinessConflict
	for host, set := range catsOf {
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
			ancSet, ok := catsOf[rest]
			if !ok {
				continue
			}
			if !sameSet(set, ancSet) {
				out = append(out, ReadinessConflict{
					Kind: "suffix_conflict", Host: host,
					Detail: fmt.Sprintf("%s{%s} under %s{%s}",
						host, strings.Join(sortedKeys(set), ","),
						rest, strings.Join(sortedKeys(ancSet), ",")),
				})
			}
		}
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sortConflicts(cs []ReadinessConflict) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Host != cs[j].Host {
			return cs[i].Host < cs[j].Host
		}
		return cs[i].Detail < cs[j].Detail
	})
}
