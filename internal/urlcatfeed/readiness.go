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
	Ready          bool
	TotalRawHosts  int
	UniqueHosts    int
	InvalidHosts   []ReadinessConflict
	MultiCategory  []ReadinessConflict
	SuffixConflict []ReadinessConflict
	CategoryName   []ReadinessConflict
}

// EvaluateReadiness produces the full inventory. It is pure and deterministic:
// every list is sorted, so the same dataset always yields identical output.
func EvaluateReadiness(ds SourceDataset) *ReadinessReport {
	r := &ReadinessReport{}
	// host -> set of categories it is assigned to (deduped)
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
	r.UniqueHosts = len(catsOf)

	// Multi-category: any host assigned to >1 distinct category.
	for host, set := range catsOf {
		if len(set) > 1 {
			cats := sortedKeys(set)
			r.MultiCategory = append(r.MultiCategory, ReadinessConflict{
				Kind: "multi_category", Host: host, Detail: strings.Join(cats, " | "),
			})
		}
	}

	// Suffix conflict: a host is a proper DNS suffix of another and their category
	// SETS differ. Walk each host's ancestor suffixes.
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
				r.SuffixConflict = append(r.SuffixConflict, ReadinessConflict{
					Kind: "suffix_conflict", Host: host,
					Detail: fmt.Sprintf("%s{%s} under %s{%s}",
						host, strings.Join(sortedKeys(set), ","),
						rest, strings.Join(sortedKeys(ancSet), ",")),
				})
			}
		}
	}

	sortConflicts(r.InvalidHosts)
	sortConflicts(r.MultiCategory)
	sortConflicts(r.SuffixConflict)
	sortConflicts(r.CategoryName)

	r.Ready = len(r.InvalidHosts) == 0 && len(r.MultiCategory) == 0 &&
		len(r.SuffixConflict) == 0 && len(r.CategoryName) == 0
	return r
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
