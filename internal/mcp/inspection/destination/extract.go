package destination

import (
	"strconv"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Candidate is one extracted destination-bearing string from a value.
type Candidate struct {
	Path    string // bounded JSON-pointer-like location
	RawURL  string // the raw string (canonicalized by the caller; never trusted)
	Modeled bool   // true: from an explicit compiled rule; false: heuristic backstop
}

// ExtractionRules is an immutable, compiled set of explicit destination-extraction
// pointers plus an optional conservative name-heuristic backstop. Destinations are
// NOT discovered by scanning arbitrary strings for "http": extraction is tied to
// explicit schema-property paths (JSON pointers). The name heuristic is a
// CONSERVATIVE BACKSTOP only — a heuristic hit is reported as an unmodeled
// destination, never used as the sole allow mechanism.
type ExtractionRules struct {
	pointers  [][]string // compiled pointer segments
	heuristic bool
}

// heuristicNames are the conservative destination field-name markers. A string
// under one of these keys that looks like a URL is a backstop candidate.
var heuristicNames = map[string]struct{}{
	"url": {}, "uri": {}, "host": {}, "hostname": {}, "endpoint": {},
	"callback": {}, "webhook": {}, "redirect": {}, "target": {}, "href": {},
}

// CompileRules compiles explicit JSON-pointer extraction paths (bounded by
// MaxExtractionPaths) plus the optional heuristic backstop.
func CompileRules(pointers []string, heuristic bool, lim limits.InspectionLimits) (ExtractionRules, error) {
	if len(pointers) > lim.MaxExtractionPaths() {
		return ExtractionRules{}, destErr(mcperr.ReasonInspectionLimitExceeded, "too many extraction paths")
	}
	compiled := make([][]string, 0, len(pointers))
	for _, p := range pointers {
		segs, err := parsePointer(p)
		if err != nil {
			return ExtractionRules{}, err
		}
		compiled = append(compiled, segs)
	}
	return ExtractionRules{pointers: compiled, heuristic: heuristic}, nil
}

// Extract returns the destination candidates in v under the compiled rules,
// bounded by MaxExtractedDests. Explicit-rule hits are Modeled; heuristic hits are
// not. Deterministic order: explicit rules first (in rule order), then heuristic
// hits in document order.
func (r ExtractionRules) Extract(v *canonical.Node, lim limits.InspectionLimits) ([]Candidate, error) {
	if v == nil {
		// A tools/call that omits the optional `arguments` member decodes to a nil
		// value: no destinations to extract (and never a nil dereference).
		return nil, nil
	}
	var out []Candidate
	for _, segs := range r.pointers {
		if n, ok := resolvePointer(v, segs); ok && n.Kind == canonical.KindString {
			out = append(out, Candidate{Path: "/" + strings.Join(segs, "/"), RawURL: n.Str, Modeled: true})
			if len(out) > lim.MaxExtractedDests() {
				return nil, destErr(mcperr.ReasonInspectionLimitExceeded, "too many extracted destinations")
			}
		}
	}
	if r.heuristic {
		if err := r.walkHeuristic(v, "", &out, lim); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r ExtractionRules) walkHeuristic(n *canonical.Node, path string, out *[]Candidate, lim limits.InspectionLimits) error {
	switch n.Kind {
	case canonical.KindObject:
		for i, k := range n.Keys {
			child := n.Vals[i]
			if child.Kind == canonical.KindString && isDestinationName(k) && looksLikeURL(child.Str) {
				*out = append(*out, Candidate{Path: joinPtr(path, k), RawURL: child.Str, Modeled: false})
				if len(*out) > lim.MaxExtractedDests() {
					return destErr(mcperr.ReasonInspectionLimitExceeded, "too many extracted destinations")
				}
			}
			if err := r.walkHeuristic(child, joinPtr(path, k), out, lim); err != nil {
				return err
			}
		}
	case canonical.KindArray:
		for i, e := range n.Arr {
			if err := r.walkHeuristic(e, path+"/"+strconv.Itoa(i), out, lim); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDestinationName(k string) bool {
	_, ok := heuristicNames[strings.ToLower(k)]
	return ok
}

// looksLikeURL is a conservative check for the heuristic backstop: a scheme
// followed by "://" (never a bare token). It intentionally does NOT match every
// URL — it only surfaces obvious ones as unmodeled candidates.
func looksLikeURL(s string) bool {
	i := strings.Index(s, "://")
	return i > 0 && i < 16
}

// parsePointer parses an RFC6901-style pointer ("/a/b/0") into segments.
func parsePointer(p string) ([]string, error) {
	if p == "" || p[0] != '/' {
		return nil, destErr(mcperr.ReasonInspectionLimitExceeded, "invalid extraction pointer")
	}
	raw := strings.Split(p[1:], "/")
	segs := make([]string, len(raw))
	for i, s := range raw {
		s = strings.ReplaceAll(s, "~1", "/")
		s = strings.ReplaceAll(s, "~0", "~")
		segs[i] = s
	}
	return segs, nil
}

func resolvePointer(n *canonical.Node, segs []string) (*canonical.Node, bool) {
	cur := n
	for _, s := range segs {
		if cur == nil {
			return nil, false
		}
		switch cur.Kind {
		case canonical.KindObject:
			child, ok := cur.Get(s)
			if !ok {
				return nil, false
			}
			cur = child
		case canonical.KindArray:
			idx, err := strconv.Atoi(s)
			if err != nil || idx < 0 || idx >= len(cur.Arr) {
				return nil, false
			}
			cur = cur.Arr[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func joinPtr(path, key string) string {
	if len(key) > 64 {
		key = key[:64]
	}
	key = strings.ReplaceAll(key, "~", "~0")
	key = strings.ReplaceAll(key, "/", "~1")
	return path + "/" + key
}
