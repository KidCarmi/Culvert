package catalog

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// safeName sanitizes an attacker-controllable property name for embedding in a
// diff detail (property names inside a schema are arbitrary strings). It never
// returns raw hostile bytes.
func safeName(s string) string { return mcperr.Sanitize(s, 64) }

// schemaSignals is the set of change signals a schema diff can emit. The
// classifier's precedence (expansion > semantic > narrowing) is applied by the
// caller; a diff never itself decides the class. A change that fires NO signal
// but altered the hash is turned into a conservative semantic signal upstream.
type schemaSignals struct {
	expansion []string // proven, or conservatively security-relevant, broadening
	narrowing []string // MECHANICALLY PROVEN restriction
	ambiguous []string // changed but neither proven — routes to semantic_drift
}

func (s *schemaSignals) expand(d string) { s.expansion = append(s.expansion, d) }
func (s *schemaSignals) narrow(d string) { s.narrowing = append(s.narrowing, d) }
func (s *schemaSignals) ambig(d string)  { s.ambiguous = append(s.ambiguous, d) }
func (s *schemaSignals) merge(o schemaSignals) {
	s.expansion = append(s.expansion, o.expansion...)
	s.narrowing = append(s.narrowing, o.narrowing...)
	s.ambiguous = append(s.ambiguous, o.ambiguous...)
}

// toFieldDiffs renders the signals as deterministic FieldDiffs for one field.
func (s schemaSignals) toFieldDiffs(field string) []FieldDiff {
	var out []FieldDiff
	for _, d := range s.expansion {
		out = append(out, FieldDiff{Field: field, Change: "expansion", Detail: d})
	}
	for _, d := range s.ambiguous {
		out = append(out, FieldDiff{Field: field, Change: "semantic", Detail: d})
	}
	for _, d := range s.narrowing {
		out = append(out, FieldDiff{Field: field, Change: "narrowing", Detail: d})
	}
	return out
}

// sensitiveTokens name property-name substrings that mark a newly-introduced or
// newly-relaxed input as capable of admin/delete/write/URL/destination/credential
// behavior — the concretely named privilege-expansion triggers, matched
// case-insensitively. Conservative by design: a false positive over-quarantines
// (safe), a miss must not silently pass, which is why an unrecognized change
// still routes to semantic_drift, never safe_narrowing.
var sensitiveTokens = []string{
	"admin", "root", "sudo", "superuser", "privilege", "permission", "grant", "scope",
	"delete", "destroy", "drop", "truncate", "remove", "purge", "wipe",
	"exec", "execute", "shell", "cmd", "command", "spawn", "system", "eval", "run",
	"sql", "query", "script",
	"url", "uri", "href", "endpoint", "host", "hostname", "domain", "address",
	"path", "filepath", "file", "dir", "directory", "location",
	"write", "put", "post", "patch", "upload", "overwrite",
	"password", "passwd", "secret", "token", "credential", "apikey", "api_key",
	"privatekey", "private_key", "auth", "key",
	"destination", "target", "redirect", "callback", "webhook", "proxy",
}

// uriFormats are JSON Schema `format` values that denote arbitrary network /
// resource references.
var uriFormats = map[string]struct{}{
	"uri": {}, "uri-reference": {}, "iri": {}, "iri-reference": {}, "url": {},
	"hostname": {}, "idn-hostname": {}, "ipv4": {}, "ipv6": {},
}

// isSensitiveName reports whether a property name contains a sensitive token.
func isSensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, tok := range sensitiveTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// diffSchema compares two schema-canonical nodes and returns the change signals.
// It supports a DOCUMENTED keyword subset (type, enum, required, properties,
// additionalProperties, minimum, maximum, minLength, maxLength, format) and fails
// conservatively — an unmodelled change that altered the canonical form yields an
// ambiguous (→ semantic) signal, never a narrowing. It is bounded by the trees'
// own (already-enforced) structural limits, so it cannot recurse unboundedly.
func diffSchema(prior, observed *canonical.Node) schemaSignals {
	var s schemaSignals
	if prior == nil || observed == nil || prior.Kind != canonical.KindObject || observed.Kind != canonical.KindObject {
		// A non-object or missing schema that changed is a behavioral change we
		// cannot mechanically prove restrictive.
		if !prior.Equal(observed) {
			s.ambig("schema shape changed")
		}
		return s
	}
	diffType(prior, observed, &s)
	diffEnum(prior, observed, &s)
	diffRequired(prior, observed, &s)
	diffAdditionalProps(prior, observed, &s)
	diffBound(prior, observed, "minimum", true, &s)
	diffBound(prior, observed, "maximum", false, &s)
	diffBound(prior, observed, "minLength", true, &s)
	diffBound(prior, observed, "maxLength", false, &s)
	diffProperties(prior, observed, &s)
	return s
}

// diffType compares the `type` keyword as a set of allowed types: a superset is
// broadening, a subset is narrowing, a disjoint change is ambiguous. An ABSENT
// `type` means "any type allowed" (the universal set), NOT the empty set — so
// dropping `type` is an EXPANSION (a specific type → anything) and adding one is
// a NARROWING. Getting this backwards would mislabel a real broadening as safe
// narrowing, exactly what the conservative rule forbids.
func diffType(prior, observed *canonical.Node, s *schemaSignals) {
	po, pok := prior.Get("type")
	oo, ook := observed.Get("type")
	switch {
	case !pok && !ook:
		return
	case pok && !ook:
		s.expand("type constraint dropped (now any type)")
		return
	case !pok && ook:
		s.narrow("type constraint added")
		return
	}
	pset := typeSet(po)
	oset := typeSet(oo)
	if eqSet(pset, oset) {
		return
	}
	switch {
	case subset(pset, oset):
		s.expand("type set broadened")
	case subset(oset, pset):
		s.narrow("type set narrowed")
	default:
		s.ambig("type changed")
	}
}

// typeSet normalizes a `type` value (string or array of strings) to a set.
func typeSet(n *canonical.Node) map[string]struct{} {
	set := map[string]struct{}{}
	if n == nil {
		return set
	}
	switch n.Kind {
	case canonical.KindString:
		set[n.Str] = struct{}{}
	case canonical.KindArray:
		for _, e := range n.Arr {
			if e.Kind == canonical.KindString {
				set[e.Str] = struct{}{}
			}
		}
	}
	return set
}

// diffEnum: values added (superset) is broadening; values only removed is
// narrowing; disjoint change is ambiguous. Enum arrays are already sorted.
func diffEnum(prior, observed *canonical.Node, s *schemaSignals) {
	po, pok := prior.Get("enum")
	oo, ook := observed.Get("enum")
	if !pok && !ook {
		return
	}
	pset := encodedSet(po)
	oset := encodedSet(oo)
	if eqSet(pset, oset) {
		return
	}
	switch {
	case subset(pset, oset):
		s.expand("enum values added")
	case subset(oset, pset):
		s.narrow("enum values removed")
	default:
		s.ambig("enum values changed")
	}
}

// diffRequired: a required member added is narrowing (more constrained); a
// required member removed is broadening (looser acceptance).
func diffRequired(prior, observed *canonical.Node, s *schemaSignals) {
	po, _ := prior.Get("required")
	oo, _ := observed.Get("required")
	pset := stringSet(po)
	oset := stringSet(oo)
	if eqSet(pset, oset) {
		return
	}
	if hasExtra(oset, pset) {
		s.narrow("required properties added")
	}
	if hasExtra(pset, oset) {
		s.expand("required properties removed")
	}
}

// diffAdditionalProps: forbidden→permissive is broadening; permissive→forbidden
// is narrowing. Forbidden means present AND boolean false; anything else
// (absent, true, or a subschema) is treated as permissive.
func diffAdditionalProps(prior, observed *canonical.Node, s *schemaSignals) {
	pf := additionalForbidden(prior)
	of := additionalForbidden(observed)
	switch {
	case pf && !of:
		s.expand("additionalProperties relaxed to permissive")
	case !pf && of:
		s.narrow("additionalProperties tightened to forbidden")
	}
}

func additionalForbidden(n *canonical.Node) bool {
	ap, ok := n.Get("additionalProperties")
	return ok && ap.Kind == canonical.KindBool && !ap.Bool
}

// diffBound compares a numeric bound. lowerIsTighter marks bounds where a LARGER
// value is more restrictive (minimum/minLength); otherwise a SMALLER value is
// tighter (maximum/maxLength). Adding a bound is narrowing; removing it is
// broadening; an unparseable numeric change is ambiguous.
func diffBound(prior, observed *canonical.Node, key string, lowerIsTighter bool, s *schemaSignals) {
	pv, pok := numberOf(prior, key)
	ov, ook := numberOf(observed, key)
	switch {
	case !pok && !ook:
		return
	case !pok && ook:
		s.narrow(key + " bound added")
		return
	case pok && !ook:
		s.expand(key + " bound removed")
		return
	}
	cmp, ok := canonical.NumCmp(pv, ov)
	if !ok {
		s.ambig(key + " bound changed")
		return
	}
	if cmp == 0 {
		return
	}
	tighter := (cmp < 0) == lowerIsTighter // observed > prior tightens a min; observed < prior tightens a max
	if tighter {
		s.narrow(key + " bound tightened")
	} else {
		s.expand(key + " bound relaxed")
	}
}

// numberOf returns the exact numeric token of a keyword, if present and numeric.
func numberOf(n *canonical.Node, key string) (string, bool) {
	v, ok := n.Get(key)
	if !ok || v.Kind != canonical.KindNumber {
		return "", false
	}
	return v.Num, true
}

// diffProperties recurses per property. A property present in both is diffed
// recursively; an added property is expansion if sensitive/URL-shaped else
// ambiguous (input-surface growth needing review); a removed property is
// narrowing (a defined input withdrawn).
func diffProperties(prior, observed *canonical.Node, s *schemaSignals) {
	pp, _ := prior.Get("properties")
	op, _ := observed.Get("properties")
	if pp == nil && op == nil {
		return
	}
	priorNames := objectKeys(pp)
	observedNames := objectKeys(op)
	for name := range observedNames {
		if _, existed := priorNames[name]; existed {
			pv, _ := pp.Get(name)
			ov, _ := op.Get(name)
			s.merge(diffSchema(pv, ov))
			continue
		}
		sub, _ := op.Get(name)
		if isSensitiveName(name) || hasURIFormat(sub) {
			s.expand("privileged optional property added: " + safeName(name))
		} else {
			s.ambig("optional property added: " + safeName(name))
		}
	}
	for name := range priorNames {
		if _, still := observedNames[name]; !still {
			s.narrow("property removed: " + safeName(name))
		}
	}
}

// hasURIFormat reports whether a property subschema declares an arbitrary
// URI/host/address format.
func hasURIFormat(sub *canonical.Node) bool {
	if sub == nil {
		return false
	}
	f, ok := sub.Get("format")
	if !ok || f.Kind != canonical.KindString {
		return false
	}
	_, isURI := uriFormats[f.Str]
	return isURI
}

// --- small set helpers over canonical nodes --------------------------------

func objectKeys(n *canonical.Node) map[string]struct{} {
	set := map[string]struct{}{}
	if n != nil && n.Kind == canonical.KindObject {
		for _, k := range n.Keys {
			set[k] = struct{}{}
		}
	}
	return set
}

func stringSet(n *canonical.Node) map[string]struct{} {
	set := map[string]struct{}{}
	if n != nil && n.Kind == canonical.KindArray {
		for _, e := range n.Arr {
			if e.Kind == canonical.KindString {
				set[e.Str] = struct{}{}
			}
		}
	}
	return set
}

func encodedSet(n *canonical.Node) map[string]struct{} {
	set := map[string]struct{}{}
	if n != nil && n.Kind == canonical.KindArray {
		for _, e := range n.Arr {
			set[string(canonical.Encode(e))] = struct{}{}
		}
	}
	return set
}

func eqSet(a, b map[string]struct{}) bool {
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

// subset reports whether a ⊆ b.
func subset(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// hasExtra reports whether a has any element not in b.
func hasExtra(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; !ok {
			return true
		}
	}
	return false
}
