package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strings"
	"sync"
)

// Rule keys this build cannot honour as written (POL-005).
//
// A rule object can carry a key this build has no field for: a typo
// ("destFQDN ", "sourceIPs", "srcIP"), or a condition added by a newer release.
// encoding/json ignores such a key. It can also carry the SAME key twice
// ({"sourceIP":"10.0.0.0/8","sourceip":""}); encoding/json keeps the last. In
// both cases a match condition that is present in the document is not
// enforced, and the rule matches more than was written: an Allow written for
// one source matches every source. That is an enforcement condition removed by
// decoding, which the governing invariant forbids.
//
// The operator doors already decoded strictly (decodeJSON) and answered a bare
// "invalid JSON" for an unknown key. Every door that reads rules from disk or
// from the wire decoded tolerantly: the policy file, a stored config version, a
// pending draft, a control-plane snapshot, an HA bundle, the data plane's
// last-good snapshot. No door noticed a duplicate.
//
// One mechanism covers all of them. PolicyRule decodes ITSELF (UnmarshalJSON
// below): the rule is decoded as before, then its keys are read once more and
// anything this build cannot honour is recorded on the rule (decodeFault)
// instead of failing the surrounding document. The POL-005 gate refuses a
// ruleset holding such a rule exactly as it refuses any other rule the build
// cannot enforce, at the doors it already guards, and the single-rule API doors
// answer a 400 that names the rule and the keys (decodeRuleJSON). There is no
// per-door copy to forget.
//
// What is and is not a fault:
//
//   - Key matching is encoding/json's: exact, else case-insensitive. "destFqdn"
//     and "sourceip" bind to their fields as they always have (stored files and
//     this repository's own tests rely on it) and are not unknown.
//   - The check covers the rule's nested objects (schedule, subjectMatch and its
//     predicates, auth): an ignored key there is an ignored condition too.
//   - It does NOT cover the documents AROUND rules. A ConfigSnapshot from a
//     newer control plane may carry sections this build does not know; that is
//     ordinary forward compatibility and is untouched.
//   - It does not look inside "annotations" (below).
//
// THE COMPATIBILITY RULE. Read this before adding a field to PolicyRule or to a
// type inside it.
//
//	A new rule key is, by definition, an enforcement condition. Every build
//	that does not know it refuses, whole, any ruleset in which a rule carries
//	it — a policy file, a stored version, and a control-plane snapshot,
//	including that snapshot's blocklist and IP-filter changes.
//
//	Anything that is NOT a condition — display metadata, server-stamped
//	identifiers, provenance, timestamps, notes — MUST NOT be a new rule key. It
//	goes INSIDE the one container every build tolerates: "annotations".
//
// "annotations" is a JSON object whose contents this build, and every later
// one, carries without interpreting: it never affects a match, an action or
// validation. It is kept through the store, the policy file, export, stored
// versions and snapshots, so what a newer node writes there survives a pass
// through an older one. It is held and bounded in CANONICAL form (see
// ruleAnnotations): the bytes encoding/json itself writes, so a rule accepted
// once is accepted again after any number of save, export, publish and reload
// round trips. The limits (ruleAnnotationsMaxBytes, ruleAnnotationsMaxDepth)
// are part of the format and must not be raised, or an older node refuses what
// a newer one accepts. It is also the legal place for a hand-editor's note. The
// rule API replaces a rule whole, so a client that omits "annotations" on PUT
// removes them.
//
// A rule LIST given twice in one document ({"policyRules":[…],"policyRules":[…]})
// is the same defect one level up: the first list is discarded. Every envelope
// that carries rules declares them as ruleList (or policyRuleRefs), which
// notices the second decode and adds an entry the gate refuses.
//
// TestRuleKeys_AreAPinnedSetAndNewOnesAreConditions pins today's keys and
// fails when one is added, so the author meets this rule. The keys that exist
// today, informational ones included, stay where they are: every build that
// refuses unknown keys already knows them.
//
// History (the clone used is shallow at the repository's first commit,
// 2026-03-05, so this is what main's history since then shows): no key of
// PolicyRule, PolicySchedule, SubjectMatch or SubjectPredicate was ever removed
// or renamed. One key was removed from the nested auth spec, "idpRef" (added
// 2026-06-08, removed within days): it was omitempty and validation refused any
// non-empty value, so no stored rule carries it. The server writes rules only
// by encoding these structs. Nothing Culvert wrote is refused, and there is no
// allowlist of legacy keys.
//
// A rule is always decoded onto a ZERO value: nothing survives from whatever
// the destination held, so the value and its fault describe exactly the bytes
// just read. No caller decodes a partial rule onto a populated one.
//
// Cost: each rule's JSON is read twice at decode. These are load-time paths; no
// rule is decoded per request.

const (
	// ruleAnnotationsKey is the one rule key whose contents are never interpreted.
	ruleAnnotationsKey = "annotations"
	// ruleAnnotationsMaxBytes and ruleAnnotationsMaxDepth bound the container
	// in its canonical form (CWE-770). Part of the format: do not raise them.
	ruleAnnotationsMaxBytes = 4096
	ruleAnnotationsMaxDepth = 8
	// ruleKeyFaultsListed bounds how many keys one rule's refusal names.
	ruleKeyFaultsListed = 8
	// ruleKeyShown bounds one key as repeated in a 400, a log line and a
	// viewer-readable Diagnostics row.
	ruleKeyShown = 64
)

// policyRulePlain is PolicyRule without its methods, so decoding into it does
// not recurse into UnmarshalJSON.
type policyRulePlain PolicyRule

// ruleAnnotations is the cold data of a rule, behind one pointer (see the
// Annotations field): the annotations container, and the decode fault.
//
// raw is the container in CANONICAL form: compact, and escaped exactly as
// encoding/json escapes when it writes ("<", ">", "&", U+2028 and U+2029 as
// \uXXXX). That form is a fixed point of every encoder Culvert uses (Marshal,
// MarshalIndent, an Encoder with or without HTML escaping): decoding what any
// of them wrote and canonicalising again gives the same bytes. The size bound
// is measured on it, so a rule cannot be accepted and then refused after a
// save, an export or a publish, and whitespace does not count. The value is
// immutable once decoded; rule copies share it.
type ruleAnnotations struct {
	raw   []byte
	fault string
}

// IsZero makes `omitzero` leave the key out for a rule with no annotations,
// including a refused rule that only carries a fault.
func (a *ruleAnnotations) IsZero() bool { return a == nil || len(a.raw) == 0 }

// MarshalJSON writes the canonical bytes.
func (a *ruleAnnotations) MarshalJSON() ([]byte, error) { //nolint:unparam // json.Marshaler's signature; this implementation cannot fail
	if a.IsZero() {
		return []byte("null"), nil
	}
	return a.raw, nil
}

// UnmarshalJSON canonicalises and bounds the container. It does not fail on a
// value out of bounds: it records the fault, for the gate. A JSON null never
// reaches it (encoding/json leaves the pointer nil), so null is "absent".
func (a *ruleAnnotations) UnmarshalJSON(data []byte) error {
	*a = ruleAnnotations{}
	canonical, err := json.Marshal(json.RawMessage(data))
	if err != nil {
		return err
	}
	if canonical[0] != '{' || len(canonical) > ruleAnnotationsMaxBytes || jsonDepth(canonical) > ruleAnnotationsMaxDepth {
		a.fault = fmt.Sprintf("%q must be a JSON object of at most %d bytes (compact, as Culvert writes it) and %d levels",
			ruleAnnotationsKey, ruleAnnotationsMaxBytes, ruleAnnotationsMaxDepth)
		return nil
	}
	a.raw = canonical
	return nil
}

// jsonDepth is the deepest nesting of objects and arrays in valid JSON. It
// does not depend on whitespace or on how strings are escaped.
func jsonDepth(raw []byte) int {
	depth, deepest, inString, escaped := 0, 0, false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case inString:
			escaped, inString = c == '\\', c != '"'
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			deepest = max(deepest, depth)
		case c == '}' || c == ']':
			depth--
		}
	}
	return deepest
}

// UnmarshalJSON decodes a rule and records what this build cannot honour as
// written: unknown keys, duplicated keys, an "annotations" value outside its
// bounds. It never fails because of them: the decision belongs to the POL-005
// gate, which names the rule and refuses the ruleset.
//
// It decodes onto a ZERO value and assigns. encoding/json reuses slice elements
// and decodes onto whatever the destination holds; merging would let values
// from an earlier decode survive beside a fault computed from this one.
func (r *PolicyRule) UnmarshalJSON(data []byte) error {
	var plain policyRulePlain
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	annotationsFault := ""
	if plain.Annotations != nil {
		annotationsFault = plain.Annotations.fault
	}
	if fault := scanRuleKeys(data).reason(annotationsFault); fault != "" {
		// A fresh cell: the annotations (if any) are dropped with the rule.
		plain.Annotations = &ruleAnnotations{fault: fault}
	} else if plain.Annotations.IsZero() {
		plain.Annotations = nil
	}
	*r = PolicyRule(plain)
	return nil
}

// ruleListGivenTwice is the entry a rule list gains when its key appears twice
// in one document. It has no name, type or action and carries the fault, so
// the gate refuses the whole ruleset and says why.
func ruleListGivenTwice() PolicyRule {
	return PolicyRule{Annotations: &ruleAnnotations{fault: "the document gives its rule list twice; only the last would be applied — keep one"}}
}

// ruleList is the type of every rule list inside a larger document (a
// config backup, a stored version, a control-plane snapshot, a pending draft).
// It decodes as []PolicyRule, onto a fresh slice, and notices a SECOND decode
// into the same field: the key was given twice, and encoding/json would keep
// only the last list. Every door decodes these documents into a fresh value, so
// a list that is already non-nil has been decoded before in this document.
type ruleList []PolicyRule

func (l *ruleList) UnmarshalJSON(data []byte) error {
	again := *l != nil
	var rules []PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	if again {
		rules = append(rules, ruleListGivenTwice())
	}
	*l = rules
	return nil
}

// policyRuleRefs is ruleList for `culvert policy-check`, which decodes
// pointers so that a null entry is reported as one, and needs to know whether
// the key was present at all. It is a value, not a pointer, in its document so
// that a second occurrence which is `null` still reaches UnmarshalJSON.
type policyRuleRefs struct {
	present bool
	rules   []*PolicyRule
}

func (l *policyRuleRefs) UnmarshalJSON(data []byte) error {
	again := l.present
	var rules []*PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	if again {
		twice := ruleListGivenTwice()
		rules = append(rules, &twice)
	}
	l.present, l.rules = true, rules
	return nil
}

// ruleLastHit32 narrows a unix-seconds timestamp to PolicyRule.lastHitUnix.
func ruleLastHit32(unix int64) uint32 {
	if unix <= 0 {
		return 0
	}
	return uint32(min(unix, math.MaxUint32)) // #nosec G115 -- bounded by the min above
}

// ruleKeyFaults is what one rule's keys hold that this build cannot honour.
type ruleKeyFaults struct {
	unknown   []string // keys with no field, in document order
	duplicate []string // "first"/"again" pairs that bind to one field
	more      int      // faults beyond ruleKeyFaultsListed
}

func (f *ruleKeyFaults) add(list *[]string, key string) {
	if len(f.unknown)+len(f.duplicate) >= ruleKeyFaultsListed {
		f.more++
		return
	}
	*list = append(*list, key)
}

// scanRuleKeys reads the keys of one rule object. data is valid JSON.
func scanRuleKeys(data []byte) *ruleKeyFaults {
	f := &ruleKeyFaults{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	f.walk(dec, reflect.TypeFor[policyRulePlain]())
	return f
}

// walk consumes one JSON value that encoding/json decodes into t. A nil t is a
// value nothing interprets (an unknown key's, or the annotations container's).
func (f *ruleKeyFaults) walk(dec *json.Decoder, t reflect.Type) {
	tok, err := dec.Token()
	delim, open := tok.(json.Delim)
	if err != nil || !open {
		return // a scalar
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == nil || reflect.PointerTo(t).Implements(reflect.TypeFor[json.Unmarshaler]()):
		skipJSONValue(dec) // nothing interprets it here: an unknown key's value, or the annotations container
	case delim == '{' && t.Kind() == reflect.Struct:
		f.walkObject(dec, t)
	case delim == '[' && t.Kind() == reflect.Slice:
		for dec.More() {
			f.walk(dec, t.Elem())
		}
		_, _ = dec.Token() // ']'
	default:
		skipJSONValue(dec)
	}
}

func (f *ruleKeyFaults) walkObject(dec *json.Decoder, t reflect.Type) {
	fields := jsonFieldsOf(t)
	seen := map[int]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		key, _ := tok.(string)
		idx, ok := fields.lookup(key)
		if !ok {
			f.add(&f.unknown, key)
			f.walk(dec, nil)
			continue
		}
		if first, again := seen[idx]; again {
			f.add(&f.duplicate, first+"\x00"+key)
		} else {
			seen[idx] = key
		}
		f.walk(dec, t.Field(idx).Type)
	}
	_, _ = dec.Token() // '}'
}

// skipJSONValue consumes the rest of a value whose opening delimiter was read.
// Iterative: the depth of an uninterpreted value is the document's, not ours.
func skipJSONValue(dec *json.Decoder) {
	for depth := 1; depth > 0; {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
}

// jsonFields is the key set encoding/json binds for one struct type.
type jsonFields struct {
	exact map[string]int // key as tagged -> field index
	names []string       // index-aligned with the struct's fields; "" = not bound
}

// lookup mirrors encoding/json: an exact match, else a case-insensitive one.
func (jf *jsonFields) lookup(key string) (int, bool) {
	if i, ok := jf.exact[key]; ok {
		return i, true
	}
	for i, name := range jf.names {
		if name != "" && strings.EqualFold(name, key) {
			return i, true
		}
	}
	return 0, false
}

var jsonFieldsCache sync.Map // reflect.Type -> *jsonFields

func jsonFieldsOf(t reflect.Type) *jsonFields {
	if cached, ok := jsonFieldsCache.Load(t); ok {
		return cached.(*jsonFields) //nolint:errcheck,forcetypeassert // only *jsonFields is stored
	}
	jf := &jsonFields{exact: map[string]int{}, names: make([]string, t.NumField())}
	for i := range t.NumField() {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !field.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		jf.exact[name], jf.names[i] = i, name
	}
	jsonFieldsCache.Store(t, jf)
	return jf
}

func ruleKeyQuoted(key string) string {
	if len(key) > ruleKeyShown {
		key = strings.ToValidUTF8(key[:ruleKeyShown], "") + "…"
	}
	return fmt.Sprintf("%q", sanitizeLog(key))
}

// reason is the refusal text for one rule, or "" when every key was honoured.
// It is bounded: it is repeated in a 400 body, a log line and a Diagnostics row.
func (f *ruleKeyFaults) reason(annotations string) string {
	var parts []string
	if len(f.unknown) > 0 {
		quoted := make([]string, len(f.unknown))
		for i, k := range f.unknown {
			quoted[i] = ruleKeyQuoted(k)
		}
		parts = append(parts, "unknown field "+strings.Join(quoted, ", ")+
			` (this version has no such rule field; ignoring it would widen the rule — correct the name, move a note under "`+
			ruleAnnotationsKey+`", or remove it)`)
	}
	if len(f.duplicate) > 0 {
		quoted := make([]string, len(f.duplicate))
		for i, pair := range f.duplicate {
			first, again, _ := strings.Cut(pair, "\x00")
			quoted[i] = ruleKeyQuoted(first) + " and " + ruleKeyQuoted(again)
		}
		parts = append(parts, "duplicate field "+strings.Join(quoted, ", ")+
			" (the same field given twice; only the last would be enforced — keep one)")
	}
	if f.more > 0 {
		parts = append(parts, fmt.Sprintf("and %d more such field(s)", f.more))
	}
	if annotations != "" {
		parts = append(parts, annotations)
	}
	return strings.Join(parts, "; ")
}

// ruleAsWrittenFault is the refusal reason for a rule decoded from JSON whose
// keys this build cannot honour, or "" (also for a rule built in Go).
func ruleAsWrittenFault(r *PolicyRule) string {
	if r == nil || r.Annotations == nil {
		return ""
	}
	return r.Annotations.fault
}

// decodeRuleJSON reads one rule from a request body for the single-rule API
// doors. It returns the 400 message, or "" to proceed. A body that is not a
// rule at all is "invalid JSON", as before; a rule whose keys cannot be
// honoured is refused by name, before anything is validated, stamped or written.
func decodeRuleJSON(r *http.Request, rule *PolicyRule) (refusal string) {
	if err := decodeJSON(r, rule); err != nil {
		return "invalid JSON"
	}
	if reason := ruleAsWrittenFault(rule); reason != "" {
		return fmt.Sprintf("rule %s: %s. Field names are not case-sensitive. Nothing was changed", ruleKeyQuoted(rule.Name), reason)
	}
	return ""
}

// rulesetRefusedRunningUnchanged is the clause the gate's errors end with. It is
// true wherever a policy is already running, and false at startup.
const rulesetRefusedRunningUnchanged = "; the whole ruleset is refused and the running policy is unchanged"

// startupPolicyFileError words a policy-file load failure for the fatal exit at
// startup, where no policy is running yet.
func startupPolicyFileError(err error, path string) string {
	msg := err.Error()
	if isRulesetGateError(err) {
		msg = strings.TrimSuffix(msg, rulesetRefusedRunningUnchanged) +
			"; the whole policy file is refused, no policy was loaded and the proxy did not start"
	}
	return fmt.Sprintf("Cannot load policy file: %s (run `culvert policy-check %s` to list every rule and field this version refuses)",
		msg, sanitizeLog(path))
}

const (
	rulesetDoorSnapshot = "control-plane snapshot"
	rulesetDoorLastGood = "last-known-good snapshot on disk"
)

// logDPLastGoodUnavailable reports a last-known-good snapshot that exists and
// could not be applied at data-plane startup. A refusal by the POL-005 gate is
// recorded for Diagnostics under its own door, not only logged: the node is
// then running without its cached policy until the control plane is reached.
func logDPLastGoodUnavailable(err error) {
	if isRulesetGateError(err) {
		policyStore.noteRulesetRefused(rulesetDoorLastGood, err)
		return
	}
	logger.Printf("DataPlane: last-known-good config unavailable: %v", err)
}

// clearSnapshotRulesetRefusals retires a refusal recorded for either snapshot
// door once a snapshot is applied that carries no policy section.
func (ps *PolicyStore) clearSnapshotRulesetRefusals() {
	ps.clearRulesetRefusal(rulesetDoorSnapshot)
	ps.clearRulesetRefusal(rulesetDoorLastGood)
}

// UnmarshalJSON keeps authRuleView decodable. It embeds PolicyRule, whose
// UnmarshalJSON would otherwise be promoted and consume the whole object,
// reporting "warnings" as an unknown rule key. Production only encodes this
// view; API clients and tests decode it.
func (v *authRuleView) UnmarshalJSON(data []byte) error {
	var aux struct {
		policyRulePlain
		Warnings []string `json:"warnings,omitempty"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	v.PolicyRule, v.Warnings = PolicyRule(aux.policyRulePlain), aux.Warnings
	return nil
}
