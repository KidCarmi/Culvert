package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
// validation. It is kept verbatim through the store, the policy file, export,
// stored versions and snapshots, so what a newer node writes there survives a
// pass through an older one. It is bounded at decode (ruleAnnotationsMaxBytes,
// ruleAnnotationsMaxDepth; the limits are part of the format and must not be
// raised, or an older node refuses what a newer one accepts). It is also the
// legal place for a hand-editor's note. The rule API replaces a rule whole, so a
// client that omits "annotations" on PUT removes them.
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
// Cost: each rule's JSON is read twice at decode. These are load-time paths; no
// rule is decoded per request.

const (
	// ruleAnnotationsKey is the one rule key whose contents are never interpreted.
	ruleAnnotationsKey = "annotations"
	// ruleAnnotationsMaxBytes and ruleAnnotationsMaxDepth bound the container as
	// written (CWE-770). Part of the format: do not raise them.
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

// UnmarshalJSON decodes a rule and records in decodeFault what this build
// cannot honour as written: unknown keys, duplicated keys, an "annotations"
// value outside its bounds. It never fails because of them: the decision
// belongs to the POL-005 gate, which names the rule and refuses the ruleset.
func (r *PolicyRule) UnmarshalJSON(data []byte) error {
	// Decode onto a copy of the receiver, as encoding/json would decode onto
	// the receiver itself: keys absent from data keep their current values.
	// The fault is recomputed below from THIS document alone, so it never
	// reflects what the variable held before.
	plain := policyRulePlain(*r)
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(plain.Annotations), []byte("null")) {
		plain.Annotations = nil
	}
	plain.decodeFault = scanRuleKeys(data).reason(ruleAnnotationsFault(plain.Annotations))
	*r = PolicyRule(plain)
	return nil
}

// ruleAnnotationsFault bounds the container: an object, of limited size and
// nesting. raw is valid JSON (it was just decoded).
func ruleAnnotationsFault(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
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
	if raw[0] != '{' || len(raw) > ruleAnnotationsMaxBytes || deepest > ruleAnnotationsMaxDepth {
		return fmt.Sprintf("%q must be a JSON object of at most %d bytes and %d levels",
			ruleAnnotationsKey, ruleAnnotationsMaxBytes, ruleAnnotationsMaxDepth)
	}
	return ""
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
	case t == nil || t == reflect.TypeFor[json.RawMessage]():
		skipJSONValue(dec)
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
	if r == nil {
		return ""
	}
	return r.decodeFault
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
