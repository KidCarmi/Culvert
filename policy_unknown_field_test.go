package main

// Unknown JSON fields on a policy rule (policy_unknown_field.go, POL-005).
//
// Measured before this change, at every door that reads rules from disk or from
// the wire: a rule carrying a key this build has no field for was installed with
// the key ignored. For
//
//	{"name":"allow-finance","action":"Allow","destFQDN":H,"srcIP":"203.0.113.0/24"}
//
// placed above a Block for H, the policy file, a stored config version, a
// pending draft and a control-plane snapshot all installed an Allow for EVERY
// source, and a client outside 203.0.113.0/24 was allowed. The operator doors
// (single-rule API, import) already refused such a body, with "invalid JSON".
//
// Each consequence test starts from a running Block under default allow, offers
// a ruleset in which an Allow sits above that Block narrowed only by the unknown
// key, and requires that the request is still blocked and nothing changed.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// unkOutsider is a client the "srcIP" condition was written to EXCLUDE.
const unkOutsider = "198.51.100.7"

// widenedRulesetJSON is the ruleset whose Allow is narrowed only by a key this
// build does not have. With the key ignored the Allow matches every source.
func widenedRulesetJSON(host string) string {
	return `[{"priority":1,"name":"allow-finance","destFQDN":"` + host + `","action":"Allow","srcIP":"203.0.113.0/24"},` +
		`{"priority":2,"name":"lkg-block","destFQDN":"` + host + `","action":"Block_Page"}]`
}

// cleanRulesetJSON is the control: the same ruleset with the key spelled as
// this build spells it. It must be accepted at every door.
func cleanRulesetJSON(host string) string {
	return strings.Replace(widenedRulesetJSON(host), `"srcIP"`, `"sourceIP"`, 1)
}

// unkSetup is draftTestSetup plus the running policy every test defends: one
// Block for host under default allow. It returns the store version.
func unkSetup(t *testing.T, host string) int64 {
	t.Helper()
	draftTestSetup(t)
	prev := defaultPolicyAction()
	setDefaultPolicyAction("allow")
	refused := policyStore.rulesetRefused.Load()
	t.Cleanup(func() {
		setDefaultPolicyAction(prev)
		policyStore.rulesetRefused.Store(refused)
	})
	return lastKnownGood(t, host)
}

func strconvQuote(s string) string { return strconv.Quote(s) }

func unkAction(host string) PolicyAction {
	m := policyStore.Evaluate(unkOutsider, "", "", host, nil)
	if m == nil {
		return ""
	}
	return m.Action
}

// assertUnkStillBlocked is the acceptance check shared by every door.
func assertUnkStillBlocked(t *testing.T, door, host string, version int64) {
	t.Helper()
	if got := pol004GetNames(); got != "lkg-block" {
		t.Fatalf("%s: running policy is now %q, want lkg-block (the refusal must be whole)", door, got)
	}
	if v := storeVersion(policyStore); v != version {
		t.Errorf("%s: policy version moved %d -> %d on a refused ruleset", door, version, v)
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Fatalf("%s: a client outside the rule's source range now gets %q, want Block_Page: the ignored key widened the Allow", door, got)
	}
}

func assertUnkRefusalText(t *testing.T, door, text string) {
	t.Helper()
	for _, want := range []string{"allow-finance", `unknown field \"srcIP\"`} {
		if !strings.Contains(text, want) && !strings.Contains(text, strings.ReplaceAll(want, `\"`, `"`)) {
			t.Errorf("%s: refusal does not name %s: %s", door, want, text)
		}
	}
	if strings.ContainsAny(text, "\r") || strings.Count(text, "\n") > 1 {
		t.Errorf("%s: refusal text carries raw line breaks: %q", door, text)
	}
}

func assertUnkRow(t *testing.T, door string) {
	t.Helper()
	rows := checkPolicyRulesetRefused(policyStore)
	if len(rows) != 1 {
		t.Fatalf("%s: %d Diagnostics refusal row(s), want 1", door, len(rows))
	}
	if rows[0].Code != "policy_ruleset_refused_unenforceable_rule" || rows[0].Status != diagWarn {
		t.Errorf("%s: Diagnostics row = %s/%s", door, rows[0].Code, rows[0].Status)
	}
	if !strings.Contains(rows[0].Message, door) {
		t.Errorf("Diagnostics message lacks the door %q: %s", door, rows[0].Message)
	}
	assertUnkRefusalText(t, door, rows[0].Message)
}

// ── What the decoder calls unknown ───────────────────────────────────────────

func TestUnknownRuleField_WhatCountsAsUnknown(t *testing.T) {
	cases := []struct {
		label, body, want string // want: the recorded key, "" when none
	}{
		{"exact names", `{"name":"r","sourceIP":"10.0.0.0/8","destFQDN":"a.example.com","action":"Allow"}`, ""},
		{"case-insensitive names are the documented tolerance", `{"NAME":"r","sourceip":"10.0.0.0/8","destFqdn":"a.example.com","Action":"Allow"}`, ""},
		{"trailing space", `{"name":"r","destFQDN ":"a.example.com","action":"Allow"}`, "destFQDN "},
		{"plural typo", `{"name":"r","sourceIPs":"10.0.0.0/8","action":"Allow"}`, "sourceIPs"},
		{"a condition from a newer release", `{"name":"r","devicePosture":"managed","action":"Allow"}`, "devicePosture"},
		{"annotation", `{"name":"r","_comment":"why","action":"Allow"}`, "_comment"},
		{"nested: schedule", `{"name":"r","action":"Allow","schedule":{"days":["Mon"],"tz":"Europe/Paris"}}`, "tz"},
		{"nested: subjectMatch predicate", `{"name":"r","ruleType":"auth","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"],"negate":true}]}}`, "negate"},
		{"nested: auth spec", `{"name":"r","ruleType":"auth","auth":{"outcome":"Exempt","idpRef":"okta"}}`, "idpRef"},
		{"annotations are known and their contents are not read", `{"name":"r","action":"Allow","annotations":{"note":"why","srcIP":"x","nested":{"a":[1,{"a":1,"a":2}]}}}`, ""},
		{"server-written fields echo back", `{"name":"r","action":"Allow","id":"01J","hitCount":4,"lastHit":"2026-01-01T00:00:00Z","createdAt":"x","modifiedAt":"y","modifiedBy":"z","destCategoryGroupId":"g","fileProfileId":"f","decryptionProfileId":"d"}`, ""},
	}
	for _, tc := range cases {
		var r PolicyRule
		if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
			t.Errorf("%s: decode failed: %v (an unknown key must not fail the surrounding document)", tc.label, err)
			continue
		}
		if (tc.want == "") != (ruleAsWrittenFault(&r) == "") || !strings.Contains(ruleAsWrittenFault(&r), strings.Trim(strconvQuote(tc.want), `"`)) {
			t.Errorf("%s: recorded fault %q, want it to name %q", tc.label, ruleAsWrittenFault(&r), tc.want)
		}
		// Differential oracle: this check and encoding/json's own strict mode
		// agree, for every case, on whether the rule holds an unknown key.
		strict := json.NewDecoder(strings.NewReader(tc.body))
		strict.DisallowUnknownFields()
		var plain policyRulePlain
		serr := strict.Decode(&plain)
		if (serr != nil) != (tc.want != "") {
			t.Errorf("%s: encoding/json strict mode says %v, this check says %q", tc.label, serr, ruleAsWrittenFault(&r))
		}
		if r.Name != "r" {
			t.Errorf("%s: name = %q; the rule must still decode so it can be named", tc.label, r.Name)
		}
		ok, reason := ruleEnforceable(&r)
		if ok != (tc.want == "") {
			t.Errorf("%s: ruleEnforceable = %v (%s)", tc.label, ok, reason)
		}
		// The marker is never written anywhere.
		out, _ := json.Marshal(r)
		if strings.Contains(string(out), "decodeFault") || (tc.want != "" && strings.Contains(string(out), tc.want)) {
			t.Errorf("%s: the unknown key leaked into the encoded rule: %s", tc.label, out)
		}
	}
	// A type error is still a decode error, as it always was.
	var r PolicyRule
	if err := json.Unmarshal([]byte(`{"name":"r","priority":"one"}`), &r); err == nil {
		t.Error("a wrongly typed field decoded without error")
	}
	// Decoding onto an existing rule REPLACES it: nothing survives from what
	// the destination held, so the value is exactly what these bytes say.
	base := PolicyRule{Name: "keep", SourceIP: "10.0.0.0/8", Action: ActionAllow}
	if err := json.Unmarshal([]byte(`{"action":"Drop"}`), &base); err != nil || base.Name != "" || base.SourceIP != "" || base.Action != ActionDrop {
		t.Errorf("decode onto an existing rule kept earlier values: %+v (%v)", base, err)
	}
}

// Every unknown key is named, the list is bounded, the fault is never left
// over from an earlier decode, and a hostile key cannot forge a log line.
func TestUnknownRuleField_EveryKeyIsNamedBoundedAndNotSticky(t *testing.T) {
	var many PolicyRule
	if err := json.Unmarshal([]byte(`{"name":"r","a1":1,"action":"Allow","a2":{"deep":[1,2]},"schedule":{"a3":1}}`), &many); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleAsWrittenFault(&many), `unknown field "a1", "a2", "a3" (`) {
		t.Errorf("not every unknown key is named, in order: %q", ruleAsWrittenFault(&many))
	}
	var keys strings.Builder
	for i := range 40 {
		keys.WriteString(`,"k` + strconv.Itoa(i) + `":1`)
	}
	var flood PolicyRule
	if err := json.Unmarshal([]byte(`{"name":"r"`+keys.String()+`}`), &flood); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleAsWrittenFault(&flood), `"k7"`) || strings.Contains(ruleAsWrittenFault(&flood), `"k8"`) || !strings.Contains(ruleAsWrittenFault(&flood), "and 32 more") {
		t.Errorf("the list of keys is not bounded at %d with a count of the rest: %q", ruleKeyFaultsListed, ruleAsWrittenFault(&flood))
	}
	// The fault is about the document just decoded, never about what the
	// variable held: a clean rule decoded onto a marked one is clean.
	reused := []PolicyRule{{}}
	if err := json.Unmarshal([]byte(`[{"name":"bad","srcIP":"x"}]`), &reused); err != nil || ruleAsWrittenFault(&reused[0]) == "" {
		t.Fatalf("setup: %v %q", err, ruleAsWrittenFault(&reused[0]))
	}
	if err := json.Unmarshal([]byte(`{"name":"good","action":"Drop"}`), &reused[0]); err != nil || ruleAsWrittenFault(&reused[0]) != "" {
		t.Errorf("a clean rule decoded onto a previously marked variable kept the old fault: %q (%v)", ruleAsWrittenFault(&reused[0]), err)
	}
	// A hostile key cannot forge a log line and cannot be unbounded.
	var hostile PolicyRule
	if err := json.Unmarshal([]byte(`{"name":"x","k\nPolicy: ALLOW all `+strings.Repeat("A", 4096)+`":1}`), &hostile); err != nil {
		t.Fatal(err)
	}
	if reason := ruleAsWrittenFault(&hostile); reason == "" || strings.ContainsAny(reason, "\r\n") || len(reason) > 400 {
		t.Errorf("reason is not sanitized and bounded (%d bytes): %q", len(reason), reason)
	}
	// The view that embeds PolicyRule still decodes its own field.
	var v authRuleView
	if err := json.Unmarshal([]byte(`{"name":"a","ruleType":"auth","warnings":["w"]}`), &v); err != nil || v.Name != "a" || len(v.Warnings) != 1 || ruleAsWrittenFault(&v.PolicyRule) != "" {
		t.Errorf("authRuleView decode = %+v (%v), want name a, one warning, no unknown key", v, err)
	}
}

// ── The compatibility rule, enforced ─────────────────────────────────────────

// ruleKeysPinned is EVERY JSON key of PolicyRule and of every type reachable
// from it, as of the release that began refusing unknown rule keys. The value
// is whether the key is written into every rule (true) or omitted when unused.
//
// DO NOT add a line here without reading "THE COMPATIBILITY RULE" in
// policy_unknown_field.go. In short: a new rule key is an enforcement
// condition, and every older build refuses, whole, a ruleset (and a
// control-plane snapshot) in which a rule carries it. If what you are adding is
// not a condition — an identifier, a timestamp, provenance, display data — it
// does not get a key: put it inside "annotations".
var ruleKeysPinned = map[string]bool{
	"PolicyRule.priority": true, "PolicyRule.name": true, "PolicyRule.sourceIP": true, "PolicyRule.sourceIdentity": true,
	"PolicyRule.sourceGroup": true, "PolicyRule.authSource": true, "PolicyRule.destFQDN": true, "PolicyRule.destCategory": true,
	"PolicyRule.destCategoryGroup": true, "PolicyRule.destCountry": true, "PolicyRule.sslAction": true,
	"PolicyRule.fileFiltering": true, "PolicyRule.fileProfile": true, "PolicyRule.logFullUri": true,
	"PolicyRule.tlsSkipVerify": true, "PolicyRule.action": true, "PolicyRule.redirectURL": true, "PolicyRule.hitCount": true,
	"PolicyRule.destCategoryGroupId": false, "PolicyRule.schedule": false, "PolicyRule.fileProfileId": false,
	"PolicyRule.logTraffic": false, "PolicyRule.stripAlpn": false, "PolicyRule.decryptionProfile": false,
	"PolicyRule.decryptionProfileId": false, "PolicyRule.enabled": false, "PolicyRule.id": false, "PolicyRule.ruleType": false,
	"PolicyRule.subjectMatch": false, "PolicyRule.auth": false, "PolicyRule.lastHit": false, "PolicyRule.annotations": false,
	"PolicyRule.createdAt": false, "PolicyRule.modifiedAt": false, "PolicyRule.modifiedBy": false, "PolicyRule.comment": false,
	"PolicySchedule.days": true, "PolicySchedule.timeStart": true, "PolicySchedule.timeEnd": true, "PolicySchedule.timezone": true,
	"SubjectMatch.schemaVersion": true, "SubjectMatch.all": true,
	"SubjectPredicate.type": true, "SubjectPredicate.op": false, "SubjectPredicate.values": true,
	"AuthRuleSpec.outcome": true, "AuthRuleSpec.protocol": false, "AuthRuleSpec.method": false, "AuthRuleSpec.owner": false,
	"AuthRuleSpec.reason": false, "AuthRuleSpec.expiresAt": false, "AuthRuleSpec.broadExemption": false, "AuthRuleSpec.providerRefs": false,
}

// ruleKeysAlwaysWritten is how many of them are written into every rule. It
// must never grow: a key written into every rule makes every older node refuse
// every ruleset from the moment the writer is upgraded.
const ruleKeysAlwaysWritten = 27

// ruleKeyTypes collects, by reflection from root, every struct type whose keys
// encoding/json reads when it decodes a rule. The annotations container is not
// descended into: nothing interprets it.
func ruleKeyTypes(t *testing.T, root reflect.Type) []reflect.Type {
	t.Helper()
	var out []reflect.Type
	var visit func(reflect.Type)
	visit = func(typ reflect.Type) {
		if typ == reflect.TypeFor[*ruleAnnotations]() {
			return // the one container: nothing in it is a rule key
		}
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || slices.Contains(out, typ) {
			return
		}
		if typ != root && reflect.PointerTo(typ).Implements(reflect.TypeFor[json.Unmarshaler]()) {
			t.Errorf("%s decodes itself: its keys are invisible to the unknown-key check", typ)
		}
		out = append(out, typ)
		for i := range typ.NumField() {
			if f := typ.Field(i); f.IsExported() {
				visit(f.Type)
			}
		}
	}
	visit(root)
	return out
}

// checkRuleKeyType checks one struct type's keys against the pin and marks
// them seen. It reports whether the type holds the uninterpreted container.
func checkRuleKeyType(t *testing.T, typ reflect.Type, seen map[string]bool, rule string) (raw int) {
	t.Helper()
	// What a rule with nothing set is written as, per type: the real encoder
	// decides, so omitempty on a non-pointer struct (which never omits)
	// cannot pass as "omitted when unused".
	encoded, err := json.Marshal(reflect.New(typ).Interface())
	if err != nil {
		t.Fatalf("%s: %v", typ.Name(), err)
	}
	written := map[string]json.RawMessage{}
	if err := json.Unmarshal(encoded, &written); err != nil {
		t.Fatalf("%s: %v", typ.Name(), err)
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		tag, tagged := f.Tag.Lookup("json")
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous || !tagged || name == "" || name == "-" {
			t.Errorf("%s.%s must be a named field with an explicit json key (embedded and untagged fields change which keys a rule accepts)", typ.Name(), f.Name)
			continue
		}
		if f.Type == reflect.TypeFor[*ruleAnnotations]() {
			raw++
		}
		key := typ.Name() + "." + name
		seen[key] = true
		always, pinned := ruleKeysPinned[key]
		if !pinned {
			t.Errorf("%s is a NEW rule key. %s", key, rule)
			continue
		}
		if _, isWritten := written[name]; isWritten != always {
			t.Errorf("%s: written into an empty %s = %v, pinned as %v. A key must stay omitted when unused (or stay always written) exactly as it shipped. %s",
				key, typ.Name(), isWritten, always, rule)
		}
	}
	return raw
}

func TestRuleKeys_AreAPinnedSetAndNewOnesAreConditions(t *testing.T) {
	const rule = `Read "THE COMPATIBILITY RULE" in policy_unknown_field.go. A new rule key is an enforcement condition: every ` +
		`older build refuses, whole, a ruleset or control-plane snapshot in which a rule carries it. If this key is a ` +
		`condition, make it omitted when unused and pin it as false in ruleKeysPinned. If it is anything else (an id, a ` +
		`timestamp, provenance, display data), it must not be a rule key: put it inside "annotations".`
	seen := map[string]bool{}
	raw := 0
	for _, typ := range ruleKeyTypes(t, reflect.TypeFor[PolicyRule]()) {
		raw += checkRuleKeyType(t, typ, seen, rule)
	}
	always := 0
	for key, isAlways := range ruleKeysPinned {
		if isAlways {
			always++
		}
		if !seen[key] {
			t.Errorf("%s is pinned but no longer exists. Removing or renaming a rule key makes every stored ruleset and every "+
				"snapshot that carries it refused by this build; keep the key.", key)
		}
	}
	if always != ruleKeysAlwaysWritten {
		t.Errorf("%d rule keys are pinned as written into every rule, want %d: that set must never grow. %s", always, ruleKeysAlwaysWritten, rule)
	}
	if raw != 1 || ruleKeysPinned["PolicyRule."+ruleAnnotationsKey] {
		t.Errorf("exactly one uninterpreted container is expected (PolicyRule.%s, omitted when empty); found %d", ruleAnnotationsKey, raw)
	}
}

// The container: carried verbatim through every stored and published form,
// never interpreted, bounded.
func TestRuleKeys_AnnotationsAreCarriedVerbatimNeverInterpretedAndBounded(t *testing.T) {
	const host = "unk-ann.example.com"
	unkSetup(t, host)
	// A newer node's stamp and a hand-editor's note. The contents LOOK like
	// conditions and like faults; none of it is read.
	const ann = `{"note":"finance VPN only","culvert.io/origin":{"node":"cp-2","rev":7},"sourceIP":"203.0.113.0/24","action":"Allow","action":"Drop"}`
	file := filepath.Join(t.TempDir(), "policy.json")
	body := `[{"priority":1,"name":"annotated","destFQDN":"` + host + `","action":"Block_Page","annotations":` + ann + `}]`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyStore.Load(file); err != nil {
		t.Fatalf("a rule with annotations was refused: %v", err)
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Errorf("annotations changed the decision: %q, want Block_Page for every source", got)
	}
	want := new(bytes.Buffer)
	if err := json.Compact(want, []byte(ann)); err != nil {
		t.Fatal(err)
	}
	// Store → API list, policy file on disk, snapshot, stored version / export.
	listed := policyStore.List()
	if err := policyStore.SaveErr(); err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(file)
	snap, _ := json.Marshal(ConfigSnapshot{Version: 1, PolicyRules: listed})
	backup, _ := json.Marshal(configBackup{Version: 1, PolicyRules: listed})
	for form, data := range map[string][]byte{"policy file": onDisk, "snapshot": snap, "config backup": backup} {
		compact := new(bytes.Buffer)
		if err := json.Compact(compact, data); err != nil || !bytes.Contains(compact.Bytes(), want.Bytes()) {
			t.Errorf("%s does not carry the annotations verbatim:\n%s", form, data)
		}
	}
	// …and back in through each: still there, still clean.
	var again ConfigSnapshot
	if err := json.Unmarshal(snap, &again); err != nil || validateConfigSnapshot(again) != nil || !bytes.Equal(again.PolicyRules[0].Annotations.raw, want.Bytes()) {
		t.Errorf("annotations did not survive a snapshot round trip: %v / %v / %s", err, validateConfigSnapshot(again), again.PolicyRules[0].Annotations.raw)
	}
	// A rule without them writes no key at all, and null is the same as absent.
	var bare PolicyRule
	if err := json.Unmarshal([]byte(`{"name":"bare","action":"Drop","annotations":null}`), &bare); err != nil || ruleAsWrittenFault(&bare) != "" {
		t.Fatalf("annotations:null: %v %q", err, ruleAsWrittenFault(&bare))
	}
	if out, _ := json.Marshal(bare); bytes.Contains(out, []byte(ruleAnnotationsKey)) {
		t.Errorf("an unannotated rule writes the key: %s", out)
	}
	// Bounds (CWE-770), and the container must be an object.
	deep := strings.Repeat(`{"a":`, ruleAnnotationsMaxDepth) + `1` + strings.Repeat(`}`, ruleAnnotationsMaxDepth)
	for label, tc := range map[string]struct {
		value string
		ok    bool
	}{
		"at the depth limit":   {deep, true},
		"one level too deep":   {`{"a":` + deep + `}`, false},
		"brackets in a string": {`{"a":"` + strings.Repeat(`[{\"`, 40) + `"}`, true},
		"at the size limit":    {`{"a":"` + strings.Repeat("x", ruleAnnotationsMaxBytes-8) + `"}`, true},
		"one byte too large":   {`{"a":"` + strings.Repeat("x", ruleAnnotationsMaxBytes-7) + `"}`, false},
		"a string":             {`"note"`, false},
		"an array":             {`[1]`, false},
	} {
		var r PolicyRule
		if err := json.Unmarshal([]byte(`{"name":"b","action":"Drop","annotations":`+tc.value+`}`), &r); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if ok, reason := ruleEnforceable(&r); ok != tc.ok || (!ok && !strings.Contains(reason, ruleAnnotationsKey)) {
			t.Errorf("%s: enforceable=%v (%s), want %v", label, ok, reason, tc.ok)
		}
	}
	// The API takes the key, and returns it.
	w := httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", `{"priority":5,"name":"api-annotated","destFQDN":"x.`+host+`","action":"Drop","sslAction":"Inspect","annotations":{"ticket":"SEC-1"}}`))
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("POST with annotations: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodGet, "/api/policy", ""))
	if !strings.Contains(w.Body.String(), `"annotations":{"ticket":"SEC-1"}`) {
		t.Errorf("GET does not return the annotations: %s", w.Body.String())
	}
}

// ── Duplicate keys ───────────────────────────────────────────────────────────

// dupRulesetJSON: the Allow's source range is given, then given again, empty,
// under another spelling of the same key. encoding/json keeps the last.
func dupRulesetJSON(host string) string {
	return `[{"priority":1,"name":"allow-finance","destFQDN":"` + host + `","action":"Allow","sourceIP":"203.0.113.0/24","sourceip":""},` +
		`{"priority":2,"name":"lkg-block","destFQDN":"` + host + `","action":"Block_Page"}]`
}

func TestRuleKeys_DuplicateKeyIsRefusedAtEveryDoorClass(t *testing.T) {
	bindFreshAdmissionOwners(t)
	const host = "unk-dup.example.com"
	version := unkSetup(t, host)
	wantText := func(door, text string) {
		t.Helper()
		if !strings.Contains(text, "allow-finance") || !strings.Contains(strings.ReplaceAll(text, `\"`, `"`), `duplicate field "sourceIP" and "sourceip"`) {
			t.Errorf("%s: refusal does not name the rule and both spellings: %s", door, text)
		}
	}
	// Persisted: the policy file.
	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, []byte(dupRulesetJSON(host)), 0o600); err != nil {
		t.Fatal(err)
	}
	err := policyStore.Load(file)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Fatalf("Load returned %v, want an unenforceableRuleError", err)
	}
	wantText("policy file", err.Error())
	assertUnkStillBlocked(t, "policy file", host, version)
	// Operator: single rule and import.
	one := `{"priority":7,"name":"allow-finance","destFQDN":"` + host + `","action":"Allow","sslAction":"Inspect","sourceIP":"203.0.113.0/24","sourceip":""}`
	w := httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", one))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/policy: %d %s, want 400", w.Code, w.Body.String())
	}
	wantText("POST /api/policy", w.Body.String())
	w = httptest.NewRecorder()
	apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?mode=replace", `{"version":1,"policyRules":`+dupRulesetJSON(host)+`}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("import: %d %s, want 400", w.Code, w.Body.String())
	}
	wantText("import", w.Body.String())
	assertUnkStillBlocked(t, "operator doors", host, version)
	// Wire.
	var snap ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":1099511627776,"policy_rules":`+dupRulesetJSON(host)+`}`), &snap); err != nil {
		t.Fatal(err)
	}
	if err := applyConfigSnapshot(snap); !errors.As(err, &ue) {
		t.Fatalf("applyConfigSnapshot returned %v, want an unenforceableRuleError", err)
	}
	assertUnkStillBlocked(t, "control-plane snapshot", host, version)

	// Every form of "the same field twice", and the forms that are not.
	for label, tc := range map[string]struct {
		body string
		dup  bool
	}{
		"same spelling":            {`{"name":"r","action":"Drop","action":"Allow"}`, true},
		"nested: schedule":         {`{"name":"r","action":"Drop","schedule":{"timezone":"UTC","timeZone":"Europe/Paris"}}`, true},
		"nested: predicate":        {`{"name":"r","ruleType":"auth","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"],"values":[]}]}}`, true},
		"the whole nested object":  {`{"name":"r","action":"Drop","schedule":{"days":["Mon"]},"schedule":null}`, true},
		"two predicates, one each": {`{"name":"r","ruleType":"auth","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]},{"type":"cidr","values":["10.1.0.0/16"]}]}}`, false},
		"same name at two levels":  {`{"name":"r","action":"Drop","annotations":{"name":"x","action":"y"}}`, false},
		"an unknown key twice":     {`{"name":"r","action":"Drop","zz":1,"zz":2}`, false},
	} {
		var r PolicyRule
		if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := strings.Contains(ruleAsWrittenFault(&r), "duplicate field"); got != tc.dup {
			t.Errorf("%s: duplicate reported = %v, want %v (%q)", label, got, tc.dup, ruleAsWrittenFault(&r))
		}
	}
	// Control: the same ruleset with the key given once loads, and scopes.
	clean := strings.Replace(dupRulesetJSON(host), `,"sourceip":""`, "", 1)
	if err := os.WriteFile(file, []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyStore.Load(file); err != nil || pol004GetNames() != "allow-finance,lkg-block" {
		t.Fatalf("control: clean file not loaded: %v (%s)", err, pol004GetNames())
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Errorf("control: outsider gets %q, want Block_Page", got)
	}
}

// ── The remaining doors, driven through their real entry points ──────────────

func TestRuleKeys_FetchAndApplyAndDeltaRemainderRefuseAndTheCleanSnapshotApplies(t *testing.T) {
	bindFreshAdmissionOwners(t)
	resetConfigSnapshotApplyHealth(t)
	t.Cleanup(resetDPLastSeenEpochForTest())
	restoreBlAndIPF(t)
	const host = "unk-fetch.example.com"
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	version := unkSetup(t, host)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	lastGood := dpLastGoodConfigSnapshotState.Load()
	t.Cleanup(func() {
		dataDir = oldDataDir
		if lastGood == nil {
			lastGood = dpLastGoodConfigSnapshotStatus{}
		}
		dpLastGoodConfigSnapshotState.Store(lastGood)
	})
	serve := func(c *DataPlaneClient, body string) {
		c.callForTest = func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(body), nil
		}
	}
	for label, rules := range map[string]string{"unknown key": widenedRulesetJSON(host), "duplicate key": dupRulesetJSON(host)} {
		// Full snapshot, as the data plane polls it.
		c := &DataPlaneClient{}
		c.lastVersion.Store(0)
		serve(c, `{"version":5,"default_action":"allow","policy_rules":`+rules+`}`)
		markConfigSnapshotApplyOK()
		c.fetchAndApply(context.Background())
		if lastConfigSnapshotApplyOK() || c.lastVersion.Load() != 0 {
			t.Errorf("%s: fetchAndApply accepted the snapshot (apply ok=%v, lastVersion=%d)", label, lastConfigSnapshotApplyOK(), c.lastVersion.Load())
		}
		assertUnkStillBlocked(t, "fetchAndApply, "+label, host, version)
		if rows := checkPolicyRulesetRefused(policyStore); len(rows) != 1 || !strings.Contains(rows[0].Message, rulesetDoorSnapshot) {
			t.Errorf("%s: fetchAndApply left no snapshot refusal row: %+v", label, rows)
		}
		// Delta: the non-blocklist remainder carries the rules.
		d := &DataPlaneClient{}
		d.lastVersion.Store(7)
		markConfigSnapshotApplyOK()
		applied := d.applyDeltaReply(getConfigDeltaReply{BaseVersion: 7, TargetVersion: 8,
			Remainder: json.RawMessage(`{"version":8,"policy_rules":` + rules + `}`)})
		if applied || lastConfigSnapshotApplyOK() || d.lastVersion.Load() != 7 {
			t.Errorf("%s: applyDeltaReply accepted the remainder (applied=%v, apply ok=%v, lastVersion=%d)", label, applied, lastConfigSnapshotApplyOK(), d.lastVersion.Load())
		}
		assertUnkStillBlocked(t, "delta remainder, "+label, host, version)
	}
	// Control: the correctly spelt snapshot IS applied through the same path.
	c := &DataPlaneClient{}
	c.lastVersion.Store(0)
	serve(c, `{"version":6,"default_action":"allow","future_section":{"a":1},"policy_rules":`+cleanRulesetJSON(host)+`}`)
	c.fetchAndApply(context.Background())
	if !lastConfigSnapshotApplyOK() || c.lastVersion.Load() != 6 || pol004GetNames() != "allow-finance,lkg-block" {
		t.Fatalf("control: a clean snapshot with an unknown section was not applied (ok=%v, lastVersion=%d, rules %q)",
			lastConfigSnapshotApplyOK(), c.lastVersion.Load(), pol004GetNames())
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Errorf("control: outsider gets %q under the correctly scoped Allow, want Block_Page", got)
	}
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("refusal row still present after an applied snapshot: %+v", rows)
	}
}

// A last-known-good snapshot the gate refuses at data-plane startup is a
// Diagnostics row under its own door, not only a log line.
func TestRuleKeys_RefusedLastGoodSnapshotAtBootIsADiagnosticsRow(t *testing.T) {
	bindFreshAdmissionOwners(t)
	const host = "unk-lkg.example.com"
	version := unkSetup(t, host)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	lastGood := dpLastGoodConfigSnapshotState.Load()
	t.Cleanup(func() {
		dataDir = oldDataDir
		if lastGood == nil {
			lastGood = dpLastGoodConfigSnapshotStatus{}
		}
		dpLastGoodConfigSnapshotState.Store(lastGood)
	})
	if err := os.WriteFile(dpLastGoodConfigSnapshotPath(), []byte(`{"version":9,"policy_rules":`+widenedRulesetJSON(host)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// As startDataPlaneEnrollment does at boot.
	_, err := applyDPLastGoodConfigSnapshot()
	if err == nil {
		t.Fatal("a last-good snapshot holding an unknown rule key was applied")
	}
	logDPLastGoodUnavailable(err)
	assertUnkStillBlocked(t, rulesetDoorLastGood, host, version)
	assertUnkRow(t, rulesetDoorLastGood)
	// It is retired by the next snapshot the node applies, with or without a policy section.
	policyStore.clearSnapshotRulesetRefusals()
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("the row was not retired: %+v", rows)
	}
	// Controls: any other failure is logged as before and records nothing;
	// and the boot path really calls this (dp_enrollment.go).
	logDPLastGoodUnavailable(errors.New("unexpected end of JSON input"))
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("a non-gate failure produced a ruleset-refusal row: %+v", rows)
	}
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "dp_enrollment.go"))
	if err != nil || !bytes.Contains(src, []byte("logDPLastGoodUnavailable(err)")) {
		t.Errorf("dp_enrollment.go no longer reports a refused last-good snapshot through logDPLastGoodUnavailable (%v)", err)
	}
}

// At startup no policy is running, so the fatal error must not say one is unchanged.
func TestRuleKeys_StartupFatalDoesNotClaimARunningPolicy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, []byte(widenedRulesetJSON("s.example.com")), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}
	err := ps.Load(file)
	if err == nil || !strings.HasSuffix(err.Error(), rulesetRefusedRunningUnchanged) {
		t.Fatalf("Load error %v does not end with the clause startupPolicyFileError rewrites", err)
	}
	msg := startupPolicyFileError(err, file)
	for _, want := range []string{"allow-finance", `"srcIP"`, ruleAnnotationsKey, "did not start", "culvert policy-check " + file} {
		if !strings.Contains(strings.ReplaceAll(msg, `\"`, `"`), want) {
			t.Errorf("startup message lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "running policy is unchanged") {
		t.Errorf("startup message claims a running policy: %s", msg)
	}
	if got := startupPolicyFileError(errors.New("unexpected end of JSON input"), file); !strings.Contains(got, "unexpected end of JSON input") {
		t.Errorf("a malformed file's own error is lost: %s", got)
	}
}

// ── Operator doors ───────────────────────────────────────────────────────────

func TestUnknownRuleField_SingleRuleAPIRefusesByNameAndChangesNothing(t *testing.T) {
	const host = "unk-api.example.com"
	version := unkSetup(t, host)
	seq := configVersions.Seq()
	bad := `{"priority":7,"name":"allow-finance","destFQDN":"` + host + `","action":"Allow","sslAction":"Inspect","srcIP":"203.0.113.0/24"}`
	lkg := policyStore.List()[0]

	doors := map[string]func() *httptest.ResponseRecorder{
		"POST /api/policy": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", bad))
			return w
		},
		"PUT /api/policy?priority": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicy(w, adminRequest(http.MethodPut, "/api/policy?priority=1", bad))
			return w
		},
		"PUT /api/policy?id": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicy(w, adminRequest(http.MethodPut, "/api/policy?id="+lkg.ID, bad))
			return w
		},
		"POST /api/authpolicy": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiAuthPolicy(w, adminRequest(http.MethodPost, "/api/authpolicy", bad))
			return w
		},
		"PUT /api/authpolicy": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiAuthPolicy(w, adminRequest(http.MethodPut, "/api/authpolicy?priority=1", bad))
			return w
		},
	}
	for door, call := range doors {
		w := call()
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400; body: %s", door, w.Code, w.Body.String())
			continue
		}
		assertUnkRefusalText(t, door, w.Body.String())
		if !strings.Contains(w.Body.String(), "Nothing was changed") {
			t.Errorf("%s: refusal does not say that nothing was changed: %s", door, w.Body.String())
		}
		assertUnkStillBlocked(t, door, host, version)
	}
	if got := configVersions.Seq(); got != seq {
		t.Errorf("a refused rule write created config version %d (was %d)", got, seq)
	}
	// Unique content, not a length delta: the audit ring is bounded.
	for _, e := range auditGet() {
		if e.Object == "allow-finance" {
			t.Errorf("a refused rule write was audited: %+v", e)
		}
	}
	// Control: a body that is not a rule at all is still "invalid JSON".
	w := httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", `{"name":`))
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != "invalid JSON" {
		t.Errorf("malformed body: %d %q, want 400 invalid JSON", w.Code, w.Body.String())
	}
	// Control: the same rule with the key spelled correctly is created.
	w = httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", strings.NewReplacer(`"srcIP"`, `"sourceIP"`, "allow-finance", "allow-finance-ok").Replace(bad)))
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("control: correctly spelled rule refused: %d %s", w.Code, w.Body.String())
	}
	if got := pol004GetNames(); got != "lkg-block,allow-finance-ok" {
		t.Errorf("control: running policy is %q, want lkg-block,allow-finance-ok", got)
	}
}

// What the server returns for a rule is accepted back unchanged, at both
// addressing forms, and so are the exact bodies each admin UI builds. This is
// the way strict rejection would most plausibly break the product.
func TestUnknownRuleField_GetThenPutRoundTripsThroughTheRealHandlers(t *testing.T) {
	const host = "unk-rt.example.com"
	unkSetup(t, host)
	logTraffic, strip, enabled := false, false, true
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "full", SourceIP: "10.0.0.0/8", SourceIdentity: "alice", SourceGroup: "eng",
		AuthSource: "local", DestFQDN: host, SSLAction: SSLInspect, LogFullURI: true,
		Schedule:   &PolicySchedule{Timezone: "UTC"},
		LogTraffic: &logTraffic, StripALPN: &strip, Enabled: &enabled, Action: ActionBlockPage, Comment: "why",
		CreatedAt: "2026-01-01T00:00:00Z", ModifiedAt: "2026-01-02T00:00:00Z", ModifiedBy: "admin"}})
	policyStore.Evaluate("10.1.2.3", "alice", "local", host, []string{"eng"}) // a hit, so hitCount/lastHit are set

	get := func(path string, handler http.HandlerFunc) []json.RawMessage {
		t.Helper()
		w := httptest.NewRecorder()
		handler(w, adminRequest(http.MethodGet, path, ""))
		var body struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Rules) == 0 {
			t.Fatalf("GET %s: %d %s (%v)", path, w.Code, w.Body.String(), err)
		}
		return body.Rules
	}
	put := func(label, path string, handler http.HandlerFunc, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		handler(w, adminRequest(http.MethodPut, path, body))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200; body: %s", label, w.Code, w.Body.String())
		}
	}

	echoed := get("/api/policy", apiPolicy)[0]
	for _, key := range []string{`"hitCount":1`, `"lastHit"`, `"id"`, `"createdAt"`, `"modifiedBy"`} {
		if !bytes.Contains(echoed, []byte(key)) {
			t.Fatalf("GET /api/policy does not return %s, so the round trip below proves less than it claims: %s", key, echoed)
		}
	}
	var got PolicyRule
	if err := json.Unmarshal(echoed, &got); err != nil {
		t.Fatal(err)
	}
	put("GET→PUT ?priority, body exactly as returned", "/api/policy?priority=1", apiPolicy, string(echoed))
	put("GET→PUT ?id, body exactly as returned", "/api/policy?id="+got.ID, apiPolicy, string(echoed))
	if rules := policyStore.List(); len(rules) != 1 || rules[0].SourceIP != "10.0.0.0/8" || rules[0].Schedule == nil || rules[0].Action != ActionBlockPage {
		t.Errorf("the rule did not survive its own round trip: %+v", rules)
	}

	// static/index.html polReadForm, every key it sends.
	legacy := `{"priority":1,"name":"full","action":"Block_Page","sourceIP":"10.0.0.0/8","sourceIdentity":"alice","sourceGroup":"eng",` +
		`"authSource":"local","redirectURL":"","destFQDN":"` + host + `","destCategory":"","destCategoryGroup":"","destCountry":["US"],` +
		`"sslAction":"Inspect","enabled":true,"fileFiltering":false,"fileProfile":"","decryptionProfile":"","tlsSkipVerify":false,` +
		`"logFullUri":true,"logTraffic":true,"schedule":{"days":[],"timeStart":"","timeEnd":"","timezone":"UTC"},"comment":"why"}`
	put("legacy UI body", "/api/policy?id="+got.ID, apiPolicy, legacy)
	// frontend/src/api/policyWrite.ts serializeAccessRuleWrite, every key it can send.
	react := `{"name":"full","sourceIP":"10.0.0.0/8","sourceIdentity":"alice","sourceGroup":"eng","authSource":"local","destFQDN":"` + host + `",` +
		`"destCategory":"","destCategoryGroup":"","destCountry":["US"],"sslAction":"Inspect","fileFiltering":false,"fileProfile":"",` +
		`"logFullUri":true,"tlsSkipVerify":false,"decryptionProfile":"","action":"Block_Page","redirectURL":"","comment":"why",` +
		`"enabled":true,"logTraffic":false,"stripAlpn":false,"schedule":{"days":[],"timeStart":"","timeEnd":"","timezone":"UTC"},"ruleType":"access"}`
	put("React UI body", "/api/policy?id="+got.ID, apiPolicy, react)

	// Auth rules: the body both UIs build, then the documented limit of the
	// round trip. GET /api/authpolicy adds "warnings", which is not a rule key.
	authBody := `{"name":"exempt-updates","ruleType":"auth","enabled":true,"subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]},` +
		`"destFQDN":"updates.example.com","destCategory":"","destCategoryGroup":"","comment":"",` +
		`"auth":{"outcome":"Exempt","owner":"secops","reason":"os updates","expiresAt":"","protocol":"","method":"","broadExemption":false}}`
	w := httptest.NewRecorder()
	apiAuthPolicy(w, adminRequest(http.MethodPost, "/api/authpolicy", authBody))
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("auth rule body as the UIs send it: %d %s", w.Code, w.Body.String())
	}
	view := get("/api/authpolicy", apiAuthPolicy)[0]
	var auth PolicyRule
	if err := json.Unmarshal(view, &auth); err != nil {
		t.Fatal(err)
	}
	withoutWarnings := map[string]json.RawMessage{}
	if err := json.Unmarshal(view, &withoutWarnings); err != nil {
		t.Fatal(err)
	}
	_, hadWarnings := withoutWarnings["warnings"]
	delete(withoutWarnings, "warnings")
	stripped, _ := json.Marshal(withoutWarnings)
	put("auth GET→PUT, rule as returned minus the view-only warnings", "/api/authpolicy?id="+auth.ID, apiAuthPolicy, string(stripped))
	if hadWarnings {
		// Unchanged behaviour, stated: the view's "warnings" is not a rule key
		// and echoing it was already a 400 before this change. Neither UI does.
		w = httptest.NewRecorder()
		apiAuthPolicy(w, adminRequest(http.MethodPut, "/api/authpolicy?id="+auth.ID, string(view)))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "warnings") {
			t.Errorf("auth view echoed with warnings: %d %s, want a 400 naming warnings", w.Code, w.Body.String())
		}
	}
}

func TestUnknownRuleField_ImportIsRefusedInEveryModeAndNamesTheRule(t *testing.T) {
	const host = "unk-import.example.com"
	version := unkSetup(t, host)
	body := `{"version":1,"defaultAction":"deny","policyRules":` + widenedRulesetJSON(host) + `}`
	for _, q := range []string{"mode=merge", "mode=replace", "mode=merge&dryRun=true", "mode=replace&dryRun=true"} {
		w := httptest.NewRecorder()
		apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?"+q, body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("import %s: status %d, want 400; body: %s", q, w.Code, w.Body.String())
			continue
		}
		assertUnkRefusalText(t, "import "+q, w.Body.String())
		if got := defaultPolicyAction(); got != "allow" {
			t.Errorf("import %s: default action is %q after a refused import (partial apply)", q, got)
		}
		assertUnkStillBlocked(t, "import "+q, host, version)
	}
	// An unknown key on the backup ENVELOPE was and stays a plain 400: a backup
	// is a supported schema this build either knows whole or does not.
	w := httptest.NewRecorder()
	apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?mode=merge&dryRun=true", `{"version":1,"futureSection":[]}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown backup section: status %d, want 400 (unchanged)", w.Code)
	}
	// Control: the correctly spelled ruleset previews cleanly.
	w = httptest.NewRecorder()
	apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?mode=replace&dryRun=true",
		`{"version":1,"policyRules":`+cleanRulesetJSON(host)+`}`))
	if w.Code != http.StatusOK {
		t.Errorf("control: clean import preview refused: %d %s", w.Code, w.Body.String())
	}
}

// ── Persisted doors ──────────────────────────────────────────────────────────

func TestUnknownRuleField_PolicyFileIsRefusedAtLoadReloadAndStartup(t *testing.T) {
	const host = "unk-file.example.com"
	version := unkSetup(t, host)
	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, []byte(widenedRulesetJSON(host)), 0o600); err != nil {
		t.Fatal(err)
	}
	err := policyStore.Load(file)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) || ue.Name != "allow-finance" || ue.Count != 1 {
		t.Fatalf("Load returned %v, want an unenforceableRuleError naming allow-finance once", err)
	}
	assertUnkRefusalText(t, "policy file", err.Error())
	assertUnkStillBlocked(t, "policy file", host, version)
	assertUnkRow(t, "policy file")
	if hotReloadPolicyFile(file) {
		t.Error("reload reports the new default action may be applied after refusing the policy file")
	}
	assertUnkStillBlocked(t, "policy file reload", host, version)
	// Startup: a fresh store gets an error and no rules, which initPolicy makes fatal.
	fresh := &PolicyStore{}
	if err := fresh.Load(file); err == nil || len(fresh.List()) != 0 {
		t.Fatalf("a fresh store loaded a file with an unknown rule key: err=%v rules=%d", err, len(fresh.List()))
	}
	// Control: the correctly spelled file loads and its scoped Allow does not
	// reach the outsider.
	if err := os.WriteFile(file, []byte(cleanRulesetJSON(host)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyStore.Load(file); err != nil || pol004GetNames() != "allow-finance,lkg-block" {
		t.Fatalf("control: clean file not loaded: %v (%s)", err, pol004GetNames())
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Errorf("control: outsider gets %q under the correctly scoped Allow, want Block_Page", got)
	}
	if m := policyStore.Evaluate("203.0.113.9", "", "", host, nil); m == nil || m.Action != ActionAllow {
		t.Errorf("control: a client inside the range is not allowed: %+v", m)
	}
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("refusal row still present after an accepted file: %+v", rows)
	}
}

func TestUnknownRuleField_StoredVersionAndPendingDraftAreRefused(t *testing.T) {
	const host = "unk-stored.example.com"
	version := unkSetup(t, host)

	raw := []byte(`{"version":1,"defaultAction":"deny","policyRules":` + widenedRulesetJSON(host) + `}`)
	target, err := configVersions.Save("test", "test.unknown-field", "2026-01-01T00:00:00Z", raw)
	if err != nil {
		t.Fatalf("seed stored version: %v", err)
	}
	seq := configVersions.Seq()
	rec := postRollback(t, target)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rollback status %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertUnkRefusalText(t, "rollback", rec.Body.String())
	if configVersions.Seq() != seq || defaultPolicyAction() != "allow" {
		t.Errorf("a refused rollback changed state: seq %d (was %d), default action %q", configVersions.Seq(), seq, defaultPolicyAction())
	}
	assertUnkStillBlocked(t, "rollback", host, version)

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	draft := `{"state":{"active":true,"actor":"admin"},"rules":` + widenedRulesetJSON(host) + `}`
	if err := os.WriteFile(policyDraftPathFor(policyPath), []byte(draft), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := policyDraft
	policyDraft = &policyDraftCoordinator{cand: &PolicyStore{}}
	t.Cleanup(func() { policyDraft = orig })
	initPolicyDraft(policyPath)
	if policyDraft.active() || len(policyDraft.candidateList()) != 0 {
		t.Fatalf("a pending draft holding an unknown rule key was reloaded (active=%v, %d rules)", policyDraft.active(), len(policyDraft.candidateList()))
	}
	assertUnkRow(t, "pending policy draft")
	assertUnkStillBlocked(t, "pending policy draft", host, version)

	// Controls: the correctly spelt draft is reloaded, and the correctly spelt
	// version is restored, with the Allow scoped as written.
	if err := os.WriteFile(policyDraftPathFor(policyPath), []byte(strings.Replace(draft, `"srcIP"`, `"sourceIP"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	policyDraft = &policyDraftCoordinator{cand: &PolicyStore{}}
	initPolicyDraft(policyPath)
	if !policyDraft.active() || len(policyDraft.candidateList()) != 2 {
		t.Errorf("control: a clean pending draft was not reloaded (active=%v, %d rules)", policyDraft.active(), len(policyDraft.candidateList()))
	}
	policyDraft = &policyDraftCoordinator{cand: &PolicyStore{}}
	clean, err := configVersions.Save("test", "test.clean", "2026-01-01T00:00:00Z", []byte(`{"version":1,"policyRules":`+cleanRulesetJSON(host)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	if rec := postRollback(t, clean); rec.Code != http.StatusOK || pol004GetNames() != "allow-finance,lkg-block" {
		t.Fatalf("control: a clean stored version was not restored: %d %s (rules %q)", rec.Code, rec.Body.String(), pol004GetNames())
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Errorf("control: outsider gets %q under the restored, correctly scoped Allow", got)
	}
}

// ── Wire doors ───────────────────────────────────────────────────────────────

func TestUnknownRuleField_SnapshotIsRefusedBeforeAnyMutationAndTheEnvelopeStaysTolerant(t *testing.T) {
	bindFreshAdmissionOwners(t) // the apply path mutates ipf and rl in place
	const host = "unk-wire.example.com"
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	version := unkSetup(t, host)
	setDefaultPolicyAction("deny")

	// As fetchAndApply reads it: bytes from the control plane into a ConfigSnapshot.
	wire := `{"version":1099511627776,"default_action":"allow","policy_rules":` + widenedRulesetJSON(host) + `}`
	var snap ConfigSnapshot
	if err := json.Unmarshal([]byte(wire), &snap); err != nil {
		t.Fatalf("a snapshot whose rule has an unknown key failed to DECODE (%v); it must decode and be refused by the gate, so the node reports it", err)
	}
	err := applyConfigSnapshot(snap)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Fatalf("applyConfigSnapshot returned %v, want an unenforceableRuleError", err)
	}
	if got := defaultPolicyAction(); got != "deny" {
		t.Errorf("default action is %q after a refused snapshot, want deny (partial apply)", got)
	}
	setDefaultPolicyAction("allow")
	assertUnkStillBlocked(t, "control-plane snapshot", host, version)
	assertUnkRow(t, "control-plane snapshot")

	// The same gate guards the HA bundle and the data plane's last-good file.
	var bundle HAStateBundle
	if err := json.Unmarshal([]byte(`{"config":`+wire+`}`), &bundle); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigSnapshot(bundle.Config); !errors.As(err, &ue) {
		t.Errorf("HA bundle config: validateConfigSnapshot = %v, want an unenforceableRuleError", err)
	}
	origDir := dataDir
	dataDir = t.TempDir()
	lastGood := dpLastGoodConfigSnapshotState.Load()
	t.Cleanup(func() {
		dataDir = origDir
		if lastGood == nil {
			lastGood = dpLastGoodConfigSnapshotStatus{}
		}
		dpLastGoodConfigSnapshotState.Store(lastGood)
	})
	if err := os.WriteFile(dpLastGoodConfigSnapshotPath(), []byte(wire), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDPLastGoodConfigSnapshot(); !errors.As(err, &ue) {
		t.Errorf("last-good snapshot: load = %v, want an unenforceableRuleError", err)
	}

	// Forward compatibility is untouched everywhere EXCEPT inside a rule: a
	// newer control plane's unknown top-level section, and an unknown key on an
	// object that is not a rule, are ignored as before.
	var nonRule ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":1,"url_categories":[{"name":"c","hosts":["h.example.com"],"futureKey":true}]}`), &nonRule); err != nil || validateConfigSnapshot(nonRule) != nil {
		t.Errorf("an unknown key on a non-rule object was not tolerated: %v / %v", err, validateConfigSnapshot(nonRule))
	}
	newer := `{"version":1099511627777,"default_action":"allow","future_section":{"a":1},"policy_rules":` + cleanRulesetJSON(host) + `}`
	var ok ConfigSnapshot
	if err := json.Unmarshal([]byte(newer), &ok); err != nil {
		t.Fatalf("a snapshot with an unknown section failed to decode: %v", err)
	}
	if err := applyConfigSnapshot(ok); err != nil || pol004GetNames() != "allow-finance,lkg-block" {
		t.Fatalf("a snapshot with an unknown top-level section and a clean ruleset was not applied: %v (rules %q)", err, pol004GetNames())
	}
	if got := unkAction(host); got != ActionBlockPage {
		t.Errorf("control: outsider gets %q under the applied, correctly scoped Allow", got)
	}
	// A snapshot this build publishes never carries an unknown key: it is
	// encoded from the typed rules, so it round-trips through the gate.
	out, err := json.Marshal(ConfigSnapshot{Version: 1, PolicyRules: ok.PolicyRules})
	if err != nil {
		t.Fatal(err)
	}
	var again ConfigSnapshot
	if err := json.Unmarshal(out, &again); err != nil || validateConfigSnapshot(again) != nil {
		t.Errorf("a snapshot encoded by this build did not pass its own gate: %v / %v", err, validateConfigSnapshot(again))
	}
}

// ── Preflight, and what is deliberately unchanged ────────────────────────────

func TestUnknownRuleField_PreflightListsEveryRuleAndPOL004IsUntouched(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	policy := write("policy.json", `[{"priority":1,"name":"typo","destFQDN ":"a.example.com","action":"Allow"},
{"priority":2,"name":"ok","destFqdn":"b.example.com","action":"Allow"},
{"priority":3,"name":"noted","_comment":"x","action":"Drop"}]`)
	backup := write("backup.json", `{"version":1,"policyRules":[{"priority":1,"name":"newer","devicePosture":"managed","action":"Allow"}]}`)
	stored := write("stored.json", `{"meta":{"version":3},"config":{"version":1,"policyRules":[{"priority":1,"name":"sched","action":"Drop","schedule":{"tz":"UTC"}}]}}`)
	var out, errb bytes.Buffer
	code := runPolicyPreflight([]string{policy, backup, stored}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stdout %q stderr %q", code, out.String(), errb.String())
	}
	for _, want := range []string{`rule #1 "typo"`, `"destFQDN "`, `rule #3 "noted"`, `"_comment"`, `"newer"`, `"devicePosture"`, `"sched"`, `"tz"`, "2 of 3 rule(s)"} {
		if !strings.Contains(out.String(), want) && !strings.Contains(out.String(), strings.ReplaceAll(want, `"`, `\"`)) {
			t.Errorf("preflight output lacks %s:\n%s", want, out.String())
		}
	}
	// A control-plane snapshot (the data plane's last-good file) and an HA
	// bundle hold rules under "policy_rules"; they used to read as a backup
	// with no rules and print OK.
	snapBad := write("dp_last_config_snapshot.json", `{"version":7,"policy_rules":[{"priority":1,"name":"wire","srcIP":"10.0.0.0/8","action":"Allow"}]}`)
	bundleBad := write("bundle.json", `{"config":{"version":7,"policy_rules":[{"priority":1,"name":"dup","action":"Drop","action":"Allow"}]}}`)
	snapGood := write("snap-good.json", `{"version":7,"future_section":{},"policy_rules":[{"priority":1,"name":"ok","destFQDN":"a.example.com","action":"Allow","annotations":{"note":"x"}}]}`)
	unknownShape := write("shape.json", `{"rule_list":[{"name":"x","srcIP":"y"}]}`)
	var sout, serr bytes.Buffer
	if code := runPolicyPreflight([]string{snapBad, bundleBad}, &sout, &serr); code != 1 ||
		!strings.Contains(sout.String(), "1 of 1 rule(s) in a control-plane snapshot") || !strings.Contains(sout.String(), `"srcIP"`) ||
		!strings.Contains(sout.String(), "duplicate field") || !strings.Contains(sout.String(), ruleAnnotationsKey) {
		t.Errorf("snapshot-shaped files: exit %d, want 1 naming both rules and pointing at annotations:\n%s%s", code, sout.String(), serr.String())
	}
	sout.Reset()
	if code := runPolicyPreflight([]string{snapGood}, &sout, &serr); code != 0 || !strings.Contains(sout.String(), "OK — 1 rule(s) in a control-plane snapshot") {
		t.Errorf("clean snapshot: exit %d %q, want 0 and one rule counted", code, sout.String())
	}
	sout.Reset()
	if code := runPolicyPreflight([]string{unknownShape}, &sout, &serr); code != 2 || strings.Contains(sout.String(), "OK") {
		t.Errorf("a document of no known shape: exit %d %q, want 2 and no OK", code, sout.String())
	}
	if strings.Contains(out.String(), `rule #2`) {
		t.Errorf("preflight reports the case-variant key as unknown:\n%s", out.String())
	}

	// POL-004: an unknown ACTION is retained and blocks; it is not an unknown key.
	ps := &PolicyStore{}
	file := write("future-action.json", `[{"priority":1,"name":"future-action","destFQDN":"y.example.com","action":"Quarantine"}]`)
	if err := ps.Load(file); err != nil || len(ps.List()) != 1 {
		t.Errorf("an unknown ACTION was not retained by Load (%v, %d rules): POL-004 must be unchanged", err, len(ps.List()))
	}
	// A rule built in Go (never decoded) is unaffected.
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "typed", DestFQDN: "z.example.com", Action: ActionBlockPage}})
	if got := ruleNames(ps.List()); len(got) != 1 || got[0] != "typed" {
		t.Errorf("a typed rule was not installed: %v", got)
	}
	// The store door is the backstop for any caller that decoded rules itself.
	var decoded []PolicyRule
	if err := json.Unmarshal([]byte(widenedRulesetJSON("q.example.com")), &decoded); err != nil {
		t.Fatal(err)
	}
	ps.ReplaceAll(decoded)
	if got := ruleNames(ps.List()); len(got) != 1 || got[0] != "typed" {
		t.Errorf("ReplaceAll installed a ruleset holding an unknown rule key: %v", got)
	}
}

// ── Annotations: the bound is a fixed point of every encoder ─────────────────

// annotationEncoders are the ways Culvert writes JSON: Marshal (snapshots, API,
// stored versions), MarshalIndent (the policy file, the pending draft), and a
// stream Encoder with and without HTML escaping.
var annotationEncoders = map[string]func(any) ([]byte, error){
	"Marshal":       json.Marshal,
	"MarshalIndent": func(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") },
	"Encoder, no HTML escaping, indented": func(v any) ([]byte, error) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent(" ", "\t")
		err := enc.Encode(v)
		return buf.Bytes(), err
	},
}

// annotationEnvelopes are the documents that carry rules, each with the gate
// its door applies after decoding it.
var annotationEnvelopes = map[string]struct {
	wrap   func([]PolicyRule) any
	reread func([]byte) ([]PolicyRule, error)
}{
	"policy file": {
		func(r []PolicyRule) any { return r },
		func(b []byte) ([]PolicyRule, error) {
			ptrs, err := (&PolicyStore{}).decodePolicyFile(b)
			out := make([]PolicyRule, 0, len(ptrs))
			for _, p := range ptrs {
				out = append(out, *p)
			}
			return out, err
		},
	},
	"config backup / stored version": {
		func(r []PolicyRule) any { return configBackup{Version: 1, PolicyRules: r} },
		func(b []byte) ([]PolicyRule, error) {
			var cb configBackup
			if err := json.Unmarshal(b, &cb); err != nil {
				return nil, err
			}
			return cb.PolicyRules, rollbackTargetRefusal(&cb)
		},
	},
	"snapshot / last-good": {
		func(r []PolicyRule) any { return ConfigSnapshot{Version: 1, PolicyRules: r} },
		func(b []byte) ([]PolicyRule, error) {
			var snap ConfigSnapshot
			if err := json.Unmarshal(b, &snap); err != nil {
				return nil, err
			}
			return snap.PolicyRules, validateConfigSnapshot(snap)
		},
	},
	"HA bundle": {
		func(r []PolicyRule) any { return HAStateBundle{Config: ConfigSnapshot{Version: 1, PolicyRules: r}} },
		func(b []byte) ([]PolicyRule, error) {
			var bundle HAStateBundle
			if err := json.Unmarshal(b, &bundle); err != nil {
				return nil, err
			}
			return bundle.Config.PolicyRules, validateConfigSnapshot(bundle.Config)
		},
	},
	"pending draft": {
		func(r []PolicyRule) any {
			return struct {
				State draftState   `json:"state"`
				Rules []PolicyRule `json:"rules"`
			}{draftState{Active: true}, r}
		},
		func(b []byte) ([]PolicyRule, error) {
			var p struct {
				Rules ruleList `json:"rules"`
			}
			if err := json.Unmarshal(b, &p); err != nil {
				return nil, err
			}
			return p.Rules, policyRulesetError(p.Rules)
		},
	},
}

// annotationsOfCanonicalSize is an object whose canonical form is exactly n bytes.
func annotationsOfCanonicalSize(n int) string {
	return `{"a":"` + strings.Repeat("x", n-len(`{"a":""}`)) + `"}`
}

func decodeAnnotated(t *testing.T, annotations string) PolicyRule {
	t.Helper()
	var r PolicyRule
	if err := json.Unmarshal([]byte(`{"priority":1,"name":"annotated","destFQDN":"a.example.com","action":"Drop","annotations":`+annotations+`}`), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return r
}

// Anything accepted once is accepted, unchanged, after any number of round
// trips through every encoder and every document that carries rules. Measured
// before this: a 4004-byte container loaded clean, the store re-saved the file
// indented (7665 bytes) and the next start refused it; `{"n":"<<<…"}` of 1008
// bytes was accepted by the API and became 6008 bytes in the snapshot, which
// every data plane then refused.
func TestRuleKeys_AnnotationsBoundIsAFixedPointOfEveryEncoder(t *testing.T) {
	var manyKeys strings.Builder
	manyKeys.WriteString(`{"k0":0`)
	for i := 1; manyKeys.Len() < 3990; i++ {
		manyKeys.WriteString(`,"k` + strconv.Itoa(i) + `":` + strconv.Itoa(i))
	}
	manyKeys.WriteString(`}`)
	deepIndented := strings.Repeat("{\n \"a\" : ", ruleAnnotationsMaxDepth) + "1" + strings.Repeat("\n}", ruleAnnotationsMaxDepth)
	cases := map[string]struct {
		annotations string
		accepted    bool
	}{
		"compact, ~4 KiB, many keys (grows when indented)":  {manyKeys.String(), true},
		"1000 '<' (6 bytes each once escaped)":              {`{"n":"` + strings.Repeat("<", 1000) + `"}`, false},
		"a few of < > &":                                    {`{"n":"a<b>c&d","<k>":"&"}`, true},
		"already escaped":                                   {`{"n":"\u003c\u003e\u0026 \" \\ \/ \u00e9 \ud83d\ude00"}`, true},
		"raw U+2028 and U+2029":                             {"{\"n\":\"a\u2028b\u2029c\"}", true},
		"10 KiB of whitespace around a small object":        {strings.Repeat(" \n\t", 3400) + `{ "n" : [ 1 , 2 ] }` + strings.Repeat("\r\n", 100), true},
		"exactly the limit in canonical bytes":              {annotationsOfCanonicalSize(ruleAnnotationsMaxBytes), true},
		"one canonical byte over the limit":                 {annotationsOfCanonicalSize(ruleAnnotationsMaxBytes + 1), false},
		"at the limit only before escaping":                 {`{"a":"` + strings.Repeat("x", ruleAnnotationsMaxBytes-13) + `<"}`, false},
		"at the depth limit, indented":                      {deepIndented, true},
		"one level over the depth limit, indented":          {"{ \"z\" :\n" + deepIndented + "}", false},
		"duplicate and condition-looking keys, uninspected": {`{"sourceIP":"10.0.0.0/8","action":"Allow","action":"Drop"}`, true},
	}
	for label, tc := range cases {
		first := decodeAnnotated(t, tc.annotations)
		ok, reason := ruleEnforceable(&first)
		if ok != tc.accepted {
			t.Errorf("%s: first decode accepted=%v (%s), want %v", label, ok, reason, tc.accepted)
			continue
		}
		if !tc.accepted {
			// Refused however it is written: compact, indented, re-escaped.
			if out, _ := json.Marshal(first); bytes.Contains(out, []byte(ruleAnnotationsKey)) {
				t.Errorf("%s: a refused rule still writes its annotations: %.80s…", label, out)
			}
			continue
		}
		canonical := append([]byte(nil), first.Annotations.raw...)
		if len(canonical) > ruleAnnotationsMaxBytes {
			t.Fatalf("%s: canonical form is %d bytes, over the bound it was accepted under", label, len(canonical))
		}
		assertAnnotationsFixedPoint(t, label, first, canonical)
	}
}

// assertAnnotationsFixedPoint sends one accepted rule three times round every
// encoder × document pair and requires that it is accepted and unchanged.
func assertAnnotationsFixedPoint(t *testing.T, label string, first PolicyRule, canonical []byte) {
	t.Helper()
	for encName, encode := range annotationEncoders {
		for envName, env := range annotationEnvelopes {
			rules := []PolicyRule{first}
			for trip := 1; trip <= 3; trip++ {
				data, err := encode(env.wrap(rules))
				if err != nil {
					t.Fatalf("%s: %s of a %s: %v", label, encName, envName, err)
				}
				rules, err = env.reread(data)
				if err != nil || len(rules) != 1 {
					t.Errorf("%s: REFUSED on round trip %d through %s of a %s (%d bytes written): %v", label, trip, encName, envName, len(data), err)
					break
				}
				if !bytes.Equal(rules[0].Annotations.raw, canonical) {
					t.Errorf("%s: annotations changed on round trip %d through %s of a %s:\n got %.120s\nwant %.120s", label, trip, encName, envName, rules[0].Annotations.raw, canonical)
					break
				}
			}
		}
	}
}

// The two reproductions, through the real doors.
func TestRuleKeys_AnnotatedRulesetSurvivesItsOwnSaveExportAndPublish(t *testing.T) {
	const host = "unk-fix.example.com"
	unkSetup(t, host)
	var big strings.Builder
	big.WriteString(`{"k0":0`)
	for i := 1; big.Len() < 4000; i++ {
		big.WriteString(`,"k` + strconv.Itoa(i) + `":` + strconv.Itoa(i))
	}
	big.WriteString(`}`)

	// Startup sequence: a hand-written policy file WITHOUT rule ids. The first
	// start loads it, backfills ids and saves the file (indented); the second
	// start must load what the first one wrote.
	file := filepath.Join(t.TempDir(), "policy.json")
	hand := `[{"priority":1,"name":"noted","destFQDN":"` + host + `","action":"Block_Page","annotations":` + big.String() + `}]`
	if err := os.WriteFile(file, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}
	firstStart := &PolicyStore{}
	if err := firstStart.Load(file); err != nil {
		t.Fatalf("first start: %v", err)
	}
	rewritten, _ := os.ReadFile(file)
	if bytes.Equal(rewritten, []byte(hand)) || !bytes.Contains(rewritten, []byte(`"id"`)) {
		t.Fatalf("setup: the first start did not re-save the file with backfilled ids (%d bytes), so the second start proves nothing", len(rewritten))
	}
	if len(rewritten) < 2*len(hand)-len(hand)/2 {
		t.Logf("note: re-saved file is %d bytes for %d written", len(rewritten), len(hand))
	}
	secondStart := &PolicyStore{}
	if err := secondStart.Load(file); err != nil {
		t.Fatalf("second start REFUSED the file the first start wrote (%d bytes for %d written): %v", len(rewritten), len(hand), err)
	}
	// …and the same through an explicit save, twice more.
	for i := range 2 {
		if err := secondStart.SaveErr(); err != nil {
			t.Fatal(err)
		}
		if err := (&PolicyStore{}).Load(file); err != nil {
			t.Fatalf("reload %d after SaveErr refused: %v", i+1, err)
		}
	}

	// API → store → snapshot / export / stored version. What the API accepts,
	// every data plane, import and rollback accept.
	w := httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", `{"priority":5,"name":"api-noted","destFQDN":"x.`+host+`","action":"Drop","sslAction":"Inspect","annotations":{"n":"a<b>&c `+strings.Repeat("<", 300)+`"}}`))
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", w.Code, w.Body.String())
	}
	listed := policyStore.List()
	snap, _ := json.Marshal(ConfigSnapshot{Version: 1, PolicyRules: listed})
	var onNode ConfigSnapshot
	if err := json.Unmarshal(snap, &onNode); err != nil || validateConfigSnapshot(onNode) != nil {
		t.Errorf("a data plane refuses the snapshot of a rule the API accepted: %v / %v", err, validateConfigSnapshot(onNode))
	}
	export, _ := json.MarshalIndent(configBackup{Version: 1, PolicyRules: listed}, "", "  ")
	w = httptest.NewRecorder()
	apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?mode=replace&dryRun=true", string(export)))
	if w.Code != http.StatusOK {
		t.Errorf("an export of the running rules is refused at import: %d %s", w.Code, w.Body.String())
	}
	// The other reproduction: accepted by nothing, at any door, in any form.
	w = httptest.NewRecorder()
	apiPolicy(w, adminRequest(http.MethodPost, "/api/policy", `{"priority":6,"name":"too-big-once-written","action":"Drop","sslAction":"Inspect","annotations":{"n":"`+strings.Repeat("<", 1000)+`"}}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), ruleAnnotationsKey) {
		t.Errorf("a container that is 6008 bytes as Culvert writes it was accepted by the API: %d %s", w.Code, w.Body.String())
	}
}

// ── A rule list given twice, and values that survive a decode ────────────────

// assertPreflightRefusesListTwice runs `culvert policy-check` over every
// document shape holding the duplicated list.
func assertPreflightRefusesListTwice(t *testing.T, label, format, body string) {
	t.Helper()
	dir := t.TempDir()
	for name, doc := range map[string]string{
		"backup.json":   body,
		"snapshot.json": `{"version":7,` + fmt.Sprintf(format, "policy_rules", "Policy_Rules") + `}`,
		"draft.json":    `{"state":{"active":true},` + fmt.Sprintf(format, "rules", "Rules") + `}`,
		"stored.json":   `{"meta":{"version":3},"config":` + body + `}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := runPolicyPreflight([]string{path}, &out, &errb); code != 1 || !strings.Contains(out.String(), "rule list twice") {
			t.Errorf("%s: policy-check %s exit %d, want 1 naming the duplicated list:\n%s%s", label, name, code, out.String(), errb.String())
		}
	}
}

func TestRuleKeys_RuleListGivenTwiceIsRefusedAtEveryDoor(t *testing.T) {
	bindFreshAdmissionOwners(t)
	const host = "unk-twice.example.com"
	version := unkSetup(t, host)
	// The exact shape reported: the first list holds the faulty, permissive
	// rule; the second, a bare rule of the same name. encoding/json reused the
	// slice element, so the VALUES came from the first and the (clean) fault
	// from the second: rule "a", Allow, any source, no refusal.
	bad := `[{"priority":1,"name":"a","action":"Allow","destFQDN":"` + host + `","sourceIPs":"10.0.0.0/8"}]`
	bare := `[{"name":"a"}]`
	lists := map[string]string{
		"faulty then bare": `"%[1]s":` + bad + `,"%[1]s":` + bare,
		"rules then empty": `"%[1]s":[{"priority":1,"name":"only-block","destFQDN":"` + host + `","action":"Block_Page"}],"%[1]s":[]`,
		"rules then null":  `"%[1]s":[{"priority":1,"name":"only-block","destFQDN":"` + host + `","action":"Block_Page"}],"%[1]s":null`,
		"other spelling":   `"%[1]s":` + bare + `,"%[2]s":` + strings.Replace(bad, "sourceIPs", "sourceIP", 1),
	}
	for label, format := range lists {
		// Import.
		body := `{"version":1,` + fmt.Sprintf(format, "policyRules", "POLICYRULES") + `}`
		for _, q := range []string{"mode=replace", "mode=merge", "mode=replace&dryRun=true"} {
			w := httptest.NewRecorder()
			apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?"+q, body))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "rule list twice") {
				t.Errorf("%s: import %s = %d %s, want 400 naming the duplicated list", label, q, w.Code, w.Body.String())
			}
		}
		assertUnkStillBlocked(t, "import, "+label, host, version)
		// Snapshot, as fetchAndApply and the last-good loader decode it.
		var snap ConfigSnapshot
		if err := json.Unmarshal([]byte(`{"version":1099511627776,`+fmt.Sprintf(format, "policy_rules", "Policy_Rules")+`}`), &snap); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		var ue *unenforceableRuleError
		if err := applyConfigSnapshot(snap); !errors.As(err, &ue) || !strings.Contains(err.Error(), "rule list twice") {
			t.Errorf("%s: applyConfigSnapshot = %v, want a refusal naming the duplicated list", label, err)
		}
		assertUnkStillBlocked(t, "snapshot, "+label, host, version)
		// Stored version and pending draft shapes.
		var cb configBackup
		if err := json.Unmarshal([]byte(body), &cb); err != nil || rollbackTargetRefusal(&cb) == nil {
			t.Errorf("%s: a stored version giving its rule list twice is restorable (%v)", label, err)
		}
		var draft struct {
			Rules ruleList `json:"rules"`
		}
		if err := json.Unmarshal([]byte(`{"state":{"active":true},`+fmt.Sprintf(format, "rules", "Rules")+`}`), &draft); err != nil || policyRulesetError(draft.Rules) == nil {
			t.Errorf("%s: a draft giving its rule list twice is reloadable (%v)", label, err)
		}
		assertPreflightRefusesListTwice(t, label, format, body)
	}
	// Controls: each list given once is accepted, and null-then-list loses nothing.
	w := httptest.NewRecorder()
	apiConfigImport(w, adminRequest(http.MethodPost, "/api/config/import?mode=replace&dryRun=true",
		`{"version":1,"policyRules":[{"priority":1,"name":"a","action":"Allow","destFQDN":"`+host+`","sourceIP":"10.0.0.0/8"}]}`))
	if w.Code != http.StatusOK {
		t.Errorf("control: a backup giving its rule list once is refused: %d %s", w.Code, w.Body.String())
	}
	var once ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":1,"policy_rules":null,"policy_rules":`+cleanRulesetJSON(host)+`}`), &once); err != nil || validateConfigSnapshot(once) != nil || len(once.PolicyRules) != 2 {
		t.Errorf("control: null then a list = %d rule(s), %v / %v", len(once.PolicyRules), err, validateConfigSnapshot(once))
	}
}

// Nothing survives from an earlier decode, at any level: a reused slice, a
// reused rule, a copy of a rule that has annotations; and what the store hands
// out cannot be used to rewrite what it enforces.
func TestRuleKeys_NothingSurvivesAnEarlierDecodeAndCopiesDoNotAlias(t *testing.T) {
	reused := []PolicyRule{}
	if err := json.Unmarshal([]byte(`[{"name":"a","action":"Allow","sourceIP":"10.0.0.0/8","annotations":{"x":1}}]`), &reused); err != nil {
		t.Fatal(err)
	}
	original := reused[0]
	kept := string(original.Annotations.raw)
	if err := json.Unmarshal([]byte(`[{"name":"a"}]`), &reused); err != nil {
		t.Fatal(err)
	}
	if reused[0].Action != "" || reused[0].SourceIP != "" || reused[0].Annotations != nil {
		t.Errorf("values survived from the earlier decode of the same slice: %+v", reused[0])
	}
	clone := original
	if err := json.Unmarshal([]byte(`{"name":"b","annotations":{"x":2,"padding":"`+strings.Repeat("a", 64)+`"}}`), &clone); err != nil {
		t.Fatal(err)
	}
	if got := string(original.Annotations.raw); got != kept || !json.Valid(original.Annotations.raw) {
		t.Errorf("decoding onto a COPY of a rule rewrote the original's annotations: %q, was %q", got, kept)
	}
	// The store's own copies: what List() hands out cannot be used to rewrite
	// what the store enforces.
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{original})
	listed := ps.List()
	if err := json.Unmarshal([]byte(`{"name":"c","annotations":{"y":3}}`), &listed[0]); err != nil {
		t.Fatal(err)
	}
	if got := string(ps.List()[0].Annotations.raw); got != kept {
		t.Errorf("the store's annotations changed through a listed copy: %q, was %q", got, kept)
	}
}

// policy-check looks at every place a document holds rules, and names the
// document for what it is.
func TestRuleKeys_PreflightChecksEveryLocationAndLabelsByShape(t *testing.T) {
	dir := t.TempDir()
	run := func(name, body string) (int, string) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := runPolicyPreflight([]string{path}, &out, &errb)
		return code, out.String() + errb.String()
	}
	bogus := `[{"priority":1,"name":"wire","action":"Allow","bogus":1}]`
	clean := `[{"priority":1,"name":"ok","action":"Drop"}]`
	for label, tc := range map[string]struct {
		body, shape string
		code        int
	}{
		"rules beside an object under config":  {`{"config":{"version":1},"policy_rules":` + bogus + `}`, "control-plane snapshot", 1},
		"rules at both levels, bad one nested": {`{"version":1,"policyRules":` + clean + `,"config":{"policy_rules":` + bogus + `}}`, "config backup + HA state bundle", 1},
		"rules under two top-level keys":       {`{"version":1,"policyRules":` + clean + `,"policy_rules":` + bogus + `}`, "config backup + control-plane snapshot", 1},
		"HA bundle":                            {`{"config":{"version":7,"policy_rules":` + bogus + `}}`, "HA state bundle", 1},
		"stored config version":                {`{"meta":{"version":3},"config":{"version":1,"policyRules":` + bogus + `}}`, "stored config version", 1},
		"clean HA bundle":                      {`{"config":{"version":7,"policy_rules":` + clean + `}}`, "1 rule(s) in a HA state bundle", 0},
		"stored version without a policy":      {`{"meta":{"version":3},"config":{"version":1}}`, "0 rule(s) in a stored config version", 0},
		"no known shape, nested":               {`{"config":{"hello":1}}`, "no policy rules found", 2},
	} {
		code, out := run("f.json", tc.body)
		if code != tc.code || !strings.Contains(out, tc.shape) || (tc.code == 1 && !strings.Contains(out, `"bogus"`)) {
			t.Errorf("%s: exit %d, want %d and %q:\n%s", label, code, tc.code, tc.shape, out)
		}
	}
}

// PolicyRule is copied into PolicyMatch on every matched request and sits
// exactly on its malloc size class. The benchgate build measures the
// allocations; this keeps the size itself in the default test run.
func TestRuleKeys_ColdDataIsOnePointerAndTheRuleKeepsItsSizeClass(t *testing.T) {
	// The size classes are 64-bit facts; on a 32-bit build both structs are smaller.
	const ruleClass, matchClass, mallocHeader = 576, 640, 8
	if got := unsafe.Sizeof(PolicyRule{}); got > ruleClass-mallocHeader {
		t.Errorf("PolicyRule is %d bytes, over %d: every matched request allocates a size class more. Cold data belongs behind the Annotations pointer.", got, ruleClass-mallocHeader)
	}
	if got := unsafe.Sizeof(PolicyMatch{}); got > matchClass-mallocHeader {
		t.Errorf("PolicyMatch is %d bytes, over %d", got, matchClass-mallocHeader)
	}
	if f, _ := reflect.TypeFor[PolicyRule]().FieldByName("Annotations"); f.Type.Kind() != reflect.Pointer {
		t.Errorf("Annotations is a %s; it must stay one pointer", f.Type)
	}
	// The last-hit time that rides on a rule value is uint32 seconds.
	for in, want := range map[int64]uint32{-5: 0, 0: 0, 1795651200: 1795651200, math.MaxUint32: math.MaxUint32, math.MaxUint32 + 1: math.MaxUint32, math.MaxInt64: math.MaxUint32} {
		if got := ruleLastHit32(in); got != want {
			t.Errorf("ruleLastHit32(%d) = %d, want %d", in, got, want)
		}
	}
	// End to end: a hit is carried out of List() and back into a new publication.
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "hit", DestFQDN: "h.example.com", Action: ActionBlockPage}})
	if m := ps.Evaluate("198.51.100.7", "", "", "h.example.com", nil); m == nil || m.Rule.lastHitUnix == 0 {
		t.Fatalf("a match does not carry its last-hit time: %+v", m)
	}
	listed := ps.List()
	if listed[0].lastHitUnix == 0 || listed[0].LastHit == "" || time.Unix(int64(listed[0].lastHitUnix), 0).UTC().Format(time.RFC3339) != listed[0].LastHit {
		t.Errorf("List() last-hit = %d / %q", listed[0].lastHitUnix, listed[0].LastHit)
	}
}
