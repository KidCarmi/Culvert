package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// These are the regression gates for the structured-field-block injection class.
//
// The JSON log encoder promotes the trailing `{key=value …}` block of a log line
// to top-level JSON fields: it locates the block at the LAST " {" on the line,
// splits it on SPACE, and uses the text before each token's first '=' as a key.
// Three things followed from that, and all three are fixed:
//
//  1. the key was appended to the record UNESCAPED, so a key carrying a '"' made
//     the whole record unparseable — a strict shipper DROPS it, so the decision
//     record for that request never reaches the SIEM (audit evasion);
//  2. a bare value carrying a SPACE inside the block forged additional
//     structured fields that a SIEM reads as the gateway's own;
//  3. a bare value carrying " {" RE-ANCHORED the block, taking req_id and
//     identity out of the structured record entirely.
//
// (1) is closed in the encoder (logger.go), so a well-formed record no longer
// depends on how carefully each call site is written. (2) and (3) are closed at
// the call site, where the untrusted value reaches the line
// (sanitizeLogFieldToken / foldLogFieldToken in proxy.go) — the same place this
// tree keeps every other CWE-117 barrier, and the same shape SEC-REQID-1 used
// for reqID.
//
// The live untrusted value is `identity`: an IdP-asserted `sub`/`email` claim,
// chosen by a federated user, with no entry-point bound of the kind reqID has.

// hostileFieldIdentities are identity values that a federated user could plausibly
// get an IdP to assert, each aimed at one of the three defects.
var hostileFieldIdentities = []struct {
	name     string
	identity string
	// forbidden keys must not appear as top-level JSON fields in the record.
	forbidden []string
}{
	{
		name:      "forges_extra_fields",
		identity:  `bob@corp.example severity=info verdict=clean`,
		forbidden: []string{"severity", "verdict"},
	},
	{
		name:      "forges_an_action_a_first_wins_parser_prefers",
		identity:  `bob@corp.example action=allow`,
		forbidden: nil, // action is real; asserted on VALUE below, not absence
	},
	{
		name:      "breaks_the_record_with_a_quote_in_a_key",
		identity:  `bob@corp.example y"z=1`,
		forbidden: []string{`y"z`},
	},
	{
		name:      "re_anchors_the_field_block",
		identity:  `bob@corp.example {attacker=owns_the_block`,
		forbidden: []string{"attacker"},
	},
	{
		name:      "tab_and_brace_together",
		identity:  "bob@corp.example\tx=1 {y=2",
		forbidden: []string{"x", "y"},
	},
}

// TestLogFieldToken_FoldsExactlyTheGrammarBytes pins what the fold does and,
// just as importantly, what it does NOT do: it must not become a second
// control-byte scrub or start rewriting ordinary identity characters.
func TestLogFieldToken_FoldsExactlyTheGrammarBytes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Benign values pass through byte for byte — this is what keeps every
		// line a parser already consumes unchanged.
		{"alice@corp.example", "alice@corp.example"},
		{"CN=alice,OU=users,DC=corp,DC=example", "CN=alice,OU=users,DC=corp,DC=example"},
		{"", ""},
		{"a}b", "a}b"},   // '}' carries no grammar: the block ends at the LINE's last byte
		{"a=b", "a=b"},   // only the FIRST '=' splits, so a '=' in a value is inert
		{"a\"b", "a\"b"}, // the encoder escapes quotes now; folding them would lose data
		{"ünïcode", "ünïcode"},
		// The two grammar bytes, and only those.
		{"a b", "a_b"},
		{"a{b", "a_b"},
		{" ", "_"},
		{"{", "_"},
		{"a {b", "a__b"},
		{"  ", "__"},
	} {
		if got := foldLogFieldToken(tc.in); got != tc.want {
			t.Errorf("foldLogFieldToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLogFieldToken_ScrubsControlBytesThenFolds is the composition check: the
// field barrier must keep sanitizeLog's record barrier, not replace it.
func TestLogFieldToken_ScrubsControlBytesThenFolds(t *testing.T) {
	// A newline would forge a whole second record; a space would forge a field.
	// Both must be gone, and the CR/LF scrub must still be the one CodeQL sees.
	got := sanitizeLogFieldToken("a\nb\rc\x00d e{f\x7fg")
	if strings.ContainsAny(got, "\n\r\x00\x7f {") {
		t.Errorf("sanitizeLogFieldToken left a record- or field-forging byte: %q", got)
	}
	if want := "a_b_c_d_e_f_g"; got != want {
		t.Errorf("sanitizeLogFieldToken = %q, want %q", got, want)
	}
}

// TestJSONLogRecord_PromotedKeyIsAlwaysWellFormedJSON is the encoder half. It
// does not assume any call site is careful: it feeds the encoder keys that the
// raw append emitted as invalid JSON and requires a parseable record.
func TestJSONLogRecord_PromotedKeyIsAlwaysWellFormedJSON(t *testing.T) {
	for _, key := range []string{
		`y"z`,  // the defect: an unescaped quote closed the key early
		`a\b`,  // a backslash started an invalid escape
		`k<t>`, // HTML bytes encoding/json rewrites
		"ké",   // non-ASCII: must still be valid, and byte-identical
		`"`,
		`\`,
		`a"b\c"d`,
	} {
		line := "MSG {req_id=abc " + key + "=v action=block}"
		rec := appendJSONLogRecord(nil, []byte(line), pinnedLogClock)
		var m map[string]any
		if err := json.Unmarshal(rec, &m); err != nil {
			t.Errorf("key %q produced an unparseable record: %v\nrecord: %s", key, err, rec)
			continue
		}
		// The key must arrive intact, not merely escaped into something else.
		if v, ok := m[key]; !ok || v != "v" {
			t.Errorf("key %q did not round-trip: record: %s", key, rec)
		}
		// And the real fields must survive alongside it.
		if m["req_id"] != "abc" || m["action"] != "block" {
			t.Errorf("key %q disturbed the real fields: record: %s", key, rec)
		}
	}
}

// TestJSONLogRecord_BenignBlockIsUnchangedByKeyEscaping is the negative control
// for the encoder change: escaping the key must be byte-for-byte invisible for
// every key the tree actually emits, or it is a silent change to the format a
// SIEM forwarder parses. The legacy encoder is the oracle, since it is the
// shape in production before this fix.
func TestJSONLogRecord_BenignBlockIsUnchangedByKeyEscaping(t *testing.T) {
	for _, c := range jsonLogCorpus {
		got := appendJSONLogRecord(nil, []byte(c.line), pinnedLogClock)
		want := legacyJSONLogRecord([]byte(c.line), pinnedLogClock)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: key escaping changed a benign record\n got: %s\nwant: %s", c.name, got, want)
		}
	}
}

// TestPolicyDecisionLine_IdentityCannotForgeJSONFields is the end-to-end gate,
// and the one that would have failed before the fix. It drives a hostile
// IdP-asserted identity through the real emitter and the real JSON encoder and
// asserts the record a SIEM would receive.
func TestPolicyDecisionLine_IdentityCannotForgeJSONFields(t *testing.T) {
	for _, tc := range hostileFieldIdentities {
		t.Run(tc.name, func(t *testing.T) {
			line := plCapture(func() {
				logPolicyBlock(plRule, 7, plClientIP, plHost, plCond, plReqID, tc.identity)
			})
			rec := appendJSONLogRecord(nil, []byte(strings.TrimRight(line, "\n")), pinnedLogClock)

			var m map[string]any
			if err := json.Unmarshal(rec, &m); err != nil {
				t.Fatalf("hostile identity produced an unparseable record (a strict shipper DROPS it, so the decision never reaches the SIEM): %v\nrecord: %s", err, rec)
			}
			for _, k := range tc.forbidden {
				if v, ok := m[k]; ok {
					t.Errorf("identity forged the structured field %q = %v\nrecord: %s", k, v, rec)
				}
			}
			// The gateway's own verdict must be the one in the record, not the
			// attacker's.
			if m["action"] != "block" {
				t.Errorf("action = %v, want \"block\" (the real verdict)\nrecord: %s", m["action"], rec)
			}
			// Asserting the PARSED action is not enough for the duplicate-key
			// case: encoding/json is last-wins, so a forged `action=allow`
			// emitted BEFORE the real one parses away here while still being
			// present in the bytes — and a first-wins consumer (several SIEM
			// field extractors are) would read the attacker's. Count the raw
			// occurrences so the gate sees what the shipper sees.
			if n := bytes.Count(rec, []byte(`"action":`)); n != 1 {
				t.Errorf("record carries %d action keys, want 1 — a first-wins parser would read the forged one\nrecord: %s", n, rec)
			}
			// Re-anchoring must not have taken the correlation fields out of
			// the structured record.
			if m["req_id"] != plReqID {
				t.Errorf("req_id = %v, want %q (field block was re-anchored)\nrecord: %s", m["req_id"], plReqID, rec)
			}
			if _, ok := m["identity"]; !ok {
				t.Errorf("identity field vanished from the record: %s", rec)
			}
		})
	}
}

// TestPolicyDecisionLine_BenignIdentityIsUnchanged is the positive control: the
// fix must not rewrite the identities real deployments actually log, including
// the LDAP DN shape policyLineBufSize was sized for.
func TestPolicyDecisionLine_BenignIdentityIsUnchanged(t *testing.T) {
	for _, id := range []string{
		"alice@corp.example",
		"CN=alice,OU=users,DC=corp,DC=example",
		"S-1-5-21-1234567890-1234567890-1234567890-1001",
		"",
	} {
		line := plCapture(func() {
			logPolicyAllow(plRule, 1, plClientIP, "GET", plHost, plCond, plReqID, id)
		})
		if !strings.Contains(line, "identity="+id+" ") {
			t.Errorf("benign identity %q was rewritten in: %s", id, line)
		}
		rec := appendJSONLogRecord(nil, []byte(strings.TrimRight(line, "\n")), pinnedLogClock)
		var m map[string]any
		if err := json.Unmarshal(rec, &m); err != nil {
			t.Fatalf("benign identity %q: unparseable record: %v\n%s", id, err, rec)
		}
		if m["identity"] != id {
			t.Errorf("identity = %v, want %q\nrecord: %s", m["identity"], id, rec)
		}
	}
}

// TestJSONLogRecord_MalformedFieldBlockStaysParseable covers the shapes that are
// neither benign nor an attack but have historically broken field parsers:
// an empty block, a token with no '=', an '=' in first position (which must NOT
// promote an empty key), and a block that is not the line's suffix.
func TestJSONLogRecord_MalformedFieldBlockStaysParseable(t *testing.T) {
	for _, line := range []string{
		"msg {}",
		"msg {bare token}",
		"msg {=novalue}",
		"msg {=}",
		"msg {k=1} trailing",
		"msg { }",
		"msg {k=1 =2 j=3}",
		" {}",
		"{}",
		"msg {" + strings.Repeat("k=v ", 200) + "}",
	} {
		rec := appendJSONLogRecord(nil, []byte(line), pinnedLogClock)
		var m map[string]any
		if err := json.Unmarshal(rec, &m); err != nil {
			t.Errorf("line %q produced an unparseable record: %v\nrecord: %s", line, err, rec)
			continue
		}
		if _, ok := m[""]; ok {
			t.Errorf("line %q promoted an EMPTY key, which no caller emits: %s", line, rec)
		}
	}
}

// ── The parameters that are NOT identity ────────────────────────────────────

// The gates above fuzz `identity`, because it is the one value on the decision
// line a federated user chooses. The barrier's correctness, though, rests on a
// claim about every OTHER string the emitter renders, and that claim was stated
// in a comment rather than tested: that the MESSAGE-part values (rule, host,
// target, cond, clientIP) cannot forge a structured field because the real
// `{…}` block is always the last thing on the line, so the encoder's LAST " {"
// anchor beats anything injected ahead of it.
//
// That reasoning is sound but it is not self-evident, and the comment it lived
// in got the supporting detail wrong twice (it described cond as %q-quoted when
// the emitter appends it bare). A claim that load-bearing belongs in a test, so
// these two gates assert it against the same hostile corpus, for every slot.
//
// Severity note for a future reader: none of these slots is request-chosen the
// way identity is — rule and cond come from policy configuration, host from the
// parsed destination, clientIP from the connection. The gates exist because the
// BARRIER's shape depends on them, not because a client can drive them.

// hostileFieldSlotValues are the shapes that forge a field, re-anchor the block,
// or break the record, if a value's grammar bytes ever reach the encoder's
// token split.
var hostileFieldSlotValues = []string{
	`x severity=info verdict=clean`,
	`x {attacker=owns_the_block`,
	`x action=allow`,
	`x" y=1`,
	`x} z=1`,
	`x=1 {y=2`,
	"x\ty=1 {z=2",
	`} {forged=1`,
}

// assertDecisionRecordIntact parses the record a SIEM would receive and asserts
// it carries the gateway's own fields and only those.
func assertDecisionRecordIntact(t *testing.T, rec []byte, slot, value string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec, &m); err != nil {
		t.Fatalf("%s=%q produced an unparseable record (a strict shipper DROPS it, so the decision never reaches the SIEM): %v\nrecord: %s", slot, value, err, rec)
	}
	for _, forged := range []string{"severity", "verdict", "attacker", "forged", "y", "z"} {
		if v, ok := m[forged]; ok {
			t.Errorf("%s=%q forged the structured field %q = %v\nrecord: %s", slot, value, forged, v, rec)
		}
	}
	if m["action"] != "block" {
		t.Errorf("%s=%q: action = %v, want \"block\" (the real verdict)\nrecord: %s", slot, value, m["action"], rec)
	}
	// encoding/json is last-wins, so a forged key emitted BEFORE the real one
	// parses away above while still being present in the bytes a first-wins
	// SIEM field extractor reads. Count what the shipper sees.
	if n := bytes.Count(rec, []byte(`"action":`)); n != 1 {
		t.Errorf("%s=%q: record carries %d action keys, want 1 — a first-wins parser would read the forged one\nrecord: %s", slot, value, n, rec)
	}
	if _, ok := m["req_id"]; !ok {
		t.Errorf("%s=%q: req_id vanished from the record (the field block was re-anchored)\nrecord: %s", slot, value, rec)
	}
	if _, ok := m["identity"]; !ok {
		t.Errorf("%s=%q: identity vanished from the record (the field block was re-anchored)\nrecord: %s", slot, value, rec)
	}
}

// TestPolicyDecisionLine_MessagePartCannotForgeJSONFields drives the hostile
// corpus through each MESSAGE-part slot of the real emitter and the real
// encoder. It is the executable form of the "the real block always follows
// them" claim on policyDecision's bare set.
func TestPolicyDecisionLine_MessagePartCannotForgeJSONFields(t *testing.T) {
	for _, slot := range []string{"rule", "host", "cond", "clientIP"} {
		for _, h := range hostileFieldSlotValues {
			t.Run(slot+"/"+h, func(t *testing.T) {
				rule, host, cond, clientIP := plRule, plHost, plCond, plClientIP
				switch slot {
				case "rule":
					rule = h
				case "host":
					host = h
				case "cond":
					cond = h
				case "clientIP":
					clientIP = h
				}
				line := plCapture(func() {
					logPolicyBlock(rule, 7, clientIP, host, cond, plReqID, "alice@corp.example")
				})
				rec := appendJSONLogRecord(nil, []byte(strings.TrimRight(line, "\n")), pinnedLogClock)
				assertDecisionRecordIntact(t, rec, slot, h)
			})
		}
	}
}

// TestPolicyDecisionLine_BoundedReqIDCannotForgeJSONFields closes the one slot
// whose safety is NOT structural. reqID is rendered bare inside the field block
// like identity, but it took an entry-point charset bound instead of the fold
// (SEC-REQID-1, request_tracing_bounds.go), so the two defences have to be read
// together to see that the slot is closed.
//
// The bound admits 0x21..0x7e, which INCLUDES '{' (0x7b) — only SPACE is
// excluded. So the question the fold answers for identity is answered for reqID
// by the absence of a space: re-anchoring needs the two-byte sequence " {", and
// inside a value with no space the byte before any '{' is another value byte or
// the '=' of `req_id=`, never a space. This gate feeds only values the bound
// actually ADMITS, so it tests the system rather than an unreachable input, and
// it fails if the bound is ever widened to let SPACE through.
func TestPolicyDecisionLine_BoundedReqIDCannotForgeJSONFields(t *testing.T) {
	for _, id := range []string{
		`abc{`,
		`{`,
		`abc{attacker=owns_the_block`,
		`}{forged=1`,
		`a=1`,
		`a"b`,
		`}`,
		`{req_id=x`,
		`abc{identity=root`,
		strings.Repeat("{", 64),
	} {
		t.Run(id, func(t *testing.T) {
			if !acceptableTracingHeaderValue(id, maxClientRequestIDLen) {
				t.Fatalf("%q is not admissible as an X-Request-Id, so this case tests an input the wire cannot deliver; pick another or re-read the bound", id)
			}
			line := plCapture(func() {
				logPolicyBlock(plRule, 7, plClientIP, plHost, plCond, id, "alice@corp.example")
			})
			rec := appendJSONLogRecord(nil, []byte(strings.TrimRight(line, "\n")), pinnedLogClock)
			assertDecisionRecordIntact(t, rec, "reqID", id)
		})
	}
}

// TestTracingHeaderBound_StillExcludesTheGrammarSpace is the negative control
// for the gate above: it states, as an assertion rather than a comment, the one
// property of acceptableTracingHeaderValue the reqID slot's safety depends on.
// '{' being admitted is deliberate and recorded; SPACE being admitted would
// reopen the re-anchor vector that the fold closes for identity.
func TestTracingHeaderBound_StillExcludesTheGrammarSpace(t *testing.T) {
	if acceptableTracingHeaderValue("a b", maxClientRequestIDLen) {
		t.Error("a SPACE is admissible in an X-Request-Id: the id is rendered bare inside the `{req_id=… identity=… action=…}` block, so it can now forge structured fields and re-anchor the block — give it the foldLogFieldToken treatment identity has, or keep the bound")
	}
	if !acceptableTracingHeaderValue("a{b", maxClientRequestIDLen) {
		t.Error("'{' is no longer admissible: that is a tightening, not a defect, but TestPolicyDecisionLine_BoundedReqIDCannotForgeJSONFields now tests unreachable inputs and should be re-pointed")
	}
}
