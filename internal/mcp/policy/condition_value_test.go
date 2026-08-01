package policy

import (
	"strings"
	"testing"
)

// This suite pins the non-empty condition-value contract. The security property it
// protects: a scalar matcher value that is empty (explicitly `""` or omitted from
// the document) must be a COMPILE ERROR, never a silently broader rule. `prefix ""`
// is vacuously true for every present value, so accepting it would let a rule that
// reads as narrowly scoped ("tool.name prefix …") permit every tool.

// condRule wraps one condition in an ALLOW rule (the weakening-relevant shape).
func condRule(cond string) string {
	return `{"id":"R","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",` +
		`"remediation":"none","conditions":[` + cond + `],"obligations":{"logging":"standard"}}`
}

// --- negative: an empty or omitted scalar value must not compile -------------

func TestCondValue_EmptyScalarRejected(t *testing.T) {
	cases := []struct{ name, cond string }{
		// prefix — the fail-OPEN shape (vacuously true ⇒ match-all).
		{"prefix omitted", `{"field":"tool.name","op":"prefix"}`},
		{"prefix empty", `{"field":"tool.name","op":"prefix","value":""}`},
		{"prefix omitted on attr", `{"field":"resource.attr:branch","op":"prefix"}`},
		{"prefix empty on subject", `{"field":"principal.subject","op":"prefix","value":""}`},
		// exact / contains — vacuously false today, rejected for uniformity so an
		// authoring slip is a loud error rather than a silently dead condition.
		{"exact omitted", `{"field":"tool.name","op":"exact"}`},
		{"exact empty", `{"field":"principal.tenant","op":"exact","value":""}`},
		{"contains omitted", `{"field":"principal.groups","op":"contains"}`},
		{"contains empty", `{"field":"tool.risk","op":"contains","value":""}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compile([]byte(gwSnap(condRule(c.cond))), CreatedMeta{}, DefaultLimits())
			if err == nil {
				t.Fatalf("an empty condition value must not compile: %s", c.cond)
			}
			if !strings.Contains(err.Error(), "MCP.POLICY.CONDITION_INVALID") &&
				!strings.Contains(strings.ToLower(err.Error()), "condition") {
				t.Fatalf("expected a condition-invalid error, got %v", err)
			}
		})
	}
}

func TestCondValue_EmptySetMemberRejected(t *testing.T) {
	cases := []struct{ name, cond string }{
		{"one_of with empty member", `{"field":"tool.name","op":"one_of","values":["read_file",""]}`},
		{"contains_any with empty member", `{"field":"principal.groups","op":"contains_any","values":[""]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Compile([]byte(gwSnap(condRule(c.cond))), CreatedMeta{}, DefaultLimits()); err == nil {
				t.Fatalf("an empty set member must not compile: %s", c.cond)
			}
		})
	}
}

// --- positive: real values still compile and still match --------------------

func TestCondValue_NonEmptyStillCompilesAndMatches(t *testing.T) {
	cases := []struct {
		name, cond string
		want       Action
	}{
		{"prefix hit", `{"field":"tool.name","op":"prefix","value":"read_"}`, ActionAllow},
		{"exact hit", `{"field":"tool.name","op":"exact","value":"read_file"}`, ActionAllow},
		{"contains hit", `{"field":"principal.groups","op":"contains","value":"developers"}`, ActionAllow},
		{"one_of hit", `{"field":"tool.name","op":"one_of","values":["read_file","stat"]}`, ActionAllow},
		{"contains_any hit", `{"field":"principal.groups","op":"contains_any","values":["developers"]}`, ActionAllow},
		// Non-matching values must still fall through to default-deny.
		{"prefix miss", `{"field":"tool.name","op":"prefix","value":"write_"}`, ActionDeny},
		{"exact miss", `{"field":"tool.name","op":"exact","value":"other"}`, ActionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := eval(t, mustCompile(t, gwSnap(condRule(c.cond))), gwInput())
			if d.Action != c.want {
				t.Fatalf("condition %s: got %v, want %v", c.cond, d.Action, c.want)
			}
		})
	}
}

// --- boundary: one byte compiles; the byte bound is still enforced ----------

func TestCondValue_LengthBoundaries(t *testing.T) {
	lim := DefaultLimits()
	single := `{"field":"tool.name","op":"prefix","value":"r"}`
	if _, err := Compile([]byte(gwSnap(condRule(single))), CreatedMeta{}, lim); err != nil {
		t.Fatalf("a one-byte value must compile: %v", err)
	}
	atCap := `{"field":"tool.name","op":"prefix","value":"` + strings.Repeat("a", lim.MaxStringBytes()) + `"}`
	if _, err := Compile([]byte(gwSnap(condRule(atCap))), CreatedMeta{}, lim); err != nil {
		t.Fatalf("a value exactly at the byte bound must compile: %v", err)
	}
	overCap := `{"field":"tool.name","op":"prefix","value":"` + strings.Repeat("a", lim.MaxStringBytes()+1) + `"}`
	if _, err := Compile([]byte(gwSnap(condRule(overCap))), CreatedMeta{}, lim); err == nil {
		t.Fatal("a value over the byte bound must not compile")
	}
}

// --- regression: the exact weakening this closes ----------------------------

// A rule scoped by `tool.name prefix <value>` whose value is omitted must NOT
// compile into an ALLOW that matches an unrelated tool. Before the fix this
// document compiled and returned ALLOW for every tool name.
func TestCondValue_OmittedPrefixCannotBecomeMatchAll(t *testing.T) {
	doc := gwSnap(condRule(`{"field":"tool.name","op":"prefix"}`))
	snap, err := Compile([]byte(doc), CreatedMeta{}, DefaultLimits())
	if err == nil {
		in := gwInput()
		in.Tool.Name = "delete_everything"
		in.Operation.Operand = in.Tool.Name
		d, _ := eval(t, snap, in)
		t.Fatalf("a scope-limited ALLOW with an omitted prefix value compiled and decided %v "+
			"for an unrelated tool — the rule silently widened to match-all", d.Action)
	}
}

// A rule that keeps a real prefix alongside a vacuous second condition must also be
// rejected: the AND semantics mean the vacuous member widens nothing on its own,
// but a document containing it is malformed and must never be published.
func TestCondValue_VacuousMemberOfConjunctionRejected(t *testing.T) {
	cond := `{"field":"tool.name","op":"prefix","value":"read_"},{"field":"principal.subject","op":"prefix","value":""}`
	if _, err := Compile([]byte(gwSnap(condRule(cond))), CreatedMeta{}, DefaultLimits()); err == nil {
		t.Fatal("a conjunction containing a vacuous condition must not compile")
	}
}
