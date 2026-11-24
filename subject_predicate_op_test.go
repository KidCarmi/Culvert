package main

// A subject predicate's `op` and a subjectMatch's `schemaVersion` were accepted
// with any value and then ignored: the matcher implements exactly one meaning,
// "the client is IN one of these networks", under schema version 1.
//
// So {"type":"cidr","op":"not_in","values":["10.0.0.0/8"]} passed validation and
// was enforced as "in". A credential-required rule written as "everyone except
// 10/8" challenged only 10/8 and nobody else; an exemption written as "not the
// guest network" exempted exactly the guest network. A subjectMatch written
// under a newer schema was enforced with this build's semantics.
//
// Both are now validated. An operator this build does not implement, or a schema
// version it does not know, is refused on write, and refused whole at the bulk
// doors like any other rule the build cannot enforce (POL-005).

import (
	"errors"
	"strings"
	"testing"
)

func opRule(op string, schema int) PolicyRule {
	r := validExemptRule()
	r.Name = "op-rule"
	r.SubjectMatch = &SubjectMatch{SchemaVersion: schema, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Op: op, Values: []string{"10.0.0.0/8"}}}}
	return r
}

func TestSubjectPredicate_OnlyTheImplementedOperatorIsAccepted(t *testing.T) {
	// What the matcher does, whatever op says: membership.
	for _, op := range []string{"", "in", "not_in"} {
		sm := opRule(op, 1).SubjectMatch
		if !matchSubject(sm, "10.1.1.1") || matchSubject(sm, "192.168.1.1") {
			t.Fatalf("matcher premise broken for op %q: it must match 10.1.1.1 and not 192.168.1.1", op)
		}
	}
	for _, op := range []string{"", "in"} {
		if err := validateSubjectMatch(opRule(op, 1).SubjectMatch); err != nil {
			t.Errorf("op %q is what the matcher implements and must be accepted: %v", op, err)
		}
	}
	for _, op := range []string{"not_in", "NOT_IN", "In", "IN", " in", "any", "contains", "!="} {
		err := validateSubjectMatch(opRule(op, 1).SubjectMatch)
		if err == nil || !strings.Contains(err.Error(), "op") {
			t.Errorf("op %q is not implemented and would be enforced as \"in\"; validateSubjectMatch = %v, want a refusal naming op", op, err)
		}
	}
	// Schema version: exactly the one this build implements.
	if err := validateSubjectMatch(opRule("", 1).SubjectMatch); err != nil {
		t.Errorf("schemaVersion 1 refused: %v", err)
	}
	for _, v := range []int{0, -1, 2, 99} {
		if err := validateSubjectMatch(opRule("", v).SubjectMatch); err == nil || !strings.Contains(err.Error(), "schemaVersion") {
			t.Errorf("schemaVersion %d: validateSubjectMatch = %v, want a schemaVersion refusal", v, err)
		}
	}
}

// The write door and the bulk doors both run this validation, so a rule that
// says "not_in" can neither be created nor arrive in a file or a snapshot.
func TestSubjectPredicate_UnimplementedOperatorIsRefusedAtEveryDoor(t *testing.T) {
	bad := opRule("not_in", 1)
	if err := validateRuleShape(bad); err == nil {
		t.Error("the write-time validator accepted an auth rule whose subject operator is not implemented")
	}
	newer := opRule("", 2)
	if err := validateRuleShape(newer); err == nil {
		t.Error("the write-time validator accepted a subjectMatch of a newer schema version")
	}
	for label, r := range map[string]PolicyRule{"op not_in": bad, "schemaVersion 2": newer} {
		err := policyRulesetError([]PolicyRule{r})
		var ue *unenforceableRuleError
		if !errors.As(err, &ue) || ue.Name != "op-rule" {
			t.Errorf("%s: the bulk gate returned %v, want an unenforceableRuleError naming op-rule", label, err)
		}
		ps := &PolicyStore{}
		ps.ReplaceAll([]PolicyRule{{Priority: 9, Name: "prior", DestFQDN: "a.example.com", Action: ActionBlockPage}})
		ps.ReplaceAll([]PolicyRule{r})
		if got := ps.List(); len(got) != 1 || got[0].Name != "prior" {
			t.Errorf("%s: a bulk replace installed it or lost the prior rule: %d rule(s)", label, len(got))
		}
	}
	// Controls: the forms the product itself writes are accepted everywhere.
	for label, r := range map[string]PolicyRule{"no op": opRule("", 1), "op in": opRule("in", 1)} {
		if err := validateRuleShape(r); err != nil {
			t.Errorf("%s: write-time validator refused it: %v", label, err)
		}
		if err := policyRulesetError([]PolicyRule{r}); err != nil {
			t.Errorf("%s: bulk gate refused it: %v", label, err)
		}
	}
}
