package main

import (
	"testing"

	"github.com/crewjam/saml"
)

func samlTestAssertion(nameID string, attrs ...saml.Attribute) *saml.Assertion {
	return &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: nameID},
		},
		AttributeStatements: []saml.AttributeStatement{
			{Attributes: attrs},
		},
	}
}

func samlTestAttr(name string, values ...string) saml.Attribute {
	out := saml.Attribute{Name: name}
	for _, v := range values {
		out.Values = append(out.Values, saml.AttributeValue{Value: v})
	}
	return out
}

func TestExtractSAMLIdentity_DefaultAttributes(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertion("alice@example.com",
		samlTestAttr("displayName", "Alice Example"),
		samlTestAttr("groups", "users", "finance"),
	), &SAMLProfileConfig{}, "saml-profile")

	if id.Provider != "saml-profile" {
		t.Fatalf("Provider = %q, want saml-profile", id.Provider)
	}
	if id.Sub != "alice@example.com" {
		t.Fatalf("Sub = %q, want alice@example.com", id.Sub)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", id.Email)
	}
	if id.Name != "Alice Example" {
		t.Fatalf("Name = %q, want Alice Example", id.Name)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "users" || id.Groups[1] != "finance" {
		t.Fatalf("Groups = %v, want [users finance]", id.Groups)
	}
}

func TestExtractSAMLIdentity_ConfiguredAttributes(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertion("persistent-id-123",
		samlTestAttr("mail", "alice@example.com"),
		samlTestAttr("cn", "Alice Example"),
		samlTestAttr("memberOf", "Engineering", "Admins"),
	), &SAMLProfileConfig{
		EmailAttribute:  "mail",
		NameAttribute:   "cn",
		GroupsAttribute: "memberOf",
	}, "corp-saml")

	if id.Sub != "persistent-id-123" {
		t.Fatalf("Sub = %q, want persistent-id-123", id.Sub)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", id.Email)
	}
	if id.Name != "Alice Example" {
		t.Fatalf("Name = %q, want Alice Example", id.Name)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "Engineering" || id.Groups[1] != "Admins" {
		t.Fatalf("Groups = %v, want [Engineering Admins]", id.Groups)
	}
}

func TestExtractSAMLIdentity_NilConfigUsesDefaults(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertion("alice@example.com",
		samlTestAttr("groups", "users"),
	), nil, "saml-profile")

	if id.Provider != "saml-profile" {
		t.Fatalf("Provider = %q, want saml-profile", id.Provider)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "users" {
		t.Fatalf("Groups = %v, want [users]", id.Groups)
	}
}

func TestExtractSAMLIdentity_GroupsFeedPolicy(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertion("alice@example.com",
		samlTestAttr("memberOf", "Finance"),
	), &SAMLProfileConfig{GroupsAttribute: "memberOf"}, "saml-profile")

	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:    1,
		Name:        "saml-finance",
		SourceGroup: "finance",
		AuthSource:  "saml:saml-profile",
		Action:      ActionAllow,
	})

	match := ps.Evaluate("10.0.0.1", id.Sub, id.Provider, "app.example.com", id.Groups)
	if match == nil || match.Action != ActionAllow {
		t.Fatalf("expected SAML finance policy allow, got %+v (id=%+v)", match, id)
	}
}
