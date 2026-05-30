package main

import (
	"testing"

	"github.com/crewjam/saml"
)

func samlTestAssertion(nameID string, attrs ...saml.Attribute) *saml.Assertion {
	return samlTestAssertionWithFormat(nameID, string(saml.EmailAddressNameIDFormat), attrs...)
}

func samlTestAssertionWithFormat(nameID, format string, attrs ...saml.Attribute) *saml.Assertion {
	return &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: nameID, Format: format},
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

func samlTestFriendlyAttr(name, friendlyName string, values ...string) saml.Attribute {
	out := samlTestAttr(name, values...)
	out.FriendlyName = friendlyName
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

func TestExtractSAMLIdentity_MatchesFriendlyAttributeNames(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertionWithFormat(
		"persistent-id-123",
		string(saml.PersistentNameIDFormat),
		samlTestFriendlyAttr("urn:oid:0.9.2342.19200300.100.1.3", "email", "alice@example.com"),
		samlTestFriendlyAttr("urn:oid:2.5.4.3", "displayName", "Alice Example"),
		samlTestFriendlyAttr("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "groups", "users", "finance"),
	), &SAMLProfileConfig{}, "corp-saml")

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

func TestExtractSAMLIdentity_MatchesEduPersonAffiliationGroups(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertionWithFormat(
		"persistent-id-123",
		string(saml.PersistentNameIDFormat),
		samlTestFriendlyAttr("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "eduPersonAffiliation", "users", "finance"),
	), &SAMLProfileConfig{}, "corp-saml")

	if len(id.Groups) != 2 || id.Groups[0] != "users" || id.Groups[1] != "finance" {
		t.Fatalf("Groups = %v, want [users finance]", id.Groups)
	}
}

func TestExtractSAMLIdentity_EmailFallbackForEmptyNameID(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertion("",
		samlTestAttr("email", "alice@example.com"),
	), &SAMLProfileConfig{}, "saml-profile")

	if id.Sub != "alice@example.com" {
		t.Fatalf("Sub = %q, want email fallback alice@example.com", id.Sub)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", id.Email)
	}
}

func TestExtractSAMLIdentity_NoStableIdentity(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertion(""), &SAMLProfileConfig{}, "saml-profile")

	if id.Sub != "" || id.Email != "" {
		t.Fatalf("expected no stable identity, got Sub=%q Email=%q", id.Sub, id.Email)
	}
	if err := requireStableSAMLIdentity(id); err == nil {
		t.Fatal("expected missing stable identity to fail closed")
	}
}

func TestExtractSAMLIdentity_RejectsTransientNameID(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertionWithFormat(
		"session-only-id",
		string(saml.TransientNameIDFormat),
	), &SAMLProfileConfig{}, "saml-profile")

	if id.Sub != "" {
		t.Fatalf("transient NameID was accepted as Sub=%q", id.Sub)
	}
	if err := requireStableSAMLIdentity(id); err == nil {
		t.Fatal("expected transient-only NameID to fail stable identity check")
	}
}

func TestExtractSAMLIdentity_RejectsUnspecifiedNameID(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertionWithFormat(
		"maybe-stable-id",
		string(saml.UnspecifiedNameIDFormat),
	), &SAMLProfileConfig{}, "saml-profile")

	if id.Sub != "" {
		t.Fatalf("unspecified NameID was accepted as Sub=%q", id.Sub)
	}
	if err := requireStableSAMLIdentity(id); err == nil {
		t.Fatal("expected unspecified-only NameID to fail stable identity check")
	}
}

func TestExtractSAMLIdentity_TransientNameIDUsesEmailFallback(t *testing.T) {
	id := extractSAMLIdentity(samlTestAssertionWithFormat(
		"session-only-id",
		string(saml.TransientNameIDFormat),
		samlTestAttr("email", "alice@example.com"),
	), &SAMLProfileConfig{}, "saml-profile")

	if id.Sub != "alice@example.com" {
		t.Fatalf("Sub = %q, want email fallback alice@example.com", id.Sub)
	}
	if err := requireStableSAMLIdentity(id); err != nil {
		t.Fatalf("email fallback should satisfy stable identity check: %v", err)
	}
}

func TestRequestedSAMLNameIDFormat_DefaultsStable(t *testing.T) {
	if got := requestedSAMLNameIDFormat(nil); got != string(saml.EmailAddressNameIDFormat) {
		t.Fatalf("requestedSAMLNameIDFormat(nil) = %q, want emailAddress", got)
	}
}

func TestValidateSAMLNameIDFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{name: "default", format: "", wantErr: false},
		{name: "email", format: string(saml.EmailAddressNameIDFormat), wantErr: false},
		{name: "persistent", format: string(saml.PersistentNameIDFormat), wantErr: false},
		{name: "transient", format: string(saml.TransientNameIDFormat), wantErr: true},
		{name: "unspecified", format: string(saml.UnspecifiedNameIDFormat), wantErr: true},
		{name: "unknown", format: "urn:example:nameid:custom", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSAMLNameIDFormat(tt.format)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSAMLNameIDFormat(%q) error = %v, wantErr %v", tt.format, err, tt.wantErr)
			}
		})
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
