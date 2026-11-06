package main

// End-to-end regressions for GO-2026-6909 through the real SAML callback path
// (SAMLProvider.ExchangeAssertion -> saml.ServiceProvider.ParseResponse). Every
// response here carries a valid IdP signature; the edits are made before the
// IdP signs, so they model what a signed-but-hostile assertion can contain. The
// library fix lives in third_party/saml (see third_party/saml/PATCHES.md).

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

const (
	go6909SpoofedIdentity = "admin@example.com"
	go6909ForeignNS       = "urn:example:not-saml"
	go6909InjectedGroup   = "culvert-superadmins"
)

// exchangeGO6909 runs the callback and fails the test (rather than the binary)
// if the library panics.
func exchangeGO6909(t *testing.T, fixture signedSAMLFixture) (id *Identity, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ExchangeAssertion panicked instead of rejecting: %v", r)
		}
	}()
	id, _, err = fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	return id, err
}

func go6909Child(t *testing.T, parent *etree.Element, tag string) *etree.Element {
	t.Helper()
	for _, child := range parent.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	t.Fatalf("<%s> has no <%s> child", parent.FullTag(), tag)
	return nil
}

func go6909ChildIndex(t *testing.T, parent *etree.Element, tag string) int {
	t.Helper()
	for i, tok := range parent.Child {
		if el, ok := tok.(*etree.Element); ok && el.Tag == tag {
			return i
		}
	}
	t.Fatalf("<%s> has no <%s> child", parent.FullTag(), tag)
	return -1
}

// go6909NameID builds a NameID element in the given prefix/namespace. An empty
// namespace reuses the assertion's own saml prefix.
func go6909NameID(prefix, namespace, value string) *etree.Element {
	el := etree.NewElement(prefix + ":NameID")
	if namespace != "" {
		el.CreateAttr("xmlns:"+prefix, namespace)
	}
	el.CreateAttr("Format", string(saml.EmailAddressNameIDFormat))
	el.SetText(value)
	return el
}

func TestSAMLGO20266909ForeignNamespaceNameIDDoesNotAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, assertion *etree.Element)
	}{
		{"foreign NameID replaces saml:NameID", func(t *testing.T, a *etree.Element) {
			subject := go6909Child(t, a, "Subject")
			subject.RemoveChildAt(go6909ChildIndex(t, subject, "NameID"))
			subject.InsertChildAt(0, go6909NameID("evil", go6909ForeignNS, go6909SpoofedIdentity))
		}},
		{"foreign NameID after saml:NameID", func(t *testing.T, a *etree.Element) {
			subject := go6909Child(t, a, "Subject")
			subject.InsertChildAt(go6909ChildIndex(t, subject, "NameID")+1,
				go6909NameID("evil", go6909ForeignNS, go6909SpoofedIdentity))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{mutateAssertionEl: tc.mutate})
			id, err := exchangeGO6909(t, fixture)
			if err != nil {
				// Rejecting the response outright is also safe.
				return
			}
			if id.Sub == go6909SpoofedIdentity || id.Email == go6909SpoofedIdentity {
				t.Fatalf("authenticated as the foreign-namespace NameID: Sub=%q Email=%q", id.Sub, id.Email)
			}
			if id.Sub != "alice@example.com" {
				t.Fatalf("Sub = %q, want the IdP's real subject alice@example.com", id.Sub)
			}
		})
	}
}

// Negative control: the same edit with the NameID in the SAML assertion
// namespace IS honored, so the test above is not passing because the edited,
// re-signed response is rejected for an unrelated reason.
func TestSAMLGO20266909AssertionNamespaceNameIDControl(t *testing.T) {
	fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{
		mutateAssertionEl: func(t *testing.T, a *etree.Element) {
			subject := go6909Child(t, a, "Subject")
			subject.RemoveChildAt(go6909ChildIndex(t, subject, "NameID"))
			subject.InsertChildAt(0, go6909NameID("saml", "", go6909SpoofedIdentity))
		},
	})
	id, err := exchangeGO6909(t, fixture)
	if err != nil {
		t.Fatalf("control response rejected: %v", err)
	}
	if id.Sub != go6909SpoofedIdentity {
		t.Fatalf("control Sub = %q, want %q", id.Sub, go6909SpoofedIdentity)
	}
}

// The same namespace-blind binding on AttributeStatement/Attribute/
// AttributeValue would let a foreign-namespace statement supply the email that
// becomes the identity (when the NameID is not a stable format) and the groups
// that feed policy.
func TestSAMLGO20266909ForeignNamespaceAttributesAreIgnored(t *testing.T) {
	fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{
		session: &saml.Session{
			NameID:       "session-only-id",
			NameIDFormat: string(saml.TransientNameIDFormat),
			UserEmail:    "alice@example.com",
			Groups:       []string{"engineering"},
		},
		mutateAssertionEl: func(t *testing.T, a *etree.Element) {
			stmt := etree.NewElement("evil:AttributeStatement")
			stmt.CreateAttr("xmlns:evil", go6909ForeignNS)
			for name, value := range map[string]string{"email": go6909SpoofedIdentity, "groups": go6909InjectedGroup} {
				attr := stmt.CreateElement("evil:Attribute")
				attr.CreateAttr("Name", name)
				attr.CreateElement("evil:AttributeValue").SetText(value)
			}
			// Ahead of the real statement: the first email value wins.
			a.InsertChildAt(go6909ChildIndex(t, a, "AttributeStatement"), stmt)
		},
	})
	id, err := exchangeGO6909(t, fixture)
	if err != nil {
		t.Fatalf("ExchangeAssertion failed: %v", err)
	}
	if id.Sub == go6909SpoofedIdentity || id.Email == go6909SpoofedIdentity {
		t.Fatalf("identity taken from a foreign-namespace attribute: Sub=%q Email=%q", id.Sub, id.Email)
	}
	for _, g := range id.Groups {
		if g == go6909InjectedGroup {
			t.Fatalf("group taken from a foreign-namespace attribute: %v", id.Groups)
		}
	}
	if id.Sub != "alice@example.com" || len(id.Groups) != 1 || id.Groups[0] != "engineering" {
		t.Fatalf("got Sub=%q Groups=%v, want alice@example.com [engineering]", id.Sub, id.Groups)
	}
}

// Signed assertions missing required elements are rejected with an error and
// never panic after signature verification.
func TestSAMLGO20266909MalformedSignedAssertionRejectedWithoutPanic(t *testing.T) {
	remove := func(path ...string) func(t *testing.T, a *etree.Element) {
		return func(t *testing.T, a *etree.Element) {
			parent := a
			for _, tag := range path[:len(path)-1] {
				parent = go6909Child(t, parent, tag)
			}
			parent.RemoveChildAt(go6909ChildIndex(t, parent, path[len(path)-1]))
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, a *etree.Element)
	}{
		{"missing Issuer", remove("Issuer")},
		{"missing Subject", remove("Subject")},
		{"missing SubjectConfirmationData", remove("Subject", "SubjectConfirmation", "SubjectConfirmationData")},
		{"missing Conditions", remove("Conditions")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{mutateAssertionEl: tc.mutate})
			id, err := exchangeGO6909(t, fixture)
			if err == nil {
				t.Fatalf("malformed signed assertion accepted as %+v", id)
			}
			if id != nil {
				t.Fatalf("identity %+v returned alongside error %v", id, err)
			}
			if !strings.Contains(err.Error(), "saml response validation:") {
				t.Fatalf("error %q missing validation context", err)
			}
		})
	}
}
