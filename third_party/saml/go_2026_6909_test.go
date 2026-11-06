package saml

// Regression tests for the Culvert fork patches that fix GO-2026-6909. See
// PATCHES.md. Each test fails (or panics) against unpatched v0.5.1.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const go6909IdPEntityID = "https://idp.example.com/metadata"

func go6909ServiceProvider(t *testing.T) *ServiceProvider {
	t.Helper()
	acs, err := url.Parse("https://sp.example.com/saml/acs")
	if err != nil {
		t.Fatal(err)
	}
	return &ServiceProvider{
		EntityID:          "https://sp.example.com/saml/metadata",
		AcsURL:            *acs,
		IDPMetadata:       &EntityDescriptor{EntityID: go6909IdPEntityID},
		AllowIDPInitiated: true,
	}
}

// go6909Assertion returns an assertion that validateAssertion accepts for
// go6909ServiceProvider at now.
func go6909Assertion(sp *ServiceProvider, now time.Time) *Assertion {
	return &Assertion{
		ID:           "id-go6909",
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       Issuer{Value: go6909IdPEntityID},
		Subject: &Subject{
			NameID: &NameID{Format: string(EmailAddressNameIDFormat), Value: "alice@example.com"},
			SubjectConfirmations: []SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &SubjectConfirmationData{
					Recipient:    sp.AcsURL.String(),
					NotOnOrAfter: now.Add(time.Minute),
				},
			}},
		},
		Conditions: &Conditions{
			NotBefore:            now.Add(-time.Minute),
			NotOnOrAfter:         now.Add(time.Minute),
			AudienceRestrictions: []AudienceRestriction{{Audience: Audience{Value: sp.EntityID}}},
		},
	}
}

// go6909Validate calls validateAssertion and turns a panic into a test failure
// so every case reports instead of aborting the test binary.
func go6909Validate(t *testing.T, sp *ServiceProvider, a *Assertion, now time.Time) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("validateAssertion panicked instead of returning an error: %v", r)
			err = nil
		}
	}()
	return sp.validateAssertion(a, nil, now)
}

func TestGO20266909ValidateAssertionAcceptsWellFormedAssertion(t *testing.T) {
	sp := go6909ServiceProvider(t)
	now := time.Now()
	if err := go6909Validate(t, sp, go6909Assertion(sp, now), now); err != nil {
		t.Fatalf("well-formed assertion rejected: %v", err)
	}
}

// Fix (a): an assertion without <saml:Issuer> is an error, never a panic, and
// is rejected even when the IdP metadata carries no entityID to compare with.
func TestGO20266909ValidateAssertionRejectsMissingIssuer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		idpEntityID string
	}{
		{"idp metadata has entityID", go6909IdPEntityID},
		{"idp metadata has empty entityID", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := go6909ServiceProvider(t)
			sp.IDPMetadata.EntityID = tc.idpEntityID
			now := time.Now()
			a := go6909Assertion(sp, now)
			a.Issuer = Issuer{}
			err := go6909Validate(t, sp, a, now)
			if err == nil {
				t.Fatal("assertion without Issuer was accepted")
			}
			if tc.idpEntityID == "" && !strings.Contains(err.Error(), "Issuer") {
				t.Fatalf("error %q does not name the missing Issuer", err)
			}
		})
	}
}

// Fix (a), the v0.5.1 shape of the advisory's nil dereference: every optional
// pointer validateAssertion dereferences after signature verification.
func TestGO20266909ValidateAssertionRejectsMissingElementsWithoutPanic(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Assertion)
	}{
		{"no Subject", func(a *Assertion) { a.Subject = nil }},
		{"no SubjectConfirmationData", func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = nil
		}},
		{"no Conditions", func(a *Assertion) { a.Conditions = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := go6909ServiceProvider(t)
			now := time.Now()
			a := go6909Assertion(sp, now)
			tc.mutate(a)
			if err := go6909Validate(t, sp, a, now); err == nil {
				t.Fatal("malformed assertion was accepted")
			}
		})
	}
}

const go6909AssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

func go6909Unmarshal(t *testing.T, doc string) *Assertion {
	t.Helper()
	var a Assertion
	if err := xml.Unmarshal([]byte(doc), &a); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, doc)
	}
	return &a
}

func go6909NameIDValue(a *Assertion) string {
	if a.Subject == nil || a.Subject.NameID == nil {
		return ""
	}
	return a.Subject.NameID.Value
}

// Fix (b): Subject.NameID binds only to NameID in the SAML assertion namespace.
func TestGO20266909SubjectNameIDRequiresAssertionNamespace(t *testing.T) {
	const head = `<saml:Assertion xmlns:saml="` + go6909AssertionNS + `" ID="id-1" Version="2.0" IssueInstant="2026-11-06T00:00:00Z">` +
		`<saml:Issuer>` + go6909IdPEntityID + `</saml:Issuer>`
	const tail = `</saml:Assertion>`
	for _, tc := range []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "prefixed saml:NameID",
			doc:  head + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID></saml:Subject>` + tail,
			want: "alice@example.com",
		},
		{
			name: "default namespace",
			doc: `<Assertion xmlns="` + go6909AssertionNS + `" ID="id-1" Version="2.0" IssueInstant="2026-11-06T00:00:00Z">` +
				`<Issuer>` + go6909IdPEntityID + `</Issuer><Subject><NameID>alice@example.com</NameID></Subject></Assertion>`,
			want: "alice@example.com",
		},
		{
			name: "other prefix declared on the element",
			doc:  head + `<saml:Subject><a:NameID xmlns:a="` + go6909AssertionNS + `">alice@example.com</a:NameID></saml:Subject>` + tail,
			want: "alice@example.com",
		},
		{
			name: "foreign-namespace NameID only",
			doc:  head + `<saml:Subject><evil:NameID xmlns:evil="urn:example:not-saml" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@example.com</evil:NameID></saml:Subject>` + tail,
			want: "",
		},
		{
			name: "unqualified NameID inside saml:Subject",
			doc:  head + `<saml:Subject><NameID>admin@example.com</NameID></saml:Subject>` + tail,
			want: "",
		},
		{
			name: "foreign NameID after the real one",
			doc: head + `<saml:Subject><saml:NameID>alice@example.com</saml:NameID>` +
				`<evil:NameID xmlns:evil="urn:example:not-saml">admin@example.com</evil:NameID></saml:Subject>` + tail,
			want: "alice@example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := go6909NameIDValue(go6909Unmarshal(t, tc.doc)); got != tc.want {
				t.Fatalf("Subject.NameID.Value = %q, want %q", got, tc.want)
			}
		})
	}
}

func go6909AttributeValues(a *Assertion) []string {
	var out []string
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			for _, v := range attr.Values {
				out = append(out, attr.Name+"="+v.Value)
			}
		}
	}
	return out
}

// Fix (b), same flaw one level over: an SP reads identity and group claims
// from AttributeStatement/Attribute/AttributeValue, which used bare tags too.
func TestGO20266909AttributesRequireAssertionNamespace(t *testing.T) {
	const head = `<saml:Assertion xmlns:saml="` + go6909AssertionNS + `" ID="id-1" Version="2.0" IssueInstant="2026-11-06T00:00:00Z">` +
		`<saml:Issuer>` + go6909IdPEntityID + `</saml:Issuer>`
	const tail = `</saml:Assertion>`
	const evil = `xmlns:evil="urn:example:not-saml"`
	for _, tc := range []struct {
		name string
		doc  string
		want []string
	}{
		{
			name: "prefixed attributes",
			doc:  head + `<saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` + tail,
			want: []string{"groups=staff"},
		},
		{
			name: "default namespace attributes",
			doc: `<Assertion xmlns="` + go6909AssertionNS + `" ID="id-1" Version="2.0" IssueInstant="2026-11-06T00:00:00Z"><Issuer>x</Issuer>` +
				`<AttributeStatement><Attribute Name="groups"><AttributeValue>staff</AttributeValue></Attribute></AttributeStatement></Assertion>`,
			want: []string{"groups=staff"},
		},
		{
			name: "foreign AttributeStatement",
			doc:  head + `<evil:AttributeStatement ` + evil + `><evil:Attribute Name="groups"><evil:AttributeValue>admins</evil:AttributeValue></evil:Attribute></evil:AttributeStatement>` + tail,
			want: nil,
		},
		{
			name: "foreign Attribute in saml:AttributeStatement",
			doc:  head + `<saml:AttributeStatement><evil:Attribute ` + evil + ` Name="groups"><evil:AttributeValue>admins</evil:AttributeValue></evil:Attribute></saml:AttributeStatement>` + tail,
			want: nil,
		},
		{
			name: "foreign AttributeValue in saml:Attribute",
			doc: head + `<saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue>` +
				`<evil:AttributeValue ` + evil + `>admins</evil:AttributeValue></saml:Attribute></saml:AttributeStatement>` + tail,
			want: []string{"groups=staff"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := go6909AttributeValues(go6909Unmarshal(t, tc.doc))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("attributes = %q, want %q", got, tc.want)
			}
		})
	}
}

// The production parse path serializes the assertion out of the enclosing
// Response (unmarshalElement); a prefix declared only on the Response must
// still resolve to the assertion namespace.
func TestGO20266909NameIDPrefixDeclaredOnResponse(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="` + go6909AssertionNS + `">` +
		`<saml:Assertion ID="id-1" Version="2.0" IssueInstant="2026-11-06T00:00:00Z"><saml:Issuer>x</saml:Issuer>` +
		`<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`)
	if err != nil {
		t.Fatal(err)
	}
	els, err := findChildren(doc.Root(), go6909AssertionNS, "Assertion")
	if err != nil || len(els) != 1 {
		t.Fatalf("findChildren = %d elements, %v", len(els), err)
	}
	var a Assertion
	if err := unmarshalElement(els[0], &a); err != nil {
		t.Fatal(err)
	}
	if got := go6909NameIDValue(&a); got != "alice@example.com" {
		t.Fatalf("Subject.NameID.Value = %q, want alice@example.com", got)
	}
}

// Fix (c): end to end through ParseXMLResponse with a real assertion
// signature. The IdP signs (exclusive c14n, as IdentityProvider does) an
// assertion whose Subject holds the real saml:NameID followed by a
// foreign-namespace p:NameID. The Response wrapper is NOT signed, so whoever
// relays it (the user's browser in the POST binding) can edit it without
// breaking the assertion signature. The relay moves the xmlns:p declaration
// from the NameID to the Response (exclusive c14n renders it on the NameID
// either way, so the signature still verifies) and adds an element, deeper in
// the document than the NameID, that binds p to the SAML assertion namespace.
// unmarshalElement used to serialize the assertion with a document-wide
// prefix map in which that deeper binding won, so the foreign p:NameID parsed
// as saml:NameID even with the namespace-qualified struct tag of fix (b).
func TestGO20266909SignedAssertionPrefixRebindingDoesNotSpoofNameID(t *testing.T) {
	sp := go6909ServiceProvider(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6909),
		Subject:      pkix.Name{CommonName: "go-2026-6909 test IdP"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sp.IDPMetadata.IDPSSODescriptors = []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
		KeyDescriptors: []KeyDescriptor{{Use: "signing", KeyInfo: KeyInfo{X509Data: X509Data{
			X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(der)}},
		}}}},
	}}}}

	now := time.Now()
	assertionEl := go6909Assertion(sp, now).Element()
	var subject *etree.Element
	for _, child := range assertionEl.ChildElements() {
		if child.Tag == "Subject" {
			subject = child
		}
	}
	foreign := etree.NewElement("p:NameID")
	foreign.CreateAttr("xmlns:p", "urn:example:not-saml")
	foreign.CreateAttr("Format", string(EmailAddressNameIDFormat))
	foreign.SetText("admin@example.com")
	subject.InsertChildAt(1, foreign) // right after the real saml:NameID

	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}))
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(canonicalizerPrefixList)
	signedAssertion, err := signer.SignEnveloped(assertionEl)
	if err != nil {
		t.Fatal(err)
	}

	responseEl := (&Response{
		ID:           "id-response",
		IssueInstant: now,
		Version:      "2.0",
		Destination:  sp.AcsURL.String(),
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
	}).Element()
	responseEl.AddChild(signedAssertion)

	parse := func(t *testing.T, relayEdits bool) *Assertion {
		t.Helper()
		doc := etree.NewDocument()
		doc.SetRoot(responseEl.Copy())
		if relayEdits {
			nameID := doc.Root().FindElement(".//Subject").ChildElements()[1] // the p:NameID
			nameID.RemoveAttr("xmlns:p")
			doc.Root().CreateAttr("xmlns:p", "urn:example:not-saml")
			deep := doc.Root().CreateElement("samlp:Extensions").CreateElement("a").CreateElement("b")
			deep.CreateElement("p:X").CreateAttr("xmlns:p", go6909AssertionNS)
		}
		buf, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		assertion, err := sp.ParseXMLResponse(buf, nil, sp.AcsURL)
		if err != nil {
			t.Fatalf("ParseXMLResponse rejected the IdP-signed assertion: %v (%v)", err, err.(*InvalidResponseError).PrivateErr)
		}
		return assertion
	}

	t.Run("as signed", func(t *testing.T) {
		if got := go6909NameIDValue(parse(t, false)); got != "alice@example.com" {
			t.Fatalf("Subject.NameID.Value = %q, want alice@example.com", got)
		}
	})
	t.Run("relay rebinds the foreign prefix", func(t *testing.T) {
		if got := go6909NameIDValue(parse(t, true)); got != "alice@example.com" {
			t.Fatalf("Subject.NameID.Value = %q, want alice@example.com", got)
		}
	})
}
