package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"golang.org/x/net/html"
)

func setup(t *testing.T) (*fixture, *saml.ServiceProvider) {
	t.Helper()
	f, err := newFixture("http://192.168.1.189:18443", netip.MustParseAddr("192.168.1.189"), &saml.EntityDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	acs, _ := url.Parse("https://192.168.1.111:9090/auth/saml/callback")
	// The real appliance metadata publishes its encryption certificate.
	// Use a separate SP keypair so the fixture must produce an encrypted
	// assertion that only the registered SP can decrypt and verify.
	spKeys, err := newFixture("http://192.168.1.189:18444", f.client, &saml.EntityDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	sp := &saml.ServiceProvider{EntityID: "https://192.168.1.111:9090", AcsURL: *acs,
		Key: spKeys.idp.Key.(*rsa.PrivateKey), Certificate: spKeys.idp.Certificate,
		IDPMetadata: f.idp.Metadata(), AuthnNameIDFormat: saml.EmailAddressNameIDFormat}
	f.sp = sp.Metadata()
	return f, sp
}

func loginURL(t *testing.T, f *fixture, sp *saml.ServiceProvider, user string) (string, string) {
	t.Helper()
	authn, err := sp.MakeAuthenticationRequest(f.idp.SSOURL.String(), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	u, err := authn.Redirect("synthetic-relay", sp)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("fixture_user", user)
	u.RawQuery = q.Encode()
	return u.String(), authn.ID
}

func issue(f *fixture, target, peer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = peer
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	return w
}

func formValues(t *testing.T, reader io.Reader) url.Values {
	t.Helper()
	n, err := html.Parse(reader)
	if err != nil {
		t.Fatal(err)
	}
	form := make(url.Values)
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "input" {
			name, value := "", ""
			for _, a := range node.Attr {
				if a.Key == "name" {
					name = a.Val
				}
				if a.Key == "value" {
					value = a.Val
				}
			}
			form.Set(name, value)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(n)
	return form
}

func TestSignedBrowserFormVerifiesWithPinnedMetadata(t *testing.T) {
	for _, user := range []string{"alice", "bob"} {
		t.Run(user, func(t *testing.T) {
			f, sp := setup(t)
			target, requestID := loginURL(t, f, sp, user)
			w := issue(f, target, "192.168.1.189:50000")
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			form := formValues(t, w.Body)
			if form.Get("RelayState") != "synthetic-relay" {
				t.Fatal("relay mismatch")
			}
			r := httptest.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			assertion, err := sp.ParseResponse(r, []string{requestID})
			if err != nil {
				var invalid *saml.InvalidResponseError
				if errors.As(err, &invalid) {
					t.Fatal(invalid.PrivateErr)
				}
				t.Fatal(err)
			}
			if assertion.Subject.NameID.Value != user+"@example.com" {
				t.Fatal("subject mismatch")
			}
			wantGroup := "engineering"
			if user == "bob" {
				wantGroup = "finance"
			}
			found := false
			for _, statement := range assertion.AttributeStatements {
				for _, attribute := range statement.Attributes {
					for _, value := range attribute.Values {
						if value.Value == wantGroup {
							found = true
						}
					}
				}
			}
			if !found {
				t.Fatal("group missing")
			}
			if got := issue(f, target, "192.168.1.189:50000").Code; got != 409 {
				t.Fatalf("repeat status %d", got)
			}
		})
	}
}

func TestRefusesOtherBrowserPeerAndUnregisteredSP(t *testing.T) {
	f, sp := setup(t)
	target, _ := loginURL(t, f, sp, "alice")
	if got := issue(f, target, "192.168.1.112:50000").Code; got != 403 {
		t.Fatalf("peer status %d", got)
	}
	sp.EntityID = "https://other.example"
	target, _ = loginURL(t, f, sp, "alice")
	if got := issue(f, target, "192.168.1.189:50000").Code; got != 400 {
		t.Fatalf("SP status %d", got)
	}
	if len(f.issued) != 0 {
		t.Fatal("refusal issued assertion")
	}
}

func TestSPMetadataHashEntityAndCallbackBinding(t *testing.T) {
	f, sp := setup(t)
	raw, err := xml.Marshal(f.sp)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	if _, err := validateSP(raw, digest, sp.EntityID); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"hash", "entity", "callback"} {
		data, expected, base := append([]byte(nil), raw...), digest, sp.EntityID
		switch change {
		case "hash":
			expected = strings.Repeat("0", 64)
		case "entity":
			base = "https://192.168.1.112:9090"
		case "callback":
			data = []byte(strings.ReplaceAll(string(raw), "/auth/saml/callback", "/wrong"))
			sum := sha256.Sum256(data)
			expected = hex.EncodeToString(sum[:])
		}
		if _, err := validateSP(data, expected, base); err == nil {
			t.Fatalf("accepted changed %s", change)
		}
	}
}
