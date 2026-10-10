package main

// saml_middleware_unreachable_test.go — samlsp is not linked at all.
//
// Culvert runs its own SAML AuthnRequest-state + ACS flow (auth_saml.go,
// internal/authstate) and needs only a saml.ServiceProvider. The vendored
// crewjam/saml samlsp package — its Middleware HTTP entry points, cookie
// session provider and request tracker, which carry CodeQL findings in
// third_party/crewjam-saml (open redirect via RelayState, cookies without a
// forced Secure flag) — used to be imported only to assemble that provider.
// It is now not imported anywhere: the provider is built directly
// (newSAMLServiceProvider) and metadata is parsed locally
// (parseSAMLMetadata). These tests keep the package out of every binary and
// pin the replacement to samlsp's behaviour for the options Culvert used.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

const samlspImportPath = "github.com/crewjam/saml/samlsp"

// The authoritative check is the BUILD GRAPH, not a source scan: any package
// of this module (tests included) that pulled samlsp in, directly or through
// another package, would compile its middleware again.
func TestSAMLSPIsNotLinked(t *testing.T) {
	if testing.Short() {
		t.Skip("go list over the module is not a -short check")
	}
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-test", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	pkgs := strings.Fields(string(out))
	if len(pkgs) < 50 || !slices.Contains(pkgs, "github.com/crewjam/saml") {
		t.Fatalf("go list returned an implausible graph (%d packages, crewjam/saml present=%v) — the check would pass against anything", len(pkgs), slices.Contains(pkgs, "github.com/crewjam/saml"))
	}
	for _, p := range pkgs {
		if p == samlspImportPath || strings.HasPrefix(p, samlspImportPath+" ") || strings.HasPrefix(p, samlspImportPath+".") {
			t.Fatalf("%s is linked again; build the ServiceProvider with newSAMLServiceProvider instead", samlspImportPath)
		}
	}
}

// newSAMLServiceProvider must produce what samlsp.DefaultServiceProvider
// produced for Options{URL, Key, Certificate, IDPMetadata,
// AllowIDPInitiated:false} (samlsp/new.go, v0.5.1): metadata/acs/slo URLs
// resolved under the root, no request signing, no forced authn, "/" default
// redirect, POST logout binding, and nothing else set.
func TestNewSAMLServiceProvider_MatchesSAMLSPDefaults(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{}
	idp := &saml.EntityDescriptor{EntityID: "https://idp.example/"}
	for _, root := range []string{"https://proxy.example:9090/", "https://proxy.example/base/"} {
		u, _ := url.Parse(root)
		at := func(p string) url.URL { return *u.ResolveReference(&url.URL{Path: p}) }
		want := saml.ServiceProvider{
			Key: key, Certificate: cert, IDPMetadata: idp,
			MetadataURL: at("saml/metadata"), AcsURL: at("saml/acs"), SloURL: at("saml/slo"),
			DefaultRedirectURI: "/",
			LogoutBindings:     []string{saml.HTTPPostBinding},
		}
		got := newSAMLServiceProvider(u, key, cert, idp)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("root %s: provider differs from samlsp's defaults:\n got %+v\nwant %+v", root, got, want)
		}
		if got.SignatureMethod != "" || got.ForceAuthn != nil || got.AllowIDPInitiated || got.HTTPClient != nil {
			t.Errorf("root %s: request signing, forced authn, IdP-initiated SSO and a custom client must stay off", root)
		}
	}
}

const testIDPEntity = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"></SingleSignOnService></IDPSSODescriptor></EntityDescriptor>`

func TestParseSAMLMetadata(t *testing.T) {
	ed, err := parseSAMLMetadata([]byte(testIDPEntity))
	if err != nil || ed.EntityID != "https://idp.example/" || len(ed.IDPSSODescriptors) != 1 {
		t.Fatalf("single EntityDescriptor: %+v, %v", ed, err)
	}
	// An EntitiesDescriptor yields the first entity that has an IdP role.
	sp := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example/"></EntityDescriptor>`
	both := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + sp + testIDPEntity + `</EntitiesDescriptor>`
	if ed, err = parseSAMLMetadata([]byte(both)); err != nil || ed.EntityID != "https://idp.example/" {
		t.Fatalf("EntitiesDescriptor: %+v, %v", ed, err)
	}
	none := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + sp + `</EntitiesDescriptor>`
	if _, err = parseSAMLMetadata([]byte(none)); err == nil || !strings.Contains(err.Error(), "no entity found with IDPSSODescriptor") {
		t.Fatalf("EntitiesDescriptor without an IdP must be refused: %v", err)
	}
	// The round-trip validator stays in front of the parser: XML whose
	// meaning changes across an encoding/xml round trip (here a multi-colon
	// attribute name, which encoding/xml splits at the first colon) is refused.
	ambiguous := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x" a:b:c="1"></EntityDescriptor>`
	if _, err = parseSAMLMetadata([]byte(ambiguous)); err == nil {
		t.Fatal("metadata that does not survive the round-trip validator must be refused")
	}
	if _, err = parseSAMLMetadata([]byte("not xml")); err == nil {
		t.Fatal("garbage must be refused")
	}
}
