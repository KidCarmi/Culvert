package main

import (
	"os"
	"strings"
	"testing"
)

func TestSAMLDocsNameIDFormatAllowlistMatchesCode(t *testing.T) {
	data, err := os.ReadFile("docs/saml-idp-configuration-reference.md")
	if err != nil {
		t.Fatalf("read SAML docs: %v", err)
	}
	doc := string(data)

	start := strings.Index(doc, "## NameID Format Reference")
	end := strings.Index(doc, "The SP defaults to `emailAddress`")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not find SAML NameID format reference section")
	}
	section := doc[start:end]

	allowedRows := []string{
		"| **emailAddress** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |",
		"| **persistent** | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |",
	}
	for _, row := range allowedRows {
		if !strings.Contains(section, row) {
			t.Fatalf("NameID format reference is missing allowed row %q", row)
		}
	}

	forbidden := []string{"transient", "unspecified", "kerberos", "windowsDomain"}
	for _, value := range forbidden {
		if strings.Contains(section, value) {
			t.Fatalf("NameID format reference still presents unsupported format %q", value)
		}
	}
	if !strings.Contains(doc, "Culvert rejects transient, unspecified, custom, and provider-specific shorthand formats") {
		t.Fatal("SAML docs should explicitly warn that unstable NameID formats are rejected")
	}
}

func TestSAMLDocsDoNotRecommendDefaultRelayState(t *testing.T) {
	data, err := os.ReadFile("docs/saml-idp-configuration-reference.md")
	if err != nil {
		t.Fatalf("read SAML docs: %v", err)
	}
	doc := string(data)

	required := []string{
		"| **Relay State** | Leave blank | Culvert supplies an opaque RelayState for each SP-initiated login |",
		"| **Default RelayState** | Leave blank |",
		"Do not configure an IdP default RelayState as a landing page",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) {
			t.Fatalf("SAML docs missing RelayState guidance %q", want)
		}
	}

	forbidden := []string{
		"Passed through unchanged",
		"set to your post-login landing page",
	}
	for _, value := range forbidden {
		if strings.Contains(doc, value) {
			t.Fatalf("SAML docs still contain unsafe RelayState guidance %q", value)
		}
	}
}

func TestSAMLDocsUseRegisteredCallbackURL(t *testing.T) {
	data, err := os.ReadFile("docs/saml-idp-configuration-reference.md")
	if err != nil {
		t.Fatalf("read SAML docs: %v", err)
	}
	doc := string(data)

	if !strings.Contains(doc, "https://<base_url>/auth/saml/callback") {
		t.Fatal("SAML docs should tell operators to use the registered callback URL")
	}
	if !strings.Contains(doc, "| **SP Entity ID** | `https://<base_url>` |") {
		t.Fatal("SAML docs should match the runtime SP EntityID")
	}
	if !strings.Contains(doc, "| **SP Metadata URL** | `https://<base_url>/auth/saml/metadata` |") {
		t.Fatal("SAML docs should publish the runtime SP metadata URL")
	}
	forbidden := []string{
		"https://<base_url>/saml/acs",
		"https://<base_url>/saml/metadata",
		"SP Metadata URL** | `https://<base_url>`",
		"Import data about the relying party published online",
		"Import from SP metadata",
	}
	for _, value := range forbidden {
		if strings.Contains(doc, value) {
			t.Fatalf("SAML docs still contain stale SP URL guidance %q", value)
		}
	}
}
