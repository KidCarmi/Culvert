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
