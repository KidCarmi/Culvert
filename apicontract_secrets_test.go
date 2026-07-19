package main

// Gate 10 (partial) — no secret-like values in the contract or its rendered
// artifacts. Examples must use placeholders only; a real key, token, or private
// address must never be committed into the API documentation.

import (
	"os"
	"regexp"
	"testing"
)

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"PEM private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"AWS access key id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
	{"private IPv4 (10/8)", regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)},
	{"private IPv4 (192.168/16)", regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`)},
	{"private IPv4 (172.16/12)", regexp.MustCompile(`\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`)},
}

func TestOpenAPI_Gate10_NoSecretsInContract(t *testing.T) {
	files := []string{
		"api/openapi/openapi.yaml",
		"api/openapi/openapi.json",
		"api/openapi/index.html",
		"api/openapi/index.public.html",
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, p := range secretPatterns {
			if loc := p.re.FindIndex(b); loc != nil {
				t.Errorf("%s contains a %s at byte %d — contract/docs must use placeholders only", f, p.name, loc[0])
			}
		}
	}
}
