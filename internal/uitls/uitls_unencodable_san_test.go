package uitls

import (
	"strings"
	"testing"
)

// An operator-supplied SAN that x509 cannot encode as an IA5String (a
// Unicode IDN typed as-is, e.g. "café.example.com", via -ui-san, the admin
// network settings' ui_sans, or CULVERT_PUBLIC_IP) used to fail
// x509.CreateCertificate for the WHOLE certificate. startUI treats a
// self-sign failure as "fall back to HTTP", so one bad SAN downgraded the
// admin UI — login credentials included — to cleartext on the next start.
// The unencodable entry must be dropped; every encodable SAN must survive.
func TestSelfSigned_UnencodableSANDoesNotFailCertificate(t *testing.T) {
	t.Setenv("CULVERT_PUBLIC_IP", "ünicode.example, 198.51.100.21")
	cfg, err := SelfSigned([]string{"café.example.com", "good.example.com"})
	if err != nil {
		t.Fatalf("SelfSigned with one unencodable SAN must still mint a certificate, got: %v", err)
	}
	leaf, err := parseLeaf(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	for _, host := range []string{"good.example.com", "127.0.0.1", "198.51.100.21", "localhost"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("cert must still cover %q: %v", host, err)
		}
	}
	for _, d := range leaf.DNSNames {
		if strings.ContainsFunc(d, func(r rune) bool { return r > 0x7e }) {
			t.Errorf("unencodable SAN %q leaked into the certificate", d)
		}
	}
}

func TestEncodableDNSSANs(t *testing.T) {
	got := encodableDNSSANs([]string{"localhost", "café.example.com", "good.example.com"})
	want := []string{"localhost", "good.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("encodableDNSSANs = %q, want %q", got, want)
	}
}
