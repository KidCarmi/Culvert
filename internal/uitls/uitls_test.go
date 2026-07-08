package uitls

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func parseLeaf(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }

func TestDeduplicateIPs(t *testing.T) {
	in := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("127.0.0.1"), // dup
	}
	out := deduplicateIPs(in)
	if len(out) != 2 {
		t.Errorf("deduplicateIPs len = %d, want 2 (%v)", len(out), out)
	}
}

func TestDeduplicateStrings(t *testing.T) {
	out := deduplicateStrings([]string{"a", "b", "a", "c", "b"})
	if len(out) != 3 {
		t.Errorf("deduplicateStrings len = %d, want 3 (%v)", len(out), out)
	}
	if out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Errorf("order not preserved: %v", out)
	}
}

func TestAppendEnvPublicIPs(t *testing.T) {
	t.Setenv("CULVERT_PUBLIC_IP", "203.0.113.7, ui.example.com, ,198.51.100.9")
	ips, dns := appendEnvPublicIPs(nil, nil)
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("203.0.113.7")) || !ips[1].Equal(net.ParseIP("198.51.100.9")) {
		t.Errorf("ips = %v, want the two literals", ips)
	}
	if len(dns) != 1 || dns[0] != "ui.example.com" {
		t.Errorf("dns = %v, want [ui.example.com]", dns)
	}
}

func TestAppendEnvPublicIPs_Unset(t *testing.T) {
	t.Setenv("CULVERT_PUBLIC_IP", "")
	ips, dns := appendEnvPublicIPs([]net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	if len(ips) != 1 || len(dns) != 1 {
		t.Errorf("unset env must be a no-op, got ips=%v dns=%v", ips, dns)
	}
}

func TestQueryMetadataEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing header", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("203.0.113.55\n"))
	}))
	defer srv.Close()

	client := srv.Client()
	ip := queryMetadataEndpoint(client, cloudMetadataEndpoint{
		name:    "test",
		url:     srv.URL,
		headers: map[string]string{"Metadata-Flavor": "Google"},
	})
	if ip == nil || !ip.Equal(net.ParseIP("203.0.113.55")) {
		t.Errorf("ip = %v, want 203.0.113.55", ip)
	}

	// Missing header → 403 → nil.
	if ip := queryMetadataEndpoint(client, cloudMetadataEndpoint{name: "test", url: srv.URL}); ip != nil {
		t.Errorf("expected nil on non-200, got %v", ip)
	}
}

func TestQueryMetadataEndpoint_NonIPBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not an ip"))
	}))
	defer srv.Close()
	if ip := queryMetadataEndpoint(srv.Client(), cloudMetadataEndpoint{name: "test", url: srv.URL}); ip != nil {
		t.Errorf("expected nil for non-IP body, got %v", ip)
	}
}

func TestIMDSv2Token(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("session-token-value\n"))
	}))
	defer srv.Close()

	if got := imdsv2Token(srv.Client(), srv.URL); got != "session-token-value" {
		t.Errorf("imdsv2Token = %q, want session-token-value", got)
	}
}

func TestIMDSv2Token_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	if got := imdsv2Token(srv.Client(), srv.URL); got != "" {
		t.Errorf("imdsv2Token on 403 = %q, want empty", got)
	}
}

func TestCollectSANs_BaselineAndExtras(t *testing.T) {
	t.Setenv("CULVERT_PUBLIC_IP", "") // keep the env path inert
	ips, dns := collectSANs([]string{"192.0.2.10", "admin.example.com", ""})

	hasIP := func(want string) bool {
		for _, ip := range ips {
			if ip.Equal(net.ParseIP(want)) {
				return true
			}
		}
		return false
	}
	if !hasIP("127.0.0.1") || !hasIP("::1") {
		t.Errorf("baseline loopback SANs missing: %v", ips)
	}
	if !hasIP("192.0.2.10") {
		t.Errorf("extra IP SAN missing: %v", ips)
	}
	hasDNS := func(want string) bool {
		for _, d := range dns {
			if d == want {
				return true
			}
		}
		return false
	}
	if !hasDNS("localhost") || !hasDNS("admin.example.com") {
		t.Errorf("DNS SANs missing: %v", dns)
	}
}

func TestSelfSigned_CertParsesAndCoversLoopback(t *testing.T) {
	t.Setenv("CULVERT_PUBLIC_IP", "")
	cfg, err := SelfSigned([]string{"selftest.example.com"})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	leaf := cfg.Certificates[0].Leaf
	if leaf == nil {
		// tls.X509KeyPair leaves Leaf unset on some Go versions; parse manually.
		var perr error
		leaf, perr = parseLeaf(cfg.Certificates[0].Certificate[0])
		if perr != nil {
			t.Fatalf("parse leaf: %v", perr)
		}
	}
	if err := leaf.VerifyHostname("selftest.example.com"); err != nil {
		t.Errorf("cert must cover the extra SAN: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("cert must cover loopback: %v", err)
	}
	if time.Now().After(leaf.NotAfter) {
		t.Error("certificate already expired")
	}
}
