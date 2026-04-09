package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// uiExtraSANs holds additional SANs for the self-signed UI TLS cert,
// set from --ui-san flag / proxy.ui_sans config before startUI() is called.
var uiExtraSANs []string

// selfSignedTLS generates a self-signed TLS certificate that includes all
// local network interface IPs (so remote access via private/Docker IPs works)
// plus any extra SANs from uiExtraSANs (--ui-san / config).
func selfSignedTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Baseline SANs — always present.
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	dns := []string{"localhost"}

	// Auto-detect all local interface IPs (private, Docker bridge, etc.).
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			cidr, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := cidr.IP
			if ip.IsLoopback() {
				continue // already in baseline
			}
			ips = append(ips, ip)
		}
	}

	// Add hostname.
	if h, err := os.Hostname(); err == nil && h != "" && h != "localhost" {
		dns = append(dns, h)
	}

	// Parse extra SANs: IPs go to IPAddresses, everything else to DNSNames.
	for _, san := range uiExtraSANs {
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, san)
		}
	}

	// Deduplicate.
	ips = deduplicateIPs(ips)
	dns = deduplicateStrings(dns)

	// Log SANs so admins can verify what the cert covers.
	if logger != nil {
		logger.Printf("UITLS: self-signed cert SANs: IPs=%v DNS=%v", ips, dns)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Culvert UI"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              dns,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// deduplicateIPs returns a deduplicated copy of the IP slice.
func deduplicateIPs(in []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(in))
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// deduplicateStrings returns a deduplicated copy of the string slice.
func deduplicateStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

