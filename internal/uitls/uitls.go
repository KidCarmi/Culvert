// Package uitls generates the self-signed TLS certificate for the admin UI:
// baseline loopback SANs, all local interface IPs, the hostname, operator
// extras (CULVERT_PUBLIC_IP + --ui-san values passed in by the caller), and
// best-effort cloud public-IP detection via instance metadata. Extracted from
// package main per ADR-0002; the uiExtraSANs global stays in main
// (admin-settings persistence + the ui_extras startup slice own it) and is
// passed to SelfSigned as a parameter.
package uitls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// SelfSigned generates a self-signed TLS certificate that includes all
// local network interface IPs (so remote access via private/Docker IPs works)
// plus any extra SANs (--ui-san / config, passed by the caller).
func SelfSigned(extraSANs []string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	ips, dns := collectSANs(extraSANs)

	// Log SANs so admins can verify what the cert covers.
	// Sanitize DNS names (may contain user-provided SANs via --ui-san).
	safeDNS := make([]string, len(dns))
	for i, d := range dns {
		safeDNS[i] = strings.ReplaceAll(strings.ReplaceAll(d, "\n", ""), "\r", "")
	}
	obs.Printf("UITLS: self-signed cert SANs: IPs=%v DNS=%v", ips, safeDNS)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Culvert UI"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
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

// collectSANs assembles the certificate's IP and DNS SANs: baseline loopback,
// local interface IPs, hostname, CULVERT_PUBLIC_IP entries, cloud-metadata
// public IPs, and the caller's extra SANs — deduplicated.
func collectSANs(extraSANs []string) (ips []net.IP, dns []string) {
	// Baseline SANs — always present.
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	dns = []string{"localhost"}

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

	ips, dns = appendEnvPublicIPs(ips, dns)

	// Auto-detect cloud public IP via instance metadata (AWS, GCP, Azure).
	// On non-cloud hosts or inside Docker bridge networking, these time out
	// in ~2s and are silently ignored. Use CULVERT_PUBLIC_IP env var instead.
	if cloudIPs := detectCloudPublicIPs(); len(cloudIPs) > 0 {
		ips = append(ips, cloudIPs...)
	}

	// Parse extra SANs: IPs go to IPAddresses, everything else to DNSNames.
	for _, san := range extraSANs {
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
	return deduplicateIPs(ips), deduplicateStrings(dns)
}

// appendEnvPublicIPs folds the CULVERT_PUBLIC_IP env var (comma-separated
// IPs or DNS names) into the SAN lists — the primary way to inject a public
// IP in Docker containers where the IMDS endpoint (169.254.169.254) is
// unreachable via bridge networking.
func appendEnvPublicIPs(ips []net.IP, dns []string) (outIPs []net.IP, outDNS []string) {
	envIP := os.Getenv("CULVERT_PUBLIC_IP")
	if envIP == "" {
		return ips, dns
	}
	for _, s := range strings.Split(envIP, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
			obs.Printf("UITLS: added public IP from CULVERT_PUBLIC_IP: %s", ip)
		} else {
			dns = append(dns, s)
		}
	}
	return ips, dns
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

// cloudMetadataEndpoint describes a cloud provider's instance metadata URL
// for discovering the public IP address of this machine.
type cloudMetadataEndpoint struct {
	name    string
	url     string
	headers map[string]string // required headers (e.g. GCP's Metadata-Flavor)
}

// cloudMetadataEndpoints lists the metadata URLs for major cloud providers.
// All use the 169.254.169.254 link-local address (except GCP DNS alias).
// On non-cloud hosts, connections to these addresses time out harmlessly.
var cloudMetadataEndpoints = []cloudMetadataEndpoint{
	{
		name: "AWS",
		url:  "http://169.254.169.254/latest/meta-data/public-ipv4",
	},
	{
		name:    "GCP",
		url:     "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
		headers: map[string]string{"Metadata-Flavor": "Google"},
	},
	{
		name:    "Azure",
		url:     "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text",
		headers: map[string]string{"Metadata": "true"},
	},
}

// detectCloudPublicIPs queries cloud instance metadata APIs to discover
// the machine's public IP address. Returns nil on non-cloud hosts or if
// no public IP is assigned. This runs synchronously on the admin-UI startup
// path (SelfSigned -> collectSANs), on every process start where no explicit
// -tls-cert/-tls-key is configured — the shipped docker-compose.yml default.
//
// Providers are probed CONCURRENTLY, not one after another: a host where
// 169.254.169.254 is unreachable in a way that HANGS rather than fails fast
// (a common enterprise/air-gapped posture — DROPPING rather than REJECTING
// metadata traffic to deter SSRF) used to pay every candidate's own timeout
// in sequence (AWS token + AWS value + GCP + Azure), so total latency grew
// with the number of providers instead of being capped by the slowest single
// one. A host is only ever on one cloud, so the first (precedence-ordered)
// success wins the same as before — only the wall-clock cost of the
// unreachable case changes.
func detectCloudPublicIPs() []net.IP {
	// Short timeout — metadata is local (< 50ms on cloud, times out on bare metal).
	// 2s total allows for IMDSv2 two-step (PUT token + GET IP) on busy instances.
	client := &http.Client{
		Timeout: 2 * time.Second,
		// Don't follow redirects — metadata endpoints return direct responses.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// results[0] = AWS, results[1:] = cloudMetadataEndpoints[1:] (GCP, Azure)
	// in their declared order — preserves the original precedence when
	// picking among successes below.
	results := make([]net.IP, len(cloudMetadataEndpoints))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0] = queryAWSMetadata(client)
	}()
	for i, ep := range cloudMetadataEndpoints[1:] { // skip AWS (index 0), handled above
		i, ep := i+1, ep
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = queryMetadataEndpoint(client, ep)
		}()
	}
	wg.Wait()

	for _, ip := range results {
		if ip != nil {
			return []net.IP{ip}
		}
	}

	// Fallback: IMDS unreachable (e.g. Docker bridge networking where
	// 169.254.169.254 is not routable). Use public IP reflection services.
	// These are trusted, plain-text endpoints from major providers.
	if ip := detectPublicIPFallback(client); ip != nil {
		return []net.IP{ip}
	}

	return nil
}

// publicIPEndpoints are public IP reflection services used as a fallback when
// cloud IMDS is unreachable (e.g. inside Docker bridge-networked containers).
// Each returns the caller's public IP as plain text.
var publicIPEndpoints = []cloudMetadataEndpoint{
	{name: "AWS-checkip", url: "https://checkip.amazonaws.com"},
	{name: "Cloudflare", url: "https://ipv4.icanhazip.com"},
}

// detectPublicIPFallback queries public IP reflection services to discover
// the machine's external IP. Used when IMDS is unreachable (Docker bridge).
// Probed concurrently for the same reason as detectCloudPublicIPs above — an
// unreachable-but-not-refused endpoint must not multiply its timeout by the
// number of fallback services tried.
func detectPublicIPFallback(client *http.Client) net.IP {
	// Only try if we appear to be running in a container — avoids adding
	// a NAT gateway IP on developer laptops.
	if !isRunningInContainer() {
		return nil
	}

	results := make([]net.IP, len(publicIPEndpoints))
	var wg sync.WaitGroup
	for i, ep := range publicIPEndpoints {
		i, ep := i, ep
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = queryMetadataEndpoint(client, ep)
		}()
	}
	wg.Wait()

	for i, ip := range results {
		if ip != nil {
			obs.Printf("UITLS: detected public IP via %s (IMDS unreachable, container fallback): %s", publicIPEndpoints[i].name, ip)
			return ip
		}
	}
	return nil
}

// isRunningInContainer returns true if the process appears to be inside a Docker/OCI container.
func isRunningInContainer() bool {
	// Docker creates /.dockerenv; podman and others use /run/.containerenv.
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// queryAWSMetadata queries AWS IMDS for the public IPv4, preferring IMDSv2.
func queryAWSMetadata(client *http.Client) net.IP {
	const metadataURL = "http://169.254.169.254/latest/meta-data/public-ipv4"
	const imdsv2SessionURL = "http://169.254.169.254/latest/api/token" // #nosec G101 -- not a credential; IMDS session endpoint URL

	// Step 1: Try IMDSv2 — get a session credential via PUT, then use it.
	if sess := imdsv2Token(client, imdsv2SessionURL); sess != "" {
		ip := queryMetadataEndpoint(client, cloudMetadataEndpoint{
			name:    "AWS",
			url:     metadataURL,
			headers: map[string]string{"X-aws-ec2-metadata-token": sess}, // #nosec G101 -- AWS IMDS header name, not a credential
		})
		if ip != nil {
			return ip
		}
	}

	// Fallback: IMDSv1 (plain GET, no token).
	return queryMetadataEndpoint(client, cloudMetadataEndpoint{
		name: "AWS",
		url:  metadataURL,
	})
}

// imdsv2Token fetches an IMDSv2 session token via PUT; "" on any failure
// (the caller falls back to IMDSv1).
func imdsv2Token(client *http.Client, sessionURL string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, sessionURL, http.NoBody)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil || len(body) == 0 {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// queryMetadataEndpoint makes a single HTTP GET to a cloud metadata URL and
// returns the parsed IP, or nil if the request fails or returns a non-IP.
func queryMetadataEndpoint(client *http.Client, ep cloudMetadataEndpoint) net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, http.NoBody)
	if err != nil {
		return nil
	}
	for k, v := range ep.headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil // timeout or not on this cloud — expected
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Read at most 64 bytes — a public IP is at most ~45 chars (IPv6).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return nil
	}

	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil
	}

	ip := net.ParseIP(raw)
	if ip != nil {
		obs.Printf("UITLS: detected %s public IP: %s", ep.name, ip)
	}
	return ip
}
