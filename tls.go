package main

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

	// CULVERT_PUBLIC_IP env var — primary way to inject public IP in Docker containers
	// where the IMDS endpoint (169.254.169.254) is unreachable via bridge networking.
	if envIP := os.Getenv("CULVERT_PUBLIC_IP"); envIP != "" {
		for _, s := range strings.Split(envIP, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
				if logger != nil {
					logger.Printf("UITLS: added public IP from CULVERT_PUBLIC_IP: %s", ip)
				}
			} else {
				dns = append(dns, s)
			}
		}
	}

	// Auto-detect cloud public IP via instance metadata (AWS, GCP, Azure).
	// On non-cloud hosts or inside Docker bridge networking, these time out
	// in ~2s and are silently ignored. Use CULVERT_PUBLIC_IP env var instead.
	if cloudIPs := detectCloudPublicIPs(); len(cloudIPs) > 0 {
		ips = append(ips, cloudIPs...)
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
		// Sanitize DNS names (may contain user-provided SANs via --ui-san).
		safeDNS := make([]string, len(dns))
		for i, d := range dns {
			safeDNS[i] = strings.ReplaceAll(strings.ReplaceAll(d, "\n", ""), "\r", "")
		}
		logger.Printf("UITLS: self-signed cert SANs: IPs=%v DNS=%v", ips, safeDNS)
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
// no public IP is assigned. Each provider is tried sequentially; the first
// successful response wins (a host is only on one cloud provider).
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

	// Try AWS first with IMDSv2 (token-based), fall back to IMDSv1.
	if ip := queryAWSMetadata(client); ip != nil {
		return []net.IP{ip}
	}

	// Try GCP and Azure.
	for _, ep := range cloudMetadataEndpoints[1:] { // skip AWS (index 0), handled above
		ip := queryMetadataEndpoint(client, ep)
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
func detectPublicIPFallback(client *http.Client) net.IP {
	// Only try if we appear to be running in a container — avoids adding
	// a NAT gateway IP on developer laptops.
	if !isRunningInContainer() {
		return nil
	}

	for _, ep := range publicIPEndpoints {
		ip := queryMetadataEndpoint(client, ep)
		if ip != nil {
			if logger != nil {
				logger.Printf("UITLS: detected public IP via %s (IMDS unreachable, container fallback): %s", ep.name, ip)
			}
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

// queryAWSMetadata tries IMDSv2 (token-based) first, then falls back to IMDSv1.
// IMDSv2 is required on newer EC2 instances where IMDSv1 is disabled.
func queryAWSMetadata(client *http.Client) net.IP {
	const metadataURL = "http://169.254.169.254/latest/meta-data/public-ipv4"
	const imdsv2SessionURL = "http://169.254.169.254/latest/api/token" // #nosec G101 -- not a credential; IMDS session endpoint URL

	// Step 1: Try IMDSv2 — get a session credential via PUT.
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	imdsReq, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsv2SessionURL, nil)
	if err != nil {
		return nil
	}
	imdsReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	imdsResp, err := client.Do(imdsReq)
	if err == nil {
		defer imdsResp.Body.Close()
		if imdsResp.StatusCode == http.StatusOK {
			sessBody, err := io.ReadAll(io.LimitReader(imdsResp.Body, 256))
			if err == nil && len(sessBody) > 0 {
				sess := strings.TrimSpace(string(sessBody))
				// Step 2: Use session value to query public IP.
				ip := queryMetadataEndpoint(client, cloudMetadataEndpoint{
					name:    "AWS",
					url:     metadataURL,
					headers: map[string]string{"X-aws-ec2-metadata-token": sess}, // #nosec G101 -- AWS IMDS header name, not a credential
				})
				if ip != nil {
					return ip
				}
			}
		}
	}

	// Fallback: IMDSv1 (plain GET, no token).
	return queryMetadataEndpoint(client, cloudMetadataEndpoint{
		name: "AWS",
		url:  metadataURL,
	})
}

// queryMetadataEndpoint makes a single HTTP GET to a cloud metadata URL and
// returns the parsed IP, or nil if the request fails or returns a non-IP.
func queryMetadataEndpoint(client *http.Client, ep cloudMetadataEndpoint) net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, nil)
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
	if ip != nil && logger != nil {
		logger.Printf("UITLS: detected %s public IP: %s", ep.name, ip)
	}
	return ip
}

