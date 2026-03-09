package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// PAC (Proxy Auto-Configuration) store
// ---------------------------------------------------------------------------

// PACConfig holds settings for the generated PAC file served at /proxy.pac.
type PACConfig struct {
	// ProxyHost is the hostname or IP of this proxy, e.g. "proxy.corp.com".
	// If empty the /proxy.pac endpoint uses the request's Host header.
	ProxyHost string `json:"proxyHost"`
	// ProxyPort is the proxy port.  Defaults to 8080.
	ProxyPort int `json:"proxyPort"`
	// Exclusions is the list of host patterns that should bypass the proxy.
	// Supports bare domains ("corp.local"), wildcard prefixes ("*.corp.local"),
	// and IP CIDR ranges ("192.168.0.0/16").
	Exclusions []string `json:"exclusions"`
}

// PACStore persists PACConfig to a JSON file.
type PACStore struct {
	mu   sync.RWMutex
	cfg  PACConfig
	path string
}

var pacStore = &PACStore{}

// Load reads config from the JSON file; a missing file is a no-op.
func (s *PACStore) Load(path string) error {
	s.path = path
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pac config: read %s: %w", path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.cfg)
}

// Get returns a snapshot of the current config.
func (s *PACStore) Get() PACConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Exclusions = append([]string(nil), s.cfg.Exclusions...)
	return c
}

// Set replaces the config and persists it.
func (s *PACStore) Set(c PACConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// GeneratePAC builds the PAC JavaScript.
// proxyAddr is the "host:port" string to use when ProxyHost is empty
// (caller passes the request's Host as a fallback).
func (s *PACStore) GeneratePAC(proxyAddr string) string {
	c := s.Get()

	host := c.ProxyHost
	port := c.ProxyPort
	if port == 0 {
		port = 8080
	}
	if host == "" {
		// Fall back to the proxy address derived from the request.
		proxyAddr = strings.TrimPrefix(proxyAddr, "https://")
		proxyAddr = strings.TrimPrefix(proxyAddr, "http://")
		host = proxyAddr
	}
	proxyDirective := fmt.Sprintf("PROXY %s:%d", host, port)
	if host == "" {
		proxyDirective = "DIRECT"
	}

	var sb strings.Builder
	sb.WriteString("function FindProxyForURL(url, host) {\n")
	sb.WriteString("  // Always bypass for plain names and loopback\n")
	sb.WriteString("  if (isPlainHostName(host)) return \"DIRECT\";\n")
	sb.WriteString("  if (isInNet(dnsResolve(host), \"127.0.0.0\", \"255.0.0.0\")) return \"DIRECT\";\n")
	sb.WriteString("  // RFC-1918 private ranges — always DIRECT\n")
	sb.WriteString("  if (isInNet(dnsResolve(host), \"10.0.0.0\",    \"255.0.0.0\"))   return \"DIRECT\";\n")
	sb.WriteString("  if (isInNet(dnsResolve(host), \"172.16.0.0\",  \"255.240.0.0\")) return \"DIRECT\";\n")
	sb.WriteString("  if (isInNet(dnsResolve(host), \"192.168.0.0\", \"255.255.0.0\")) return \"DIRECT\";\n")

	if len(c.Exclusions) > 0 {
		sb.WriteString("\n  // Custom exclusions — go DIRECT\n")
		for _, exc := range c.Exclusions {
			exc = strings.TrimSpace(exc)
			if exc == "" {
				continue
			}
			if isIPCIDR(exc) {
				// IP CIDR — use isInNet with mask derived from prefix length.
				ip, mask, ok := cidrToIPMask(exc)
				if ok {
					sb.WriteString(fmt.Sprintf("  if (isInNet(dnsResolve(host), %q, %q)) return \"DIRECT\";\n", ip, mask))
				}
			} else if strings.HasPrefix(exc, "*.") {
				// *.corp.com → all subdomains of corp.com
				suffix := exc[1:] // .corp.com
				sb.WriteString(fmt.Sprintf("  if (dnsDomainIs(host, %q)) return \"DIRECT\";\n", suffix))
			} else {
				// bare domain — exact match + all subdomains
				sb.WriteString(fmt.Sprintf("  if (host === %q || dnsDomainIs(host, %q)) return \"DIRECT\";\n", exc, "."+exc))
			}
		}
	}

	sb.WriteString("\n  // All other traffic routes through the proxy\n")
	sb.WriteString(fmt.Sprintf("  return %q;\n", proxyDirective))
	sb.WriteString("}\n")
	return sb.String()
}

// isIPCIDR returns true if s looks like an IP CIDR range (contains '/').
func isIPCIDR(s string) bool { return strings.Contains(s, "/") }

// cidrToIPMask converts "192.168.0.0/16" → ("192.168.0.0", "255.255.0.0", true).
// Only handles IPv4.
func cidrToIPMask(cidr string) (ip, mask string, ok bool) {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	ip = parts[0]
	var prefix int
	if _, err := fmt.Sscanf(parts[1], "%d", &prefix); err != nil || prefix < 0 || prefix > 32 {
		return "", "", false
	}
	var m uint32
	if prefix > 0 {
		m = ^uint32(0) << (32 - prefix)
	}
	mask = fmt.Sprintf("%d.%d.%d.%d",
		(m>>24)&0xff, (m>>16)&0xff, (m>>8)&0xff, m&0xff)
	return ip, mask, true
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// apiPACConfig handles GET/POST /api/pac-config.
func apiPACConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := pacStore.Get()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c) //nolint:errcheck
	case http.MethodPost:
		var c PACConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := pacStore.Set(c); err != nil {
			http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c) //nolint:errcheck
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// servePACFile handles GET /proxy.pac — serves the dynamically generated PAC file.
func servePACFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pac := pacStore.GeneratePAC(r.Host)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	fmt.Fprint(w, pac)
}
