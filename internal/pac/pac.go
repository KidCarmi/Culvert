// Package pac is the PAC (proxy auto-config) engine: the persisted PAC
// configuration store and the FindProxyForURL generator. Extracted from
// package main per ADR-0002; the HTTP handlers, route registration, and the
// pacStore singleton stay in main (pac.go shim). The former
// pacDefaultProxyPort package global is now a Store field (SetDefaultPort),
// set once by the startup slice.
package pac

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Config is the persisted PAC configuration.
type Config struct {
	// ProxyHost is the hostname or IP of this proxy, e.g. "proxy.corp.com".
	// If empty the /proxy.pac endpoint uses the hostname from the request's
	// Host header (stripping the port, which belongs to the UI — not the proxy).
	ProxyHost string `json:"proxyHost"`
	// ProxyPort is the port the proxy server listens on.
	// If zero it falls back to the runtime proxy port set at startup.
	ProxyPort int `json:"proxyPort"`
	// Exclusions is the list of host patterns that should bypass the proxy.
	// Supports bare domains ("corp.local"), wildcard prefixes ("*.corp.local"),
	// and IP CIDR ranges ("192.168.0.0/16").
	Exclusions []string `json:"exclusions"`
}

// Store persists Config to a JSON file.
type Store struct {
	mu   sync.RWMutex
	cfg  Config
	path string
	// defaultPort is set at startup to the actual proxy listening port.
	// Used when Config.ProxyPort is zero, so /proxy.pac auto-detects the
	// right port even when the admin hasn't explicitly configured it.
	defaultPort int
}

// Load reads config from the JSON file; a missing file is a no-op.
func (s *Store) Load(path string) error {
	s.path = path
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
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
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Exclusions = append([]string(nil), s.cfg.Exclusions...)
	return c
}

// Set replaces the config and persists it.
func (s *Store) Set(c Config) error {
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

// SetDefaultPort records the runtime proxy listening port used as the
// fallback when Config.ProxyPort is zero. Called once by the startup slice.
func (s *Store) SetDefaultPort(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultPort = port
}

// DefaultPort returns the startup-time fallback proxy port (0 if unset).
func (s *Store) DefaultPort() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultPort
}

// State is a full snapshot of a Store for test isolation (Snapshot/Restore).
type State struct {
	Cfg         Config
	Path        string
	DefaultPort int
}

// Snapshot returns the store's full state. Test support: pair with Restore
// so tests that mutate the process-wide store stay hermetic under -shuffle.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return State{Cfg: s.cfg, Path: s.path, DefaultPort: s.defaultPort}
}

// Restore resets the store to a previously captured State (test support).
func (s *Store) Restore(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = st.Cfg
	s.path = st.Path
	s.defaultPort = st.DefaultPort
}

// GeneratePAC builds the PAC JavaScript.
// proxyAddr is the "host:port" string to use when ProxyHost is empty
// (caller passes the request's Host as a fallback).
func (s *Store) GeneratePAC(proxyAddr string) string {
	c := s.Get()

	host := c.ProxyHost
	port := c.ProxyPort
	if port == 0 {
		if def := s.DefaultPort(); def > 0 {
			port = def
		} else {
			port = 8080
		}
	}
	if host == "" {
		// r.Host is "uiHost:uiPort" — we only want the hostname part.
		// The port we serve /proxy.pac from is the UI port, NOT the proxy port;
		// using it as-is would send client traffic to the wrong listener.
		proxyAddr = strings.TrimPrefix(proxyAddr, "https://")
		proxyAddr = strings.TrimPrefix(proxyAddr, "http://")
		h, _, err := net.SplitHostPort(proxyAddr)
		if err == nil && h != "" {
			host = h // bare hostname; port comes from Config.ProxyPort
		} else {
			host = proxyAddr // already bare (no port suffix)
		}
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
			writeExclusion(&sb, strings.TrimSpace(exc))
		}
	}

	sb.WriteString("\n  // All other traffic routes through the proxy\n")
	fmt.Fprintf(&sb, "  return %q;\n", proxyDirective)
	sb.WriteString("}\n")
	return sb.String()
}

// writeExclusion appends the PAC DIRECT rule for a single exclusion entry:
// IP CIDR → isInNet, "*."-wildcard → dnsDomainIs, bare domain → exact match
// plus subdomains. Blank entries are skipped.
func writeExclusion(sb *strings.Builder, exc string) {
	switch {
	case exc == "":
		// blank / whitespace-only — silently skipped
	case isIPCIDR(exc):
		// IP CIDR — use isInNet with mask derived from prefix length.
		if ip, mask, ok := cidrToIPMask(exc); ok {
			fmt.Fprintf(sb, "  if (isInNet(dnsResolve(host), %q, %q)) return \"DIRECT\";\n", ip, mask)
		}
	case strings.HasPrefix(exc, "*."):
		// *.corp.com → all subdomains of corp.com
		suffix := exc[1:] // .corp.com
		fmt.Fprintf(sb, "  if (dnsDomainIs(host, %q)) return \"DIRECT\";\n", suffix)
	default:
		// bare domain — exact match + all subdomains
		fmt.Fprintf(sb, "  if (host === %q || dnsDomainIs(host, %q)) return \"DIRECT\";\n", exc, "."+exc)
	}
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
