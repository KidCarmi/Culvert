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
	"os"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
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
	// Revision is the optimistic-concurrency token of the legacy config
	// (2F-A): it advances by exactly one on every Set, whatever the caller
	// supplied (rollback and cluster-apply replay historical configs whose
	// revision is meaningless here), and reads as 1 before any mutation so a
	// client always holds a non-zero token. The admin API refuses a mutation
	// whose token is absent (428) or stale (409); see pac.go apiPACConfig.
	Revision int64 `json:"revision,omitempty"`
}

// effectiveRevision is the token a reader observes: never zero, so a config
// loaded from a pre-2F-A file (no revision key) still hands out a usable token.
func (c Config) effectiveRevision() int64 {
	if c.Revision < 1 {
		return 1
	}
	return c.Revision
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
	// modTime is when the config last changed (load or mutation) — the
	// Last-Modified source for /proxy.pac. Operational metadata only.
	modTime time.Time
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
	if err := json.Unmarshal(data, &s.cfg); err != nil {
		return err
	}
	s.modTime = time.Now()
	return nil
}

// LoadMigrate loads from path, one-way migrating from legacyPath when path
// does not exist yet but legacyPath does: the legacy file is loaded, the
// store is re-pointed at path, and the config is persisted there. The legacy
// file is left in place (frozen; a downgraded binary reads it stale — see
// docs/operator/pac-traffic-steering.md).
func (s *Store) LoadMigrate(path, legacyPath string) (migrated bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil || legacyPath == "" {
		return false, s.Load(path)
	}
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		return false, s.Load(path)
	}
	if err := s.Load(legacyPath); err != nil {
		return false, err
	}
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	return true, s.Set(s.Get())
}

// Get returns a snapshot of the current config.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Exclusions = append([]string(nil), s.cfg.Exclusions...)
	c.Revision = c.effectiveRevision()
	return c
}

// Set replaces the config and persists it. Set is deliberately TOLERANT of
// entry content (no validation): its callers include config-version rollback
// and cluster snapshot apply, which replay historical data and discard
// errors. Strict validation lives at the admin API boundary (ValidateConfig).
func (s *Store) Set(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The token is owned by the store, never by the caller: every committed
	// Set advances it by one from the current effective value.
	c.Revision = s.cfg.effectiveRevision() + 1
	s.cfg = c
	s.modTime = time.Now()
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(s.path, data, 0o600)
}

// ModTime reports when the config last changed (zero before any load/set).
func (s *Store) ModTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.modTime
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
	ModTime     time.Time
}

// Snapshot returns the store's full state. Test support: pair with Restore
// so tests that mutate the process-wide store stay hermetic under -shuffle.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return State{Cfg: s.cfg, Path: s.path, DefaultPort: s.defaultPort, ModTime: s.modTime}
}

// Restore resets the store to a previously captured State (test support).
func (s *Store) Restore(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = st.Cfg
	s.path = st.Path
	s.defaultPort = st.DefaultPort
	s.modTime = st.ModTime
}

// Compile builds the PAC artifact for the current config. proxyAddr is the
// request-derived "host[:port]" used only when Config.ProxyHost is empty
// (the port part is discarded — /proxy.pac is served from the UI or proxy
// listener, whose port is not necessarily the proxy port clients must use).
func (s *Store) Compile(proxyAddr string) Artifact {
	return CompileConfig(s.Get(), proxyAddr, s.DefaultPort())
}

// GeneratePAC builds the PAC JavaScript (compatibility wrapper over Compile).
func (s *Store) GeneratePAC(proxyAddr string) string {
	return s.Compile(proxyAddr).JS
}
