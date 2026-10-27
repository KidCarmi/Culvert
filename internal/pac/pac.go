// Package pac is the PAC (proxy auto-config) engine: the persisted PAC
// configuration store and the FindProxyForURL generator. Extracted from
// package main per ADR-0002; the HTTP handlers, route registration, and the
// pacStore singleton stay in main (pac.go shim). The former
// pacDefaultProxyPort package global is now a Store field (SetDefaultPort),
// set once by the startup slice.
package pac

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// storeAtomicWrite is the store's durable-write seam. Production is
// fileutil.AtomicWrite; a test swaps it to drive a write outcome that cannot
// be produced from a real filesystem — notably the post-rename
// fileutil.ErrReplacedNotSynced. Mirrors uiTLSAtomicWrite in package main.
var storeAtomicWrite = fileutil.AtomicWrite

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
	s.modTime = nextModTime(s.modTime)
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

// Set persists the config and then replaces it: the durable write is the
// commit point, so a failed write leaves the serving view untouched and
// returns the error (see the body, and ProfileStore.setLocked for the same
// contract on the profiles store).
//
// Set is deliberately TOLERANT of entry content (no validation): its callers
// include config-version rollback and cluster snapshot apply, which replay
// historical data and discard errors. Strict validation lives at the admin
// API boundary (ValidateConfig). Tolerant of CONTENT is not tolerant of a
// failed write — those callers rely on the commit ordering above, not on
// inspecting the error.
func (s *Store) Set(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The token is owned by the store, never by the caller: every committed
	// Set advances it by one from the current effective value.
	c.Revision = s.cfg.effectiveRevision() + 1
	// Persist-before-swap: the durable write is the commit point, the same
	// contract ProfileStore.setLocked states for the profiles store (2F-B,
	// C1). Memory is replaced only after the file is durably written, so a
	// full or read-only volume leaves the SERVING view exactly where it was
	// instead of handing the whole PAC client fleet a routing change that
	// nothing persisted, nothing audited, no config version captured, and
	// that reverts on the next restart. Three of the four callers discard or
	// merely log this error (config-version rollback, the Data Plane's
	// snapshot apply, config import), so the ordering is the only thing
	// keeping their failure modes consistent. See CHAOS-77.
	stamp := nextModTime(s.modTime)
	if s.path != "" {
		data, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		if err := storeAtomicWrite(s.path, data, 0o600); err != nil {
			// ErrReplacedNotSynced is a POST-rename failure: the target
			// already carries the new content, every reader sees it, and a
			// restart loads it. Returning here would leave memory
			// contradicting the visible file — the exact inverse of the
			// divergence this ordering exists to prevent, and it would
			// activate a fleet-wide routing change on the next restart that
			// the admin was told had failed. fileutil documents the rule
			// ("callers ... must NOT restore prior in-memory state"), and
			// every other handler in the tree follows it
			// (rosterChangeCommitted, policylearn.saveLocked, policy_draft,
			// ui_security, mcp_canary_runtime). The commit HELD, so fall
			// through to the swap. The durability degradation is already
			// surfaced by the write-failure observer (CHAOS-45), which this
			// branch has fired, so swallowing the sentinel here hides
			// nothing from the operator.
			if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
				return err
			}
		}
	}
	s.cfg = c
	s.modTime = stamp
	return nil
}

// nextModTime returns the modTime stamp for a committing write: the wall
// clock, unless that would not be strictly newer than the stamp already
// served at HTTP (whole-second) granularity, in which case it is one second
// past the previous stamp.
//
// modTime is the Last-Modified source for /proxy.pac, and pacNotModified
// honours If-Modified-Since for the WinHTTP/WinINET PAC clients that send no
// If-None-Match. A stamp that fails to advance therefore makes a genuinely
// changed PAC revalidate to 304 and leaves those clients executing the
// superseded artifact. Two causes, one fix: a wall clock that moved backwards
// (NTP step correction, VM snapshot restore, chrony makestep at boot) and two
// commits inside the same wall-clock second, which HTTP dates cannot tell
// apart. The ETag over the artifact bytes remains the primary validator and
// is unaffected either way.
//
// The stamp can therefore sit ahead of the wall clock while commits arrive
// faster than one per second, or until a backwards step is made up. That is
// deliberate: a Last-Modified in the future costs a revalidation the ETag
// then answers, whereas a stamp that does not advance costs correctness.
//
// The advanced stamp carries now's sub-second component rather than being a
// pure function of prev, because ArtifactCache keys compiled artifacts on
// this value by EQUALITY (cache.go). A stamp derived only from prev would be
// reproducible — two commits from the same prev would mint the same key and
// the cache would answer the second with the first one's artifact. Keeping a
// nanosecond component makes the stamp as unique as the time.Now() it
// replaces, which is what the cache has always relied on.
func nextModTime(prev time.Time) time.Time {
	now := time.Now()
	if now.Truncate(time.Second).After(prev.Truncate(time.Second)) {
		return now
	}
	return prev.Truncate(time.Second).Add(time.Second + time.Duration(now.Nanosecond()))
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
