// Package scanexcl holds the admin-managed scan-exclusion store: known-good
// SHA-256 content hashes and hostnames that bypass all body scanning. It is a
// self-contained leaf (stdlib + the hostutil seam) extracted from the flat
// package main per ADR-0002.
//
// It is designed for an extreme read:write ratio (IsHashExcluded /
// IsHostExcluded run on every request; writes happen only when an admin updates
// the lists), so it uses sync.RWMutex per the read-heavy store convention.
package scanexcl

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Store holds admin-managed exclusions: known-good content hashes and hostnames
// that bypass all body scanning.
type Store struct {
	mu     sync.RWMutex
	hashes map[string]bool
	hosts  map[string]bool
	path   string // JSON file for persistence (optional)
}

// New returns an empty Store ready for use.
func New() *Store {
	return &Store{hashes: map[string]bool{}, hosts: map[string]bool{}}
}

// exclusionsFile is the on-disk JSON envelope for Store.
type exclusionsFile struct {
	Hashes []string `json:"hashes"`
	Hosts  []string `json:"hosts"`
}

// Load reads the JSON file at path into the store. Missing file is not an error.
func (s *Store) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path) // #nosec G304 -- admin-configured path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan exclusions read: %w", err)
	}
	var f exclusionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("scan exclusions parse: %w", err)
	}
	s.mu.Lock()
	s.hashes = make(map[string]bool, len(f.Hashes))
	for _, h := range f.Hashes {
		s.hashes[strings.ToLower(h)] = true
	}
	s.hosts = make(map[string]bool, len(f.Hosts))
	for _, h := range f.Hosts {
		s.hosts[hostutil.StripHostPort(strings.ToLower(h))] = true
	}
	s.mu.Unlock()
	return nil
}

// Save persists the exclusion lists to the configured file path using an
// atomic tmp+rename write. No-op if no path configured.
func (s *Store) Save() error {
	s.mu.RLock()
	path := s.path
	f := exclusionsFile{
		Hashes: make([]string, 0, len(s.hashes)),
		Hosts:  make([]string, 0, len(s.hosts)),
	}
	for h := range s.hashes {
		f.Hashes = append(f.Hashes, h)
	}
	for h := range s.hosts {
		f.Hosts = append(f.Hosts, h)
	}
	s.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(path, data, 0o600)
}

// Replace atomically swaps the exclusion lists, normalising to lower case.
func (s *Store) Replace(hashes, hosts []string) {
	hmap := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			hmap[h] = true
		}
	}
	hostMap := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = hostutil.StripHostPort(strings.TrimSpace(strings.ToLower(h)))
		if h != "" {
			hostMap[h] = true
		}
	}
	s.mu.Lock()
	s.hashes = hmap
	s.hosts = hostMap
	s.mu.Unlock()
}

// IsHashExcluded reports whether the SHA-256 hex is on the hash allowlist.
// Hot path: called on every ScanBody invocation. RLock-only.
func (s *Store) IsHashExcluded(hash string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hashes[strings.ToLower(hash)]
}

// IsHostExcluded reports whether the hostname is on the host allowlist.
// Hot path: called once per proxied HTTP request before buffering. RLock-only.
func (s *Store) IsHostExcluded(host string) bool {
	if s == nil || host == "" {
		return false
	}
	// Strip port suffix and IPv6 brackets if present.
	host = hostutil.StripHostPort(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hosts[strings.ToLower(host)]
}

// Lists returns copies of the current hash and host lists, sorted for stable
// admin output.
func (s *Store) Lists() (hashes, hosts []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hashes = make([]string, 0, len(s.hashes))
	for h := range s.hashes {
		hashes = append(hashes, h)
	}
	hosts = make([]string, 0, len(s.hosts))
	for h := range s.hosts {
		hosts = append(hosts, h)
	}
	sortStrings(hashes)
	sortStrings(hosts)
	return hashes, hosts
}

// sortStrings is a tiny insertion sort — exclusion lists are short (dozens of
// entries) so the constant-factor cost of reflection-based sort.Strings is not
// worth it.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
