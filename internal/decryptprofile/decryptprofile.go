// Package decryptprofile is the named SSL-decryption-profile engine: a
// PAN-OS-style "how to decrypt" object that policy rules reference by name to
// control HOW an inspected (SSLAction=Inspect) tunnel is decrypted — whether to
// inspect natively as HTTP/2, the upstream server-certificate-verification
// posture, the unsupported-TLS failure posture, the TLS version floor/cap, and
// the per-stream inactivity bound. It is the "how" half that complements the
// "what to match" half already in package main's policy rules + sslbypass.
//
// This engine owns storage + validation ONLY. The resolvers that turn a matched
// rule's profile reference into a runtime decision (resolveStripALPN and friends)
// live in package main on the proxy hot path, mirroring how catgroup exposes the
// pure store while categoryGroupMatchesHost stays in main.
//
// Concurrency: an RWMutex protects the store; reads (GetByName) take RLock,
// writes rebuild order under Lock. All validation is enforced in Add/Update AND
// ReplaceAll, because profiles are written by THREE paths — the admin API, config
// import, and CP→DP snapshot apply — and a handler-only check would be bypassed by
// the latter two.
package decryptprofile

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// Clamp bounds for StallTimeoutSecs. 0 means "engine default" (the caller
// substitutes sslInspectBodyStallTimeout); any other value must fall in
// [MinStallSecs, MaxStallSecs]. A too-low value kills legitimate long-poll/SSE/
// large-download streams; a too-high value lets a slow-loris stream pin a handler
// + scan buffer. MaxStallSecs matches the default tunnel-idle ceiling (1h).
const (
	MinStallSecs = 5
	MaxStallSecs = 3600
)

// Enum value sets. The empty string always means "inherit the engine/rule
// default" (back-compat: an absent choice never changes today's behavior).
var (
	validCertVerification = map[string]bool{"": true, "strict": true, "permissive": true, "skip": true}
	validOnUnsupported    = map[string]bool{"": true, "fail-close": true, "fail-open": true}
	validOnInspectError   = map[string]bool{"": true, "fail-close": true, "fail-open": true}
	validTLSVersion       = map[string]bool{"": true, "1.2": true, "1.3": true}
	// nameRe bounds the profile name charset (referenced by rules, rendered in the
	// UI); keep it to printable identifier-ish characters to avoid surprises.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
)

// Profile is a named decryption profile. Zero/empty fields mean "inherit the
// default" so an absent or partially-filled profile never silently changes
// today's behavior (back-compat with the pre-profile inline rule fields).
type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// InspectHTTP2: nil = inherit (strip → HTTP/1.1, today's default); true =
	// native HTTP/2 inspection; false = force strip/HTTP-1.1.
	InspectHTTP2 *bool `json:"inspectHttp2,omitempty"`

	// CertVerification of the upstream (origin) cert on the inspect leg:
	// "" inherit (rule's TLSSkipVerify) | "strict" (verify, block untrusted/expired)
	// | "permissive" (verify, allow+log — DEFERRED enforcement) | "skip".
	CertVerification string `json:"certVerification,omitempty"`

	// OnUnsupported posture when the origin TLS can't be inspected (version/cipher
	// below floor): "" inherit | "fail-close" (drop — today's behavior) | "fail-open"
	// (raw-relay bypass — DEFERRED, superseded by OnInspectError for fail-open).
	OnUnsupported string `json:"onUnsupported,omitempty"`

	// OnInspectError is the adaptive decryption-exclusion / fail-open posture when
	// an inspected tunnel CANNOT be established because the host is incompatible
	// with inspection (origin demands a client cert we can't present, or the TLS
	// parameters are unsupported, or a pinned client rejects our forged leaf):
	// "" inherit (fail-close, today's behavior) | "fail-close" (502/drop) |
	// "fail-open" (record the host in the auto-exclusion cache after a
	// confirm-count of distinct clients, rescue the current session where it has
	// not yet committed to the client, and bypass subsequent sessions to the host
	// until the entry expires). It deliberately does NOT fire on an untrusted/
	// expired origin cert — that stays a block. See internal/autoexclude.
	OnInspectError string `json:"onInspectError,omitempty"`

	// MinTLSVersion / MaxTLSVersion floor and cap on the inspect handshakes:
	// "" inherit | "1.2" | "1.3".
	MinTLSVersion string `json:"minTlsVersion,omitempty"`
	MaxTLSVersion string `json:"maxTlsVersion,omitempty"`

	// StallTimeoutSecs per-stream inactivity bound; 0 = engine default, else
	// clamped to [MinStallSecs, MaxStallSecs].
	StallTimeoutSecs int `json:"stallTimeoutSecs,omitempty"`

	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Store manages persistent decryption profiles with O(1) name lookups.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile // keyed by lowercase name
	order    []string            // insertion order for stable list output
	path     string
}

// New builds an empty store.
func New() *Store { return &Store{profiles: make(map[string]*Profile)} }

// Validate checks a profile's fields. Enforced on EVERY write path (Add/Update/
// ReplaceAll) so config-import and CP→DP snapshot-apply cannot smuggle an invalid
// profile onto the data plane. Does not check name uniqueness (that's store-scoped).
func Validate(p *Profile) error {
	name := strings.TrimSpace(p.Name)
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid name %q (allowed: letters, digits, space, . _ -, 1-64 chars)", p.Name)
	}
	if !validCertVerification[p.CertVerification] {
		return fmt.Errorf("invalid certVerification %q", p.CertVerification)
	}
	if !validOnUnsupported[p.OnUnsupported] {
		return fmt.Errorf("invalid onUnsupported %q", p.OnUnsupported)
	}
	if !validOnInspectError[p.OnInspectError] {
		return fmt.Errorf("invalid onInspectError %q", p.OnInspectError)
	}
	if !validTLSVersion[p.MinTLSVersion] {
		return fmt.Errorf("invalid minTlsVersion %q", p.MinTLSVersion)
	}
	if !validTLSVersion[p.MaxTLSVersion] {
		return fmt.Errorf("invalid maxTlsVersion %q", p.MaxTLSVersion)
	}
	if p.MinTLSVersion != "" && p.MaxTLSVersion != "" && p.MinTLSVersion > p.MaxTLSVersion {
		return fmt.Errorf("minTlsVersion %q exceeds maxTlsVersion %q", p.MinTLSVersion, p.MaxTLSVersion)
	}
	if p.StallTimeoutSecs != 0 && (p.StallTimeoutSecs < MinStallSecs || p.StallTimeoutSecs > MaxStallSecs) {
		return fmt.Errorf("stallTimeoutSecs %d out of range [%d,%d] (0 = default)", p.StallTimeoutSecs, MinStallSecs, MaxStallSecs)
	}
	return nil
}

// copyOut returns a fully independent value copy — the InspectHTTP2 pointee is
// deep-copied so a caller cannot mutate stored state through the returned *bool
// (enforcing the read-only invariant rather than only documenting it).
func copyOut(p *Profile) Profile {
	c := *p
	if p.InspectHTTP2 != nil {
		v := *p.InspectHTTP2
		c.InspectHTTP2 = &v
	}
	return c
}

// Load reads profiles from a JSON file. Invalid profiles on disk are skipped with
// a log line (fail-safe — a corrupt entry never blocks startup or the valid ones).
func (s *Store) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil // first run — no file
	}
	var profiles []Profile
	if err := json.Unmarshal(data, &profiles); err != nil {
		obs.Printf("DecryptionProfiles: unmarshal error from %s", path)
		return err
	}
	migrated := s.replace(profiles, true)
	obs.Printf("DecryptionProfiles: loaded %d profile(s) from %s", len(profiles), path)
	// Persist backfilled IDs so ?id= addressing is stable across restart
	// (idempotent: a second load finds all IDs present and writes nothing).
	if migrated > 0 {
		s.Save()
		obs.Printf("DecryptionProfiles: assigned stable IDs to %d legacy profile(s)", migrated)
	}
	return nil
}

// Save persists the current profiles to disk (atomic write). No-op when path unset.
func (s *Store) Save() {
	s.mu.RLock()
	path := s.path
	if path == "" {
		s.mu.RUnlock()
		return
	}
	profiles := make([]Profile, 0, len(s.order))
	for _, key := range s.order {
		if p, ok := s.profiles[key]; ok {
			profiles = append(profiles, copyOut(p))
		}
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return
	}
	_ = fileutil.AtomicWrite(path, data, 0o600)
}

// List returns a copy of all profiles (safe for JSON serialization).
func (s *Store) List() []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Profile, 0, len(s.order))
	for _, key := range s.order {
		if p, ok := s.profiles[key]; ok {
			out = append(out, copyOut(p))
		}
	}
	return out
}

// FailOpenScope returns the profile's ID and true IFF a profile with the given
// name exists AND opts into fail-open (OnInspectError=="fail-open"). It is a
// HOT-PATH accessor (resolveSSLAction calls it per CONNECT for fail-open rules):
// it reads only two string fields under the RLock and returns NO copy, avoiding
// the copyOut allocation a full GetByName pays. The learn/cold paths keep the
// copy-returning accessors.
func (s *Store) FailOpenScope(name string) (id string, ok bool) {
	s.mu.RLock()
	p := s.profiles[strings.ToLower(strings.TrimSpace(name))]
	if p == nil || p.OnInspectError != "fail-open" {
		s.mu.RUnlock()
		return "", false
	}
	id = p.ID
	s.mu.RUnlock()
	return id, true
}

// GetByName returns a profile by name (case-insensitive). O(1). nil if not found.
func (s *Store) GetByName(name string) *Profile {
	s.mu.RLock()
	p := s.profiles[strings.ToLower(strings.TrimSpace(name))]
	s.mu.RUnlock()
	if p == nil {
		return nil
	}
	c := copyOut(p)
	return &c
}

// Add creates a new profile. Validates fields, then name uniqueness. Assigns a
// short unique ID (a truncated UUID) when absent (ID-preserving otherwise).
func (s *Store) Add(p Profile) (*Profile, error) {
	p.Name = strings.TrimSpace(p.Name)
	if err := Validate(&p); err != nil {
		return nil, err
	}
	key := strings.ToLower(p.Name)
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.profiles[key]; exists {
		return nil, fmt.Errorf("profile %q already exists", p.Name)
	}
	if p.ID == "" {
		p.ID = uuid.NewString()[:12]
	}
	p.CreatedAt = now
	p.UpdatedAt = now
	np := p
	s.profiles[key] = &np
	s.order = append(s.order, key)
	c := copyOut(&np)
	return &c, nil
}

// Update replaces an existing profile's fields (by name). Preserves ID + CreatedAt.
func (s *Store) Update(p Profile) error {
	p.Name = strings.TrimSpace(p.Name)
	if err := Validate(&p); err != nil {
		return err
	}
	key := strings.ToLower(p.Name)

	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.profiles[key]
	if !ok {
		return fmt.Errorf("profile %q not found", p.Name)
	}
	p.ID = cur.ID
	p.CreatedAt = cur.CreatedAt
	p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	np := p
	s.profiles[key] = &np
	return nil
}

// Delete removes a profile by name.
func (s *Store) Delete(name string) error {
	key := strings.ToLower(strings.TrimSpace(name))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.profiles[key]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	delete(s.profiles, key)
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// ReplaceAll atomically replaces all profiles (cluster sync / rollback / import).
// Invalid profiles are skipped (fail-safe) so a bad remote/imported entry never
// takes down the store or the valid entries. IDs are PRESERVED as provided
// (backfilled only when empty) so a capture→apply→re-capture round-trip is stable.
func (s *Store) ReplaceAll(profiles []Profile) { s.replace(profiles, false) }

// replace is the shared install path. skipInvalidLog controls whether skipped
// entries are logged (Load logs; ReplaceAll stays quiet on the hot sync path).
// Returns the number of profiles that had a stable ID backfilled (Load persists
// when > 0 so ?id= addressing survives restart).
func (s *Store) replace(profiles []Profile, logSkips bool) int {
	built := make(map[string]*Profile, len(profiles))
	order := make([]string, 0, len(profiles))
	migrated := 0
	for i := range profiles {
		p := profiles[i]
		p.Name = strings.TrimSpace(p.Name)
		if err := Validate(&p); err != nil {
			if logSkips {
				obs.Printf("DecryptionProfiles: skipping invalid profile %q: %v", p.Name, err)
			}
			continue
		}
		key := strings.ToLower(p.Name)
		if _, dup := built[key]; dup {
			continue // last-write-wins would reorder; keep first, drop dup
		}
		if p.ID == "" {
			p.ID = uuid.NewString()[:12]
			migrated++
		}
		np := p
		built[key] = &np
		order = append(order, key)
	}
	s.mu.Lock()
	s.profiles = built
	s.order = order
	s.mu.Unlock()
	return migrated
}

// GetByID returns a copy of the profile with the given stable ID, or nil.
func (s *Store) GetByID(id string) *Profile {
	if id == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			cp := copyOut(p)
			return &cp
		}
	}
	return nil
}

// UpdateByID replaces the content of the profile with the given stable ID
// (rename-safe addressing). Like the name-keyed Update, it edits content and
// keeps the profile's current name + CreatedAt + ID — position/identity are not
// changed by an edit. Returns error if no profile carries the id.
func (s *Store) UpdateByID(id string, p Profile) error {
	if id == "" {
		return fmt.Errorf("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, cur := range s.profiles {
		if cur.ID != id {
			continue
		}
		p.ID = id
		p.Name = cur.Name // edits address by id and keep the name (mirrors Update)
		p.CreatedAt = cur.CreatedAt
		if err := Validate(&p); err != nil {
			return err
		}
		np := p
		s.profiles[key] = &np
		return nil
	}
	return fmt.Errorf("profile id %q not found", id)
}

// DeleteByID removes the profile with the given stable ID. Returns the removed
// profile's name (for audit) or an error if not found.
func (s *Store) DeleteByID(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, p := range s.profiles {
		if p.ID == id {
			name := p.Name
			delete(s.profiles, key)
			for i, k := range s.order {
				if k == key {
					s.order = append(s.order[:i], s.order[i+1:]...)
					break
				}
			}
			return name, nil
		}
	}
	return "", fmt.Errorf("profile id %q not found", id)
}

// Names returns all profile names (for UI dropdowns), in insertion order.
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.order))
	for _, key := range s.order {
		if p, ok := s.profiles[key]; ok {
			out = append(out, p.Name)
		}
	}
	return out
}

// Path reports the persistence path ("" = disabled).
func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// SetPathForTest points persistence at path without loading.
func (s *Store) SetPathForTest(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}
