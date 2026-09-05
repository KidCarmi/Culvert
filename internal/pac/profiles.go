package pac

// profiles.go — PAC traffic-steering profiles and proxy pools (initiative
// PR 2). A Profile selects an ordered proxy-failover Pool, carries ordered
// routing rules, and pins explicit availability + private-network semantics.
//
// The DEFAULT profile is deliberately NOT stored here: it is a virtual view
// over the legacy Config (pac_config.json), so /proxy.pac and
// /pac/default.pac stay byte-identical with the pre-profiles output, the
// legacy /api/pac-config surface keeps working unchanged, and the cluster
// pac_exclusions sync continues to govern default-profile exclusions.
// Custom profiles and pools persist in <dataDir>/pac_profiles.json.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// DefaultProfileID names the virtual legacy-backed profile.
const DefaultProfileID = "default"

// Availability modes: what the terminal directive chain may contain.
const (
	// ModeSecure: pool chain only — NO DIRECT anywhere (DIRECT rules and the
	// private-network bypass are rejected too). If every proxy is down,
	// traffic fails closed. NOTE: the legacy /proxy.pac output corresponds
	// to BALANCED + PrivateDirect (its exclusions are explicit DIRECT
	// carve-outs), not to secure.
	ModeSecure = "secure"
	// ModeBalanced: pool chain terminal (no DIRECT), but explicit DIRECT
	// rules are permitted where the admin authored them.
	ModeBalanced = "balanced"
	// ModeAvailability: pool chain then DIRECT — fail open when all proxies
	// are unreachable.
	ModeAvailability = "availability"
)

// Private-network behaviors (replaces the legacy hardcoded RFC1918 bypass).
const (
	// PrivateDirect: loopback + RFC-1918 destinations go DIRECT (legacy).
	PrivateDirect = "direct"
	// PrivateProxy: private ranges get no built-in bypass — they follow the
	// profile's rules and terminal chain like any other destination.
	PrivateProxy = "proxy"
)

// Rule kinds.
const (
	RuleKindDomain   = "domain"   // exact host + subdomains
	RuleKindSuffix   = "suffix"   // subdomains only (dnsDomainIs)
	RuleKindWildcard = "wildcard" // shExpMatch host glob
	RuleKindCIDR4    = "cidr4"    // IPv4 CIDR against resolved IP
)

// Rule actions.
const (
	ActionUsePool = "use_pool"
	ActionDirect  = "direct"
)

// Engine caps for profiles/pools (mirrored by the cluster snapshot caps).
const (
	MaxProfiles        = 64
	MaxPools           = 64
	MaxRulesPerProfile = 1000
	MaxPoolEndpoints   = 3
)

// PoolEndpoint is one ordered proxy target. Only PROXY directives are
// emitted (the WinHTTP portability floor).
type PoolEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Pool is an ordered proxy-failover chain (primary → secondary → tertiary).
type Pool struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Endpoints []PoolEndpoint `json:"endpoints"`
}

// Rule is one ordered routing rule. Order is admin-authored and
// order-sensitive (first match wins); the compiler honors it verbatim.
type Rule struct {
	// Kind is one of RuleKind*.
	Kind string `json:"kind"`
	// Pattern is the kind-specific match target (domain, suffix, glob, CIDR).
	Pattern string `json:"pattern"`
	// Scheme optionally restricts the rule to "http" or "https" URLs.
	Scheme string `json:"scheme,omitempty"`
	// Port optionally restricts the rule to an explicit destination port as
	// it appears in the URL (default ports are omitted by clients and cannot
	// be matched — documented limitation).
	Port int `json:"port,omitempty"`
	// Action is ActionUsePool or ActionDirect.
	Action string `json:"action"`
	// PoolID optionally overrides the profile's pool for ActionUsePool.
	PoolID string `json:"poolId,omitempty"`
}

// Profile is one PAC steering profile, served at /pac/<id>.pac.
type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	// PoolID names the profile's default pool (required).
	PoolID string `json:"poolId"`
	// Rules are evaluated in order before the terminal chain.
	Rules []Rule `json:"rules,omitempty"`
	// PrivateNetworks is PrivateDirect or PrivateProxy.
	PrivateNetworks string `json:"privateNetworks"`
	// AvailabilityMode is ModeSecure, ModeBalanced, or ModeAvailability.
	AvailabilityMode string `json:"availabilityMode"`
	// Revision increments on every mutation of this profile.
	Revision int64 `json:"revision"`
}

// ProfilesConfig is the persisted shape of pac_profiles.json.
type ProfilesConfig struct {
	Profiles []Profile `json:"profiles"`
	Pools    []Pool    `json:"pools"`
}

// ProfileStore persists ProfilesConfig to a JSON file. Like the legacy
// Store, Set is TOLERANT (no validation) — replay callers (rollback, cluster
// apply, import apply) discard errors; strict validation lives at the admin
// API boundary (ValidateProfilesConfig).
type ProfileStore struct {
	mu      sync.RWMutex
	cfg     ProfilesConfig
	path    string
	modTime time.Time
	// gen is the store GENERATION (2F-E correction round 4): a monotonic
	// counter advanced by every successful replacement of the config (Set,
	// SetIfGeneration, Load, Restore). A writer that builds a candidate from
	// one generation and commits it later can prove, atomically, that no
	// other writer landed in between (SetIfGeneration) — the compare-and-swap
	// wall behind the shared pacProfilesAPIMu transaction boundary.
	gen uint64
}

// ErrProfilesChanged is returned by SetIfGeneration when the store's
// generation is no longer the one the candidate was built from: another
// writer landed between the candidate's construction and its commit, and
// nothing was written.
var ErrProfilesChanged = errors.New("pac profiles: the active store changed since the candidate was built")

// Load reads config from the JSON file; a missing file is a no-op.
func (s *ProfileStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pac profiles: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.cfg); err != nil {
		return fmt.Errorf("pac profiles: parse %s: %w", path, err)
	}
	normalizeProfileRevisions(&s.cfg)
	s.modTime = time.Now()
	s.gen++
	return nil
}

// normalizeProfileRevisions migrates a profile carrying revision 0 (written by
// a pre-2F-A binary, a tolerant import, or a hand-edited file) to revision 1,
// so every stored profile hands out a non-zero optimistic-concurrency token
// and the historical "revision 0 skips the fence" path can never be reached
// through a stored object. Idempotent; positive revisions are untouched.
func normalizeProfileRevisions(cfg *ProfilesConfig) {
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Revision < 1 {
			cfg.Profiles[i].Revision = 1
		}
	}
}

// PoolETag is the pool's optimistic-concurrency token (2F-A): a digest of the
// pool's canonical JSON (id, name, endpoints in order). Pools carry no stored
// revision, and none is needed — any content change yields a new token, and
// the token is identical on every node for the same content.
func PoolETag(p Pool) string {
	b, _ := json.Marshal(p) //nolint:errcheck // Pool is plain data; Marshal cannot fail
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ConfigETag is the collection token for profile/pool CREATE operations
// (2F-A): a digest of the whole canonical ProfilesConfig. Profiles embed their
// revision, so every profile or pool mutation changes it, and it is computed
// (never stored), so it is identical on every node holding the same config.
func ConfigETag(cfg ProfilesConfig) string {
	b, _ := json.Marshal(cfg) //nolint:errcheck // ProfilesConfig is plain data; Marshal cannot fail
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Get returns a deep-enough snapshot of the current config (slices copied;
// nested slices copied per element).
func (s *ProfileStore) Get() ProfilesConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyProfilesConfig(s.cfg)
}

// ProfileSetHook is a TEST-ONLY observation seam invoked at the entry of
// every Set with the candidate about to be written (before the store lock is
// taken). It lets an interleaving proof observe WHICH writer reached the
// authoritative store and when, without adding any synchronization the
// production path lacks. Production leaves it nil.
var ProfileSetHook func(cfg ProfilesConfig)

// Set replaces the config and persists it (tolerant — see type comment).
func (s *ProfileStore) Set(cfg ProfilesConfig) error {
	if h := ProfileSetHook; h != nil {
		h(cfg)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setLocked(cfg)
}

// GetWithGeneration returns a copy of the config together with the store
// generation it was read at — the pair a writer needs to build a candidate
// it can later commit with SetIfGeneration.
func (s *ProfileStore) GetWithGeneration() (cfg ProfilesConfig, gen uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyProfilesConfig(s.cfg), s.gen
}

// Generation returns the current store generation.
func (s *ProfileStore) Generation() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gen
}

// SetIfGeneration is Set guarded by a compare-and-swap on the store
// generation: the candidate is written ONLY if the store is still at
// expected (the generation GetWithGeneration reported when the candidate was
// built); otherwise ErrProfilesChanged is returned and NOTHING is written.
// The comparison and the write happen under one lock, so an intervening
// writer is detected atomically — it can never be overwritten by a candidate
// that predates it.
func (s *ProfileStore) SetIfGeneration(cfg ProfilesConfig, expected uint64) error {
	if h := ProfileSetHook; h != nil {
		h(cfg)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != expected {
		return fmt.Errorf("%w (generation %d, candidate built at %d)", ErrProfilesChanged, s.gen, expected)
	}
	return s.setLocked(cfg)
}

// setLocked is the persist-before-swap commit (2F-B, C1): the durable write
// is the commit point. Memory is replaced only after the file is durably
// written, so a failed write leaves the in-memory (and therefore the
// cluster-synced) view exactly where it was — never a torn "memory says
// candidate, disk says previous" state. Caller holds s.mu.
func (s *ProfileStore) setLocked(cfg ProfilesConfig) error {
	next := copyProfilesConfig(cfg)
	normalizeProfileRevisions(&next)
	if s.path != "" {
		data, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return err
		}
		if err := fileutil.AtomicWrite(s.path, data, 0o600); err != nil {
			return err
		}
	}
	s.cfg = next
	s.modTime = time.Now()
	s.gen++
	return nil
}

// ModTime reports when the config last changed (zero before any load/set).
func (s *ProfileStore) ModTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.modTime
}

// ProfileByID returns the profile and true when present (custom profiles
// only — the virtual default profile lives outside this store).
func (s *ProfileStore) ProfileByID(id string) (Profile, bool) {
	cfg := s.Get()
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID == id {
			return cfg.Profiles[i], true
		}
	}
	return Profile{}, false
}

// PoolByID returns the pool and true when present.
func (s *ProfileStore) PoolByID(id string) (Pool, bool) {
	cfg := s.Get()
	for i := range cfg.Pools {
		if cfg.Pools[i].ID == id {
			return cfg.Pools[i], true
		}
	}
	return Pool{}, false
}

// PoolMap returns pools keyed by ID (for the compiler/simulator).
func (s *ProfileStore) PoolMap() map[string]Pool {
	cfg := s.Get()
	m := make(map[string]Pool, len(cfg.Pools))
	for i := range cfg.Pools {
		m[cfg.Pools[i].ID] = cfg.Pools[i]
	}
	return m
}

// ProfileState is a full ProfileStore snapshot for test isolation.
type ProfileState struct {
	Cfg     ProfilesConfig
	Path    string
	ModTime time.Time
}

// Snapshot returns the store's full state (test support, -shuffle hermetic).
func (s *ProfileStore) Snapshot() ProfileState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ProfileState{Cfg: copyProfilesConfig(s.cfg), Path: s.path, ModTime: s.modTime}
}

// Restore resets the store to a previously captured state (test support).
func (s *ProfileStore) Restore(st ProfileState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = copyProfilesConfig(st.Cfg)
	s.path = st.Path
	s.modTime = st.ModTime
	s.gen++
}

func copyProfilesConfig(cfg ProfilesConfig) ProfilesConfig {
	out := ProfilesConfig{}
	if cfg.Profiles != nil {
		out.Profiles = make([]Profile, len(cfg.Profiles))
		copy(out.Profiles, cfg.Profiles)
		for i := range out.Profiles {
			out.Profiles[i].Rules = append([]Rule(nil), out.Profiles[i].Rules...)
		}
	}
	if cfg.Pools != nil {
		out.Pools = make([]Pool, len(cfg.Pools))
		copy(out.Pools, cfg.Pools)
		for i := range out.Pools {
			out.Pools[i].Endpoints = append([]PoolEndpoint(nil), out.Pools[i].Endpoints...)
		}
	}
	return out
}

// profileIDRe pins URL-safe profile/pool IDs: lowercase alphanumeric with
// inner hyphens, 1-64 chars, must start with [a-z0-9].
var profileIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ValidIdentifier reports whether id is a valid URL-safe profile/pool ID.
func ValidIdentifier(id string) bool { return profileIDRe.MatchString(id) }
