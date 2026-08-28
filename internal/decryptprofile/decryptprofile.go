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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// writeFile is the persistence primitive, swappable ONLY for fault injection in
// package-internal tests (the ErrReplacedNotSynced branch cannot be induced
// through the real filesystem deterministically). Production behavior is always
// fileutil.AtomicWrite.
var writeFile = fileutil.AtomicWrite

// ErrPersist marks a durable-persistence failure surfaced by MutateDurable
// AFTER the in-memory mutation was rolled back: nothing durable changed and the
// in-memory store was restored to the pre-mutation truth. Handlers map it to a
// 5xx — never a success.
var ErrPersist = errors.New("decryption profiles: durable persistence failed")

// ErrNameTaken marks a name-collision refusal (create against an existing name,
// or rename onto a name a DIFFERENT profile owns). Handlers map it to a 409 —
// the server-authoritative refusal, checked under the store lock so a
// concurrent create/rename cannot slip past a handler-level pre-check.
var ErrNameTaken = errors.New("name already in use")

// VersionConflictError is the optimistic-concurrency failure returned by
// MutateDurable when the caller's asserted store generation no longer matches:
// another admin mutated the store since the caller loaded it. The mutation
// never ran. Mirrors package main's policyVersionConflictError contract.
type VersionConflictError struct {
	Current  int64 // the store generation at the locked moment of the check
	Asserted int64 // the caller's ?ifVersion= assertion
}

func (e *VersionConflictError) Error() string {
	return fmt.Sprintf("the decryption profiles changed since you loaded them (your version %d, current %d) — reload and reapply your change", e.Asserted, e.Current)
}

// storeEnvelope is the durable persistence unit (2D-A fence correction):
// object CONTENT and the concurrency EPOCH land in ONE atomic write, so an
// acknowledged mutation can never leave new content with an old durable
// generation — including under ErrReplacedNotSynced, where the landed
// replacement carries the new epoch with the new content. See the catgroup
// twin for the full rationale; both implementations are proven independently.
//
// Backward compatibility: a legacy bare-array file (optionally with the
// retired path+".meta" sidecar) still loads; the first durable save migrates
// the format and removes the superseded sidecar. An older binary cannot read
// the envelope (unmarshal error → empty store; recorded downgrade residual —
// rules reference profiles by stable ID, so resolution degrades fail-closed).
type storeEnvelope struct {
	SchemaVersion int       `json:"schema_version"`
	Version       int64     `json:"version"`
	Profiles      []Profile `json:"profiles"`
}

// storeMeta is the RETIRED legacy sidecar shape (path+".meta") — read only
// when loading a legacy bare-array file, never written.
type storeMeta struct {
	Version int64 `json:"version"`
}

// isLegacyArrayFile reports whether the persisted bytes are the legacy
// bare-array format (pre-envelope).
func isLegacyArrayFile(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

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
//
// certVerification note: "permissive" is DELIBERATELY ABSENT. Earlier builds
// accepted it and documented it as "verify, allow on failure, and log", but that
// allow-on-failure enforcement was never implemented — the runtime always
// verified like "strict" (fail-closed). Rather than ship a misleading operator
// contract, the value is retired: every write path rejects it, and any existing
// persisted/synced profile carrying it is fail-closed-migrated to "strict" (see
// migrateLegacyCertVerification). Re-introducing allow-on-failure requires a
// separate approved design, not this map.
var (
	validCertVerification = map[string]bool{"": true, "strict": true, "skip": true}
	validOnUnsupported    = map[string]bool{"": true, "fail-close": true, "fail-open": true}
	validOnInspectError   = map[string]bool{"": true, "fail-close": true, "fail-open": true}
	validTLSVersion       = map[string]bool{"": true, "1.2": true, "1.3": true}
	// nameRe bounds the profile name charset (referenced by rules, rendered in the
	// UI); keep it to printable identifier-ish characters to avoid surprises.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
)

// certVerification migration constants. The retired value verified like the
// fail-closed strict posture, so the migration is byte-identical at runtime — it
// only corrects the stored contract so the operator-visible value matches the
// enforced behavior.
const (
	legacyCertVerification = "permissive"
	strictCertVerification = "strict"
)

// certMigrationSink, when published, is invoked once per profile whose
// unsupported certVerification=="permissive" was fail-closed-migrated to
// "strict" on a BULK install path (disk Load, config import, config-version
// rollback, CP→DP snapshot apply). package main wires it at startup to emit an
// audit-ring diagnostic; nil = no-op (the obs.Warnf warning fires regardless).
// Guarded by an atomic pointer (publish-once at startup, read under replace()
// which runs concurrently on the CP→DP sync path). Mirrors the obs.SetSink /
// audit.SetSIEM seam pattern — the engine stays free of a package-main import.
var certMigrationSink atomic.Pointer[func(profileName string)]

// SetCertMigrationSink publishes the migration-notice callback (see
// certMigrationSink). A nil fn clears it. Call once at startup, before the store
// is loaded or any CP→DP sync begins.
func SetCertMigrationSink(fn func(profileName string)) {
	if fn == nil {
		certMigrationSink.Store(nil)
		return
	}
	certMigrationSink.Store(&fn)
}

// migrateLegacyCertVerification rewrites the retired "permissive" posture to the
// fail-closed "strict" posture and reports whether it changed the profile.
// Applied on bulk install paths BEFORE Validate so a legacy entry survives
// fail-closed instead of being dropped as invalid. The interactive Add/Update
// paths intentionally do NOT call this — a caller actively submitting the retired
// value gets an explicit validation error, not a silent rewrite.
func migrateLegacyCertVerification(p *Profile) bool {
	if p.CertVerification == legacyCertVerification {
		p.CertVerification = strictCertVerification
		return true
	}
	return false
}

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
	// | "skip" (no verification).
	//
	// The retired "permissive" value is no longer accepted (its documented
	// allow-on-failure semantics were never implemented; it verified like
	// "strict"). A legacy persisted "permissive" is fail-closed-migrated to
	// "strict" on load/sync — see migrateLegacyCertVerification.
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

	// securityGen is the precomputed security generation (see computeSecurityGen):
	// a fingerprint over ONLY the fields whose change alters the meaning/safety of a
	// learned adaptive-decryption exclusion. Set by the store on every write; read by
	// the fail-open scope accessors so the CONNECT hot path never hashes. Unexported
	// ⇒ never JSON-serialized (never persisted, never CP→DP-synced); it is recomputed
	// identically on every node and across restarts from the fields it fingerprints.
	securityGen string
}

// securityGenVersion tags the fingerprint scheme so the encoding can evolve
// without silently colliding with an old one. Bump on any field-set/encoding change.
const securityGenVersion = "v1"

// computeSecurityGen returns the profile's security generation: a deterministic
// fingerprint over ONLY the fields whose change alters the meaning or safety of a
// learned adaptive-decryption exclusion — OnInspectError (the fail-open gate),
// CertVerification, OnUnsupported, MinTLSVersion, MaxTLSVersion, and the InspectHTTP2
// tri-state. Cosmetic/identity fields (ID, Name, CreatedAt, UpdatedAt) and the
// operational StallTimeoutSecs (a per-stream timeout, not a decrypt-compatibility or
// bypass-authorization determinant) are DELIBERATELY excluded, so a rename or
// display-only edit never invalidates learned entries. Pure function of the listed
// fields ⇒ identical on every node (CP→DP) and across restarts. Not on the hot path
// (precomputed at store-write time), so the write-time allocation is irrelevant.
//
// SCOPE BOUNDARY (deliberate): this fingerprints the PROFILE's own declared posture.
// When a profile leaves a field to INHERIT — CertVerification=="" or InspectHTTP2==nil
// — the effective per-session value falls back to the matched rule (rule.TLSSkipVerify
// / rule.StripALPN, see decryptprofile_resolve.go). Those are RULE-level, and the
// learned exclusion is PROFILE-scoped ((profileID, host), the mission's fixed isolation
// boundary), so a rule-level change to an inherited field is NOT a profile edit and does
// not move the gen. This is safe for the cert-verify axis (an untrusted/expired cert is a
// BLOCK, never a learn reason, and a bypassed session runs no inspect leg for
// TLSSkipVerify to govern) and at most leaves a self-healing (TTL-bounded) bypass on the
// inspection-mode axis. An operator who wants a field to fence learned exclusions should
// set it EXPLICITLY on the profile (then it is fingerprinted here). Per-RULE effective-
// posture fencing would re-scope the (profileID, host) boundary and is out of scope for
// this wave — a separate ADR (see roadmap/PR2-...md §Rejected alternatives).
func computeSecurityGen(p *Profile) string {
	h := sha256.New()
	h.Write([]byte(securityGenVersion))
	// Fixed order, 0x00-delimited. The values are a closed ASCII vocabulary (enum
	// strings + "1.2"/"1.3") that never contains NUL, so the delimiter is unambiguous.
	for _, v := range []string{p.OnInspectError, p.CertVerification, p.OnUnsupported, p.MinTLSVersion, p.MaxTLSVersion} {
		h.Write([]byte{0x00})
		h.Write([]byte(v))
	}
	h.Write([]byte{0x00, inspectHTTP2Byte(p.InspectHTTP2)})
	return hex.EncodeToString(h.Sum(nil)[:8]) // 64-bit fingerprint (16 hex chars); collision-negligible for this closed input space
}

// inspectHTTP2Byte encodes the InspectHTTP2 *bool tri-state (nil=inherit / true /
// false) into a single distinct byte, so the three states fingerprint distinctly.
func inspectHTTP2Byte(b *bool) byte {
	switch {
	case b == nil:
		return 0
	case *b:
		return 1
	default:
		return 2
	}
}

// SecurityGen returns the profile's security generation (see computeSecurityGen).
// The store precomputes it on every write; for a Profile constructed OUTSIDE the
// store (tests, direct literals, a copyOut value) it computes on demand, so the
// value is always correct and identical to the stored one.
func (p *Profile) SecurityGen() string {
	if p.securityGen != "" {
		return p.securityGen
	}
	return computeSecurityGen(p)
}

// Store manages persistent decryption profiles with O(1) name lookups.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile // keyed by lowercase name
	order    []string            // insertion order for stable list output
	path     string

	// version is the DURABLE per-store mutation generation (2D-A object
	// concurrency): bumped on every successful admin mutation and on bulk
	// installs (ReplaceAll), persisted ATOMICALLY WITH THE CONTENT in the
	// storeEnvelope so it stays monotonic across restarts and can never
	// diverge from the objects it fences, surfaced on the list read, and
	// asserted by MutateDurable's optional ifVersion fence.
	version int64

	// mutMu serializes EVERY runtime writer of the fenced domain — admin
	// mutations (MutateDurable) AND bulk installs (ReplaceAll from cluster
	// sync / import / rollback) — so no writer can alter contents or version
	// between a client's version comparison and its protected mutation
	// (2D-A fence correction, Blocker B). Readers and the proxy hot path
	// never touch it. Startup-only writers (Load, seedDefault*, before
	// listeners) are exempt by ordering.
	mutMu sync.Mutex

	// saveMu is the durable-PUBLICATION serializer (2D-A publication-ordering
	// correction; PolicyStore.saveMu's sibling): it covers SNAPSHOT → marshal
	// → AtomicWrite as one unit, so publications land in acquisition order and
	// each writes the store state CURRENT at its own snapshot — an older Save
	// that lost the race to a confirmed MutateDurable can never resume and
	// rename a stale envelope over the acknowledged one. Locking only the
	// write (after the snapshot) would NOT restore the invariant. LOCK ORDER:
	// mutMu → saveMu → mu. EVERY runtime persistence entry goes through mutMu
	// first (public SaveErr acquires it; MutateDurable holds it across the
	// whole transaction and calls the internal saveErrLocked, which must
	// never reacquire mutMu — the commit-boundary correction, so a standalone
	// save can never publish an in-flight mutation's memory). Nothing takes
	// mu then saveMu or mutMu, nothing takes saveMu then mutMu.
	saveMu sync.Mutex
}

// Version returns the durable per-store mutation generation (the ifVersion
// fence value clients echo back on mutations).
func (s *Store) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
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
	// Format sniff (2D-A fence correction): the envelope couples content +
	// epoch; a legacy bare array is still accepted, with its version taken
	// from the retired sidecar (absent ⇒ 0 — safe for LEGACY files only:
	// every mutation acknowledged under the envelope model persists its epoch
	// atomically with the content).
	var profiles []Profile
	var loadedVersion int64
	if isLegacyArrayFile(data) {
		if err := json.Unmarshal(data, &profiles); err != nil {
			obs.Printf("DecryptionProfiles: unmarshal error from %s", path)
			return err
		}
		var meta storeMeta
		if mdata, merr := os.ReadFile(path + ".meta"); merr == nil { // #nosec G304 -- sibling of the operator-configured path
			_ = json.Unmarshal(mdata, &meta)
		}
		loadedVersion = meta.Version
	} else {
		var env storeEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			obs.Printf("DecryptionProfiles: unmarshal error from %s", path)
			return err
		}
		// The schema discriminator is LOAD-BEARING (fail-closed format
		// validation): exactly schema_version 1 is accepted. Missing/zero,
		// negative, and unknown/future versions are refused with an explicit
		// error — a future envelope must never be silently parsed with
		// today's struct (fields it relies on would be dropped and the
		// truncated state re-persisted as if authoritative).
		if env.SchemaVersion != 1 {
			obs.Printf("DecryptionProfiles: unsupported envelope schema_version %d in %s (this binary supports 1)", env.SchemaVersion, path)
			return fmt.Errorf("decryption profiles: unsupported envelope schema_version %d (want 1)", env.SchemaVersion)
		}
		// A negative persisted fence generation is impossible for this store
		// to have written — refuse rather than install a corrupt epoch.
		if env.Version < 0 {
			obs.Printf("DecryptionProfiles: invalid negative persisted version %d in %s", env.Version, path)
			return fmt.Errorf("decryption profiles: invalid negative persisted version %d", env.Version)
		}
		profiles = env.Profiles
		loadedVersion = env.Version
	}
	migrated, skipped, certMigrated := s.replaceContents(profiles, true)
	s.mu.Lock()
	s.version = loadedVersion
	s.mu.Unlock()
	obs.Printf("DecryptionProfiles: loaded %d profile(s) from %s", len(profiles), path)
	// Persist backfilled IDs (?id= stability) and any fail-closed
	// certVerification migration so the on-disk file stops carrying the retired
	// value across restarts (idempotent: a clean reload finds nothing to change).
	// Only when NOTHING was skipped: a Save here rewrites the file with just the
	// accepted profiles, so persisting while invalid/dup entries were skipped
	// would permanently delete them (Load's contract is to log-and-leave them on
	// disk). With skipped entries present we keep the changes in-memory only for
	// this session; a later clean load persists them stably.
	if (migrated > 0 || certMigrated > 0) && skipped == 0 {
		s.Save()
		if migrated > 0 {
			obs.Printf("DecryptionProfiles: assigned stable IDs to %d legacy profile(s)", migrated)
		}
		if certMigrated > 0 {
			obs.Printf("DecryptionProfiles: migrated %d profile(s) from certVerification=permissive to strict", certMigrated)
		}
	}
	return nil
}

// Save persists the current profiles to disk (atomic write). No-op when path
// unset. Best-effort legacy wrapper for old non-critical callers; the hardened
// v2 mutation path (MutateDurable) uses the error-returning SaveErr and rolls
// back on failure.
func (s *Store) Save() { _ = s.SaveErr() }

// SaveErr is the error-returning persistence core (2D-A durable-or-nothing).
// Content and the fence epoch are ONE envelope in ONE atomic write, so they
// can never diverge durably — including under ErrReplacedNotSynced, where the
// landed replacement carries the new epoch with the new content. The retired
// legacy sidecar is removed once the envelope has landed.
//
// SaveErr is the PUBLIC entry: it acquires mutMu FIRST (2D-A commit-boundary
// correction), so a standalone save orders against the whole mutation domain
// and can never observe — let alone publish — the memory state of an
// in-flight MutateDurable transaction: fn's uncommitted content paired with
// the not-yet-advanced epoch. Without this, a caller-side Save (the
// production ReplaceAll+Save bulk shape) racing an admin mutation could
// persist uncommitted-new-content + old-epoch; if that mutation then failed
// its own publication and rolled back, the failed, unacknowledged mutation
// stayed on disk. MutateDurable already holds mutMu and calls saveErrLocked
// directly — mutMu is not reentrant, so an internal SaveErr call from inside
// the mutation path would deadlock and must never be added.
func (s *Store) SaveErr() error {
	s.mutMu.Lock()
	defer s.mutMu.Unlock()
	return s.saveErrLocked()
}

// saveErrLocked is the INTERNAL publication helper. LOCK OWNERSHIP CONTRACT:
// the caller MUST hold mutMu (public SaveErr acquires it; MutateDurable holds
// it across the whole transaction) — it is never called bare, and it must
// NOT reacquire mutMu.
//
// The WHOLE helper runs under saveMu — snapshot included, not just the
// write — so publications form one monotonic order and durable state never
// goes backwards: once MutateDurable has returned success for epoch N, no
// older in-flight Save can replace the envelope with epoch < N. Every runtime
// persistence path routes through here (Save is a thin wrapper over
// SaveErr), so no caller sits outside the ordering domain. Lock order
// within: saveMu → mu(RLock).
func (s *Store) saveErrLocked() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	path := s.path
	if path == "" {
		s.mu.RUnlock()
		return nil
	}
	profiles := make([]Profile, 0, len(s.order))
	for _, key := range s.order {
		if p, ok := s.profiles[key]; ok {
			profiles = append(profiles, copyOut(p))
		}
	}
	env := storeEnvelope{SchemaVersion: 1, Version: s.version, Profiles: profiles}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal decryption profiles: %w", err)
	}
	werr := writeFile(path, data, 0o600)
	if werr == nil || errors.Is(werr, fileutil.ErrReplacedNotSynced) {
		_ = os.Remove(path + ".meta") // superseded legacy sidecar (best-effort)
	}
	if werr != nil {
		return fmt.Errorf("write decryption profiles: %w", werr)
	}
	return nil
}

// MutateDurable runs ONE admin mutation with the OPTIONAL expected-version
// fence AND the durable persist evaluated in the same serialized critical
// section — the exact contract documented on catgroup.Store.MutateDurable
// (fence mismatch ⇒ *VersionConflictError, fn error ⇒ atomic rollback,
// persist failure ⇒ rollback + ErrPersist, ErrReplacedNotSynced ⇒
// landed-content success WITH the epoch, since content + version are one
// atomic envelope). ReplaceAll holds the same mutMu, so no writer can alter
// the fenced domain between the version comparison and the mutation.
func (s *Store) MutateDurable(ifVersion *int64, fn func() error) error {
	s.mutMu.Lock()
	defer s.mutMu.Unlock()

	s.mu.RLock()
	cur := s.version
	s.mu.RUnlock()
	if ifVersion != nil && *ifVersion != cur {
		return &VersionConflictError{Current: cur, Asserted: *ifVersion}
	}
	prev := s.List() // value snapshot for the rollback path
	if err := fn(); err != nil {
		// fn is ATOMIC-or-nothing too: a composed mutation (content update +
		// rename) that fails partway (e.g. rename collision after the content
		// applied) must not half-land — restore the pre-mutation state.
		s.restoreSnapshot(prev, cur)
		return err
	}
	s.mu.Lock()
	// Bump the LIVE value, never "captured + 1" (§7): serialized writers make
	// them equal, but the live increment stays monotonic regardless.
	s.version++
	s.mu.Unlock()
	// mutMu is already held for the whole transaction — call the internal
	// publication helper directly (public SaveErr would self-deadlock).
	if err := s.saveErrLocked(); err != nil {
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			obs.Warnf("DecryptionProfiles: mutation persisted but parent-dir sync failed: %v", err)
			return nil
		}
		s.restoreSnapshot(prev, cur)
		return fmt.Errorf("%w: %w", ErrPersist, err)
	}
	return nil
}

// restoreSnapshot reinstalls a pre-mutation value snapshot and generation (the
// MutateDurable rollback path). Rebuilds the name index like replace() but does
// NOT re-validate (the snapshot came from this store) and does NOT bump version
// (the failed mutation never happened).
func (s *Store) restoreSnapshot(profiles []Profile, version int64) {
	built := make(map[string]*Profile, len(profiles))
	order := make([]string, 0, len(profiles))
	for i := range profiles {
		p := profiles[i]
		p.securityGen = computeSecurityGen(&p)
		key := strings.ToLower(p.Name)
		np := p
		built[key] = &np
		order = append(order, key)
	}
	s.mu.Lock()
	s.profiles = built
	s.order = order
	s.version = version
	s.mu.Unlock()
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

// Snapshot is one coherent read of the whole list contract: the profiles, the
// derived name list, and the durable fence version, all describing the SAME
// store state (POST-2D-A COHERENT-READ CORRECTION DISCOVERED DURING 2D-B
// REVIEW).
type Snapshot struct {
	Profiles []Profile
	Names    []string
	Version  int64
}

// SnapshotView captures profiles + names + version under ONE hold of the read
// lock. List()/Names()/Version() assembled by a caller are three independent
// reads — a writer landing between any two hands the client rows from one
// state paired with the fence version of another, and an edit from that pair
// passes the ifVersion fence against content the client never saw. Handlers
// serving the fenced list contract must use this, never the trio.
func (s *Store) SnapshotView() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		Profiles: make([]Profile, 0, len(s.order)),
		Names:    make([]string, 0, len(s.order)),
		Version:  s.version,
	}
	for _, key := range s.order {
		if p, ok := s.profiles[key]; ok {
			snap.Profiles = append(snap.Profiles, copyOut(p))
			snap.Names = append(snap.Names, p.Name)
		}
	}
	return snap
}

// FailOpenScope returns the profile's ID, its precomputed security generation, and
// true IFF a profile with the given name exists AND opts into fail-open
// (OnInspectError=="fail-open"). It is a HOT-PATH accessor (resolveSSLAction calls
// it per CONNECT for fail-open rules): it reads only three stored string fields under
// the RLock and returns NO copy, avoiding the copyOut allocation a full GetByName
// pays. The gen fences the learned-exclusion cache to the exact inspection posture,
// so a security-relevant profile edit invalidates entries without re-hashing here.
// The learn/cold paths keep the copy-returning accessors.
func (s *Store) FailOpenScope(name string) (id, gen string, ok bool) {
	s.mu.RLock()
	p := s.profiles[strings.ToLower(strings.TrimSpace(name))]
	if p == nil || p.OnInspectError != "fail-open" {
		s.mu.RUnlock()
		return "", "", false
	}
	id = p.ID
	gen = p.SecurityGen() // precomputed at write time (no hashing); self-heals to a compute iff a write path ever left it empty — same source as the learn path (decryptionScope), so read and learn can never disagree
	s.mu.RUnlock()
	return id, gen, true
}

// FailOpenScopeByID resolves the autoexclude scope + security generation by the
// profile's stable ULID (references-by-id / rename-safe). resolved=true iff a profile
// with that id EXISTS; scope is its ID and gen its precomputed security generation
// when that profile is fail-open, else both "". The ID is
// AUTHORITATIVE: a resolved fail-close profile returns ("", true) so the caller
// does NOT fall back to the name — otherwise a rule whose id points at a
// fail-close profile but whose stale name points at a different fail-open one
// could get its (fail-close) session bypassed, violating the "fail-close is
// un-poisonable" invariant. Mirrors resolveDecryptionProfile: name fallback only
// when the id resolves to no profile at all. No-copy fast path; O(profiles), a
// small admin set, only on the SSL-inspect CONNECT path.
func (s *Store) FailOpenScopeByID(id string) (scope, gen string, resolved bool) {
	if id == "" {
		return "", "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			if p.OnInspectError == "fail-open" {
				return p.ID, p.SecurityGen(), true // resolved + fail-open → scope + security generation (same source as the learn path)
			}
			return "", "", true // resolved but fail-close → no scope, and no name fallback
		}
	}
	return "", "", false // not found → caller may fall back to the name
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
		return nil, fmt.Errorf("profile %q already exists: %w", p.Name, ErrNameTaken)
	}
	if p.ID == "" {
		p.ID = uuid.NewString()[:12]
	}
	p.CreatedAt = now
	p.UpdatedAt = now
	np := p
	np.securityGen = computeSecurityGen(&np)
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
	np.securityGen = computeSecurityGen(&np)
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
// Bulk install = a content change: the client-visible fence advances so any admin
// edit loaded against the pre-install contents conflicts instead of silently
// overwriting the installed truth.
//
// SERIALIZATION (2D-A fence correction, Blocker B): ReplaceAll holds the SAME
// mutMu as MutateDurable, so a bulk install can never interleave between a
// client's ifVersion comparison and its protected mutation — the two writer
// classes observe exactly one serial order, and the fence generation cannot
// alias across them.
func (s *Store) ReplaceAll(profiles []Profile) {
	s.mutMu.Lock()
	defer s.mutMu.Unlock()
	s.replaceContents(profiles, false)
	s.mu.Lock()
	s.version++
	s.mu.Unlock()
}

// replaceContents is the shared install path (no serialization, no version
// movement — Load and the mutMu-holding ReplaceAll own those). skipInvalidLog
// controls whether skipped
// entries are logged (Load logs; ReplaceAll stays quiet on the hot sync path).
// Returns the number of profiles that had a stable ID backfilled (migrated), the
// number skipped as invalid/duplicate (skipped), and the number whose retired
// certVerification=permissive was fail-closed-migrated to strict (certMigrated).
// Load persists (migrated>0 || certMigrated>0) only when skipped==0, so a rewrite
// never drops skipped entries.
func (s *Store) replaceContents(profiles []Profile, logSkips bool) (migrated, skipped, certMigrated int) {
	built := make(map[string]*Profile, len(profiles))
	order := make([]string, 0, len(profiles))
	for i := range profiles {
		p := profiles[i]
		p.Name = strings.TrimSpace(p.Name)
		// Fail-closed rewrite of the retired "permissive" cert-verification value
		// to "strict" BEFORE Validate, so a legacy entry is corrected rather than
		// dropped as invalid. The migration NOTICE (warn/audit/counter) is deferred
		// until the profile is actually installed below — a profile that carries
		// permissive AND an independently-invalid field (or is a duplicate) is
		// still skipped, and must not be reported as "migrated & retained".
		wasCertMigrated := migrateLegacyCertVerification(&p)
		if err := Validate(&p); err != nil {
			if logSkips {
				obs.Printf("DecryptionProfiles: skipping invalid profile %q: %v", p.Name, err)
			}
			skipped++
			continue
		}
		key := strings.ToLower(p.Name)
		if _, dup := built[key]; dup {
			skipped++
			continue // last-write-wins would reorder; keep first, drop dup
		}
		if p.ID == "" {
			p.ID = uuid.NewString()[:12]
			migrated++
		}
		p.securityGen = computeSecurityGen(&p)
		// Profile is committed to the new store — now (and only now) report the
		// certVerification migration for it. Always warns (Load and the sync
		// paths) and, when wired, emits an audit-ring diagnostic.
		if wasCertMigrated {
			certMigrated++
			obs.Warnf("DecryptionProfiles: profile %q used unsupported certVerification=%q; migrated to fail-closed %q (permissive contract removed)",
				p.Name, legacyCertVerification, strictCertVerification)
			if sink := certMigrationSink.Load(); sink != nil {
				(*sink)(p.Name)
			}
		}
		np := p
		built[key] = &np
		order = append(order, key)
	}
	s.mu.Lock()
	s.profiles = built
	s.order = order
	s.mu.Unlock()
	return migrated, skipped, certMigrated
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
		p.UpdatedAt = time.Now().UTC().Format(time.RFC3339) // parity with the name-keyed Update
		if err := Validate(&p); err != nil {
			return err
		}
		np := p
		np.securityGen = computeSecurityGen(&np)
		s.profiles[key] = &np
		return nil
	}
	return fmt.Errorf("profile id %q not found", id)
}

// Rename changes the display name of the profile with the given stable ID,
// re-keying the name index (references-by-id: rules link by ID, so the rename is
// safe — the caller cascades the denormalized name onto referencing rules).
// Validates the new name is non-empty and not already taken by a DIFFERENT
// profile. Returns the OLD name (for audit + the caller's cascade). A case-only
// change updates the display name in place without a collision check.
func (s *Store) Rename(id, newName string) (oldName string, err error) {
	newName = strings.TrimSpace(newName)
	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	if newName == "" {
		return "", fmt.Errorf("name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var curKey string
	var cur *Profile
	for key, p := range s.profiles {
		if p.ID == id {
			curKey, cur = key, p
			break
		}
	}
	if cur == nil {
		return "", fmt.Errorf("profile id %q not found", id)
	}
	oldName = cur.Name
	newKey := strings.ToLower(newName)
	now := time.Now().UTC().Format(time.RFC3339)
	if newKey == curKey {
		// Same key (no change or case-only) — update the display name in place.
		cur.Name = newName
		cur.UpdatedAt = now
		return oldName, nil
	}
	if _, taken := s.profiles[newKey]; taken {
		return "", fmt.Errorf("a profile named %q already exists: %w", newName, ErrNameTaken)
	}
	np := *cur
	np.Name = newName
	np.UpdatedAt = now
	delete(s.profiles, curKey)
	s.profiles[newKey] = &np
	// Re-key s.order too (mirrors catgroup.Store.Rename): List/Save/Names all
	// iterate s.order and skip keys absent from s.profiles, so leaving the stale
	// curKey in s.order (and newKey out of it) silently DROPS the renamed
	// profile from the list, the on-disk file, and the CP→DP ConfigSnapshot —
	// durable, fleet-wide config loss from one rename.
	for i, k := range s.order {
		if k == curKey {
			s.order[i] = newKey
			break
		}
	}
	return oldName, nil
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
