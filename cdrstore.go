package main

// Sluice CDR instance registry + process-wide client lifecycle.
//
// An "instance" is one enrolled Sluice server.  Phase 1 shipped the client
// primitives (cdr.go); Phase 2a adds:
//
//   - A JSON-backed instance registry so Culvert remembers enrolled Sluice
//     servers across restarts.  Structured for N instances even though
//     Phase 2 only uses the first one — the shape needs to stabilise now
//     so Phase 2b's proxy wiring doesn't churn.
//
//   - A process-wide singleton CDRClient, initialised from config + registry
//     at startup, closed cleanly at shutdown.  handleTunnelInspect (Phase 2b)
//     will call `cdrActiveClient()` to get the live client.
//
// The client is NOT a ConfigSnapshot-syncable field yet.  Phase 2c adds
// that when the Control Plane starts pushing CDR config to Data Planes.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Instance model ─────────────────────────────────────────────────────────

// CDREnrolledInstance is one Sluice server Culvert has completed enrollment
// against.  The mTLS material lives on disk (paths point at PEM files) so
// keys never enter the JSON registry — leak resistance follows the same
// pattern as Culvert's DataPlane cert storage.
type CDREnrolledInstance struct {
	// Name is a unique operator-chosen label (e.g. "sluice-us-east-01").
	Name string `json:"name"`

	// Endpoint is the gRPC address (host:port) Culvert dials.
	Endpoint string `json:"endpoint"`

	// ServerFingerprint is the TOFU-pinned SHA-256 hex of Sluice's server
	// cert.  "sha256:" prefix stripped on store.
	ServerFingerprint string `json:"serverFingerprint"`

	// On-disk paths for the mTLS bundle returned by Sluice.Enroll.
	// All three MUST be under the same directory (enforced at write time).
	CACertPath     string `json:"caCertPath"`
	ClientCertPath string `json:"clientCertPath"`
	ClientKeyPath  string `json:"clientKeyPath"`

	// Metadata for the admin GUI (Phase 3); populated from Enroll + Health.
	EnrolledAt time.Time `json:"enrolledAt"`
	Version    string    `json:"version,omitempty"`    // from last Health
	LastHealth time.Time `json:"lastHealth,omitempty"` // zero = never probed

	// Enabled is a soft toggle separate from registration.  Disabled
	// instances are skipped by the client picker but kept in the registry
	// so re-enabling doesn't require re-enrollment.
	Enabled *bool `json:"enabled,omitempty"` // nil or true = active

	// RotatedFingerprint + RotatedFingerprintUntilUnix track an active
	// Sluice server-cert rotation.  Populated by the health poller from
	// HealthResponse.rotated_fingerprint* fields.  Empty / 0 when no
	// rotation is active.  When the window passes, the poller promotes
	// RotatedFingerprint to ServerFingerprint and clears these two
	// fields — the new cert is now the canonical pin.
	RotatedFingerprint          string `json:"rotatedFingerprint,omitempty"`
	RotatedFingerprintUntilUnix int64  `json:"rotatedFingerprintUntilUnix,omitempty"`
}

// IsEnabled mirrors policy.go's ruleIsEnabled — nil pointer = active.
func (i *CDREnrolledInstance) IsEnabled() bool {
	return i == nil || i.Enabled == nil || *i.Enabled
}

// ─── Registry ───────────────────────────────────────────────────────────────

// CDRInstanceRegistry is the persisted list of enrolled Sluice servers.
// Thread-safe; JSON-backed at `path`.
type CDRInstanceRegistry struct {
	mu        sync.RWMutex
	instances []*CDREnrolledInstance
	path      string
	version   int64
	updatedAt string
}

var cdrInstances = &CDRInstanceRegistry{}

// Version reports the monotonic counter + last-updated RFC3339 timestamp.
func (r *CDRInstanceRegistry) Version() (int64, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version, r.updatedAt
}

// bumpVersion MUST be called under r.mu.Lock().
func (r *CDRInstanceRegistry) bumpVersion() {
	r.version++
	r.updatedAt = time.Now().UTC().Format(time.RFC3339)
}

// Load reads the registry from disk.  Missing file = empty registry.
func (r *CDRInstanceRegistry) Load(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cdr instances: read %q: %w", sanitizeLog(path), err)
	}
	var list []*CDREnrolledInstance
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("cdr instances: parse %q: %w", sanitizeLog(path), err)
	}
	r.instances = list
	r.bumpVersion()
	return nil
}

// Save atomically persists the registry.  No-op when path is empty
// (in-memory mode for tests).
func (r *CDRInstanceRegistry) Save() error {
	r.mu.RLock()
	path := r.path
	list := append([]*CDREnrolledInstance(nil), r.instances...)
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("cdr instances: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("cdr instances: write %q: %w", sanitizeLog(tmp), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cdr instances: rename: %w", err)
	}
	return nil
}

// List returns a shallow snapshot, in registration order.
func (r *CDRInstanceRegistry) List() []*CDREnrolledInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*CDREnrolledInstance, len(r.instances))
	copy(out, r.instances)
	return out
}

// Add registers a new instance.  Name must be unique and non-empty.
// Returns a copy of the stored entry (with normalised fingerprint).
func (r *CDRInstanceRegistry) Add(inst CDREnrolledInstance) (CDREnrolledInstance, error) {
	if strings.TrimSpace(inst.Name) == "" {
		return CDREnrolledInstance{}, fmt.Errorf("cdr instances: name required")
	}
	if strings.TrimSpace(inst.Endpoint) == "" {
		return CDREnrolledInstance{}, fmt.Errorf("cdr instances: endpoint required")
	}
	inst.ServerFingerprint = normaliseFingerprint(inst.ServerFingerprint)
	if inst.EnrolledAt.IsZero() {
		inst.EnrolledAt = time.Now().UTC()
	}

	r.mu.Lock()
	for _, existing := range r.instances {
		if existing.Name == inst.Name {
			r.mu.Unlock()
			safe := strings.ReplaceAll(strings.ReplaceAll(inst.Name, "\n", "_"), "\r", "_")
			return CDREnrolledInstance{}, fmt.Errorf("cdr instances: %q already enrolled", safe)
		}
	}
	copy := inst
	r.instances = append(r.instances, &copy)
	r.bumpVersion()
	r.mu.Unlock()

	if err := r.Save(); err != nil {
		return CDREnrolledInstance{}, err
	}
	return copy, nil
}

// RemoveByName removes an instance; returns false if no match.
// Callers are responsible for shredding the cert files on disk — this
// store doesn't know the retention policy.
func (r *CDRInstanceRegistry) RemoveByName(name string) (bool, error) {
	r.mu.Lock()
	found := -1
	for i := range r.instances {
		if r.instances[i].Name == name {
			found = i
			break
		}
	}
	if found < 0 {
		r.mu.Unlock()
		return false, nil
	}
	r.instances = append(r.instances[:found], r.instances[found+1:]...)
	r.bumpVersion()
	r.mu.Unlock()
	if err := r.Save(); err != nil {
		return true, err
	}
	return true, nil
}

// Get returns a pointer to the stored instance by name, or nil.
// The returned pointer is into the registry's internal slice — do not
// mutate without holding r.mu.
func (r *CDRInstanceRegistry) Get(name string) *CDREnrolledInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := range r.instances {
		if r.instances[i].Name == name {
			return r.instances[i]
		}
	}
	return nil
}

// firstEnabled returns the first enabled instance, or nil.  Phase 2a's
// single-instance client picker uses this; Phase 2b's pool will replace it.
func (r *CDRInstanceRegistry) firstEnabled() *CDREnrolledInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := range r.instances {
		if r.instances[i].IsEnabled() {
			return r.instances[i]
		}
	}
	return nil
}

// ─── Fingerprint normalisation ──────────────────────────────────────────────

// normaliseFingerprint strips the "sha256:" prefix and any colons,
// lowercasing the result.  Returns "" unchanged.
func normaliseFingerprint(fp string) string {
	s := strings.TrimSpace(fp)
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.TrimPrefix(s, "SHA256:")
	s = strings.ReplaceAll(s, ":", "")
	return strings.ToLower(s)
}

// ─── Process-wide client lifecycle ──────────────────────────────────────────

// cdrClientState wraps the config snapshot so tests can reset it without
// data races.  The pool itself (cdr_pool.go) owns the actual clients.
var (
	cdrClientMu  sync.RWMutex
	cdrActiveCfg CDRConfig
)

// cdrRuntimeEnabledPath is the sentinel file whose existence indicates
// CDR is enabled at runtime — written by the admin toggle / first
// enrollment, read at boot.  Separate from YAML/CLI so admins can flip
// CDR on without restarting Culvert (and so the first enrollment via
// the GUI works without ops pre-setting the flag).
const cdrRuntimeEnabledPath = "/data/cdr_enabled"

// cdrRuntimeEnabled reports whether the runtime-enable sentinel exists.
// Called at startup (config merge time) and whenever the toggle
// handler needs to check current state.
func cdrRuntimeEnabled() bool {
	info, err := os.Stat(cdrRuntimeEnabledPath)
	return err == nil && !info.IsDir()
}

// setCDRRuntimeEnabled creates or removes the runtime-enable sentinel.
// Called by the admin toggle handler and the auto-enable-on-enroll
// path.  Errors are returned for the caller to surface in audit logs —
// a failed write means the next boot will see the previous state.
func setCDRRuntimeEnabled(on bool) error {
	if !on {
		if err := os.Remove(cdrRuntimeEnabledPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cdr toggle: remove sentinel: %w", err)
		}
		return nil
	}
	// Ensure parent dir exists (matches the 0700 perms we use for
	// other CDR state).  Empty file — presence is the signal.
	if dir := filepath.Dir(cdrRuntimeEnabledPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("cdr toggle: mkdir: %w", err)
		}
	}
	if err := os.WriteFile(cdrRuntimeEnabledPath, nil, 0o600); err != nil {
		return fmt.Errorf("cdr toggle: write sentinel: %w", err)
	}
	return nil
}

// setCDREnabledRuntime flips the in-memory cfg.Enabled AND the
// on-disk sentinel.  Used by the enroll auto-enable path and the
// admin toggle.  Does NOT call initCDRClient — callers decide
// whether/when to dial.
func setCDREnabledRuntime(on bool) error {
	if err := setCDRRuntimeEnabled(on); err != nil {
		return err
	}
	cdrClientMu.Lock()
	cdrActiveCfg.Enabled = on
	cdrClientMu.Unlock()
	return nil
}

// cdrActiveClient returns any live CDR client from the pool, or nil when
// CDR is disabled / no instance is available.
//
// Backwards-compat: callers that just want "is CDR live?" treat nil as
// "no" and keep working.  The proxy hot path should call cdrPickPooled()
// instead to pick a healthy instance with circuit-breaker awareness.
func cdrActiveClient() *CDRClient {
	if pc := cdrPool.Pick(); pc != nil {
		return pc.Client
	}
	return nil
}

// cdrActiveConfig returns a snapshot of the effective CDR config as wired
// at the last initCDRClient() call.  Safe to call from hot paths; callers
// receive a value copy — mutating it does not affect live state.
func cdrActiveConfig() CDRConfig {
	cdrClientMu.RLock()
	defer cdrClientMu.RUnlock()
	return cdrActiveCfg
}

// initCDRClient wires up the client pool from CDRConfig + the instance
// registry.  Safe to call when disabled (no-op).  Idempotent: callers
// may reinvoke after hot-config-reload; the old pool is replaced
// atomically and old connections are closed after the swap.
//
// Phase 2d: each enabled instance gets its own pooled client with its
// own circuit breaker.  Phase 2c's single-client behaviour is preserved
// when the registry has exactly one enabled instance.
func initCDRClient(cfg CDRConfig) error {
	if !cfg.Enabled {
		shutdownCDRClient()
		return nil
	}

	oldPool := cdrPool.List()
	newPool, err := buildCDRPoolFromRegistry(cfg, oldPool)
	if err != nil && len(newPool) == 0 {
		// Complete failure — every instance failed to dial.
		return fmt.Errorf("cdr: init pool: %w", err)
	}
	cdrPool.replace(newPool)

	cdrClientMu.Lock()
	cdrActiveCfg = cfg
	cdrClientMu.Unlock()

	names := make([]string, 0, len(newPool))
	for _, pc := range newPool {
		names = append(names, pc.Name)
	}
	logger.Printf("CDR: pool active — %d instance(s): %s",
		len(newPool), sanitizeLog(strings.Join(names, ",")))

	// Fire non-blocking Health probes against every pool member so the
	// first real user request doesn't eat the TLS-handshake latency
	// (and so we detect broken certs / fingerprint mismatches at boot,
	// not under load).
	warmupCDRClient()
	return nil
}

// shutdownCDRClient closes every pooled client and clears the active
// config.  Safe to call when no pool was ever built.  Invoked from
// main.go's graceful shutdown.
func shutdownCDRClient() {
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{}
	cdrClientMu.Unlock()
	cdrPool.shutdown()
}

// cdrCertBundle is the set of PEM blobs + naming context loaded from a
// loadCDRCertBundle reads the three PEM files from disk, validating that
// none contain path traversal and all exist.
func loadCDRCertBundle(caPath, certPath, keyPath string) (ca, cert, key []byte, err error) {
	for _, p := range []string{caPath, certPath, keyPath} {
		if strings.Contains(p, "..") {
			return nil, nil, nil, fmt.Errorf("cdr certs: path traversal: %q", sanitizeLog(p))
		}
	}
	var rerr error
	ca, rerr = os.ReadFile(filepath.Clean(caPath))
	if rerr != nil {
		return nil, nil, nil, fmt.Errorf("cdr certs: read ca: %w", rerr)
	}
	cert, rerr = os.ReadFile(filepath.Clean(certPath))
	if rerr != nil {
		return nil, nil, nil, fmt.Errorf("cdr certs: read client cert: %w", rerr)
	}
	key, rerr = os.ReadFile(filepath.Clean(keyPath))
	if rerr != nil {
		return nil, nil, nil, fmt.Errorf("cdr certs: read client key: %w", rerr)
	}
	return ca, cert, key, nil
}
