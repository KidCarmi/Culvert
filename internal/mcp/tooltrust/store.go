package tooltrust

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// persistedStore is the on-disk envelope. A schema-versioned wrapper so a
// pre-change reader rejects a newer layout (fail closed) rather than silently
// dropping fields it cannot interpret. The whole file is rewritten atomically on
// every mutation, so current/previous can never be observed inconsistently.
type persistedStore struct {
	SchemaVersion uint16          `json:"schema_version"`
	Approvals     []*ToolApproval `json:"approvals"`
}

// Config configures a Store. Path is the durable file; the bounds keep the file
// (and the in-memory index) from growing without limit under a hostile or
// careless caller. Zero bounds fall back to conservative defaults.
type Config struct {
	// Path is the durable approvals file, e.g. <dataDir>/mcp_tooltrust/approvals.json.
	Path string
	// Clock is the injected time source (default time.Now). Every expiry decision
	// reads it, so tests drive expiry deterministically.
	Clock func() time.Time
	// MaxRecords bounds the TOTAL number of stored records (pending + active +
	// terminal). At capacity a new request prunes the oldest terminal record; if
	// none can be pruned the request fails closed.
	MaxRecords int
	// MaxPerTenant bounds the number of NON-terminal (pending + active) records per
	// tenant, so one tenant cannot exhaust the global budget.
	MaxPerTenant int
}

const (
	defaultMaxRecords   = 4096
	defaultMaxPerTenant = 256
)

// Store is the durable, bounded, tenant-scoped, secret-free ToolApproval store —
// the SOURCE OF TRUTH for MCP tool trust (ADR-0034 D2/D3). It persists to a single
// atomically-rewritten file and is recoverable independently of the MCP events
// spool. All state transitions happen under the store lock and are made durable
// BEFORE they are published to the in-memory index (persist-before-effect): a
// persistence failure leaves the in-memory state byte-unchanged and fails closed.
//
// The catalog's Usable state is a MATERIALIZED PROJECTION of this store; the
// coordinator (package main) owns the derivation and reconciles the catalog. The
// store itself never touches the catalog, dials a server, or materializes a
// credential.
type Store struct {
	mu           sync.Mutex
	clock        func() time.Time
	path         string
	byID         map[string]*ToolApproval
	maxRecords   int
	maxPerTenant int
	// writeFile is the durable-write seam (default fileutil.AtomicWrite). Tests
	// inject a failing implementation to prove that a persistence failure leaves the
	// in-memory state byte-unchanged (durable-before-effect); production never
	// replaces it.
	writeFile func(path string, data []byte, perm os.FileMode) error
}

// NewStore constructs a Store bound to cfg. It does NOT read the durable file;
// call Load once at startup (kept separate so tests control recovery). The parent
// directory is created if absent so the first AtomicWrite succeeds.
func NewStore(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.new", "empty store path")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = time.Now
	}
	maxRecords := cfg.MaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultMaxRecords
	}
	maxPerTenant := cfg.MaxPerTenant
	if maxPerTenant <= 0 {
		maxPerTenant = defaultMaxPerTenant
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.new", "create store dir", err)
	}
	return &Store{
		clock:        clk,
		path:         cfg.Path,
		byID:         make(map[string]*ToolApproval),
		maxRecords:   maxRecords,
		maxPerTenant: maxPerTenant,
		writeFile:    fileutil.AtomicWrite,
	}, nil
}

// Load reads the durable file into the in-memory index. A missing file is a fresh
// store (no error). A corrupt file, an unknown/newer schema version, or any record
// that fails structural validation is a fail-CLOSED error (never a permissive
// empty state that would silently revoke every prior trust decision).
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path) // #nosec G304 -- fixed store path under the data dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // fresh store
		}
		return mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.load", "read store", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env persistedStore
	if err := dec.Decode(&env); err != nil {
		return mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.load", "corrupt store file", err)
	}
	// A single Decode accepts the first valid value and ignores anything after it, so
	// trailing bytes (a second JSON value, arbitrary garbage, or a stray closing
	// delimiter from a partial/tampered write) would still load. Decoder.More is an
	// array/object iteration predicate and returns false for a trailing `]`/`}`, so it
	// is NOT an EOF check — a second decode that must report io.EOF is. Fail closed on
	// anything but a clean end of stream.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "store file has trailing data")
	}
	if env.SchemaVersion != SchemaVersion {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "unknown store schema version")
	}
	byID := make(map[string]*ToolApproval, len(env.Approvals))
	for _, a := range env.Approvals {
		if a == nil {
			return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "nil approval record")
		}
		if err := a.validateStored(); err != nil {
			return err
		}
		if _, dup := byID[a.ApprovalID]; dup {
			return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "duplicate approval id")
		}
		byID[a.ApprovalID] = a
	}
	s.byID = byID
	return nil
}

// RequestInput is the caller-supplied input to CreateRequest. It carries only safe
// references, the reviewed fingerprint digest, and the revisions the reviewer
// reasoned about — never a token, credential, raw schema/body, or client-submitted
// server fact. Tenancy flows through the server (its registry OwnerScope), resolved
// by the coordinator; it is never a value a client submits directly here.
type RequestInput struct {
	Tenant                   string
	ServerID                 string
	ToolName                 string
	Fingerprint              FingerprintDigest
	FingerprintFormatVersion uint16
	Purpose                  Purpose
	CatalogRevision          uint64
	ServerRevision           uint64
	RequestedBy              string
	Reason                   string
	TicketRef                string
	ExpiresAt                *time.Time
}

// CreateRequest records a new pending trust request. It validates every bound,
// refuses a non-issuable purpose fail-closed, and persists the request durably
// before it becomes visible. The generated ApprovalID is unpredictable
// (crypto/rand). No catalog state changes here — a request is not a grant.
func (s *Store) CreateRequest(in RequestInput) (*ToolApproval, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	// Decide capacity + id BEFORE any mutation, so an id-generation failure prunes
	// nothing.
	pruneID, err := s.capacityCheckLocked(in.Tenant, now)
	if err != nil {
		return nil, err
	}
	id, err := newApprovalID()
	if err != nil {
		return nil, err
	}
	if _, exists := s.byID[id]; exists {
		// Astronomically unlikely with 128 bits of entropy; fail closed rather than
		// clobber an existing record.
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "id collision")
	}
	a := &ToolApproval{
		SchemaVersion:            SchemaVersion,
		ApprovalID:               id,
		Tenant:                   in.Tenant,
		ServerID:                 in.ServerID,
		ToolName:                 in.ToolName,
		Fingerprint:              in.Fingerprint,
		FingerprintFormatVersion: in.FingerprintFormatVersion,
		CatalogRevision:          in.CatalogRevision,
		ServerRevision:           in.ServerRevision,
		Purpose:                  in.Purpose,
		Status:                   StatusPending,
		RequestedBy:              in.RequestedBy,
		RequestedAt:              now,
		Reason:                   in.Reason,
		TicketRef:                in.TicketRef,
		ExpiresAt:                cloneTimePtr(in.ExpiresAt),
	}
	// Apply the prune + the insert together, then persist. On a persist failure BOTH
	// are reverted (delete the new record AND restore the pruned one) so the durable
	// file and the in-memory index never diverge.
	var pruned *ToolApproval
	if pruneID != "" {
		pruned = s.byID[pruneID]
		delete(s.byID, pruneID)
	}
	s.byID[id] = a
	if err := s.persistLocked(); err != nil {
		delete(s.byID, id)
		if pruned != nil {
			s.byID[pruneID] = pruned // restore the evicted record
		}
		return nil, err
	}
	return a.clone(), nil
}

// CurrentTarget is the authoritative, coordinator-loaded set of CURRENT facts an
// Approve decision is verified against (ADR-0034 D6). The coordinator reads these
// from the LIVE catalog + registry immediately before the decision; the store
// never trusts caller-submitted facts and never retargets to a different tool.
type CurrentTarget struct {
	ServerExists             bool
	ServerUsable             bool
	Tenant                   string // the server's registry OwnerScope
	ToolExists               bool
	Approvable               bool // current eligibility is promotable (not ServerDisabled)
	Fingerprint              FingerprintDigest
	FingerprintFormatVersion uint16
	CatalogRevision          uint64
	ServerRevision           uint64
}

// Approve transitions a pending request to an active grant, after re-verifying the
// bound target against the CURRENT facts (ADR-0034 D5/D6): the purpose must be
// issuable (shadow only), the server must still exist, be usable, and belong to the
// approval's tenant, the tool must still exist in an approvable state, and its
// current fingerprint (and format version) must EXACTLY match the reviewed digest.
// Any mismatch fails closed and never retargets. The transition is persisted
// durably before it is published. A repeat approve of an already-active grant is
// idempotent. It does NOT touch the catalog — the coordinator promotes after.
func (s *Store) Approve(id, approver string, target CurrentTarget) (*ToolApproval, error) {
	if approver == "" || len(approver) > maxActorBytes {
		return nil, mcperr.New(mcperr.ReasonApprovalNotAuthorized, "tooltrust.approve", "invalid approver")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return nil, mcperr.New(mcperr.ReasonApprovalNotFound, "tooltrust.approve", "not found")
	}
	now := s.clock()
	// Expiry is checked REGARDLESS of status (pastExpiry, not expiredAsOf): a pending
	// request whose TTL elapsed before approval must be rejected, never activated into
	// an already-expired grant that would promote a tool to Usable until the next
	// reconcile. It is derivable and cheap, so it is not itself persisted here.
	if a.pastExpiry(now) {
		return nil, mcperr.New(mcperr.ReasonApprovalExpired, "tooltrust.approve", "expired")
	}
	switch a.Status {
	case StatusActive:
		// Idempotent: the grant already exists. Re-verify the bound target still
		// matches so a stale re-approve of a since-drifted tool is not reported as
		// success.
		if err := a.verifyTarget(target); err != nil {
			return nil, err
		}
		return a.clone(), nil
	case StatusPending:
		// fall through to the decision below
	default:
		return nil, terminalApproveErr(a.Status)
	}
	if !a.Purpose.Issuable() {
		return nil, mcperr.New(mcperr.ReasonApprovalPurposeUnsupported, "tooltrust.approve", "purpose not issuable")
	}
	if err := a.verifyTarget(target); err != nil {
		return nil, err
	}
	// Optimistic-concurrency (ADR-0034 D6): the reviewed catalog/registry revision must
	// not have advanced between request and approval, even when the fingerprint is
	// unchanged (an identical rediscovery bumps the revision). Enforced ONLY on the
	// pending→active transition, never on the idempotent re-approve of an already-active
	// grant (whose recorded revisions may legitimately trail an unrelated later ingest).
	if a.revisionStale(target) {
		return nil, mcperr.New(mcperr.ReasonToolApprovalStale, "tooltrust.approve", "reviewed catalog/registry revision advanced")
	}
	prior := a.clone()
	a.Status = StatusActive
	a.ApprovedBy = approver
	a.ApprovedAt = now
	// The recorded revisions stay the REVIEWED ones (they equal the current facts here,
	// since revisionStale just proved no advance) — the decision evidence at review time.
	if err := s.persistLocked(); err != nil {
		*a = *prior // durable-before-effect: revert on persist failure
		return nil, err
	}
	return a.clone(), nil
}

// terminalApproveErr maps a non-pending, non-active status to the precise reason an
// approve is refused (terminal states are immutable; a revoked/expired grant needs a
// fresh decision).
func terminalApproveErr(status Status) error {
	switch status {
	case StatusRevoked:
		return mcperr.New(mcperr.ReasonApprovalRevoked, "tooltrust.approve", "revoked")
	case StatusExpired:
		return mcperr.New(mcperr.ReasonApprovalExpired, "tooltrust.approve", "expired")
	case StatusRejected:
		return mcperr.New(mcperr.ReasonApprovalTerminalState, "tooltrust.approve", "already rejected")
	default:
		return mcperr.New(mcperr.ReasonApprovalTerminalState, "tooltrust.approve", "not approvable")
	}
}

// verifyTarget checks the approval's bound identity + fingerprint against the
// current facts, failing closed with the precise reason. It NEVER mutates and
// NEVER retargets: a different fingerprint is a mismatch, not a new binding.
func (a *ToolApproval) verifyTarget(t CurrentTarget) error {
	if !t.ServerExists || !t.ToolExists {
		return mcperr.New(mcperr.ReasonToolNotFound, "tooltrust.approve", "target tool not found")
	}
	if t.Tenant != a.Tenant {
		return mcperr.New(mcperr.ReasonApprovalTenantConflict, "tooltrust.approve", "tenant conflict")
	}
	if !t.ServerUsable {
		return mcperr.New(mcperr.ReasonServerNotUsable, "tooltrust.approve", "server not usable")
	}
	if t.FingerprintFormatVersion != a.FingerprintFormatVersion || t.Fingerprint != a.Fingerprint {
		return mcperr.New(mcperr.ReasonToolFingerprintMismatch, "tooltrust.approve", "tool fingerprint changed")
	}
	if !t.Approvable {
		return mcperr.New(mcperr.ReasonToolNotApprovable, "tooltrust.approve", "tool not in an approvable state")
	}
	return nil
}

// revisionStale reports whether the catalog (or registry) revision the request was
// reasoned about has advanced under the decision. A recorded revision of 0 means the
// reviewer did not assert it, so it is not enforced. This is the optimistic-concurrency
// half of the exact-target contract (the fingerprint is the capability half): an
// identical rediscovery keeps the fingerprint but bumps the revision, and approving it
// would confer trust on a snapshot the reviewer never saw.
func (a *ToolApproval) revisionStale(t CurrentTarget) bool {
	if a.CatalogRevision != 0 && a.CatalogRevision != t.CatalogRevision {
		return true
	}
	if a.ServerRevision != 0 && a.ServerRevision != t.ServerRevision {
		return true
	}
	return false
}

// Reject decides a pending request as rejected (terminal). It persists durably
// before publishing. A repeat identical rejection is idempotent; rejecting a
// non-pending request fails closed with the precise terminal reason.
func (s *Store) Reject(id, actor, reason string) error {
	if actor == "" || len(actor) > maxActorBytes {
		return mcperr.New(mcperr.ReasonApprovalNotAuthorized, "tooltrust.reject", "invalid actor")
	}
	if len(reason) > maxReasonBytes {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.reject", "reason exceeds byte bound")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return mcperr.New(mcperr.ReasonApprovalNotFound, "tooltrust.reject", "not found")
	}
	now := s.clock()
	if a.expiredAsOf(now) {
		return mcperr.New(mcperr.ReasonApprovalExpired, "tooltrust.reject", "expired")
	}
	switch a.Status {
	case StatusRejected:
		return nil // idempotent
	case StatusPending:
		// fallthrough
	case StatusActive:
		return mcperr.New(mcperr.ReasonApprovalTerminalState, "tooltrust.reject", "already active")
	case StatusRevoked:
		return mcperr.New(mcperr.ReasonApprovalRevoked, "tooltrust.reject", "revoked")
	case StatusExpired:
		return mcperr.New(mcperr.ReasonApprovalExpired, "tooltrust.reject", "expired")
	default:
		return mcperr.New(mcperr.ReasonApprovalTerminalState, "tooltrust.reject", "not rejectable")
	}
	prior := a.clone()
	a.Status = StatusRejected
	a.ApprovedBy = actor
	a.ApprovedAt = now
	a.RejectedReason = reason
	if err := s.persistLocked(); err != nil {
		*a = *prior
		return err
	}
	return nil
}

// Revoke terminates an active (or pending) grant. Revocation is durable,
// tenant-scoped, exact-ApprovalID, idempotent, and fail-closed; it causes an
// IMMEDIATE loss of usability once the coordinator demotes the returned tool. A
// revoked approval NEVER re-activates from a later identical tools/list — a fresh
// human decision is required (ADR-0034 D7). The revoked approval is returned so the
// coordinator can demote its tool.
func (s *Store) Revoke(id, actor, tenant, reason string) (*ToolApproval, error) {
	if actor == "" || len(actor) > maxActorBytes {
		return nil, mcperr.New(mcperr.ReasonApprovalNotAuthorized, "tooltrust.revoke", "invalid actor")
	}
	if len(reason) > maxReasonBytes {
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.revoke", "reason exceeds byte bound")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok || a.Tenant != tenant {
		// Uniform not-found so a caller cannot probe another tenant's approval ids.
		return nil, mcperr.New(mcperr.ReasonApprovalNotFound, "tooltrust.revoke", "not found")
	}
	now := s.clock()
	switch a.Status {
	case StatusRevoked:
		return a.clone(), nil // idempotent
	case StatusActive, StatusPending:
		// revocable
	case StatusRejected:
		return nil, mcperr.New(mcperr.ReasonApprovalTerminalState, "tooltrust.revoke", "already rejected")
	case StatusExpired:
		return nil, mcperr.New(mcperr.ReasonApprovalExpired, "tooltrust.revoke", "expired")
	default:
		return nil, mcperr.New(mcperr.ReasonApprovalTerminalState, "tooltrust.revoke", "not revocable")
	}
	prior := a.clone()
	a.Status = StatusRevoked
	a.RevokedBy = actor
	a.RevokedAt = &now
	a.RevocationReason = reason
	if err := s.persistLocked(); err != nil {
		*a = *prior
		return nil, err
	}
	return a.clone(), nil
}

// ExpireDue transitions every active grant past its expiry to Expired durably and
// returns copies of those transitioned, so the coordinator can demote their tools.
// It is idempotent and driven by the injected clock (a periodic coordinator sweep
// and startup Recover call it). Expiry is also derivable at read time, so trust is
// never live for an expired grant even before a sweep runs.
func (s *Store) ExpireDue(now time.Time) ([]*ToolApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []*ToolApproval
	var priors []*ToolApproval
	var targets []*ToolApproval
	for _, a := range s.byID {
		if a.expiredAsOf(now) {
			priors = append(priors, a.clone())
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	for _, a := range targets {
		a.Status = StatusExpired
	}
	if err := s.persistLocked(); err != nil {
		for i, a := range targets {
			*a = *priors[i] // revert all on persist failure
		}
		return nil, err
	}
	for _, a := range targets {
		expired = append(expired, a.clone())
	}
	return expired, nil
}

// ToolRef identifies a (server, tool) an approval refers to.
type ToolRef struct {
	ServerID string
	ToolName string
}

// ToolRefs returns the distinct (server, tool) pairs referenced by ANY stored
// approval, active or terminal. The coordinator re-derives each so a tool whose only
// grants have expired or been revoked is demoted even when persisting the terminal
// status failed — the catalog demotion must not depend on the durable write.
func (s *Store) ToolRefs() []ToolRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[ToolRef]struct{}, len(s.byID))
	for _, a := range s.byID {
		seen[ToolRef{ServerID: a.ServerID, ToolName: a.ToolName}] = struct{}{}
	}
	out := make([]ToolRef, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID != out[j].ServerID {
			return out[i].ServerID < out[j].ServerID
		}
		return out[i].ToolName < out[j].ToolName
	})
	return out
}

// Get returns a copy of the approval iff it exists within the caller's tenant
// scope. A tenant mismatch returns a uniform not-found so existence never leaks
// across tenants.
func (s *Store) Get(id, tenant string) (*ToolApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok || a.Tenant != tenant {
		return nil, mcperr.New(mcperr.ReasonApprovalNotFound, "tooltrust.get", "not found")
	}
	return a.clone(), nil
}

// List returns a bounded, tenant-scoped view of approvals in a deterministic order
// (RequestedAt, then ApprovalID). Results are copies.
func (s *Store) List(tenant string, limit int) []*ToolApproval {
	if limit <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ToolApproval, 0, limit)
	for _, a := range s.byID {
		if a.Tenant != tenant {
			continue
		}
		out = append(out, a.clone())
	}
	sortApprovals(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ActiveApprovals returns copies of every grant that is live as of now (active,
// shadow-purpose, unexpired) across ALL tenants. The coordinator (a trusted,
// in-process caller — never a tenant-scoped request handler) uses it to derive the
// catalog Usable projection at startup Recover and after each ingest. It NEVER
// consults a fingerprint — the coordinator matches each against the tool's CURRENT
// observed fingerprint, so a drifted tool is not promoted.
func (s *Store) ActiveApprovals(now time.Time) []*ToolApproval {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ToolApproval
	for _, a := range s.byID {
		if a.activeAsOf(now) {
			out = append(out, a.clone())
		}
	}
	sortApprovals(out)
	return out
}

// --- locked helpers -------------------------------------------------------

// persistLocked rewrites the whole durable file atomically. Called with s.mu held,
// AFTER the in-memory mutation and BEFORE it is considered published — the caller
// reverts the in-memory change on error so a persistence failure never leaves a
// durable/in-memory divergence.
func (s *Store) persistLocked() error {
	list := make([]*ToolApproval, 0, len(s.byID))
	for _, a := range s.byID {
		list = append(list, a)
	}
	sortApprovals(list)
	env := persistedStore{SchemaVersion: SchemaVersion, Approvals: list}
	raw, err := json.Marshal(env)
	if err != nil {
		return mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.persist", "marshal store", err)
	}
	if err := s.writeFile(s.path, raw, 0o600); err != nil {
		return mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.persist", "atomic write", err)
	}
	return nil
}

// capacityCheckLocked enforces the per-tenant non-terminal bound and the total record
// bound WITHOUT mutating: it returns the id of the oldest terminal record to prune when
// the store is at the total cap (empty string when no prune is needed), or an error when
// a bound is exceeded and nothing can be pruned. The caller applies the prune inside the
// same persist transaction so a persistence failure can restore it — pruning here (as an
// eager side effect) left an evicted record unrecoverable on a later persist failure.
func (s *Store) capacityCheckLocked(tenant string, now time.Time) (pruneID string, err error) {
	nonTerminal := 0
	for _, a := range s.byID {
		if a.Tenant == tenant && !a.effectiveTerminal(now) {
			nonTerminal++
		}
	}
	if nonTerminal >= s.maxPerTenant {
		return "", mcperr.New(mcperr.ReasonAdminRangeExceeded, "tooltrust.request", "tenant approval capacity reached")
	}
	if len(s.byID) < s.maxRecords {
		return "", nil
	}
	// At the total cap: pick the single oldest terminal record. A non-terminal record
	// is never evicted (that would drop live trust); if none is prunable, fail closed.
	var oldest *ToolApproval
	for _, a := range s.byID {
		if !a.effectiveTerminal(now) {
			continue
		}
		if oldest == nil || a.RequestedAt.Before(oldest.RequestedAt) {
			oldest = a
		}
	}
	if oldest == nil {
		return "", mcperr.New(mcperr.ReasonAdminRangeExceeded, "tooltrust.request", "approval store capacity reached")
	}
	return oldest.ApprovalID, nil
}

// effectiveTerminal reports whether the approval is terminal as of now, treating an
// active-but-expired grant as terminal (it will be swept to Expired) for capacity
// accounting.
func (a *ToolApproval) effectiveTerminal(now time.Time) bool {
	if a.Status.terminal() {
		return true
	}
	return a.expiredAsOf(now)
}

// --- request validation ---------------------------------------------------

func (in RequestInput) validate() error {
	if err := boundedToken(in.Tenant, maxTenantBytes, "tenant"); err != nil {
		return err
	}
	if err := boundedToken(in.ServerID, maxServerIDBytes, "server id"); err != nil {
		return err
	}
	if err := boundedToken(in.ToolName, maxToolNameBytes, "tool name"); err != nil {
		return err
	}
	if err := boundedToken(in.RequestedBy, maxActorBytes, "requested_by"); err != nil {
		return err
	}
	if !in.Purpose.Issuable() {
		// live_execution (and any non-shadow purpose) is refused at issue — fail
		// closed. The live-execution firewall's negative half.
		return mcperr.New(mcperr.ReasonApprovalPurposeUnsupported, "tooltrust.request", "purpose not issuable")
	}
	if len(in.Reason) > maxReasonBytes {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "reason exceeds byte bound")
	}
	if len(in.TicketRef) > maxTicketBytes {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "ticket_ref exceeds byte bound")
	}
	if !utf8.ValidString(in.Reason) || !utf8.ValidString(in.TicketRef) {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "reason/ticket_ref not valid UTF-8")
	}
	return nil
}

// boundedToken enforces non-empty, byte-bounded, valid-UTF-8 for an identity-shaped
// field. Over-bound input is a request error, never silently truncated into the
// durable record.
func boundedToken(s string, maxBytes int, name string) error {
	if s == "" {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", name+" is empty")
	}
	if len(s) > maxBytes {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", name+" exceeds byte bound")
	}
	if !utf8.ValidString(s) {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", name+" is not valid UTF-8")
	}
	return nil
}

// validateStored re-checks a record loaded from disk: schema version, purpose
// issuability (a persisted non-shadow purpose is corruption — it was never
// issuable), status/id/tenant/server/tool bounds, and expiry-pointer sanity. A bad
// record fails the whole Load closed.
func (a *ToolApproval) validateStored() error {
	if a.SchemaVersion != SchemaVersion {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "record schema version mismatch")
	}
	if err := boundedToken(a.ApprovalID, maxIDBytes, "approval_id"); err != nil {
		return err
	}
	if err := boundedToken(a.Tenant, maxTenantBytes, "tenant"); err != nil {
		return err
	}
	if err := boundedToken(a.ServerID, maxServerIDBytes, "server id"); err != nil {
		return err
	}
	if err := boundedToken(a.ToolName, maxToolNameBytes, "tool name"); err != nil {
		return err
	}
	if a.Purpose != PurposeShadowEvaluation {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "record carries a non-issuable purpose")
	}
	if a.Status == StatusUnset {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "record has no status")
	}
	if a.freeTextOverBound() {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "record free-text field exceeds byte bound")
	}
	return nil
}

// freeTextOverBound reports whether any of the record's free-text / actor fields
// exceeds its byte bound (a corrupt or hand-edited durable record).
func (a *ToolApproval) freeTextOverBound() bool {
	return len(a.Reason) > maxReasonBytes || len(a.TicketRef) > maxTicketBytes ||
		len(a.RevocationReason) > maxReasonBytes || len(a.RejectedReason) > maxReasonBytes ||
		len(a.RequestedBy) > maxActorBytes || len(a.ApprovedBy) > maxActorBytes || len(a.RevokedBy) > maxActorBytes
}

// --- small helpers --------------------------------------------------------

// sortApprovals orders by RequestedAt then ApprovalID for deterministic output and
// a deterministic on-disk layout (so an unchanged store rewrites byte-stable).
func sortApprovals(a []*ToolApproval) {
	sort.Slice(a, func(i, j int) bool {
		if !a[i].RequestedAt.Equal(a[j].RequestedAt) {
			return a[i].RequestedAt.Before(a[j].RequestedAt)
		}
		return a[i].ApprovalID < a[j].ApprovalID
	})
}

// newApprovalID returns an unpredictable 128-bit hex identifier.
func newApprovalID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", mcperr.Wrap(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "id generation failed", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// cloneTimePtr deep-copies an optional time so the stored record never aliases the
// caller's pointer.
func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}
