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

	// maxRecordJSONBytes is a WORST-CASE upper bound on one serialized ToolApproval, used only
	// to size the recovery read cap. It must never under-count, or Load would reject the
	// store's OWN persisted file: encoding/json expands a control byte (and <, >, &) to a
	// 6-byte \u00xx escape, so a bounded string can serialize at up to 6x its byte length. The
	// bound is therefore 6x the sum of every byte-bounded string field plus a fixed overhead
	// for JSON keys, the timestamps, the fingerprint hex, the numeric fields, and punctuation.
	// It is a deliberate over-estimate (a real record is far smaller); the cap only rejects a
	// pathologically large file before it is fully decoded.
	maxRecordStringBounds = 3*maxReasonBytes + 4*maxActorBytes + maxTenantBytes + maxServerIDBytes + maxToolNameBytes + maxTicketBytes + maxIDBytes
	recordFixedOverhead   = 2048
	maxRecordJSONBytes    = 6*maxRecordStringBounds + recordFixedOverhead
	// storeEnvelopeSlackBytes covers the persistedStore wrapper (schema_version, the array
	// brackets/commas) independent of record count.
	storeEnvelopeSlackBytes = 4096
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
	f, err := os.Open(s.path) // #nosec G304 -- fixed store path under the data dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // fresh store
		}
		return mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.load", "open store", err)
	}
	defer func() { _ = f.Close() }()
	// Bound the recovery read: a store within its configured cap cannot exceed this many
	// bytes, so a larger file is corruption or a restore from a bigger-cap store. Reading it
	// unbounded would let a schema-valid but oversized file exhaust memory during startup.
	// LimitReader to cap+1 so hitting the ceiling is detectable without materializing more.
	readLimit := int64(s.maxRecords)*maxRecordJSONBytes + storeEnvelopeSlackBytes
	raw, err := io.ReadAll(io.LimitReader(f, readLimit+1))
	if err != nil {
		return mcperr.Wrap(mcperr.ReasonConfigInvalid, "tooltrust.load", "read store", err)
	}
	if int64(len(raw)) > readLimit {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "store file exceeds size bound")
	}
	// Reject invalid UTF-8 on the RAW bytes BEFORE decoding. encoding/json silently replaces an
	// invalid byte sequence in any string with U+FFFD rather than erroring, so a corrupted or
	// tampered file whose strings contain invalid UTF-8 would decode cleanly and the per-field
	// utf8.ValidString checks in validateStored would then see the (valid) replacement runes and
	// pass — publishing active grants despite the fail-closed corruption contract. A legitimately
	// written store is always valid UTF-8 (json.Marshal emits it), so this only ever rejects
	// corruption/tampering. JSON is UTF-8 by definition (RFC 8259).
	if !utf8.Valid(raw) {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "store file is not valid UTF-8")
	}
	// utf8.Valid catches invalid UTF-8 BYTES, but a JSON \uXXXX escape for an unpaired UTF-16
	// surrogate is pure ASCII (so it passes above), and encoding/json decodes it to U+FFFD rather
	// than erroring — the same silent-replacement gap one level up. json.Marshal never emits a
	// surrogate escape (it escapes only control chars and U+2028/U+2029), so a lone surrogate is
	// always tampering. Reject it before decoding.
	if hasUnpairedSurrogateEscape(raw) {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "store file has an unpaired surrogate escape")
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
		// Name the pre-four-eyes-principal version explicitly. It is not corruption: the
		// file was written correctly by an older build whose RequestedBy/ApprovedBy carry
		// a client-controlled network coordinate, which the four-eyes comparison in
		// Approve cannot trust. Failing closed here is the intended outcome — no trust is
		// materialized and every decision is retaken — but an operator must be able to
		// tell that from a damaged file, because the two call for opposite responses.
		if env.SchemaVersion == schemaVersionPreFourEyesPrincipal {
			return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load",
				"store predates the four-eyes principal change; its approvals carry unattributable requester/approver identities and must be re-decided")
		}
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "unknown store schema version")
	}
	// Enforce the configured TOTAL-record bound before publishing: a file with more records
	// than this store's cap (e.g. restored from a larger-cap deployment, or tampered) must
	// fail closed rather than load an over-capacity index the mutation paths would then keep.
	if len(env.Approvals) > s.maxRecords {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "store record count exceeds configured bound")
	}
	byID, err := s.buildLoadedIndexLocked(env.Approvals)
	if err != nil {
		return err
	}
	s.byID = byID
	return nil
}

// hasUnpairedSurrogateEscape reports whether raw contains a JSON \uXXXX escape for an unpaired
// UTF-16 surrogate: a high surrogate (D800–DBFF) not immediately followed by a low-surrogate
// escape (DC00–DFFF), or a low surrogate appearing on its own. encoding/json decodes such an
// escape to U+FFFD instead of erroring, so a tampered record whose bytes are otherwise valid
// UTF-8 (the escape itself is ASCII) would slip past utf8.Valid and the per-field checks. A
// store written by json.Marshal never emits a surrogate escape, so this only ever rejects
// tampering. An escaped backslash (\\) is consumed as a pair, so literal "\\uD800" text is not
// misread as an escape; a malformed \u is left for the JSON decoder to reject.
func hasUnpairedSurrogateEscape(raw []byte) bool {
	for i := 0; i+1 < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		if raw[i+1] != 'u' {
			i += 2 // any other escape (including \\) consumes two bytes
			continue
		}
		hi, ok := parseHex4(raw, i+2)
		if !ok {
			i += 2 // malformed \u — the JSON decoder will report it
			continue
		}
		if hi < 0xD800 || hi > 0xDFFF {
			i += 6 // an ordinary BMP escape
			continue
		}
		if hi >= 0xDC00 {
			return true // a low surrogate with no preceding high — unpaired
		}
		// hi is a high surrogate; a valid pair needs a low-surrogate escape immediately after.
		if i+7 < len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
			if lo, lok := parseHex4(raw, i+8); lok && lo >= 0xDC00 && lo <= 0xDFFF {
				i += 12 // consumed a valid surrogate pair
				continue
			}
		}
		return true // high surrogate not followed by a low surrogate — unpaired
	}
	return false
}

// parseHex4 reads the 4 hex digits at off and returns their value. ok is false if fewer than
// four bytes remain or any is not a hex digit.
func parseHex4(b []byte, off int) (value uint32, ok bool) {
	if off+4 > len(b) {
		return 0, false
	}
	for j := 0; j < 4; j++ {
		c := b[off+j]
		switch {
		case c >= '0' && c <= '9':
			value = value<<4 | uint32(c-'0')
		case c >= 'a' && c <= 'f':
			value = value<<4 | uint32(c-'a'+10)
		case c >= 'A' && c <= 'F':
			value = value<<4 | uint32(c-'A'+10)
		default:
			return 0, false
		}
	}
	return value, true
}

// buildLoadedIndexLocked validates every recovered record and enforces the per-tenant
// non-terminal bound, returning the in-memory index or a fail-closed error. Split out of
// Load to keep each function's control flow within the cyclomatic bound.
func (s *Store) buildLoadedIndexLocked(approvals []*ToolApproval) (map[string]*ToolApproval, error) {
	now := s.clock()
	perTenantNonTerminal := make(map[string]int)
	byID := make(map[string]*ToolApproval, len(approvals))
	for _, a := range approvals {
		if a == nil {
			return nil, mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "nil approval record")
		}
		if err := a.validateStored(); err != nil {
			return nil, err
		}
		if _, dup := byID[a.ApprovalID]; dup {
			return nil, mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "duplicate approval id")
		}
		// Enforce the per-tenant non-terminal bound too, using the same effectiveTerminal
		// accounting CreateRequest uses, so recovery can never publish a store already over
		// the per-tenant cap (which would let one tenant hold more live slots than allowed).
		if !a.effectiveTerminal(now) {
			perTenantNonTerminal[a.Tenant]++
			if perTenantNonTerminal[a.Tenant] > s.maxPerTenant {
				return nil, mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "tenant non-terminal count exceeds configured bound")
			}
		}
		byID[a.ApprovalID] = a
	}
	return byID, nil
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
	// Four-eyes (separation of duties). A tool-trust grant is a supply-chain trust
	// decision that promotes a tool to catalog.Usable, so the human who ASKED for it may
	// not be the human who GRANTS it — the same rule internal/mcp/approval has always
	// enforced for operational/publication approvals, and the rule canary.EvaluateTrust
	// already REQUIRES of this record (TrustNoFourEyes: RequestedBy == ApprovedBy).
	//
	// Until now that requirement was only OBSERVED, at Canary-readiness time, long after
	// the grant had already taken effect: a self-approved approval still promoted the tool
	// to Usable immediately and the gate merely refused Canary later. Enforcing it HERE
	// makes the readiness fact a consequence of the decision boundary rather than a
	// late audit of it, so a self-approved grant can never become effective at all.
	//
	// Checked on the pending→active transition only (mirroring approval.Store.Approve):
	// the idempotent re-approve of an ALREADY-active grant above has, by construction,
	// already passed this gate. An empty approver was rejected at entry, and an empty
	// RequestedBy cannot reach here (RequestInput.validate requires it), so this can
	// never collapse into "" == "".
	if approver == a.RequestedBy {
		return nil, mcperr.New(mcperr.ReasonApprovalSelfApproval, "tooltrust.approve", "requester may not approve own tool-trust request")
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
	// Record the denial in its OWN evidence fields, NOT ApprovedBy/ApprovedAt: a rejection
	// must be distinguishable from a grant so a single status-byte flip (Rejected → Active)
	// cannot pass Load's lifecycle check (validateStatusLifecycle) as an approved grant.
	a.RejectedBy = actor
	a.RejectedAt = &now
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
		// Sweep ANY non-terminal record past its expiry — pending as well as active — to
		// Expired, so abandoned short-lived requests do not hold tenant/global capacity.
		if !a.Status.terminal() && a.pastExpiry(now) {
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

// List returns a bounded, tenant-scoped view of approvals in NEWEST-FIRST order
// (RequestedAt descending, then ApprovalID for determinism). Results are copies. The order
// is deliberately newest-first: the endpoint exposes no cursor/offset, so an ascending sort
// followed by truncation would return only the OLDEST records and hide every request past
// the limit — including brand-new pending approvals an admin needs to decide.
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
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].RequestedAt.After(out[j].RequestedAt) // newest first
		}
		return out[i].ApprovalID < out[j].ApprovalID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// AllForTenant returns copies of EVERY approval for the tenant, unsorted and unbounded
// (the store's total-record cap already bounds it). It exists so a caller enriching a whole
// inventory response snapshots the tenant's approvals ONCE and builds a per-tool index,
// instead of calling List (which pre-allocates a large slice and scans/sorts) once per tool.
func (s *Store) AllForTenant(tenant string) []*ToolApproval {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ToolApproval, 0, len(s.byID))
	for _, a := range s.byID {
		if a.Tenant == tenant {
			out = append(out, a.clone())
		}
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
		// A failed durable write (full/read-only disk, I/O error) is RETRYABLE: the in-memory
		// state is reverted by the caller and the same mutation can succeed once storage
		// recovers. Classify it as service-unavailable (503), never invalid-input (400).
		return mcperr.Wrap(mcperr.ReasonApprovalStoreUnavailable, "tooltrust.persist", "atomic write", err)
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
	// At the total cap: pick the single oldest PRUNABLE record. Prunable is NARROWER than
	// effectiveTerminal — it deliberately EXCLUDES a past-expiry ACTIVE grant, because such a
	// grant may still project catalog.Usable and the store cannot withdraw that projection
	// (only the coordinator's reconcile can). Deleting it here would remove its last ToolRef
	// before demotion, leaving the tool Usable with no record left for reconcile to discover.
	// A past-expiry active grant is swept to Expired (and demoted) by the periodic reconcile
	// within one tick, after which it becomes genuinely terminal and prunable. If nothing is
	// prunable yet, fail closed (safe, self-healing) rather than orphan a live projection.
	var oldest *ToolApproval
	for _, a := range s.byID {
		if !a.prunableAsOf(now) {
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

// effectiveTerminal reports whether the approval is terminal as of now, treating ANY
// past-expiry record (pending as well as active) as terminal for capacity accounting —
// an abandoned short-lived request must not permanently hold a tenant/global slot until
// an admin manually rejects it. Used for the per-tenant non-terminal COUNT (never for
// prune selection — see prunableAsOf).
func (a *ToolApproval) effectiveTerminal(now time.Time) bool {
	if a.Status.terminal() {
		return true
	}
	return a.pastExpiry(now)
}

// prunableAsOf reports whether the record can be safely EVICTED to reclaim a capacity
// slot. It is narrower than effectiveTerminal: a genuinely-terminal record (its tool was
// demoted at the transition, or never promoted) and a past-expiry PENDING record (a
// pending record never projects catalog.Usable) are prunable, but a past-expiry ACTIVE
// grant is NOT — it may still be a Usable projection whose only withdrawal path is the
// coordinator re-deriving its tool, and pruning it would delete the last ToolRef before
// that demotion. It becomes prunable once reconcile sweeps it to Expired.
func (a *ToolApproval) prunableAsOf(now time.Time) bool {
	if a.Status.terminal() {
		return true
	}
	return a.Status == StatusPending && a.pastExpiry(now)
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
	if a.freeTextOverBound() {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", "record free-text field exceeds byte bound")
	}
	if err := a.validateStatusLifecycle(); err != nil {
		return err
	}
	return nil
}

// validateStatusLifecycle enforces the per-status decision-evidence invariants a
// legitimately-persisted record always satisfies, so a corrupt or hand-edited file
// (e.g. a pending record's numeric status flipped to Active) cannot materialize an
// active grant with NO recorded human approval. The status must be a known enum, and:
//
//   - Active   ⇒ an approver + approval time, AND no terminal-decider evidence;
//   - Rejected ⇒ a rejecter + rejection time (its OWN fields, not the approver's);
//   - Revoked  ⇒ a revoker + revocation time;
//   - Pending  ⇒ no decision fields yet; Expired ⇒ no decider required (automatic).
//
// The Active branch additionally REJECTS any record that also carries rejection or
// revocation evidence: a rejection and a revocation each record their decider in their
// OWN fields, so a single valid-JSON status-byte flip from a terminal denial to Active
// leaves that terminal evidence behind and is caught here (the previous shared
// ApprovedBy/ApprovedAt shape made a Rejected→Active flip indistinguishable from a real
// grant). Any violation fails the whole Load closed (recovery is fail-closed, never
// fail-open into an unapproved active grant).
func (a *ToolApproval) validateStatusLifecycle() error {
	bad := func(detail string) error {
		return mcperr.New(mcperr.ReasonConfigInvalid, "tooltrust.load", detail)
	}
	switch a.Status {
	case StatusPending:
		return a.validatePendingEvidence(bad)
	case StatusActive:
		return a.validateActiveEvidence(bad)
	case StatusRejected:
		if a.RejectedBy == "" || a.RejectedAt == nil {
			return bad("rejected record without recorded rejection evidence")
		}
	case StatusRevoked:
		if a.RevokedBy == "" || a.RevokedAt == nil {
			return bad("revoked record without recorded revocation evidence")
		}
	case StatusExpired:
		return nil // automatic transition; no decider required
	default:
		return bad("record has an unknown status")
	}
	return nil
}

// validatePendingEvidence enforces that a StatusPending record carries NO decision fields
// yet. This is load-bearing, not cosmetic: Approve only sets the status + approver, so a
// corrupt pending record that retains terminal (rejection/revocation) evidence would be
// laundered by a normal approve into an Active record that STILL carries that evidence —
// which validateActiveEvidence then rejects on the next restart, leaving tool trust
// uncomposed. Fail closed so Load never admits state a supported mutation makes unrecoverable.
func (a *ToolApproval) validatePendingEvidence(bad func(string) error) error {
	if a.ApprovedBy != "" || !a.ApprovedAt.IsZero() || a.hasTerminalEvidence() {
		return bad("pending record carries decision evidence")
	}
	return nil
}

// hasTerminalEvidence reports whether the record carries ANY rejection or revocation
// evidence — the decider, the timestamp, OR the reason. Only a Rejected/Revoked record
// legitimately carries it; a pending or active record that does is corrupt/hand-edited, and
// the REASON fields count because Reject/Revoke persist them alongside the actor/timestamp.
func (a *ToolApproval) hasTerminalEvidence() bool {
	return a.RejectedBy != "" || a.RejectedAt != nil || a.RejectedReason != "" ||
		a.RevokedBy != "" || a.RevokedAt != nil || a.RevocationReason != ""
}

// validateActiveEvidence enforces the StatusActive invariants: an approver + approval time
// must be present, AND no terminal-decision evidence may be — a rejection/revocation flipped
// to Active by a single status-byte edit keeps its own decider fields (including the reason),
// which a real active grant never carries.
func (a *ToolApproval) validateActiveEvidence(bad func(string) error) error {
	if a.ApprovedBy == "" || a.ApprovedAt.IsZero() {
		return bad("active record without recorded approval evidence")
	}
	if a.hasTerminalEvidence() {
		return bad("active record carries terminal-decision evidence")
	}
	return nil
}

// freeTextOverBound reports whether any of the record's free-text / actor fields
// exceeds its byte bound (a corrupt or hand-edited durable record).
func (a *ToolApproval) freeTextOverBound() bool {
	return len(a.Reason) > maxReasonBytes || len(a.TicketRef) > maxTicketBytes ||
		len(a.RevocationReason) > maxReasonBytes || len(a.RejectedReason) > maxReasonBytes ||
		len(a.RequestedBy) > maxActorBytes || len(a.ApprovedBy) > maxActorBytes ||
		len(a.RevokedBy) > maxActorBytes || len(a.RejectedBy) > maxActorBytes
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
