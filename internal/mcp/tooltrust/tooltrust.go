// Package tooltrust is the MCP tool-trust primitive (ADR-0034): a privileged human
// explicitly trusts ONE exact observed tool fingerprint for ONE declared purpose, and
// that trust disappears the instant the observed capability no longer matches what was
// reviewed. It is a SUPPLY-CHAIN TRUST decision, never an execution authorization —
// runtime policy remains authoritative for every call, and a tool becoming catalog.Usable
// bypasses nothing (policy, approvals, confirmation, allowances, inspection, rollout, kill
// switch, identity, credential controls all still apply).
//
// The durable ToolApproval store is the SOURCE OF TRUTH; catalog.Usable is a materialized
// projection of it (ADR-0034 D2). This package is I/O-free on its decision path: every
// current fact it validates against is supplied by the caller (the coordinator loads live
// catalog/registry facts), so the trust decision is deterministic and unit-testable, and
// the clock is injected. Persistence and reconciliation live in store.go.
//
// Nothing here executes a business operation, calls an upstream MCP server, materializes a
// credential, contacts a provider, or activates a rollout mode.
package tooltrust

import "time"

// SchemaVersion is the durable ToolApproval envelope version. A pre-change reader rejects a
// newer version (fail closed); a same-version reader is byte-stable.
//
// v2 — the four-eyes principal change. Up to v1, RequestedBy/ApprovedBy were written from
// the admin plane's AUDIT actor, "<identity>@<clientIP>", whose second half is a network
// coordinate the acting principal controls. Approve now refuses approver == RequestedBy,
// but that comparison is only meaningful between values in the SAME, coordinate-free
// format: a v1 pending record recording "alice@198.51.100.1" would compare unequal to the
// very same human approving as "alice", so she could approve her own request and walk
// straight through the new gate (Codex P2).
//
// The version bump is the fix, and it is deliberately whole-store rather than per-record.
// A v1 record's four-eyes evidence is untrustworthy whether it is pending or ALREADY
// ACTIVE — an active v1 grant may itself have been self-approved under the old,
// bypassable comparison — so keeping the active ones while refusing the pending ones would
// preserve exactly the grants whose provenance this change calls into question. Load fails
// closed on a v1 file, no trust is materialized, and every decision must be retaken with
// attributable principals. See Store.Load for the operator-facing message.
const SchemaVersion uint16 = 2

// schemaVersionPreFourEyesPrincipal is the last envelope version written before the
// four-eyes principal change. It exists so Load can tell an operator "this store predates
// the principal change and must be re-decided" instead of the generic
// unknown-schema/corruption message, which would send them looking for a fault that is
// not there.
const schemaVersionPreFourEyesPrincipal uint16 = 1

// Bounds on the free-text and reference fields, so a hostile or careless caller can never
// grow the durable record without limit. Enforced at construction; over-bound input is a
// request error, never silently truncated into evidence.
const (
	maxReasonBytes = 512
	maxTicketBytes = 128
	maxIDBytes     = 96
	// maxTenantBytes MUST be >= the catalog's authoritative MaxOwnerScopeBytes
	// (internal/mcp/limits DefaultCatalog = 512): the tenant is the server's registry
	// OwnerScope, so a bound below it would reject an otherwise-valid inventory tenant and
	// make every tool on that server impossible to approve (CreateRequest fails validation).
	maxTenantBytes   = 512
	maxServerIDBytes = 256
	maxToolNameBytes = 256
	maxActorBytes    = 256
)

// FingerprintDigest is the 32-byte canonical tool fingerprint — catalog.Fingerprint.Sum().
// An approval binds to this exact value; any change to any of the fingerprint's dimensions
// changes the digest and the approval no longer matches (the rug-pull invariant, ADR-0034
// D4). It is a digest of PUBLIC capability facts, never a secret.
type FingerprintDigest [32]byte

// Purpose is a ToolApproval's trust ceiling (ADR-0034 D5). It is deliberately NOT a boolean:
// a shadow_evaluation approval MUST NEVER be usable as a live-execution authorization, and a
// future live phase must introduce a stronger purpose explicitly.
type Purpose uint8

const (
	// PurposeUnset is the invalid zero value (fails closed).
	PurposeUnset Purpose = iota
	// PurposeShadowEvaluation trusts the tool ONLY for Controlled Shadow evaluation. It is
	// the ONLY purpose issuable in this slice.
	PurposeShadowEvaluation
	// PurposeLiveExecution is defined so the model is complete and the firewall is
	// expressible, but it is NEVER issuable here — Approve refuses it fail-closed. A future
	// live-execution phase must add its own explicit issue path and stronger controls.
	PurposeLiveExecution
)

// String returns a stable wire label for the purpose.
func (p Purpose) String() string {
	switch p {
	case PurposeShadowEvaluation:
		return "shadow_evaluation"
	case PurposeLiveExecution:
		return "live_execution"
	default:
		return "unset"
	}
}

// ParsePurpose resolves a wire label to a Purpose. It returns (PurposeUnset, false) for an
// unknown label — the caller fails closed rather than guessing.
func ParsePurpose(s string) (Purpose, bool) {
	switch s {
	case "shadow_evaluation":
		return PurposeShadowEvaluation, true
	case "live_execution":
		return PurposeLiveExecution, true
	default:
		return PurposeUnset, false
	}
}

// Issuable reports whether this purpose may be issued in the current slice. Only
// shadow_evaluation is issuable; live_execution is defined but fail-closed (ADR-0034 D5).
func (p Purpose) Issuable() bool { return p == PurposeShadowEvaluation }

// PermitsShadowEvaluation reports whether an approval of this purpose may satisfy the
// Controlled Shadow "usable scoped tool" prerequisite. ONLY shadow_evaluation qualifies —
// this is the live-execution firewall's positive half.
func (p Purpose) PermitsShadowEvaluation() bool { return p == PurposeShadowEvaluation }

// PermitsLiveExecution reports whether an approval of this purpose may satisfy a CANARY /
// live-execution trust requirement. ONLY live_execution qualifies — the firewall's OTHER
// positive half, and the mirror of PermitsShadowEvaluation: a shadow_evaluation approval
// can NEVER authorize a real upstream side effect, and a live_execution approval can never
// satisfy the Shadow "usable tool" prerequisite. The two purposes are disjoint by
// construction (a Purpose is exactly one value), so no approval satisfies both. This makes
// the "shadow != live" invariant a compile-checkable predicate, not a runtime convention.
// Issuance of live_execution stays refused fail-closed (Issuable) in this build; this
// predicate only defines what a live_execution approval WOULD permit once a future,
// separately-reviewed live phase makes it issuable under stronger governance.
func (p Purpose) PermitsLiveExecution() bool { return p == PurposeLiveExecution }

// Status is the ToolApproval lifecycle status. Rejected/Revoked/Expired are terminal and
// never re-activate — a revoked or expired approval never becomes valid again from a later
// identical tools/list; re-approval requires a NEW human decision (ADR-0034 D7).
type Status uint8

const (
	// StatusUnset is the invalid zero value (fails closed).
	StatusUnset Status = iota
	// StatusPending is a request awaiting an approve/reject decision.
	StatusPending
	// StatusActive is a live grant — the only status that can materialize catalog.Usable.
	StatusActive
	// StatusRejected is a terminal denial of a pending request.
	StatusRejected
	// StatusRevoked is a terminal operator revocation of an active grant.
	StatusRevoked
	// StatusExpired is a terminal expiry of an active grant.
	StatusExpired
)

// String returns a stable wire label for the status.
func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusActive:
		return "active"
	case StatusRejected:
		return "rejected"
	case StatusRevoked:
		return "revoked"
	case StatusExpired:
		return "expired"
	default:
		return "unset"
	}
}

// terminal reports whether the status is terminal (immutable).
func (s Status) terminal() bool {
	return s == StatusRejected || s == StatusRevoked || s == StatusExpired
}

// ToolApproval is one durable, typed, secret-free trust decision (ADR-0034 D2/D4). It binds
// a tenant + server + tool + EXACT fingerprint digest + purpose to an authenticated human
// decision. It carries only safe references and the fingerprint digest — never a token,
// credential, raw schema/argument/output body, or private identity material.
//
// Only StatusActive approvals whose Fingerprint matches a tool's CURRENT observed
// fingerprint (and whose server is usable, purpose permits, and which are not expired)
// materialize catalog.Usable. Every other status keeps the tool at its observed disposition.
type ToolApproval struct {
	SchemaVersion uint16 `json:"schema_version"`

	ApprovalID string `json:"approval_id"`

	// Tenant is the server's registry OwnerScope. Tenancy flows through the server, never a
	// field a client may submit.
	Tenant   string `json:"tenant"`
	ServerID string `json:"server_id"`
	ToolName string `json:"tool_name"`

	// Fingerprint is the exact reviewed capability digest. FingerprintFormatVersion records
	// which fingerprint scheme produced it so a format change can never silently re-interpret
	// an old digest.
	Fingerprint              FingerprintDigest `json:"fingerprint"`
	FingerprintFormatVersion uint16            `json:"fingerprint_format_version"`

	// CatalogRevision / ServerRevision record the catalog (and, when carried, registry)
	// revision the decision was reasoned about — the optimistic-concurrency / stale-target
	// evidence (ADR-0034 D6). ServerRevision is 0 when the registry carries no per-server
	// revision.
	CatalogRevision uint64 `json:"catalog_revision"`
	ServerRevision  uint64 `json:"server_revision,omitempty"`

	Purpose Purpose `json:"purpose"`
	Status  Status  `json:"status"`

	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
	ApprovedBy  string    `json:"approved_by,omitempty"`
	ApprovedAt  time.Time `json:"approved_at,omitempty"`

	Reason    string `json:"reason,omitempty"`
	TicketRef string `json:"ticket_ref,omitempty"`

	// ExpiresAt is an optional expiry; nil means no expiry. An expired active approval keeps
	// no tool Usable (ADR-0034 D7).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`

	// RejectedBy / RejectedAt record WHO denied a pending request and WHEN. They are the
	// rejection's OWN decision-evidence fields — deliberately DISTINCT from ApprovedBy /
	// ApprovedAt, which a rejection previously reused. A shared evidence shape let a single
	// valid-JSON status byte flip (Rejected 3 → Active 2) pass Load's per-status lifecycle
	// check and materialize an active grant from a denial (ADR-0034 recovery is fail-closed
	// against single-field tamper). With distinct fields, a flipped-to-Active record still
	// carries RejectedBy/RejectedAt, which the Active-lifecycle invariant forbids.
	RejectedBy string     `json:"rejected_by,omitempty"`
	RejectedAt *time.Time `json:"rejected_at,omitempty"`
	// RejectedReason records why a pending request was rejected (governance evidence).
	RejectedReason string `json:"rejected_reason,omitempty"`
}

// activeAsOf reports whether the approval is a live grant as of now: StatusActive, purpose
// permits shadow evaluation, and not past its (optional) expiry. It NEVER consults the tool
// fingerprint — the caller matches the fingerprint separately so a mismatch and an expiry are
// distinguishable, and so the fingerprint match is always against the CURRENT observation.
func (a *ToolApproval) activeAsOf(now time.Time) bool {
	if a.Status != StatusActive || !a.Purpose.PermitsShadowEvaluation() {
		return false
	}
	if a.ExpiresAt != nil && !now.Before(*a.ExpiresAt) {
		return false
	}
	return true
}

// pastExpiry reports whether the approval carries an expiry that has elapsed as of now,
// REGARDLESS of status. A pending request whose TTL elapsed before an admin approved it is
// past its expiry too — approving it would activate an already-expired grant, so the approve
// path must consult this (not expiredAsOf, which is Active-only) before any transition.
func (a *ToolApproval) pastExpiry(now time.Time) bool {
	return a.ExpiresAt != nil && !now.Before(*a.ExpiresAt)
}

// expiredAsOf reports whether an ACTIVE approval has passed its expiry as of now. Used by the
// lazy expiry sweep to transition Active → Expired deterministically under the injected clock.
func (a *ToolApproval) expiredAsOf(now time.Time) bool {
	return a.Status == StatusActive && a.pastExpiry(now)
}

// MatchesTool reports whether this approval binds to the given tool identity AND exact
// fingerprint. Tenant, server, name, and the full fingerprint digest must all match — an
// approval never authorizes two different fingerprints or a same-named tool on another server
// (ADR-0034 D4). The fingerprint-format version must also match so a scheme change invalidates.
func (a *ToolApproval) MatchesTool(tenant, serverID, toolName string, fp FingerprintDigest, fpFormat uint16) bool {
	return a.Tenant == tenant &&
		a.ServerID == serverID &&
		a.ToolName == toolName &&
		a.FingerprintFormatVersion == fpFormat &&
		a.Fingerprint == fp
}

// clone returns a deep copy so a caller can never mutate stored state (the *time.Time fields
// are copied by value behind fresh pointers).
func (a *ToolApproval) clone() *ToolApproval {
	out := *a
	if a.ExpiresAt != nil {
		t := *a.ExpiresAt
		out.ExpiresAt = &t
	}
	if a.RevokedAt != nil {
		t := *a.RevokedAt
		out.RevokedAt = &t
	}
	if a.RejectedAt != nil {
		t := *a.RejectedAt
		out.RejectedAt = &t
	}
	return &out
}
