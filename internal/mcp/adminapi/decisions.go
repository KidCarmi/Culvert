package adminapi

import (
	"strconv"
	"strings"

	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Decision partitions scanned for decision/outcome evidence. P-DEN (denial
// aggregates) is not a decision-search source.
const (
	partitionCrit = "P-CRIT"
	partitionOrd  = "P-ORD"
)

// EventReader is the narrow, bounded read seam over PR-8 committed events.
// package main adapts events.Manager / spool.CommittedForExport; tests fake it.
// It returns only committed, safe, typed event projections — never a raw spool
// record or encrypted segment.
type EventReader interface {
	CommittedEvents(capability, partition string, afterSeq uint64, max int) (events []evmodel.Event, seqs []uint64, next uint64, err error)
}

// DecisionFilter carries the safe, bounded query filters. A zero field is "any".
type DecisionFilter struct {
	Action          string
	ReasonCode      string
	RuleID          string
	ServerID        string
	ToolName        string
	ToolFingerprint string
	PrincipalID     string
	AgentID         string
	StartUnixNano   int64
	EndUnixNano     int64
}

// DecisionView is a safe, bounded search-result summary of one committed event.
type DecisionView struct {
	EventID        string `json:"event_id"`
	Sequence       uint64 `json:"sequence"`
	Partition      string `json:"partition"`
	Capability     string `json:"capability"`
	TimeUnixNano   int64  `json:"time_unix_nano"`
	Tenant         string `json:"tenant"`
	PrincipalID    string `json:"principal_id"`
	PrincipalType  string `json:"principal_type"`
	AgentID        string `json:"agent_id,omitempty"`
	ServerID       string `json:"server_id,omitempty"`
	ToolName       string `json:"tool_name,omitempty"`
	Action         string `json:"action"`
	ReasonCode     string `json:"reason_code"`
	MatchedRuleID  string `json:"matched_rule_id,omitempty"`
	OperationClass string `json:"operation_class,omitempty"`
	ExecutionState string `json:"execution_state,omitempty"`
}

// SearchResult is a bounded page of decisions plus the next opaque cursor
// (empty when the stream is exhausted).
type SearchResult struct {
	Decisions  []DecisionView `json:"decisions"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

// ExplanationView is the full, safe historical explanation of ONE committed
// decision — projected exclusively from the persisted event, never re-evaluated
// against the current policy. It contains no raw arguments, output, secret, PII,
// token, credential material, sensitive query or provider error.
type ExplanationView struct {
	EventID       string `json:"event_id"`
	CorrelationID string `json:"correlation_id"`
	ReplayID      string `json:"replay_id"`
	Capability    string `json:"capability"`
	Partition     string `json:"partition"`
	TimeUnixNano  int64  `json:"time_unix_nano"`

	Tenant          string `json:"tenant"`
	PrincipalID     string `json:"principal_id"`
	PrincipalType   string `json:"principal_type"`
	AgentID         string `json:"agent_id,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ServerID        string `json:"server_id,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	ToolFingerprint string `json:"tool_fingerprint,omitempty"`
	ResourceRef     string `json:"resource_ref,omitempty"`
	ResourceHash    string `json:"resource_hash,omitempty"`
	Assurance       string `json:"assurance,omitempty"`

	Action              string   `json:"action"`
	ReasonCode          string   `json:"reason_code"`
	MatchedRuleID       string   `json:"matched_rule_id,omitempty"`
	DecisiveConditionID string   `json:"decisive_condition_id,omitempty"`
	Remediation         string   `json:"remediation,omitempty"`
	OperationClass      string   `json:"operation_class,omitempty"`
	RiskClass           string   `json:"risk_class,omitempty"`
	ExecutionState      string   `json:"execution_state,omitempty"`
	Obligations         []string `json:"obligations,omitempty"`

	PolicyRevision     uint64 `json:"policy_revision"`
	CatalogRevision    uint64 `json:"catalog_revision"`
	RegistryRevision   uint64 `json:"registry_revision,omitempty"`
	InspectionRevision uint64 `json:"inspection_revision,omitempty"`
	RuntimeRevision    uint64 `json:"runtime_revision,omitempty"`
	PolicySnapshotHash string `json:"policy_snapshot_hash,omitempty"`

	InspectionSchemaStatus string   `json:"inspection_schema_status,omitempty"`
	FindingClasses         []string `json:"finding_classes,omitempty"`
	MaxSeverity            string   `json:"max_severity,omitempty"`
	DLPDisposition         string   `json:"dlp_disposition,omitempty"`
	DestinationClass       string   `json:"destination_class,omitempty"`

	CredentialProfileRef string `json:"credential_profile_ref,omitempty"`
	CredentialPower      string `json:"credential_power_ceiling,omitempty"`

	// Source marks the explanation as historical (never a live re-evaluation).
	Source string `json:"source"`
}

// DecisionService answers bounded, tenant-scoped decision search and historical
// explanation over PR-8 committed events. It never re-evaluates policy.
type DecisionService struct {
	reader EventReader
	lim    Limits
}

// NewDecisionService builds a decision query service.
func NewDecisionService(reader EventReader, lim Limits) *DecisionService {
	return &DecisionService{reader: reader, lim: lim}
}

// capString maps a model.Capability to a wire string.
func capString(c evmodel.Capability) string {
	switch c {
	case evmodel.CapGateway:
		return "gateway"
	case evmodel.CapManagement:
		return "management"
	default:
		return "unknown"
	}
}

type scanCursor struct {
	part string
	seq  uint64
}

func decodeCursor(s string) (scanCursor, error) {
	if s == "" {
		return scanCursor{part: partitionCrit, seq: 0}, nil
	}
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return scanCursor{}, mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.cursor", "malformed cursor")
	}
	part := s[:i]
	if part != partitionCrit && part != partitionOrd {
		return scanCursor{}, mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.cursor", "bad cursor partition")
	}
	seq, err := strconv.ParseUint(s[i+1:], 10, 64)
	if err != nil {
		return scanCursor{}, mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.cursor", "bad cursor sequence")
	}
	return scanCursor{part: part, seq: seq}, nil
}

func encodeCursor(part string, seq uint64) string {
	return part + ":" + strconv.FormatUint(seq, 10)
}

// Search returns a bounded, deterministic, tenant-scoped page of decisions.
// Events for other tenants are skipped uniformly (no count or existence leak).
func (s *DecisionService) Search(capability, tenant, cursor string, limit int, f DecisionFilter) (SearchResult, error) {
	if tenant == "" {
		return SearchResult{}, mcperr.New(mcperr.ReasonAdminTenantScope, "adminapi.decisions", "tenant required")
	}
	if _, err := capToPolicy(capability); err != nil {
		return SearchResult{}, err
	}
	if err := s.validateRange(f); err != nil {
		return SearchResult{}, err
	}
	cur, err := decodeCursor(cursor)
	if err != nil {
		return SearchResult{}, err
	}
	if limit <= 0 || limit > s.lim.MaxPageSize() {
		limit = s.lim.MaxPageSize()
	}
	// out is intentionally NOT pre-sized from the user-provided limit (CodeQL:
	// no allocation sized by an external value); limit only bounds appends.
	var out []DecisionView
	st := &searchScan{svc: s, capability: capability, tenant: tenant, limit: limit, f: f, batch: s.lim.MaxPageSize()}
	for _, part := range []string{partitionCrit, partitionOrd} {
		if partRank(part) < partRank(cur.part) {
			continue // already passed this partition
		}
		afterSeq := uint64(0)
		if part == cur.part {
			afterSeq = cur.seq
		}
		cursor, done, err := st.scan(part, afterSeq, &out)
		if err != nil {
			return SearchResult{}, err
		}
		if done {
			return SearchResult{Decisions: out, NextCursor: cursor}, nil
		}
	}
	return SearchResult{Decisions: out}, nil
}

// searchScan holds the per-call scan state for Search. Extracted so Search
// itself stays under the cognitive-complexity bound.
type searchScan struct {
	svc                *DecisionService
	capability, tenant string
	limit              int
	f                  DecisionFilter
	batch              int
	scanned            int
}

// scan reads one partition after afterSeq, appending tenant+filter matches to
// out. It returns (resumeCursor, done): done=true means the page filled or the
// bounded scan budget was hit and the caller should stop. The resume cursor
// always points at the LAST event actually EXAMINED, so the event that triggered
// the scan-budget stop is re-read on the next call and never skipped.
func (st *searchScan) scan(part string, afterSeq uint64, out *[]DecisionView) (resumeCursor string, done bool, err error) {
	for {
		evs, seqs, next, err := st.svc.reader.CommittedEvents(st.capability, part, afterSeq, st.batch)
		if err != nil {
			return "", false, err
		}
		for i := range evs {
			if st.scanned >= st.svc.lim.MaxProjectionScan() {
				return encodeCursor(part, prevSeq(seqs, i, afterSeq)), true, nil
			}
			st.scanned++
			if evs[i].Identity.Tenant != st.tenant || !matchFilter(&evs[i], st.f) {
				continue
			}
			*out = append(*out, decisionView(&evs[i], part, seqs[i]))
			if len(*out) >= st.limit {
				return encodeCursor(part, seqs[i]), true, nil
			}
		}
		if len(evs) < st.batch {
			return "", false, nil // partition exhausted
		}
		afterSeq = next
	}
}

// prevSeq returns the sequence of the last event examined before index i (the
// batch's prior element, or afterSeq when i==0), so a scan-budget stop resumes
// at — not past — the unexamined boundary event.
func prevSeq(seqs []uint64, i int, afterSeq uint64) uint64 {
	if i > 0 {
		return seqs[i-1]
	}
	return afterSeq
}

// Explain returns the full historical explanation of one committed decision,
// projected from the persisted event. Uniform not-found across tenants.
func (s *DecisionService) Explain(capability, tenant, eventID string) (ExplanationView, error) {
	if tenant == "" {
		return ExplanationView{}, mcperr.New(mcperr.ReasonAdminTenantScope, "adminapi.decisions", "tenant required")
	}
	if _, err := capToPolicy(capability); err != nil {
		return ExplanationView{}, err
	}
	if eventID == "" {
		return ExplanationView{}, mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.decisions", "event id required")
	}
	scanned := 0
	batch := s.lim.MaxPageSize()
	for _, part := range []string{partitionCrit, partitionOrd} {
		afterSeq := uint64(0)
		for {
			evs, _, next, rerr := s.reader.CommittedEvents(capability, part, afterSeq, batch)
			if rerr != nil {
				return ExplanationView{}, rerr
			}
			for i := range evs {
				scanned++
				if scanned > s.lim.MaxProjectionScan() {
					return ExplanationView{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.decisions", "not found")
				}
				if evs[i].EventID == eventID && evs[i].Identity.Tenant == tenant {
					return explanationView(&evs[i], part), nil
				}
			}
			if len(evs) < batch {
				break
			}
			afterSeq = next
		}
	}
	return ExplanationView{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.decisions", "not found")
}

func (s *DecisionService) validateRange(f DecisionFilter) error {
	if f.StartUnixNano == 0 && f.EndUnixNano == 0 {
		return nil
	}
	if f.EndUnixNano < f.StartUnixNano {
		return mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.decisions", "end before start")
	}
	span := f.EndUnixNano - f.StartUnixNano
	if span > int64(s.lim.MaxQueryRange()) {
		return mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminapi.decisions", "time range exceeds bound")
	}
	return nil
}

func partRank(part string) int {
	if part == partitionCrit {
		return 0
	}
	return 1
}

func matchFilter(e *evmodel.Event, f DecisionFilter) bool {
	// Exact-match string filters, as (want, have) pairs — a table keeps this
	// under the cyclomatic bound as filters grow.
	eq := [...][2]string{
		{f.Action, e.Decision.Action},
		{f.ReasonCode, e.Decision.ReasonCode},
		{f.RuleID, e.Decision.MatchedRuleID},
		{f.ServerID, e.Identity.ServerID},
		{f.ToolName, e.Identity.ToolName},
		{f.ToolFingerprint, e.Identity.ToolFingerprint},
		{f.PrincipalID, e.Identity.PrincipalID},
		{f.AgentID, e.Identity.AgentID},
	}
	for _, p := range eq {
		if p[0] != "" && p[1] != p[0] {
			return false
		}
	}
	if f.StartUnixNano != 0 && e.TimeUnixNano < f.StartUnixNano {
		return false
	}
	if f.EndUnixNano != 0 && e.TimeUnixNano > f.EndUnixNano {
		return false
	}
	return true
}

func decisionView(e *evmodel.Event, part string, seq uint64) DecisionView {
	return DecisionView{
		EventID: e.EventID, Sequence: seq, Partition: part, Capability: capString(e.Capability),
		TimeUnixNano: e.TimeUnixNano, Tenant: e.Identity.Tenant, PrincipalID: e.Identity.PrincipalID,
		PrincipalType: e.Identity.PrincipalType, AgentID: e.Identity.AgentID, ServerID: e.Identity.ServerID,
		ToolName: e.Identity.ToolName, Action: e.Decision.Action, ReasonCode: e.Decision.ReasonCode,
		MatchedRuleID: e.Decision.MatchedRuleID, OperationClass: e.Decision.OperationClass,
		ExecutionState: e.Decision.ExecutionState,
	}
}

func explanationView(e *evmodel.Event, part string) ExplanationView {
	return ExplanationView{
		EventID: e.EventID, CorrelationID: e.CorrelationID, ReplayID: e.ReplayID,
		Capability: capString(e.Capability), Partition: part, TimeUnixNano: e.TimeUnixNano,
		Tenant: e.Identity.Tenant, PrincipalID: e.Identity.PrincipalID, PrincipalType: e.Identity.PrincipalType,
		AgentID: e.Identity.AgentID, ClientID: e.Identity.ClientID, ServerID: e.Identity.ServerID,
		ToolName: e.Identity.ToolName, ToolFingerprint: e.Identity.ToolFingerprint,
		ResourceRef: e.Identity.ResourceRef, ResourceHash: e.Identity.ResourceHash, Assurance: e.Identity.Assurance,
		Action: e.Decision.Action, ReasonCode: e.Decision.ReasonCode, MatchedRuleID: e.Decision.MatchedRuleID,
		DecisiveConditionID: e.Decision.DecisiveConditionID, Remediation: e.Decision.Remediation,
		OperationClass: e.Decision.OperationClass, RiskClass: e.Decision.RiskClass,
		ExecutionState: e.Decision.ExecutionState, Obligations: e.Decision.Obligations,
		PolicyRevision: e.Decision.PolicyRevision, CatalogRevision: e.Decision.CatalogRevision,
		RegistryRevision: e.Decision.RegistryRevision, InspectionRevision: e.Decision.InspectionRevision,
		RuntimeRevision: e.Decision.RuntimeRevision, PolicySnapshotHash: e.Decision.PolicySnapshotHash,
		InspectionSchemaStatus: e.Inspection.SchemaStatus, FindingClasses: e.Inspection.FindingClasses,
		MaxSeverity: e.Inspection.MaxSeverity, DLPDisposition: e.Inspection.DLPDisposition,
		DestinationClass:     e.Inspection.DestinationClass,
		CredentialProfileRef: e.Credential.ProfileID, CredentialPower: e.Credential.PowerCeiling,
		Source: "historical",
	}
}
