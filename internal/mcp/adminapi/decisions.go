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
	parts := []string{partitionCrit, partitionOrd}
	out := make([]DecisionView, 0, limit)
	scanned := 0
	batch := s.lim.MaxPageSize()
	for pi := range parts {
		part := parts[pi]
		if partRank(part) < partRank(cur.part) {
			continue // already passed this partition
		}
		afterSeq := uint64(0)
		if part == cur.part {
			afterSeq = cur.seq
		}
		for {
			evs, seqs, next, rerr := s.reader.CommittedEvents(capability, part, afterSeq, batch)
			if rerr != nil {
				return SearchResult{}, rerr
			}
			for i := range evs {
				scanned++
				if scanned > s.lim.MaxProjectionScan() {
					return SearchResult{Decisions: out, NextCursor: encodeCursor(part, seqs[i])}, nil
				}
				if evs[i].Identity.Tenant != tenant {
					continue
				}
				if !matchFilter(&evs[i], f) {
					continue
				}
				out = append(out, decisionView(&evs[i], part, seqs[i]))
				if len(out) >= limit {
					return SearchResult{Decisions: out, NextCursor: encodeCursor(part, seqs[i])}, nil
				}
			}
			if len(evs) < batch {
				break // partition exhausted
			}
			afterSeq = next
		}
	}
	return SearchResult{Decisions: out}, nil
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
	if f.Action != "" && e.Decision.Action != f.Action {
		return false
	}
	if f.ReasonCode != "" && e.Decision.ReasonCode != f.ReasonCode {
		return false
	}
	if f.RuleID != "" && e.Decision.MatchedRuleID != f.RuleID {
		return false
	}
	if f.ServerID != "" && e.Identity.ServerID != f.ServerID {
		return false
	}
	if f.ToolName != "" && e.Identity.ToolName != f.ToolName {
		return false
	}
	if f.ToolFingerprint != "" && e.Identity.ToolFingerprint != f.ToolFingerprint {
		return false
	}
	if f.PrincipalID != "" && e.Identity.PrincipalID != f.PrincipalID {
		return false
	}
	if f.AgentID != "" && e.Identity.AgentID != f.AgentID {
		return false
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
