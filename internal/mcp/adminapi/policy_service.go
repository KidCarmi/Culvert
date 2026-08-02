package adminapi

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/policy/simulate"
)

// capToPolicy maps a wire capability string to a policy.Capability. Unknown
// values fail closed.
func capToPolicy(capability string) (policy.Capability, error) {
	switch capability {
	case "gateway":
		return policy.CapGateway, nil
	case "management":
		return policy.CapManagement, nil
	default:
		return policy.CapabilityUnset, mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.cap", "unknown capability")
	}
}

// PolicyStores resolves the capability-local PR-6 policy store. package main
// supplies the real stores; tests supply fakes.
type PolicyStores interface {
	Store(capability string) (*policy.Store, bool)
}

// ValidateResult is the safe result of compiling/validating a candidate policy.
type ValidateResult struct {
	OK            bool   `json:"ok"`
	Capability    string `json:"capability"`
	CandidateHash string `json:"candidate_hash"`
	RuleCount     int    `json:"rule_count"`
	DefaultAction string `json:"default_action"`
	SchemaVersion int    `json:"schema_version"`
	Reason        string `json:"reason,omitempty"` // classified reason code on failure
}

// SimResult is the safe result of simulating a candidate against a corpus.
type SimResult struct {
	Capability    string          `json:"capability"`
	CandidateHash string          `json:"candidate_hash"`
	Cases         []SimCaseResult `json:"cases"`
}

// SimCaseResult is one simulated case's safe outcome.
type SimCaseResult struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	MatchedRule string `json:"matched_rule"`
}

// CompareResult is the safe blast-radius summary of active-vs-candidate.
type CompareResult struct {
	Capability          string   `json:"capability"`
	CandidateHash       string   `json:"candidate_hash"`
	BaseRevision        uint64   `json:"base_revision"`
	NewAllow            int      `json:"new_allow"`
	NewDeny             int      `json:"new_deny"`
	NewQuarantine       int      `json:"new_quarantine"`
	NewApprovalRequired int      `json:"new_approval_required"`
	AffectedRules       []string `json:"affected_rules"`
	SampleCaseIDs       []string `json:"sample_case_ids"`
}

// PolicyService implements validate / simulate / compare over the SAME PR-6
// engine the runtime uses (via policy.Compile + policy/simulate). It never
// publishes or mutates a store — those are the publication workflow's job.
type PolicyService struct {
	stores PolicyStores
	sim    *simulate.Simulator
	plim   policy.Limits
	lim    Limits
	clock  func() time.Time
}

// NewPolicyService builds a PolicyService. plim is the policy engine limit set
// (shared with the runtime); lim bounds candidate/corpus/sample sizes.
func NewPolicyService(stores PolicyStores, plim policy.Limits, lim Limits, clock func() time.Time) *PolicyService {
	if clock == nil {
		clock = time.Now
	}
	return &PolicyService{stores: stores, sim: simulate.New(plim), plim: plim, lim: lim, clock: clock}
}

// candidateHash returns the hex SHA-256 of the raw candidate bytes. The hash
// binds an approval to an exact candidate (TOCTOU guard).
func candidateHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// compile validates size, then compiles the candidate with the PR-6 compiler.
func (s *PolicyService) compile(capability string, raw []byte) (*policy.Snapshot, error) {
	if len(raw) == 0 {
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "adminapi.compile", "empty candidate")
	}
	if len(raw) > s.lim.MaxCandidateBytes() {
		return nil, mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminapi.compile", "candidate exceeds byte bound")
	}
	if _, err := capToPolicy(capability); err != nil {
		return nil, err
	}
	meta := policy.CreatedMeta{Author: "adminapi", CreatedAt: s.clock().UTC().Format(time.RFC3339), Note: "candidate"}
	snap, err := policy.Compile(raw, meta, s.plim)
	if err != nil {
		// Surface as a publication-validation failure with the classified reason.
		return nil, mcperr.Wrap(mcperr.ReasonPublicationValidationFailed, "adminapi.compile", "candidate failed validation", err)
	}
	if snap.Capability() != mustCap(capability) {
		return nil, mcperr.New(mcperr.ReasonPublicationValidationFailed, "adminapi.compile", "candidate capability mismatch")
	}
	return snap, nil
}

func mustCap(capability string) policy.Capability {
	c, _ := capToPolicy(capability)
	return c
}

// Validate compiles the candidate and returns its safe metadata.
func (s *PolicyService) Validate(capability string, raw []byte) ValidateResult {
	snap, err := s.compile(capability, raw)
	if err != nil {
		return ValidateResult{OK: false, Capability: capability, Reason: mcperr.ReasonOf(err).Code()}
	}
	return ValidateResult{
		OK: true, Capability: capability, CandidateHash: candidateHash(raw),
		RuleCount: snap.RuleCount(), DefaultAction: snap.DefaultAction().String(),
		SchemaVersion: snap.SchemaVersion(),
	}
}

// Simulate compiles the candidate and runs the bounded corpus through the shared
// evaluator. It publishes nothing.
func (s *PolicyService) Simulate(capability string, raw []byte, cases []simulate.Case) (SimResult, error) {
	if len(cases) > s.lim.MaxSimCorpus() {
		return SimResult{}, mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminapi.simulate", "corpus exceeds bound")
	}
	snap, err := s.compile(capability, raw)
	if err != nil {
		return SimResult{}, err
	}
	results, err := s.sim.Corpus(snap, cases)
	if err != nil {
		return SimResult{}, err
	}
	out := SimResult{Capability: capability, CandidateHash: candidateHash(raw), Cases: make([]SimCaseResult, 0, len(results))}
	for i := range results {
		d := results[i].Decision
		out.Cases = append(out.Cases, SimCaseResult{
			ID: results[i].ID, Action: d.Action.String(),
			Reason: string(d.Reason), MatchedRule: string(d.MatchedRule),
		})
	}
	return out, nil
}

// Compare compiles the candidate and compares active-vs-candidate over the
// corpus, returning a bounded blast-radius summary. It publishes nothing.
func (s *PolicyService) Compare(capability string, raw []byte, cases []simulate.Case) (CompareResult, error) {
	if len(cases) > s.lim.MaxSimCorpus() {
		return CompareResult{}, mcperr.New(mcperr.ReasonAdminRangeExceeded, "adminapi.compare", "corpus exceeds bound")
	}
	newSnap, err := s.compile(capability, raw)
	if err != nil {
		return CompareResult{}, err
	}
	store, ok := s.stores.Store(capability)
	if !ok {
		return CompareResult{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.compare", "no policy store for capability")
	}
	active := store.Current() // may be nil (nothing published yet)
	cmp, err := s.sim.Compare(active, newSnap, cases)
	if err != nil {
		return CompareResult{}, err
	}
	res := CompareResult{
		Capability: capability, CandidateHash: candidateHash(raw),
		BaseRevision:        uint64(store.CurrentRevision()),
		NewAllow:            cmp.NewAllow,
		NewDeny:             cmp.NewDeny,
		NewQuarantine:       cmp.NewQuarantine,
		NewApprovalRequired: cmp.NewApprovalRequired,
	}
	for _, r := range cmp.AffectedRules {
		res.AffectedRules = append(res.AffectedRules, string(r))
	}
	limit := s.lim.MaxCompareSamples()
	for i := range cmp.Samples {
		if len(res.SampleCaseIDs) >= limit {
			break
		}
		res.SampleCaseIDs = append(res.SampleCaseIDs, cmp.Samples[i].ID)
	}
	return res, nil
}
