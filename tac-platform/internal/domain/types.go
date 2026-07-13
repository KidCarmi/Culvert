// Package domain holds the stable types for the infra-ops spine. No I/O here.
package domain

import "time"

type State string

const (
	StateCreated          State = "CREATED"
	StateDiscovering      State = "DISCOVERING"
	StatePlanning         State = "PLANNING"
	StatePolicyRejected   State = "POLICY_REJECTED"
	StateReviewPending    State = "REVIEW_PENDING"
	StateApprovalPending  State = "APPROVAL_PENDING"
	StateApproved         State = "APPROVED"
	StateExecutionQueued  State = "EXECUTION_QUEUED"
	StateExecuting        State = "EXECUTING"
	StateValidating       State = "VALIDATING"
	StateSucceeded        State = "SUCCEEDED"
	StateFailed           State = "FAILED"
	StateRollbackPending  State = "ROLLBACK_PENDING"
	StateRollingBack      State = "ROLLING_BACK"
	StateRolledBack       State = "ROLLED_BACK"
	StateCancelled        State = "CANCELLED"
	StateExpired          State = "EXPIRED"
	StateManualRequired   State = "MANUAL_INTERVENTION_REQUIRED"
)

type Kind string

const (
	KindRestart Kind = "restart"
	KindDeploy  Kind = "deploy"
)

type Level string

const (
	L2 Level = "L2"
	L3 Level = "L3"
)

type ActorKind string

const (
	ActorModel   ActorKind = "model"
	ActorHuman   ActorKind = "human"
	ActorService ActorKind = "service"
)

// SigDomain separates signer identities by purpose (R7-F1). A signature from one
// domain is invalid in any other.
type SigDomain string

const (
	SigPlan     SigDomain = "plan"
	SigApproval SigDomain = "approval"
	SigAudit    SigDomain = "audit"
)

// Scope is the composite tenant/env/region scope required on every domain object.
type Scope struct {
	TenantID    string
	Environment string
	Region      string
}

func (s Scope) LeaseKey(workerID string) string {
	return s.TenantID + ":" + s.Environment + ":" + s.Region + ":" + workerID
}

type Operation struct {
	ID              string
	Scope           Scope
	Kind            Kind
	Level           Level
	WorkerID        string
	Intent          string
	State           State
	CurrentPlanID   string
	RollbackTarget  RollbackTarget
	IdempotencyKey  string
	InitiatingActor string
	SessionMeta     map[string]any
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ExpiresAt       time.Time
}

type RollbackTarget struct {
	CommitSHA    string `json:"commit_sha"`
	ImageDigest  string `json:"image_digest"`
	ConfigDigest string `json:"config_digest"`
}

type ExpectedChanges struct {
	Create           int              `json:"create"`
	Delete           int              `json:"delete"`
	Update           int              `json:"update"`
	TouchesForbidden bool             `json:"touches_forbidden"`
	NewPaid          bool             `json:"new_paid"`
	ProviderChanged  bool             `json:"provider_changed"`
	Action           string           `json:"action,omitempty"`
	Resources        []map[string]any `json:"resources,omitempty"`
}

type PolicyRuleResult struct {
	ID     string `json:"id"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

type PolicyResult struct {
	Passed bool               `json:"passed"`
	Rules  []PolicyRuleResult `json:"rules"`
}

func (p PolicyResult) FailedIDs() []string {
	var out []string
	for _, r := range p.Rules {
		if !r.Pass {
			out = append(out, r.ID)
		}
	}
	return out
}

type Plan struct {
	PlanID             string
	Scope              Scope
	OpID               string
	Kind               Kind
	CommitSHA          string
	ConfigDigest       string
	ProviderLockDigest string
	TargetImageDigest  string
	ExpectedChanges    ExpectedChanges
	PolicyResult       PolicyResult
	RollbackTarget     RollbackTarget
	CostDeltaUSD       float64
	HealthValidation   bool
	Signature          string
	SignerKeyID        string
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

type Approval struct {
	ApprovalID         string
	Scope              Scope
	OpID               string
	PlanID             string
	BoundPlanSignature string
	Approver           string
	ApproverIsAuthor   bool
	ApproverSignature  string
	Decision           string
	SingleUseConsumed  bool
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

type Event struct {
	Seq       int
	TenantID  string
	OpID      string
	TS        time.Time
	Actor     string
	ActorKind ActorKind
	EventType string
	FromState State
	ToState   State
	Detail    map[string]any
	PrevHash  string
	Hash      string
	SigDomain SigDomain
	Signature string
}

type Worker struct {
	Scope           Scope
	WorkerID        string
	Allowlisted     bool
	ApprovedReg     string
	CurrentDigest   string
	KnownGoodDigest string
	Config          map[string]string
	ApprovedDigests []string
}
