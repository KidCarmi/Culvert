package domain

import "time"

// PlanBody is the canonical, content-addressed body of a plan. Its exact bytes are
// hashed to form the plan_id and signed (domain=plan). Any field change => new
// plan_id => any prior approval is invalidated. Field order is stable for
// deterministic JSON (content addressing).
type PlanBody struct {
	OpID               string          `json:"op_id"`
	TenantID           string          `json:"tenant_id"`
	Environment        string          `json:"environment"`
	Region             string          `json:"region"`
	WorkerID           string          `json:"worker_id"`
	Kind               Kind            `json:"kind"`
	CommitSHA          string          `json:"commit_sha"`
	ConfigDigest       string          `json:"config_digest"`
	ProviderLockDigest string          `json:"provider_lock_digest"`
	TargetImageDigest  string          `json:"target_image_digest"`
	ExpectedChanges    ExpectedChanges `json:"expected_changes"`
	RollbackTarget     RollbackTarget  `json:"rollback_target"`
	CostDeltaUSD       float64         `json:"cost_delta_usd"`
	HealthValidation   bool            `json:"health_validation"`
	CreatedAt          time.Time       `json:"created_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
}
