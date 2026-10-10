package releasetrust

import (
	"errors"
	"fmt"
)

// Reason classifies why a persisted release-trust ledger was refused. Startup
// stays fail-closed for every reason; the class only selects the remedy.
type Reason string

const (
	// ReasonUnsafe means the file is not a bounded, private, agent-owned regular
	// file. The operator fixes ownership/mode; recovery never rewrites it.
	ReasonUnsafe Reason = "unsafe"
	// ReasonCorrupt means the document (or its replay floor) cannot be decoded.
	// Recovery requires the operator to state the floor explicitly.
	ReasonCorrupt Reason = "corrupt"
	// ReasonPolicyMismatch means the floor is readable but persisted evidence does
	// not verify under the CURRENT host policy (for example after rotating
	// release_trust_keys / release_trust_root / release_catalog_repo), or is
	// inconsistent with the floor. Recovery keeps the floor and drops only the
	// entries that no longer verify.
	ReasonPolicyMismatch Reason = "policy_mismatch"
)

// RecoveryDoc names the operator procedure referenced by every refusal.
const RecoveryDoc = "docs/appliance/signed-update-agent-boundary.md, \"Recovering a refused release-trust ledger\""

// LedgerError is a classified ledger refusal.
type LedgerError struct {
	Reason Reason
	Detail string
}

func (e *LedgerError) Error() string {
	if e.Reason == ReasonUnsafe {
		return fmt.Sprintf("release trust: %s (reason=%s); fix the ledger's ownership/mode (an agent-owned regular file, mode 0600) and restart the agent — recovery never rewrites an unsafe ledger; see %s", e.Detail, e.Reason, RecoveryDoc)
	}
	return fmt.Sprintf("release trust: %s (reason=%s); recover offline as root: stop the agent, run `culvert-maint --recover-release-trust` (dry run), then repeat with --confirm; see %s", e.Detail, e.Reason, RecoveryDoc)
}

// ReasonOf reports the classification of a ledger refusal, if err is one.
func ReasonOf(err error) (Reason, bool) {
	var le *LedgerError
	if errors.As(err, &le) {
		return le.Reason, true
	}
	return "", false
}
