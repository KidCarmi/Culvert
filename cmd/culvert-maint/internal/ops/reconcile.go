package ops

import (
	"fmt"
)

// OverrideInterrupted re-terminalizes an op that MarkAllInterrupted registered
// as failed(agent_restart_interrupted), replacing that provisional verdict with
// the outcome the startup reconciler established from Docker truth (e.g.
// succeeded(reconciled) when the target image is live and healthy).
//
// This is the P0-B fix from the PR-E design: Finish hard-refuses a
// terminal→terminal transition, so without an explicit override the adopt path
// could never make GET /v1/operations/{id} agree with what the reconciler did.
// The override is deliberately NARROW — it applies ONLY to an op whose current
// failure reason is agent_restart_interrupted; any other terminal op (a real
// failure, a real success) is refused, so this can never rewrite history for an
// op that actually ran to completion in this process.
func (m *Manager) OverrideInterrupted(opID string, finalState State, reason FailureReason, result map[string]interface{}) error {
	if !finalState.IsTerminal() {
		return fmt.Errorf("ops: OverrideInterrupted called with non-terminal state %q", finalState)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.active[opID]
	if !ok {
		return fmt.Errorf("ops: unknown op_id %q", opID)
	}
	if op.State != StateFailed || op.FailureReason != string(ReasonAgentRestartInterrupted) {
		return fmt.Errorf("ops: op %s is %s(%s), not an interrupted op — refusing override", opID, op.State, op.FailureReason)
	}
	now := m.now()
	op.State = finalState
	op.Finished = &now
	op.FailureReason = string(reason)
	if result != nil {
		op.Result = result
	}
	return nil
}
