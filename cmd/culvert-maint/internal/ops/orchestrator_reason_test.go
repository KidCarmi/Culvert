package ops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestRun_ReasonErrorOverridesTheStageReason: a stage that wraps its error in
// ReasonError fails the op with that reason instead of the stage's own; the
// stage's own reason still applies to every other error, and to a ReasonError
// that names none. The error text is unchanged.
func TestRun_ReasonErrorOverridesTheStageReason(t *testing.T) {
	plain := errors.New("the command failed")
	for _, tc := range []struct {
		name string
		err  error
		want FailureReason
	}{
		{"plain error keeps the stage reason", plain, ReasonCLIError},
		{"ReasonError overrides it", &ReasonError{Reason: ReasonCommandError, Err: plain}, ReasonCommandError},
		{"wrapped ReasonError is found", fmt.Errorf("stage: %w", &ReasonError{Reason: ReasonCommandError, Err: plain}), ReasonCommandError},
		{"ReasonError without a reason keeps the stage reason", &ReasonError{Err: plain}, ReasonCLIError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newOrchTestRig(t)
			Run(context.Background(), rig.deps, rig.opID, KindRestoreCommit, "uid=1", nil, "",
				[]FlowStage{{
					Name:          "run_cli_restore_commit",
					FailureReason: ReasonCLIError,
					Run:           func(context.Context) ([]byte, []byte, error) { return nil, nil, tc.err },
				}}, nil)
			op := rig.mgr.Get(rig.opID)
			if op.State != StateFailed || op.FailureReason != string(tc.want) {
				t.Errorf("op = %s(%s), want failed(%s)", op.State, op.FailureReason, tc.want)
			}
			if len(op.Progress) != 1 || !strings.Contains(op.Progress[0].Output, "the command failed") {
				t.Errorf("stage output lost the error text: %+v", op.Progress)
			}
			if !strings.Contains(rig.auditContent(t), `"failure_reason":"`+string(tc.want)+`"`) {
				t.Errorf("audit does not carry %s", tc.want)
			}
		})
	}
}

// TestRun_ReasonErrorDoesNotBeatTheFirstFailure: first failure still wins. A
// later stage's ReasonError changes nothing unless that stage promotes.
func TestRun_ReasonErrorDoesNotBeatTheFirstFailure(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindRestoreCommit, "uid=1", nil, "",
		[]FlowStage{
			failStage("first", "boom", ReasonHealthFailed),
			{
				Name: "later", ContinueOnError: true, FailureReason: ReasonCLIError,
				Run: func(context.Context) ([]byte, []byte, error) {
					return nil, nil, &ReasonError{Reason: ReasonCommandError, Err: errors.New("later")}
				},
			},
		}, nil)
	if op := rig.mgr.Get(rig.opID); op.FailureReason != string(ReasonHealthFailed) {
		t.Errorf("failure_reason = %q, want the first failure's health_failed", op.FailureReason)
	}
}
