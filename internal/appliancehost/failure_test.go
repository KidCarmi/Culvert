package appliancehost

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestFailureClassifiesCausesWithoutPublishingRawErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{syscall.ENOSPC, "no_space"}, {syscall.EROFS, "read_only"},
		{os.ErrPermission, "permission_denied"}, {context.DeadlineExceeded, "timeout"},
		{context.Canceled, "cancelled"}, {errNetworkDrift, "configuration_changed"},
		{errors.New("PRIVATE_CANARY checksum mismatch"), "operation_failed"},
	} {
		got := classifyFailure(AtStage("rollback_write", tc.err))
		if got != (Failure{Stage: "rollback_write", Code: tc.code}) {
			t.Fatalf("unexpected classification: %+v", got)
		}
	}
}

func TestUnreadableApplyInputRemainsRetryable(t *testing.T) {
	s, store, host, candidate := transactionFixture(t)
	if _, err := s.Stage(candidate); err != nil {
		t.Fatal(err)
	}
	host.readErr = os.ErrPermission
	if err := s.Tick(context.Background()); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	s = store.session(t, host, s.Identity)
	if s.State.Network.Phase != "queued" || len(host.writes) != 0 {
		t.Fatal("unavailable observation treated as conflicting config")
	}
	host.readErr = nil
	if err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State.Network.Phase != "testing" {
		t.Fatal("transient read failure did not recover")
	}
}

func TestJoinedFailureUsesStageAndCauseFromSameBranch(t *testing.T) {
	err := errors.Join(AtStage("rollback_command", AtStage("netplan_apply", syscall.EROFS)), AtStage("apply_write", syscall.ENOSPC))
	if got := classifyFailure(err); got != (Failure{Stage: "netplan_apply", Code: "read_only"}) {
		t.Fatalf("mixed unrelated failure branches: %+v", got)
	}
}
