package appliancehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Failure contains stable classifications only; raw command output and paths
// must never be copied into public recovery evidence.
type Failure struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return fmt.Sprintf("%s: %v", e.stage, e.err) }
func (e *stageError) Unwrap() error { return e.err }

// AtStage preserves the underlying error for classification by the worker.
func AtStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stageError{stage: stage, err: err}
}

var errNetworkDrift = errors.New("network configuration changed outside the transaction")

func classifyFailure(err error) Failure {
	f := Failure{Stage: "recovery", Code: "operation_failed"}
	var stage *stageError
	for errors.As(err, &stage) {
		f.Stage = stage.stage
		err = stage.err
	}
	switch {
	case errors.Is(err, syscall.ENOSPC):
		f.Code = "no_space"
	case errors.Is(err, syscall.EROFS):
		f.Code = "read_only"
	case errors.Is(err, os.ErrPermission):
		f.Code = "permission_denied"
	case errors.Is(err, context.DeadlineExceeded):
		f.Code = "timeout"
	case errors.Is(err, context.Canceled):
		f.Code = "cancelled"
	case errors.Is(err, errNetworkDrift):
		f.Code = "configuration_changed"
	}
	return f
}

func (s *Session) recordFailure(err error) error {
	failure := classifyFailure(err)
	for i := range s.State.Records {
		r := &s.State.Records[i]
		if r.ID != s.State.Network.ID {
			continue
		}
		r.Failure = &failure
		return errors.Join(err, AtStage("persist_failure", s.Save(s.State)))
	}
	return err
}
