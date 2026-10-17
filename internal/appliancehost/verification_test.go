package appliancehost

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

type deceptiveBackend struct {
	*memoryBackend
	discardWrite bool
	afterApply   func()
}

func (b *deceptiveBackend) Write(file File) error {
	if b.discardWrite {
		return nil
	}
	return b.memoryBackend.Write(file)
}

func (b *deceptiveBackend) Apply(ctx context.Context) error {
	err := b.memoryBackend.Apply(ctx)
	if b.afterApply != nil {
		b.afterApply()
	}
	return err
}

func TestRollbackVerifiesFilesAfterSuccessfulApply(t *testing.T) {
	for _, fault := range []string{"discard_write", "changed_bytes", "changed_mode", "changed_base", "read_failure"} {
		t.Run(fault, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			if err := s.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			original := copyFile(s.State.Network.Original)
			backend := &deceptiveBackend{memoryBackend: host}
			backend.afterApply = func() {
				switch fault {
				case "changed_bytes":
					host.file.Data = []byte("external writer")
				case "changed_mode":
					host.file.Mode = 0o644
				case "changed_base":
					host.digest = "external base"
				case "read_failure":
					host.readErr = os.ErrPermission
				}
			}
			backend.discardWrite = fault == "discard_write"
			s.Host = backend
			s.Identity.Uptime += 121 * time.Second
			if err := s.Tick(context.Background()); err == nil {
				t.Fatal("unverified restoration accepted")
			}
			durable := store.session(t, backend, s.Identity)
			if !durable.State.Network.Pending() || !same(durable.State.Network.Original, original) {
				t.Fatal("unverified rollback completed or lost its backup")
			}
			if durable.State.Network.Verification.Files != "unverified" || durable.State.Network.Verification.Apply != "succeeded" {
				t.Fatal("command success conflated with file verification")
			}
			if got := durable.State.Records[0].Failure; got == nil || got.Stage != "rollback_verify" {
				t.Fatalf("missing stage: %+v", got)
			}
		})
	}
}

func TestApplyCannotOfferConfirmationForUnwrittenCandidate(t *testing.T) {
	s, _, host, candidate := transactionFixture(t)
	s.Host = &deceptiveBackend{memoryBackend: host, discardWrite: true}
	id, err := s.Stage(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tick(context.Background()); err == nil {
		t.Fatal("lying writer accepted")
	}
	if err := s.Confirm(id); err == nil {
		t.Fatal("unapplied candidate confirmed")
	}
}

func TestRollbackStorageFaultCanResumeWithoutLosingBackup(t *testing.T) {
	for _, fault := range []error{syscall.ENOSPC, syscall.EROFS, os.ErrPermission} {
		t.Run(fault.Error(), func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			if err := s.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			s.Identity.Boot = "after-reboot"
			host.writeErr = fault
			if err := s.Tick(context.Background()); !errors.Is(err, fault) {
				t.Fatalf("lost cause: %v", err)
			}
			s = store.session(t, host, s.Identity)
			if s.State.Network.Phase != "rolling_back" || !same(host.file, candidate) {
				t.Fatal("failed restore reported success")
			}
			host.writeErr = nil
			if err := s.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			if s.State.Network.Phase != "rolled_back" || !same(host.file, s.State.Network.Original) {
				t.Fatal("retry failed to restore original")
			}
			if s.State.Network.Verification.ClientAccess != "unverified" {
				t.Fatal("invented client reachability")
			}
			if s.State.Records[0].Failure == nil {
				t.Fatal("recovery erased prior failure evidence")
			}
		})
	}
}

func TestFailureEvidenceCannotCommitFailedTransition(t *testing.T) {
	s, store, host, candidate := transactionFixture(t)
	if _, err := s.Stage(candidate); err != nil {
		t.Fatal(err)
	}
	if err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Identity.Boot = "after-reboot"
	store.fail = "rolled_back"
	if err := s.Tick(context.Background()); err == nil {
		t.Fatal("failed save hidden")
	}
	durable := store.session(t, host, s.Identity)
	if durable.State.Network.Phase != "rolling_back" {
		t.Fatal("failure reporting committed refused transition")
	}
	store.fail = ""
	if err := durable.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if durable.State.Network.Phase != "rolled_back" {
		t.Fatal("restart did not finish verification")
	}
}

func TestCancelledTickDoesNotStartMutation(t *testing.T) {
	s, _, host, candidate := transactionFixture(t)
	if _, err := s.Stage(candidate); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Tick(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(host.writes) != 0 || host.applyCount != 0 || s.State.Network.Phase != "queued" {
		t.Fatal("cancelled work mutated network")
	}
}

func TestDriftInvalidatesEarlierFileVerification(t *testing.T) {
	for _, action := range []string{"rollback", "confirm"} {
		t.Run(action, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			id, err := s.Stage(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			host.digest = "external writer"
			if action == "confirm" {
				err = s.Confirm(id)
			} else {
				s.Identity.Uptime += 121 * time.Second
				err = s.Tick(context.Background())
			}
			if err == nil {
				t.Fatal("drift accepted")
			}
			s = store.session(t, host, s.Identity)
			if s.State.Network.Phase != "conflict" || s.State.Network.Verification.Files != "unverified" {
				t.Fatal("known stale file verification retained")
			}
		})
	}
}
