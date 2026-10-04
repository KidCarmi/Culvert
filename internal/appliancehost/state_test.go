package appliancehost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

type memoryBackend struct {
	file       File
	digest     string
	readErr    error
	writeErr   error
	applyErrs  []error
	writes     []File
	applyCount int
}

func copyFile(file File) File { file.Data = slices.Clone(file.Data); return file }

func (b *memoryBackend) Read() (File, string, error) {
	return copyFile(b.file), b.digest, b.readErr
}

func (b *memoryBackend) Write(file File) error {
	if b.writeErr != nil {
		return b.writeErr
	}
	b.file = copyFile(file)
	b.writes = append(b.writes, copyFile(file))
	return nil
}

func (b *memoryBackend) Apply(ctx context.Context) error {
	b.applyCount++
	if len(b.applyErrs) > 0 {
		err := b.applyErrs[0]
		b.applyErrs = b.applyErrs[1:]
		return err
	}
	return ctx.Err()
}

type memoryStore struct {
	data []byte
	fail string
}

func (m *memoryStore) save(state State) error {
	if m.fail == "all" || state.Network != nil && m.fail == state.Network.Phase {
		return errors.New("injected durable save failure")
	}
	data, err := json.Marshal(state)
	if err == nil {
		m.data = data
	}
	return err
}

func (m *memoryStore) session(t *testing.T, backend Backend, identity Identity) *Session {
	t.Helper()
	state := State{Version: 1}
	if len(m.data) != 0 {
		if err := json.Unmarshal(m.data, &state); err != nil {
			t.Fatal(err)
		}
	}
	return &Session{State: state, Save: m.save, Host: backend, Identity: identity}
}

func transactionFixture(t *testing.T) (*Session, *memoryStore, *memoryBackend, File) {
	t.Helper()
	backend := &memoryBackend{file: File{Data: []byte("original exact bytes\n"), Exists: true, Mode: 0o640}, digest: "unchanged base configuration"}
	store := &memoryStore{}
	identity := Identity{Boot: "boot-one", Machine: "machine-one", Uptime: 10 * time.Second}
	session := store.session(t, backend, identity)
	candidate := File{Data: []byte("candidate configuration\n"), Exists: true, Mode: 0o600}
	return session, store, backend, candidate
}

func TestStagePersistsBackupWithoutMutatingNetwork(t *testing.T) {
	s, store, host, candidate := transactionFixture(t)
	original := copyFile(host.file)
	id, err := s.Stage(candidate)
	if err != nil {
		t.Fatal(err)
	}
	reloaded := store.session(t, host, s.Identity)
	transaction := reloaded.State.Network
	if len(id) != 32 || transaction.ID != id || transaction.Phase != "queued" || transaction.Deadline != 130*time.Second || !same(transaction.Original, original) || !same(transaction.Candidate, candidate) {
		t.Fatalf("invalid durable intent: %+v", transaction)
	}
	if len(host.writes) != 0 || host.applyCount != 0 || !same(host.file, original) {
		t.Fatal("staging changed live network")
	}
}

func TestSaveFailurePreventsNetworkMutation(t *testing.T) {
	for _, fail := range []string{"queued", "applying", "rolling_back"} {
		t.Run(fail, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			if fail == "queued" {
				store.fail = fail
				if _, err := s.Stage(candidate); err == nil {
					t.Fatal("save failure accepted")
				}
				if len(host.writes) != 0 || host.applyCount != 0 {
					t.Fatal("network changed without durable intent")
				}
				return
			}
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			store.fail = fail
			if fail == "rolling_back" {
				s.Identity.Uptime = s.State.Network.Deadline
			}
			if err := s.Tick(context.Background()); err == nil {
				t.Fatal("save failure accepted")
			}
			if len(host.writes) != 0 || host.applyCount != 0 {
				t.Fatal("network changed without durable intent")
			}
		})
	}
}

func TestPendingTransactionRollsBackAcrossDeadlineBootAndCrash(t *testing.T) {
	for _, scenario := range []string{"expired", "new boot", "crashed applying", "crashed before write", "crashed rollback", "queued expired", "queued new boot", "original absent"} {
		t.Run(scenario, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			if scenario == "original absent" {
				host.file = File{}
			}
			original := copyFile(host.file)
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			if scenario != "queued expired" && scenario != "queued new boot" {
				if err := s.Tick(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			interruptTransaction(t, s, host, original, scenario)
			restarted := store.session(t, host, s.Identity)
			if err := restarted.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			if restarted.State.Network.Phase != "rolled_back" || !same(host.file, original) || !same(restarted.State.Network.Original, original) {
				t.Fatalf("rollback lost original: %+v; file %+v", restarted.State.Network, host.file)
			}
			writes, applies := len(host.writes), host.applyCount
			if err := restarted.Tick(context.Background()); err != nil || len(host.writes) != writes || host.applyCount != applies {
				t.Fatal("completed rollback repeated side effects")
			}
		})
	}
}

func interruptTransaction(t *testing.T, s *Session, host *memoryBackend, original File, scenario string) {
	t.Helper()
	switch scenario {
	case "new boot", "queued new boot":
		s.Identity.Boot, s.Identity.Uptime = "boot-two", time.Second
	case "crashed applying", "crashed before write":
		if err := s.phase("applying"); err != nil {
			t.Fatal(err)
		}
		if scenario == "crashed before write" {
			host.file = copyFile(original)
		}
	case "crashed rollback":
		if err := s.phase("rolling_back"); err != nil {
			t.Fatal(err)
		}
	default:
		s.Identity.Uptime = s.State.Network.Deadline
	}
}

func TestFailedApplyRestoresAndFailedRollbackRetainsBackup(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(fmt.Sprint(rollbackFails), func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			original := copyFile(host.file)
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			host.applyErrs = []error{errors.New("candidate apply failed")}
			if rollbackFails {
				host.applyErrs = append(host.applyErrs, errors.New("rollback apply failed"))
			}
			if err := s.Tick(context.Background()); err == nil {
				t.Fatal("failed candidate reported success")
			}
			restarted := store.session(t, host, s.Identity)
			want := "rolled_back"
			if rollbackFails {
				want = "rolling_back"
			}
			if restarted.State.Network.Phase != want || !same(host.file, original) || !same(restarted.State.Network.Original, original) {
				t.Fatalf("lost recovery evidence: %+v", restarted.State.Network)
			}
			if rollbackFails {
				if _, err := restarted.Stage(candidate); err == nil {
					t.Fatal("overwrote failed recovery backup")
				}
				if err := restarted.Tick(context.Background()); err != nil || restarted.State.Network.Phase != "rolled_back" {
					t.Fatal("rollback did not resume", err)
				}
			}
		})
	}
}

func TestInterruptedApplyRetainsDurableBackupWhenWriteOrFinalSaveFails(t *testing.T) {
	for _, scenario := range []string{"write fails", "testing save fails"} {
		t.Run(scenario, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			original := copyFile(host.file)
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			if scenario == "write fails" {
				host.writeErr = errors.New("filesystem became read only")
			} else {
				store.fail = "testing"
			}
			if err := s.Tick(context.Background()); err == nil {
				t.Fatal("incomplete apply reported success")
			}
			restarted := store.session(t, host, s.Identity)
			if restarted.State.Network.Phase != "applying" || !same(restarted.State.Network.Original, original) {
				t.Fatal("interrupted apply backup lost")
			}
			host.writeErr, store.fail = nil, ""
			if err := restarted.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			if restarted.State.Network.Phase != "rolled_back" || !same(host.file, original) {
				t.Fatal("interrupted apply did not restore original")
			}
		})
	}
}

func TestConfirmRequiresCurrentWindowIdentityAndFiles(t *testing.T) {
	for _, scenario := range []string{"wrong id", "deadline", "new boot", "file drift", "base drift", "before apply", "save failure", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			id, err := s.Stage(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "before apply" {
				if err := s.Tick(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "wrong id":
				id = "unrelated"
			case "deadline":
				s.Identity.Uptime = s.State.Network.Deadline
			case "new boot":
				s.Identity.Boot = "boot-two"
			case "file drift":
				host.file.Data = []byte("external edits")
			case "base drift":
				host.digest = "changed"
			case "save failure":
				store.fail = "confirmed"
			}
			writes, applies := len(host.writes), host.applyCount
			err = s.Confirm(id)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("confirmation result %v", err)
			}
			durable := store.session(t, host, s.Identity)
			if (durable.State.Network.Phase == "confirmed") != (scenario == "valid") || len(host.writes) != writes || host.applyCount != applies {
				t.Fatal("confirmation altered network or accepted stale evidence")
			}
		})
	}
}

func TestDriftPreservesExternalConfigurationAndBackup(t *testing.T) {
	for _, scenario := range []string{"before apply", "managed file", "permissions", "base file"} {
		t.Run(scenario, func(t *testing.T) {
			s, store, host, candidate := transactionFixture(t)
			original := copyFile(host.file)
			if _, err := s.Stage(candidate); err != nil {
				t.Fatal(err)
			}
			if scenario != "before apply" {
				if err := s.Tick(context.Background()); err != nil {
					t.Fatal(err)
				}
				s.Identity.Uptime = s.State.Network.Deadline
			}
			switch scenario {
			case "permissions":
				host.file.Mode = 0o644
			case "base file":
				host.digest = "external base edit"
			default:
				host.file.Data = []byte("external administrator edit")
			}
			external := copyFile(host.file)
			writes, applies := len(host.writes), host.applyCount
			if err := s.Tick(context.Background()); err == nil {
				t.Fatal("drift not reported")
			}
			reloaded := store.session(t, host, s.Identity)
			if reloaded.State.Network.Phase != "conflict" || !same(host.file, external) || !same(reloaded.State.Network.Original, original) || len(host.writes) != writes || host.applyCount != applies {
				t.Fatal("drift was overwritten or backup lost")
			}
			if _, err := reloaded.Stage(candidate); err == nil {
				t.Fatal("conflict backup overwritten by new transaction")
			}
			if err := reloaded.Tick(context.Background()); err != nil || len(host.writes) != writes {
				t.Fatal("conflict worker kept mutating")
			}
		})
	}
}

func TestParallelStagesUnderStoreLockChooseOneDurableTransaction(t *testing.T) {
	s, store, host, candidate := transactionFixture(t)
	var lock sync.Mutex
	var wg sync.WaitGroup
	winners := make(chan string, 16)
	for range 16 {
		wg.Go(func() {
			// Session requires the real store's exclusive lock; this models its
			// serialized load/read/save semantics without a platform-specific flock.
			lock.Lock()
			defer lock.Unlock()
			attempt := store.session(t, host, s.Identity)
			if id, err := attempt.Stage(candidate); err == nil {
				winners <- id
			}
		})
	}
	wg.Wait()
	close(winners)
	if len(winners) != 1 {
		t.Fatalf("%d stages accepted", len(winners))
	}
	if winner := <-winners; store.session(t, host, s.Identity).State.Network.ID != winner || len(host.writes) != 0 {
		t.Fatal("winning durable transaction mismatch")
	}
}

func TestOperationEvidenceIsBoundedCorrelatedAndDurable(t *testing.T) {
	s, store, host, _ := transactionFixture(t)
	var last string
	for range 70 {
		id, err := s.Append("reboot", "intent", "firstboot:queued")
		if err != nil {
			t.Fatal(err)
		}
		last = id
	}
	if err := s.Finish(last, "dispatch_failed"); err != nil {
		t.Fatal(err)
	}
	reloaded := store.session(t, host, s.Identity)
	if len(reloaded.State.Records) != 64 {
		t.Fatal("history is not bounded")
	}
	record := reloaded.State.Records[63]
	if record.ID != last || record.Phase != "dispatch_failed" || record.Boot != s.Identity.Boot || record.Machine != s.Identity.Machine || record.Observation != "firstboot:queued" {
		t.Fatalf("intent evidence lost: %+v", record)
	}
	if err := reloaded.Finish("not-an-operation", "complete"); err == nil {
		t.Fatal("invented operation completion")
	}
	store.fail = "all"
	if _, err := reloaded.Append("poweroff", "intent", ""); err == nil {
		t.Fatal("unpersisted intent reported success")
	}
}
