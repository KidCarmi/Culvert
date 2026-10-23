// Package appliancehost owns durable local recovery transactions. It exposes no
// network service and does not manage application containers or credentials.
package appliancehost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// Identity captures monotonic time within a particular kernel boot.
type Identity struct {
	Boot, Machine string
	Uptime        time.Duration
}

// Record is bounded, allowlisted evidence, not a transcript or security attestation.
type Record struct {
	ID          string   `json:"id"`
	Action      string   `json:"action"`
	Phase       string   `json:"phase"`
	Boot        string   `json:"boot"`
	Machine     string   `json:"machine"`
	At          string   `json:"at"`
	Observation string   `json:"observation,omitempty"`
	Failure     *Failure `json:"failure,omitempty"`
}

// File preserves absence, content and permissions for exact rollback.
type File struct {
	Data   []byte `json:"data"`
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode"`
}

// Transaction retains the original configuration even after a failed rollback.
type Transaction struct {
	ID           string        `json:"id"`
	Phase        string        `json:"phase"`
	Boot         string        `json:"boot"`
	Deadline     time.Duration `json:"deadline"`
	Original     File          `json:"original"`
	Candidate    File          `json:"candidate"`
	OtherDigest  string        `json:"other_digest"`
	Verification Verification  `json:"verification"`
}

// Verification separates restored files and command completion from remote
// reachability. Empty values in older records mean unknown, never success.
type Verification struct {
	Files        string `json:"files"`
	Apply        string `json:"apply"`
	ClientAccess string `json:"client_access"`
}

// State has one pending network transaction and a bounded operation history.
type State struct {
	Version int          `json:"version"`
	Records []Record     `json:"records"`
	Network *Transaction `json:"network,omitempty"`
}

// Backend owns fixed host paths and bounded execution; callers never pass argv.
type Backend interface {
	Read() (File, string, error)
	Write(File) error
	Apply(context.Context) error
}

// Session is used while the store's exclusive cross-process lock is held.
type Session struct {
	State    State
	Save     func(State) error
	Host     Backend
	Identity Identity
}

func newID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

// Append saves the intent before callers may perform a disruptive action.
func (s *Session) Append(action, phase, observation string) (string, error) {
	id := newID()
	s.remember(Record{ID: id, Action: action, Phase: phase, Boot: s.Identity.Boot, Machine: s.Identity.Machine, At: time.Now().UTC().Format(time.RFC3339), Observation: observation})
	return id, s.Save(s.State)
}

func (s *Session) remember(record Record) {
	s.State.Records = append(s.State.Records, record)
	if len(s.State.Records) > 64 {
		s.State.Records = s.State.Records[len(s.State.Records)-64:]
	}
}

// Finish preserves correlation with the pre-action record.
func (s *Session) Finish(id, phase string) error {
	for i := range s.State.Records {
		if s.State.Records[i].ID == id {
			s.State.Records[i].Phase = phase
			return s.Save(s.State)
		}
	}
	return errors.New("operation record missing")
}

func pending(p string) bool { return p != "confirmed" && p != "rolled_back" && p != "external_kept" }

// Pending reports whether a transaction still needs confirmation or recovery.
func (t Transaction) Pending() bool { return pending(t.Phase) }

// KeepExternal ends only a conflicted transaction following explicit operator
// acknowledgement. It performs no network writes and makes no health claim.
func (s *Session) KeepExternal(id string) error {
	t := s.State.Network
	if t == nil || t.ID != id || t.Phase != "conflict" {
		return errors.New("no matching network conflict")
	}
	if _, _, err := s.Host.Read(); err != nil {
		return err
	}
	t.Verification = Verification{ClientAccess: "unverified"}
	return s.phase("external_kept")
}

// Stage only queues work. The worker owns applying and reverting it.
func (s *Session) Stage(candidate File) (string, error) {
	if t := s.State.Network; t != nil && pending(t.Phase) {
		return "", errors.New("a network transaction already needs resolution")
	}
	original, digest, err := s.Host.Read()
	if err != nil {
		return "", err
	}
	t := &Transaction{ID: newID(), Phase: "queued", Boot: s.Identity.Boot, Deadline: s.Identity.Uptime + 120*time.Second, Original: original, Candidate: candidate, OtherDigest: digest}
	s.State.Network = t
	s.remember(Record{ID: t.ID, Action: "network", Phase: t.Phase, Boot: s.Identity.Boot, Machine: s.Identity.Machine, At: time.Now().UTC().Format(time.RFC3339)})
	return t.ID, s.Save(s.State)
}

// Confirm requires a live test window, matching identity and unchanged files.
func (s *Session) Confirm(id string) error {
	t := s.State.Network
	if t == nil || t.ID != id || t.Phase != "testing" || t.Boot != s.Identity.Boot || s.Identity.Uptime >= t.Deadline {
		return errors.New("network confirmation is stale or unavailable")
	}
	if err := s.verifyFiles(t.Candidate, "confirm_verify"); err != nil {
		return s.recordFailure(err)
	}
	t.Verification.Files = "verified"
	t.Verification.ClientAccess = "operator_confirmed"
	return s.phase("confirmed")
}

func same(a, b File) bool {
	return a.Exists == b.Exists && a.Mode == b.Mode && bytes.Equal(a.Data, b.Data)
}
func (s *Session) matches(expected File) error {
	current, digest, err := s.Host.Read()
	if err != nil {
		return err
	}
	if digest != s.State.Network.OtherDigest || !same(current, expected) {
		return errNetworkDrift
	}
	return nil
}

// Tick must run under the durable store lock in the independent root worker.
// Interrupted apply always rolls back. A new boot never confirms old work.
func (s *Session) Tick(ctx context.Context) (result error) {
	t := s.State.Network
	if t == nil || !pending(t.Phase) || t.Phase == "conflict" {
		return nil
	}
	defer func() {
		if result != nil {
			result = s.recordFailure(result)
		}
	}()
	if err := ctx.Err(); err != nil {
		return AtStage("recovery", err)
	}
	if t.Phase == "queued" && t.Boot == s.Identity.Boot && s.Identity.Uptime < t.Deadline {
		return s.apply(ctx)
	}
	if t.Phase == "testing" && t.Boot == s.Identity.Boot && s.Identity.Uptime < t.Deadline {
		return nil
	}
	return s.rollback(ctx)
}

func (s *Session) phase(value string) error {
	previous := s.State.Network.Phase
	s.setPhase(value)
	if err := s.Save(s.State); err != nil {
		// Failure evidence must not accidentally commit the refused transition.
		s.setPhase(previous)
		return AtStage("persist_phase", err)
	}
	return nil
}

func (s *Session) setPhase(value string) {
	s.State.Network.Phase = value
	for i := range s.State.Records {
		if s.State.Records[i].ID == s.State.Network.ID {
			s.State.Records[i].Phase = value
		}
	}
}

func (s *Session) apply(ctx context.Context) error {
	if err := s.matches(s.State.Network.Original); err != nil {
		if errors.Is(err, errNetworkDrift) {
			return errors.Join(AtStage("apply_precheck", err), s.phase("conflict"))
		}
		return AtStage("apply_precheck", err)
	}
	s.State.Network.Verification = Verification{ClientAccess: "unverified"}
	if err := s.phase("applying"); err != nil {
		return err
	}
	if err := s.Host.Write(s.State.Network.Candidate); err != nil {
		return AtStage("apply_write", err)
	}
	if err := s.Host.Apply(ctx); err != nil {
		return errors.Join(s.rollback(ctx), AtStage("apply_command", err))
	}
	s.State.Network.Verification.Apply = "succeeded"
	if err := s.verifyFiles(s.State.Network.Candidate, "apply_verify"); err != nil {
		return err
	}
	return s.phase("testing")
}

func (s *Session) rollback(ctx context.Context) error {
	t := s.State.Network
	t.Verification = Verification{ClientAccess: "unverified"}
	// Either version is valid after a crash between file replacement and save.
	current, digest, err := s.Host.Read()
	if err != nil {
		return AtStage("rollback_read", err)
	}
	if digest != t.OtherDigest || (!same(current, t.Candidate) && !same(current, t.Original)) {
		t.Verification.Files = "unverified"
		return errors.Join(AtStage("rollback_precheck", errNetworkDrift), s.phase("conflict"))
	}
	if err := s.phase("rolling_back"); err != nil {
		return err
	}
	if err := s.Host.Write(t.Original); err != nil {
		return AtStage("rollback_write", err)
	}
	if err := s.Host.Apply(ctx); err != nil {
		return AtStage("rollback_command", err)
	}
	t.Verification.Apply = "succeeded"
	if err := s.verifyFiles(t.Original, "rollback_verify"); err != nil {
		return err
	}
	return s.phase("rolled_back")
}

func (s *Session) verifyFiles(expected File, stage string) error {
	if err := s.matches(expected); err != nil {
		s.State.Network.Verification.Files = "unverified"
		if errors.Is(err, errNetworkDrift) {
			return errors.Join(AtStage(stage, err), s.phase("conflict"))
		}
		return AtStage(stage, err)
	}
	s.State.Network.Verification.Files = "verified"
	return nil
}
