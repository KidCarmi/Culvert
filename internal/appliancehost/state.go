// Package appliancehost owns durable local recovery transactions. It exposes no
// network service and does not manage application containers or credentials.
package appliancehost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Identity captures monotonic time within a particular kernel boot.
type Identity struct {
	Boot, Machine string
	Uptime        time.Duration
}

// Record is bounded, allowlisted evidence, not a transcript or security attestation.
type Record struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Phase       string `json:"phase"`
	Boot        string `json:"boot"`
	Machine     string `json:"machine"`
	At          string `json:"at"`
	Observation string `json:"observation,omitempty"`
}

// File preserves absence, content and permissions for exact rollback.
type File struct {
	Data   []byte `json:"data"`
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode"`
}

// Transaction retains the original configuration even after a failed rollback.
type Transaction struct {
	ID          string        `json:"id"`
	Phase       string        `json:"phase"`
	Boot        string        `json:"boot"`
	Deadline    time.Duration `json:"deadline"`
	Original    File          `json:"original"`
	Candidate   File          `json:"candidate"`
	OtherDigest string        `json:"other_digest"`
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

func pending(p string) bool { return p != "confirmed" && p != "rolled_back" }

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
	if err := s.matches(t.Candidate); err != nil {
		return err
	}
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
		return errors.New("network configuration changed outside the transaction")
	}
	return nil
}

// Tick must run under the durable store lock in the independent root worker.
// Interrupted apply always rolls back. A new boot never confirms old work.
func (s *Session) Tick(ctx context.Context) error {
	t := s.State.Network
	if t == nil || !pending(t.Phase) || t.Phase == "conflict" {
		return nil
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
	s.State.Network.Phase = value
	for i := range s.State.Records {
		if s.State.Records[i].ID == s.State.Network.ID {
			s.State.Records[i].Phase = value
		}
	}
	return s.Save(s.State)
}

func (s *Session) apply(ctx context.Context) error {
	if err := s.matches(s.State.Network.Original); err != nil {
		return errors.Join(err, s.phase("conflict"))
	}
	if err := s.phase("applying"); err != nil {
		return err
	}
	if err := s.Host.Write(s.State.Network.Candidate); err != nil {
		return fmt.Errorf("stage network file: %w", err)
	}
	if err := s.Host.Apply(ctx); err != nil {
		return errors.Join(err, s.rollback(ctx))
	}
	return s.phase("testing")
}

func (s *Session) rollback(ctx context.Context) error {
	t := s.State.Network
	// Either version is valid after a crash between file replacement and save.
	current, digest, err := s.Host.Read()
	if err != nil {
		return err
	}
	if digest != t.OtherDigest || (!same(current, t.Candidate) && !same(current, t.Original)) {
		return errors.Join(errors.New("rollback conflict; preserved backup requires recovery"), s.phase("conflict"))
	}
	if err := s.phase("rolling_back"); err != nil {
		return err
	}
	if err := s.Host.Write(t.Original); err != nil {
		return err
	}
	if err := s.Host.Apply(ctx); err != nil {
		return err
	}
	return s.phase("rolled_back")
}
