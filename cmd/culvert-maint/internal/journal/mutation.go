package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MutationLog keeps the mutation marker: a durable note that a docker command
// which can stop the proxy container (`compose up`, `compose down`) is in
// flight.
//
// It is written and fsynced BEFORE the command starts and removed only when
// the caller says the command, and every one before it since the last removal,
// is known to be over (End). So at the next agent start:
//
//   - no marker: every such command any earlier process ran returned success
//     with nothing before it in doubt. Nothing is left in dockerd to finish.
//   - marker: a command was cut (the agent died, or the command ended in an
//     error and may have been killed after it sent its request), or succeeded
//     while an earlier one was still in doubt. dockerd may still be carrying
//     out a container stop.
//
// The marker is deliberately not part of an operation record: restores and
// data rollbacks run `compose down` without an image-change record, and the
// marker must cover every such command by construction.
//
// Every failure errs towards "marker present": a marker that cannot be
// written stops the command from being run; one that cannot be removed stays
// and costs a wait at the next start; a marker directory that did not exist
// yet (first start of an agent that writes markers, after one that did not)
// gets an "unknown" marker written at once, so the worst is assumed until a
// command clears it, however many starts that takes.
type MutationLog struct {
	dir string

	mu sync.Mutex
	// open is every command begun since the marker was last removed,
	// including what was found on disk at open. The marker names all of them:
	// a later command must not make an earlier, unfinished one look milder.
	open []string
}

// The commands a marker can name.
const (
	MutationComposeUp   = "compose up"
	MutationComposeDown = "compose down"
	mutationUnknown     = "unknown"
)

// MutationMarker is the marker's content.
type MutationMarker struct {
	Commands  []string  `json:"commands"`
	StartedAt time.Time `json:"started_at"`
}

// MutationAtOpen is what OpenMutationLog found.
type MutationAtOpen struct {
	// Pending: a marker was there (or could not be ruled out).
	Pending bool
	// FirstUse: the marker directory did not exist. An earlier agent version
	// wrote no markers, so their absence proves nothing; an "unknown" marker
	// was written and Pending is set.
	FirstUse bool
	// NamesCommand: a readable marker was there and names at least one compose
	// command (not just the first-use "unknown").
	NamesCommand bool
	// OnlyUp: a marker was there, was readable, and names nothing but
	// `compose up`. Anything else (a `compose down`, an unreadable or empty
	// marker) is false.
	OnlyUp bool
}

const (
	mutationDirName  = "mutation"
	mutationFileName = "pending.json"
)

// OpenMutationLog creates <stateDir>/mutation if needed and reports whether a
// marker was left there. Call it once, at agent start, before any command.
func OpenMutationLog(stateDir string) (*MutationLog, MutationAtOpen, error) {
	dir := filepath.Join(stateDir, mutationDirName)
	var at MutationAtOpen
	if _, err := os.Stat(dir); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, at, fmt.Errorf("journal: stat %s: %w", mutationDirName, err)
		}
		at.FirstUse = true
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return nil, at, fmt.Errorf("journal: mkdir %s: %w", mutationDirName, err)
		}
		if err := fsyncDir(stateDir); err != nil {
			return nil, at, err
		}
	}
	m := &MutationLog{dir: dir}
	if at.FirstUse {
		// Make the doubt durable: an "unknown" marker, so that a second start
		// inside the window (or a start after this one failed half-way) still
		// finds it. It is removed like any other marker.
		at.Pending = true
		if err := m.Begin(mutationUnknown); err != nil {
			return nil, at, err
		}
		return m, at, nil
	}
	data, err := os.ReadFile(m.path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return m, at, nil
	case err != nil:
		// Unreadable is not "absent".
		at.Pending = true
		m.open = []string{mutationUnknown}
		return m, at, nil
	}
	at.Pending = true
	var mk MutationMarker
	if json.Unmarshal(data, &mk) != nil || len(mk.Commands) == 0 {
		m.open = []string{mutationUnknown}
		return m, at, nil
	}
	m.open = mk.Commands
	at.OnlyUp = true
	for _, c := range mk.Commands {
		if c != MutationComposeUp {
			at.OnlyUp = false
		}
		if c == MutationComposeUp || c == MutationComposeDown {
			at.NamesCommand = true
		}
	}
	return m, at, nil
}

func (m *MutationLog) path() string { return filepath.Join(m.dir, mutationFileName) }

// Pending reports whether a marker is in place now: one was found at open or
// written by Begin, and End has not removed it since.
func (m *MutationLog) Pending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.open) > 0
}

// Begin writes the marker durably, naming command and every command begun
// since the marker was last removed. An error means the command must not be
// run.
func (m *MutationLog) Begin(command string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmds := append(append([]string(nil), m.open...), command)
	data, err := json.Marshal(MutationMarker{Commands: cmds, StartedAt: time.Now().UTC()})
	if err != nil {
		return fmt.Errorf("journal: marshal mutation marker: %w", err)
	}
	if err := atomicWrite(m.path(), data, fileMode); err != nil {
		return err
	}
	m.open = cmds
	return nil
}

// End removes the marker durably. Call it only when the command returned
// success AND nothing begun before it can still be pending in dockerd. An
// error leaves the marker (or its durability) in doubt, which is the safe
// direction; the caller may log it and carry on.
func (m *MutationLog) End() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.Remove(m.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("journal: remove mutation marker: %w", err)
	}
	if err := fsyncDir(m.dir); err != nil {
		return err
	}
	m.open = nil
	return nil
}
