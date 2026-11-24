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
// and costs a wait at the next start; a state directory without the sentinel
// (first start of an agent that writes markers, after one that did not)
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
	// FirstUse: the sentinel that says "markers have been kept here" was not
	// there. An earlier agent version wrote no markers, so their absence
	// proves nothing; an "unknown" marker was written and Pending is set.
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
	// mutationSentinelName exists once the first-use marker has been written.
	mutationSentinelName = "tracking"
)

// OpenMutationLog creates <stateDir>/mutation if needed and reports whether a
// marker was left there. Call it once, at agent start, before any command. On
// error it still returns a log, with Pending set: see the body.
//
// First use is recognised by the absence of a sentinel file that is written
// only AFTER the "unknown" marker is durable. A first open that dies or fails
// anywhere before that (directory made, marker not yet written; marker written,
// sentinel not yet) is therefore a first use again at the next start, and the
// doubt cannot be lost in between.
func OpenMutationLog(stateDir string) (*MutationLog, MutationAtOpen, error) {
	dir := filepath.Join(stateDir, mutationDirName)
	m := &MutationLog{dir: dir}
	var at MutationAtOpen
	// From here on every error is returned WITH a usable log and Pending set:
	// the caller can keep running, treats the start as hazardous, and Begin
	// will refuse to run a compose command for as long as nothing can be
	// written.
	if err := os.MkdirAll(dir, dirMode); err != nil {
		at.Pending = true
		m.open = []string{mutationUnknown}
		return m, at, fmt.Errorf("journal: mkdir %s: %w", mutationDirName, err)
	}
	sentinel := filepath.Join(dir, mutationSentinelName)
	if _, err := os.Stat(sentinel); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			at.Pending = true
			m.open = []string{mutationUnknown}
			return m, at, fmt.Errorf("journal: stat %s: %w", mutationSentinelName, err)
		}
		at.FirstUse = true
	}
	onDisk := m.readMarker(&at)
	if at.FirstUse {
		at.Pending, at.OnlyUp = true, false
		if err := m.recordFirstUse(stateDir, sentinel, onDisk); err != nil {
			return m, at, err
		}
	}
	return m, at, nil
}

// recordFirstUse makes the first-use doubt durable (an "unknown" marker) and
// only then writes the sentinel that says "past first use". onDisk: a marker
// was read and understood.
func (m *MutationLog) recordFirstUse(stateDir, sentinel string, onDisk bool) error {
	// Not appended again when a failing first use is retried at every restart:
	// the marker would grow without bound.
	if !onDisk || m.open[len(m.open)-1] != mutationUnknown {
		if err := m.Begin(mutationUnknown); err != nil {
			m.mu.Lock()
			m.open = append(m.open, mutationUnknown) // in memory at least
			m.mu.Unlock()
			return err
		}
	}
	if err := fsyncDir(stateDir); err != nil {
		return err
	}
	return atomicWrite(sentinel, []byte("markers kept since first use\n"), fileMode)
}

// readMarker loads what is on disk into m.open and at. It reports whether a
// marker was read and understood (a durable list of commands is on disk).
func (m *MutationLog) readMarker(at *MutationAtOpen) bool {
	data, err := os.ReadFile(m.path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false
	case err != nil:
		// Unreadable is not "absent".
		at.Pending = true
		m.open = []string{mutationUnknown}
		return false
	}
	at.Pending = true
	var mk MutationMarker
	if json.Unmarshal(data, &mk) != nil || len(mk.Commands) == 0 {
		m.open = []string{mutationUnknown}
		return false
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
	return true
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
