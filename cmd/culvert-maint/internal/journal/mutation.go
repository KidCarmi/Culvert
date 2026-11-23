package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// MutationLog keeps the mutation marker: a durable note that a docker command
// which can stop the proxy container (`compose up`, `compose down`) is in
// flight.
//
// It is written and fsynced BEFORE the command starts and removed only after
// the command has returned success. So at the next agent start:
//
//   - no marker: the previous agent process had no such command in flight when
//     it ended. Nothing is left in dockerd for it to finish.
//   - marker: the command was cut (the agent died, or the command ended in an
//     error and may have been killed after it sent its request). dockerd may
//     still be carrying out a container stop.
//
// The marker is deliberately not part of an operation record: restores and
// data rollbacks run `compose down` without an image-change record, and the
// marker must cover every such command by construction.
//
// Every failure errs towards "marker present": a marker that cannot be
// written stops the command from being run; one that cannot be removed stays
// and costs a wait at the next start; a marker directory that did not exist
// yet (first start of an agent that writes markers, after one that did not)
// is reported as FirstUse so the caller assumes the worst once.
type MutationLog struct {
	dir string
}

// MutationMarker is the marker's content. Diagnostics only: nothing decides on
// its fields, only on its presence.
type MutationMarker struct {
	Command   string    `json:"command"`
	StartedAt time.Time `json:"started_at"`
}

// MutationAtOpen is what OpenMutationLog found.
type MutationAtOpen struct {
	// Pending: a marker was there (or could not be ruled out).
	Pending bool
	// FirstUse: the marker directory did not exist. An earlier agent version
	// wrote no markers, so their absence proves nothing this once.
	FirstUse bool
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
	if _, err := os.Stat(m.path()); err == nil || !errors.Is(err, fs.ErrNotExist) {
		// Present, or unreadable: unreadable is not "absent".
		at.Pending = true
	}
	return m, at, nil
}

func (m *MutationLog) path() string { return filepath.Join(m.dir, mutationFileName) }

// Begin writes the marker durably. An error means the command must not be run.
func (m *MutationLog) Begin(command string) error {
	data, err := json.Marshal(MutationMarker{Command: command, StartedAt: time.Now().UTC()})
	if err != nil {
		return fmt.Errorf("journal: marshal mutation marker: %w", err)
	}
	return atomicWrite(m.path(), data, fileMode)
}

// End removes the marker durably. Call it only when the command returned
// success. An error leaves the marker (or its durability) in doubt, which is
// the safe direction; the caller may log it and carry on.
func (m *MutationLog) End() error {
	if err := os.Remove(m.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("journal: remove mutation marker: %w", err)
	}
	return fsyncDir(m.dir)
}
