// Package dataepoch is the data-compatibility contract between proxy builds
// (ADR-0062 slice 6a, contract UPG-003).
//
// A data epoch is a whole number that changes only when a release migrates
// persisted state under /data into a form an older build cannot read. Two
// facts are compared before any older image is put back on this data:
//
//   - the data directory's epoch: the marker file <dataDir>/.data-epoch,
//     which only ever rises. A build raises it to its own Current before it
//     writes anything in the newer form, and never lowers it. An absent
//     marker means epoch 1: only builds released before this package existed
//     have written the data, and every one of them reads and writes epoch 1.
//   - the epochs an image reads: the labels io.culvert.data-epoch.min and
//     io.culvert.data-epoch.max on the image, which are this package's
//     OldestReadable and Current (Dockerfile; a drift test keeps them equal).
//
// An image may run on data whose epoch lies in [min, max]. An image without
// the labels says nothing, and nothing may assume it can read the data.
//
// Bumping Current is a release decision with obligations recorded in
// docs/engineering/data-epoch.md; a tripwire test in the root package fails
// while they are not met.
package dataepoch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const (
	// Current is the epoch this build writes.
	Current = 1
	// OldestReadable is the oldest epoch this build reads.
	OldestReadable = 1

	// MarkerName is the marker's file name under the data directory.
	MarkerName = ".data-epoch"
	// LabelMin is the image label naming the oldest epoch the image reads.
	LabelMin = "io.culvert.data-epoch.min"
	// LabelMax is the image label naming the newest epoch the image reads.
	LabelMax = "io.culvert.data-epoch.max"

	// ImplicitEpoch is the epoch of a data directory with no marker.
	ImplicitEpoch = 1

	markerSchema = 1
	maxMarker    = 4 << 10
)

// Marker is the on-disk marker.
type Marker struct {
	Schema int `json:"schema"`
	Epoch  int `json:"epoch"`
}

// Reading is what Read found.
type Reading struct {
	Epoch int
	// Present is false when there is no marker (Epoch is then ImplicitEpoch).
	Present bool
}

// Read returns the data directory's epoch. A marker that cannot be read, is
// too large, is not exactly the expected JSON, or names an epoch below 1 is
// an error: it is never taken for an absent marker.
func Read(dataDir string) (Reading, error) {
	// A missing data directory (an interrupted restore renamed it aside) says
	// nothing about the data: only an existing directory without a marker is
	// the implicit epoch.
	if di, err := os.Stat(dataDir); err != nil || !di.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return Reading{}, fmt.Errorf("data directory %q: %w", dataDir, err)
	}
	path := filepath.Join(dataDir, MarkerName)
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Reading{Epoch: ImplicitEpoch}, nil
	}
	if err != nil {
		return Reading{}, fmt.Errorf("data epoch marker: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Reading{}, fmt.Errorf("data epoch marker %q is not a regular file", path)
	}
	f, err := os.Open(path) // #nosec G304 -- fixed name under the configured data directory
	if err != nil {
		return Reading{}, fmt.Errorf("data epoch marker: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxMarker+1))
	if err != nil {
		return Reading{}, fmt.Errorf("data epoch marker: %w", err)
	}
	if len(data) > maxMarker {
		return Reading{}, fmt.Errorf("data epoch marker is larger than %d bytes", maxMarker)
	}
	var m Marker
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Reading{}, fmt.Errorf("data epoch marker: %w", err)
	}
	// Exactly one JSON value: trailing bytes or a second object make the
	// marker malformed, never the first object's epoch.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Reading{}, errors.New("data epoch marker: trailing data after the marker object")
	}
	if m.Schema != markerSchema {
		return Reading{}, fmt.Errorf("data epoch marker has schema %d, this build reads %d", m.Schema, markerSchema)
	}
	if m.Epoch < 1 {
		return Reading{}, fmt.Errorf("data epoch marker names epoch %d", m.Epoch)
	}
	return Reading{Epoch: m.Epoch, Present: true}, nil
}

// Outcome of RaiseTo.
type Outcome int

const (
	// Unchanged means the data was already at the epoch (or the marker is absent
	// and the epoch is the implicit one), so nothing was written.
	Unchanged Outcome = iota
	// Raised means the marker now names the epoch.
	Raised
	// Newer means the data is at a higher epoch than asked; nothing was written.
	Newer
)

// RaiseTo makes the marker name at least epoch and never lowers it. It writes
// only when the data is below epoch (an absent marker counts as the implicit
// epoch, so a build at epoch 1 never writes). An unreadable marker is an
// error and is left as it is.
func RaiseTo(dataDir string, epoch int) (Outcome, Reading, error) {
	cur, err := Read(dataDir)
	if err != nil {
		return Unchanged, Reading{}, err
	}
	switch {
	case cur.Epoch > epoch:
		return Newer, cur, nil
	case cur.Epoch == epoch:
		return Unchanged, cur, nil
	}
	data, err := json.Marshal(Marker{Schema: markerSchema, Epoch: epoch})
	if err != nil {
		return Unchanged, cur, err
	}
	if err := fileutil.AtomicWrite(filepath.Join(dataDir, MarkerName), append(data, '\n'), 0o640); err != nil {
		return Unchanged, cur, fmt.Errorf("data epoch marker: %w", err)
	}
	return Raised, Reading{Epoch: epoch, Present: true}, nil
}

// Report is what `culvert --print-data-epoch` prints: the data directory's
// epoch and the range this build reads.
type Report struct {
	Schema        int  `json:"schema"`
	Epoch         int  `json:"epoch"`
	MarkerPresent bool `json:"marker_present"`
	BuildMin      int  `json:"build_min"`
	BuildMax      int  `json:"build_max"`
}

// ReportFor builds the Report for dataDir.
func ReportFor(dataDir string) (Report, error) {
	r, err := Read(dataDir)
	if err != nil {
		return Report{}, err
	}
	return Report{Schema: 1, Epoch: r.Epoch, MarkerPresent: r.Present, BuildMin: OldestReadable, BuildMax: Current}, nil
}
