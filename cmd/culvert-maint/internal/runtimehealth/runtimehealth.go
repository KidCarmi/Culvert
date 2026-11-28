// Package runtimehealth is the agent's runtime health evidence (ADR-0062
// slice 5): what the non-mutating observer last saw of the running proxy, and
// the last image that passed the production health gate while the observer
// watched it.
//
// It is the one store ADR-0062 allows beside the journal, and it is not
// lifecycle state: it belongs to no operation, and nothing here reads or
// writes a journal record or the audit log. Two files under
// <state_dir>/health/:
//
//   - latest.json: the most recent observation, overwritten by every sample
//     the observer keeps (gated, unhealthy or unknown).
//   - last_good.json: the last image the production gate passed with the
//     container and its image unchanged across the probe. Written ONLY then.
//     No other observation overwrites or clears it, so an unhealthy, unknown
//     or stale reading never erases the evidence a later recovery would rely
//     on (owner decision 5). It is the only runtime source of a trusted
//     recovery target (slice 6 reads it; nothing acts on it yet).
//
// Both are written atomically (temp, fsync, rename, fsync of the directory)
// and read with a size bound and a schema check: a file that is too large,
// malformed, or from an unknown schema is an error, never evidence.
package runtimehealth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Observed states. The observer writes gated, unhealthy or unknown; Classify
// adds ungated and stale, which describe how a sample relates to the present.
const (
	// StateGated: the production gate passed against this container and
	// image, with both unchanged across the probe.
	StateGated = "gated"
	// StateUngated: the running image has not passed the gate while the
	// observer watched it (no sample yet, or the sample is of another image).
	StateUngated = "ungated"
	// StateUnhealthy: the proxy was read and is not serving: no container, a
	// container that is not running, or a gate that failed.
	StateUnhealthy = "unhealthy"
	// StateUnknown: Docker or the probe could not be read; nothing is known.
	StateUnknown = "unknown"
	// StateStale: the latest sample is too old to describe the present.
	StateStale = "stale"
)

// GateRuntimeObserver names the gate that wrote a LastGood.
const GateRuntimeObserver = "runtime_observer"

// SchemaVersion is the version of both files. A reader refuses any other.
const SchemaVersion = 1

const (
	dirName      = "health"
	latestName   = "latest.json"
	lastGoodName = "last_good.json"
	// maxFileBytes bounds a read: both files are a few hundred bytes.
	maxFileBytes = 16 << 10
	// MaxDetail bounds the free-text probe summary kept in a sample.
	MaxDetail = 512
)

// Sample is one kept observation.
type Sample struct {
	Schema     int       `json:"schema"`
	State      string    `json:"state"`
	Reason     string    `json:"reason"`
	ObservedAt time.Time `json:"observed_at"`
	// ContainerID and ImageID identify what was observed (empty when Docker
	// showed no proxy container, or could not be read).
	ContainerID string `json:"container_id,omitempty"`
	ImageID     string `json:"image_id,omitempty"`
	// PinnedTagImageID is what the fixed tag resolved to; empty when it could
	// not be read.
	PinnedTagImageID string `json:"pinned_tag_image_id,omitempty"`
	// Detail is the probe's own summary, bounded by MaxDetail.
	Detail string `json:"detail,omitempty"`
}

// LastGood is the last image the production gate passed.
type LastGood struct {
	Schema  int    `json:"schema"`
	ImageID string `json:"image_id"`
	// Ref is a validated, allow-listed `<proxy_repo>@sha256:<64hex>` reference
	// of the image, and Digest its bare `sha256:<64hex>`. A gated image with
	// no such reference is never recorded here: nothing could resolve it.
	Ref         string    `json:"ref"`
	Digest      string    `json:"digest"`
	ContainerID string    `json:"container_id"`
	PassedAt    time.Time `json:"passed_at"`
	Gate        string    `json:"gate"`
	GateDetail  string    `json:"gate_detail,omitempty"`
}

var (
	imageIDRE   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	digestRE    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	containerRE = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
	reasonRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Store reads and writes the two files under <state_dir>/health.
type Store struct{ dir string }

// Open creates <state_dir>/health (0750) and returns its store.
func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("runtimehealth: state_dir required")
	}
	dir := filepath.Join(stateDir, dirName)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("runtimehealth: mkdir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir is the store's directory.
func (s *Store) Dir() string { return s.dir }

// WriteLatest replaces latest.json with smp.
func (s *Store) WriteLatest(smp Sample) error {
	smp.Schema = SchemaVersion
	smp.Detail = Bound(smp.Detail)
	if err := validSample(&smp); err != nil {
		return err
	}
	return s.write(latestName, smp)
}

// WriteLastGood replaces last_good.json with lg. Only a gate that passed with
// identity unchanged may call it (the observer); every field is checked.
func (s *Store) WriteLastGood(lg LastGood) error {
	lg.Schema = SchemaVersion
	lg.GateDetail = Bound(lg.GateDetail)
	if err := validLastGood(&lg); err != nil {
		return err
	}
	return s.write(lastGoodName, lg)
}

// ReadLatest returns the latest sample, or nil when there is none.
func (s *Store) ReadLatest() (*Sample, error) {
	var smp Sample
	ok, err := s.read(latestName, &smp)
	if err != nil || !ok {
		return nil, err
	}
	if smp.Schema != SchemaVersion {
		return nil, fmt.Errorf("runtimehealth: %s has schema %d, this agent reads %d", latestName, smp.Schema, SchemaVersion)
	}
	if err := validSample(&smp); err != nil {
		return nil, err
	}
	return &smp, nil
}

// ReadLastGood returns the last-known-good record, or nil when there is none.
func (s *Store) ReadLastGood() (*LastGood, error) {
	var lg LastGood
	ok, err := s.read(lastGoodName, &lg)
	if err != nil || !ok {
		return nil, err
	}
	if lg.Schema != SchemaVersion {
		return nil, fmt.Errorf("runtimehealth: %s has schema %d, this agent reads %d", lastGoodName, lg.Schema, SchemaVersion)
	}
	if err := validLastGood(&lg); err != nil {
		return nil, err
	}
	return &lg, nil
}

// Classify says what a sample means now. runningImageID is the image the
// running proxy container is on, as the caller just read it ("" when unknown
// or when nothing runs). staleAfter is how old a sample may be.
//
//   - no sample: ungated when something runs, unknown otherwise;
//   - a sample older than staleAfter, or dated in the future beyond it: stale;
//   - a sample of another image than the one running: ungated;
//   - otherwise the sample's own state.
func Classify(smp *Sample, runningImageID string, now time.Time, staleAfter time.Duration) (state, reason string) {
	switch {
	case smp == nil && runningImageID != "":
		return StateUngated, "not_observed_yet"
	case smp == nil:
		return StateUnknown, "not_observed_yet"
	case now.Sub(smp.ObservedAt) > staleAfter || smp.ObservedAt.Sub(now) > staleAfter:
		return StateStale, "observation_too_old"
	case runningImageID != "" && smp.ImageID != runningImageID:
		return StateUngated, "running_image_not_observed"
	}
	return smp.State, smp.Reason
}

// Bound truncates free text to MaxDetail bytes on a rune boundary and drops
// control characters.
func Bound(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= MaxDetail {
		return s
	}
	cut := MaxDetail
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func validSample(smp *Sample) error {
	switch smp.State {
	case StateGated, StateUnhealthy, StateUnknown:
	default:
		return fmt.Errorf("runtimehealth: sample state %q is not one the observer writes", smp.State)
	}
	if !reasonRE.MatchString(smp.Reason) {
		return fmt.Errorf("runtimehealth: sample reason %q is malformed", smp.Reason)
	}
	if smp.ObservedAt.IsZero() {
		return errors.New("runtimehealth: sample has no observed_at")
	}
	if err := optional(imageIDRE, "image_id", smp.ImageID); err != nil {
		return err
	}
	if err := optional(imageIDRE, "pinned_tag_image_id", smp.PinnedTagImageID); err != nil {
		return err
	}
	if err := optional(containerRE, "container_id", smp.ContainerID); err != nil {
		return err
	}
	if smp.State == StateGated && (smp.ImageID == "" || smp.ContainerID == "") {
		return errors.New("runtimehealth: a gated sample must name its container and image")
	}
	return nil
}

func validLastGood(lg *LastGood) error {
	switch {
	case !imageIDRE.MatchString(lg.ImageID):
		return fmt.Errorf("runtimehealth: last_good image_id %q is malformed", lg.ImageID)
	case !digestRE.MatchString(lg.Digest):
		return fmt.Errorf("runtimehealth: last_good digest %q is malformed", lg.Digest)
	case !strings.HasSuffix(lg.Ref, "@"+lg.Digest):
		return fmt.Errorf("runtimehealth: last_good ref %q does not carry its digest %q", lg.Ref, lg.Digest)
	case !containerRE.MatchString(lg.ContainerID):
		return fmt.Errorf("runtimehealth: last_good container_id %q is malformed", lg.ContainerID)
	case lg.PassedAt.IsZero():
		return errors.New("runtimehealth: last_good has no passed_at")
	case lg.Gate != GateRuntimeObserver:
		return fmt.Errorf("runtimehealth: last_good gate %q is unknown", lg.Gate)
	}
	return nil
}

func optional(re *regexp.Regexp, name, v string) error {
	if v != "" && !re.MatchString(v) {
		return fmt.Errorf("runtimehealth: %s %q is malformed", name, v)
	}
	return nil
}

func (s *Store) write(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("runtimehealth: encode %s: %w", name, err)
	}
	data = append(data, '\n')
	return atomicWrite(filepath.Join(s.dir, name), data, 0o640)
}

// read decodes name into v. ok is false when the file does not exist.
func (s *Store) read(name string, v any) (ok bool, err error) {
	f, err := os.Open(filepath.Join(s.dir, name)) // #nosec G304 -- fixed name in the agent-owned state directory
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("runtimehealth: open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return false, fmt.Errorf("runtimehealth: read %s: %w", name, err)
	}
	if len(data) > maxFileBytes {
		return false, fmt.Errorf("runtimehealth: %s is larger than %d bytes", name, maxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return false, fmt.Errorf("runtimehealth: decode %s: %w", name, err)
	}
	return true, nil
}

// atomicWrite writes data to path via a temp file in the same directory, then
// chmod, fsync(file), rename, fsync(directory). Same sequence as the journal's.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".health-*.tmp")
	if err != nil {
		return fmt.Errorf("runtimehealth: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("runtimehealth: write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("runtimehealth: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("runtimehealth: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("runtimehealth: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("runtimehealth: rename: %w", err)
	}
	d, err := os.Open(dir) // #nosec G304 -- the agent-owned health directory
	if err != nil {
		return fmt.Errorf("runtimehealth: open dir for fsync: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("runtimehealth: fsync dir: %w", err)
	}
	return nil
}
