// Provenance and gated history (ADR-0062 slice 6, PR 1; owner decision
// 2026-11-28: runtime recovery acts only on images this agent installed).
//
// Two more files under <state_dir>/health/, data only — nothing acts on them
// in this change:
//
//   - installed.json: the image the agent's last verified upgrade installed,
//     and the image it replaced. Written by that upgrade once its health gate
//     and digest verify passed. It describes the running image only while the
//     running image is still that one; a reader must compare.
//   - gated.json: the last two distinct images the runtime observer gated
//     (newest first). last_good.json stays the newest entry's twin.
//
// Absent or unreadable means "no provenance", which a runtime recovery must
// treat as a reason not to act.
package runtimehealth

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	installedName = "installed.json"
	gatedName     = "gated.json"
	// GatedHistoryLen is how many distinct gated images gated.json keeps.
	GatedHistoryLen = 2
)

// Installed is the provenance of the image the agent installed last.
type Installed struct {
	Schema int    `json:"schema"`
	OpID   string `json:"op_id"`
	Kind   string `json:"kind"`
	// ImageID, Ref and Digest are the installed image; Ref is a validated
	// repo-bound digest reference ending in Digest.
	ImageID string `json:"image_id"`
	Ref     string `json:"ref"`
	Digest  string `json:"digest"`
	// ReplacedImageID and ReplacedRef are the image the upgrade replaced.
	// ReplacedRef is empty when the upgrade had no validated reference for it
	// (it could not be restored then).
	ReplacedImageID string    `json:"replaced_image_id"`
	ReplacedRef     string    `json:"replaced_ref,omitempty"`
	InstalledAt     time.Time `json:"installed_at"`
}

// GatedEntry is one gated image.
type GatedEntry struct {
	ImageID string    `json:"image_id"`
	Ref     string    `json:"ref"`
	Digest  string    `json:"digest"`
	GatedAt time.Time `json:"gated_at"`
}

// GatedHistory is the last GatedHistoryLen distinct gated images, newest first.
type GatedHistory struct {
	Schema  int          `json:"schema"`
	Entries []GatedEntry `json:"entries"`
}

// WriteInstalled replaces installed.json.
func (s *Store) WriteInstalled(in Installed) error {
	in.Schema = SchemaVersion
	if err := validInstalled(&in); err != nil {
		return err
	}
	return s.write(installedName, in)
}

// ReadInstalled returns the provenance record, or nil when there is none.
func (s *Store) ReadInstalled() (*Installed, error) {
	var in Installed
	ok, err := s.read(installedName, &in)
	if err != nil || !ok {
		return nil, err
	}
	if in.Schema != SchemaVersion {
		return nil, fmt.Errorf("runtimehealth: %s has schema %d, this agent reads %d", installedName, in.Schema, SchemaVersion)
	}
	if err := validInstalled(&in); err != nil {
		return nil, err
	}
	return &in, nil
}

// NoteGated puts e at the head of gated.json: an image already in the history
// moves to the front with its new time; the history keeps GatedHistoryLen
// distinct images. An unreadable history is replaced by one holding e alone.
func (s *Store) NoteGated(e GatedEntry) error {
	if err := validGatedEntry(&e); err != nil {
		return err
	}
	h, err := s.ReadGated()
	if err != nil || h == nil {
		h = &GatedHistory{}
	}
	out := []GatedEntry{e}
	for _, old := range h.Entries {
		if old.ImageID != e.ImageID && len(out) < GatedHistoryLen {
			out = append(out, old)
		}
	}
	return s.write(gatedName, GatedHistory{Schema: SchemaVersion, Entries: out})
}

// ReadGated returns the gated history, or nil when there is none.
func (s *Store) ReadGated() (*GatedHistory, error) {
	var h GatedHistory
	ok, err := s.read(gatedName, &h)
	if err != nil || !ok {
		return nil, err
	}
	if h.Schema != SchemaVersion {
		return nil, fmt.Errorf("runtimehealth: %s has schema %d, this agent reads %d", gatedName, h.Schema, SchemaVersion)
	}
	if len(h.Entries) == 0 || len(h.Entries) > GatedHistoryLen {
		return nil, fmt.Errorf("runtimehealth: %s holds %d entries", gatedName, len(h.Entries))
	}
	seen := map[string]bool{}
	for i := range h.Entries {
		if err := validGatedEntry(&h.Entries[i]); err != nil {
			return nil, err
		}
		if seen[h.Entries[i].ImageID] {
			return nil, fmt.Errorf("runtimehealth: %s repeats an image", gatedName)
		}
		seen[h.Entries[i].ImageID] = true
	}
	return &h, nil
}

// Contains reports whether imageID is in the history.
func (h *GatedHistory) Contains(imageID string) bool {
	if h == nil {
		return false
	}
	for _, e := range h.Entries {
		if e.ImageID == imageID {
			return true
		}
	}
	return false
}

func validInstalled(in *Installed) error {
	switch {
	case in.OpID == "" || len(in.OpID) > 64 || strings.ContainsAny(in.OpID, "/\\\n\r\t "):
		return fmt.Errorf("runtimehealth: installed op_id %q is malformed", in.OpID)
	case in.Kind != "upgrades.apply":
		return fmt.Errorf("runtimehealth: installed kind %q is not one this agent records", in.Kind)
	case !imageIDRE.MatchString(in.ImageID):
		return fmt.Errorf("runtimehealth: installed image_id %q is malformed", in.ImageID)
	case !refCarries(in.Ref, in.Digest):
		return fmt.Errorf("runtimehealth: installed ref %q does not carry its digest %q", in.Ref, in.Digest)
	case !imageIDRE.MatchString(in.ReplacedImageID):
		return fmt.Errorf("runtimehealth: installed replaced_image_id %q is malformed", in.ReplacedImageID)
	case in.ReplacedImageID == in.ImageID:
		return errors.New("runtimehealth: installed replaced its own image")
	case in.ReplacedRef != "" && !strings.Contains(in.ReplacedRef, "@sha256:"):
		return fmt.Errorf("runtimehealth: installed replaced_ref %q is not a digest reference", in.ReplacedRef)
	case in.InstalledAt.IsZero():
		return errors.New("runtimehealth: installed has no installed_at")
	}
	return nil
}

func validGatedEntry(e *GatedEntry) error {
	switch {
	case !imageIDRE.MatchString(e.ImageID):
		return fmt.Errorf("runtimehealth: gated image_id %q is malformed", e.ImageID)
	case !refCarries(e.Ref, e.Digest):
		return fmt.Errorf("runtimehealth: gated ref %q does not carry its digest %q", e.Ref, e.Digest)
	case e.GatedAt.IsZero():
		return errors.New("runtimehealth: gated entry has no gated_at")
	}
	return nil
}

func refCarries(ref, digest string) bool {
	return digestRE.MatchString(digest) && strings.HasSuffix(ref, "@"+digest) && len(ref) > len(digest)+1
}
