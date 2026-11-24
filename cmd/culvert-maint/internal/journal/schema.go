package journal

// Schema versioning, lossless rewrite and the downgrade fence (ADR-0062,
// slice 2).
//
// A record is rewritten in place by every agent start (main.go
// reportInterrupted), by phase advances and by the startup reconcile. Before
// this file, encoding/json silently dropped any key the running agent did
// not know, so an older agent downgraded the evidence a newer one wrote
// (rollback_armed, restore_stage, reconcile_*), and nothing detected it.
//
// Three rules close that:
//
//  1. Lossless rewrite. Keys this build does not know are carried through
//     every Read → Write cycle unchanged (Record.extra).
//  2. A record from a newer schema is never rewritten or removed by this
//     build (Write and Remove refuse it with ErrNewerSchema). Every caller
//     that acts on a record writes or removes it, fail-closed, before or
//     instead of a Docker change, so refusing here means the record is
//     reported and never acted on.
//  3. The downgrade fence. Agents released before this file cannot be
//     taught rule 2. What they already do is refuse to serve when the
//     journal holds a record with an unknown phase (Read → ErrCorruptRecord,
//     List fails closed, main.go initJournal stops). While any record relies
//     on a field such an agent would drop or misread (Schema >= SchemaFenced),
//     the journal therefore also holds a fence record whose phase no older
//     agent knows. An older agent started on this state directory stops
//     instead of acting on a record it cannot fully read. This build skips
//     the fence by name.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	// SchemaCurrent is the record schema this build reads and writes. An
	// absent "schema" key is schema 1, the format of every agent before it.
	SchemaCurrent = 2
	// SchemaFenced is the first schema whose records an agent without the
	// newer-schema rules must not touch. A record that sets Schema to at
	// least this value is written only after the fence is durable.
	SchemaFenced = 2

	// fenceOpID is the fence record's file name: a valid ULID (timestamp 0)
	// no real operation can have, so an older agent's strict-ULID name check
	// accepts the file and goes on to read it.
	fenceOpID = "00000000000000000000000000"
	// PhaseSchemaFence is the fence record's phase. It is deliberately NOT in
	// validPhases: an agent that reads it through Read fails closed.
	PhaseSchemaFence Phase = "schema_fence"
	// fenceMode is read-only: the fence is created and removed, never edited.
	fenceMode = 0o440
)

// ErrNewerSchema is returned by Write and Remove for a record written by a
// newer agent: this build reports it and never rewrites or removes it.
var ErrNewerSchema = errors.New("journal: record was written by a newer agent")

// EffectiveSchema is the record's schema, with an absent key read as 1.
func (r *Record) EffectiveSchema() int {
	if r.Schema <= 0 {
		return 1
	}
	return r.Schema
}

// FromNewerAgent reports whether this build must treat r as read-only.
func (r *Record) FromNewerAgent() bool { return r.EffectiveSchema() > SchemaCurrent }

// recordAlias has Record's fields without its methods, so the custom
// (un)marshalers below can use the default encoding without recursing.
type recordAlias Record

// knownKeys is the set of JSON keys Record declares; anything else in a file
// is a key from another build and is carried through as-is.
var knownKeys = sync.OnceValue(func() map[string]struct{} {
	out := map[string]struct{}{}
	t := reflect.TypeOf(recordAlias{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
})

// UnmarshalJSON decodes the declared fields and keeps every other key.
func (r *Record) UnmarshalJSON(b []byte) error {
	var a recordAlias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	known := knownKeys()
	for k := range raw {
		if _, ok := known[k]; ok {
			delete(raw, k)
		}
	}
	*r = Record(a)
	if len(raw) > 0 {
		r.extra = raw
	}
	return nil
}

// MarshalJSON encodes the declared fields and, if the record was read with
// keys this build does not know, those keys unchanged. A record without such
// keys encodes exactly as it did before this method existed.
func (r Record) MarshalJSON() ([]byte, error) {
	a := recordAlias(r)
	if a.restoreStageRaw != "" && a.RestoreStage == RestoreStageUnknown {
		a.RestoreStage = RestoreStage(a.restoreStageRaw)
	}
	if len(r.extra) == 0 {
		return json.Marshal(a)
	}
	base, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range r.extra {
		if _, clash := merged[k]; !clash {
			merged[k] = v
		}
	}
	return json.Marshal(merged)
}

// fenceRecord is what an older agent decodes from the fence file. It has the
// fields Read checks before the phase, so the only thing that stops an older
// agent is the phase itself.
type fenceRecord struct {
	OpID      string    `json:"op_id"`
	Kind      string    `json:"kind"`
	Phase     Phase     `json:"phase"`
	Schema    int       `json:"schema"`
	Reason    string    `json:"reason"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (j *Journal) fencePath() string { return filepath.Join(j.dir, fenceOpID+fileExt) }

// FenceActive reports whether the downgrade fence is present.
func (j *Journal) FenceActive() (bool, error) {
	_, err := os.Stat(j.fencePath())
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("journal: stat fence: %w", err)
	}
}

// ensureFence writes the fence if it is absent. Fail-closed: the caller does
// not write a fenced record unless the fence is durable.
func (j *Journal) ensureFence() error {
	if on, err := j.FenceActive(); err != nil || on {
		return err
	}
	now := time.Now().UTC()
	data, err := json.MarshalIndent(fenceRecord{
		OpID: fenceOpID, Kind: "journal.schema_fence", Phase: PhaseSchemaFence, Schema: SchemaFenced,
		Reason: "records in this directory need a maintenance agent that understands journal schema " +
			fmt.Sprint(SchemaFenced) + "; an older agent must not act on them (ADR-0062)",
		StartedAt: now, UpdatedAt: now,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("journal: marshal fence: %w", err)
	}
	return atomicWrite(j.fencePath(), data, fenceMode)
}

// releaseFenceIfUnused removes the fence once no remaining record needs it.
// A record that cannot be read keeps the fence (fail closed).
func (j *Journal) releaseFenceIfUnused() error {
	on, err := j.FenceActive()
	if err != nil || !on {
		return err
	}
	recs, err := j.List()
	if err != nil {
		return nil // keep the fence: what is left cannot be judged
	}
	for i := range recs {
		if recs[i].EffectiveSchema() >= SchemaFenced {
			return nil
		}
	}
	if rerr := os.Remove(j.fencePath()); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("journal: remove fence: %w", rerr)
	}
	return fsyncDir(j.dir)
}
