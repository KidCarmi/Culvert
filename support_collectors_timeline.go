package main

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M3 operational-timeline collector. A single chronologically-ordered view that
// STITCHES already-collected, already-redaction-modeled lifecycle events into one
// bounded index, so support can see "what happened when" without cross-referencing
// three separate sections. It reads ONLY side-effect-free accessors that other
// collectors already use — the last recovered crash and the config-version audit
// trail — so it adds no new data surface and no network or mutation.
//
// It is deliberately a lightweight index, not a payload: the crash section still
// owns the masked panic summary/stack; here a crash contributes a single dated row.
// Ordering uses each source's OWN timestamp (crash TS millis; config-version
// created_at parsed as RFC3339) — never a wall-clock read — so the section is
// deterministic and safe under the no-Date-in-collectors discipline.

const supportMaxTimelineEvents = 200 // defensive cap; sources are already bounded (1 crash, ≤50 versions)

// timelineEvent is one dated lifecycle row. Actor is the only identifying field
// (an admin identity or IP on a config change) → SENSITIVE, masked to a salted
// token. Crash rows carry no actor. Time/Kind are non-identifying; Ref/Label are
// low-cardinality internal labels (a version number, an action name, a component).
type timelineEvent struct {
	Time  string `json:"time" redact:"public"`               // RFC3339 UTC, from the source event
	Kind  string `json:"kind" redact:"public"`               // "crash" | "config_version"
	Ref   string `json:"ref,omitempty" redact:"internal"`    // version number / crash correlation id
	Actor string `json:"actor,omitempty" redact:"sensitive"` // admin identity/IP → masked (config changes only)
	Label string `json:"label,omitempty" redact:"internal"`  // action name / crash component
}

type timelineSection struct {
	Count  int             `json:"count" redact:"public"`
	Events []timelineEvent `json:"events" redact:"internal"`
}

type timelineCollector struct{}

func (timelineCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "timeline", Path: "sections/timeline.json", Owner: "observability", SchemaVersion: 1,
		Description: "Merged lifecycle timeline (crash + config-version events; actor masked)", Timeout: 3 * time.Second,
		ByteBudget: 64 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

// timelineSortKey returns comparable millis for descending time sort. It parses
// the source's own RFC3339 stamp; an unparseable stamp yields 0 so it sorts last
// rather than crashing or reordering non-deterministically.
func timelineSortKey(rfc3339 string) int64 {
	if t, err := time.Parse(time.RFC3339, rfc3339); err == nil {
		return t.UnixMilli()
	}
	return 0
}

func (timelineCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	type keyed struct {
		key int64
		ev  timelineEvent
	}
	var rows []keyed

	// Config-version audit trail — bounded at ≤50 by the store; each carries an
	// admin actor (masked) and an action label.
	for _, m := range configVersions.ListMeta() {
		rows = append(rows, keyed{
			key: timelineSortKey(m.CreatedAt),
			ev: timelineEvent{
				Time:  m.CreatedAt,
				Kind:  "config_version",
				Ref:   strconv.Itoa(m.Version),
				Actor: m.Actor,
				Label: m.Action,
			},
		})
	}

	// Most-recent recovered crash (0 or 1). The crash section owns the masked
	// summary/stack; the timeline carries only the dated index row.
	if rec, ok := lastCrashSnapshot(); ok {
		rows = append(rows, keyed{
			key: rec.TS,
			ev: timelineEvent{
				Time:  rec.Time,
				Kind:  "crash",
				Ref:   rec.CorrelationID,
				Label: rec.Component,
			},
		})
	}

	// Newest-first; stable so equal timestamps keep insertion order (deterministic).
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key > rows[j].key })
	if len(rows) > supportMaxTimelineEvents {
		rows = rows[:supportMaxTimelineEvents]
	}

	sec := timelineSection{Count: len(rows), Events: make([]timelineEvent, 0, len(rows))}
	for i := range rows {
		sec.Events = append(sec.Events, rows[i].ev)
	}

	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

func init() {
	support.Register(timelineCollector{})
}
