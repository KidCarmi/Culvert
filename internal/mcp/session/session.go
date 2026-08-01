// Package session holds per-session protocol state for the MCP kernel: the
// bounded outstanding-request table, response correlation, cancellation with
// ownership/direction rules, completion, and expiration/cleanup.
//
// The load-bearing invariant is direction isolation (MCP-PROTO-015 / #925): all
// correlation state is keyed by (session, direction, request-id), the same
// JSON-RPC id may be outstanding in BOTH directions at once, and no operation in
// one direction may resolve, cancel, complete, overwrite, release or delete the
// other direction's state. A second, closely-related guard (MCP-PROTO-013): an
// outstanding-request entry is released ONLY on trustworthy same-session
// correlation — never on an id lifted from a message the kernel just rejected —
// so a hostile peer cannot delete a legitimate in-flight request by naming its id.
package session

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
)

// Clock returns the current time. It is injected so tests are deterministic and
// so the kernel never reads a wall clock implicitly.
type Clock func() time.Time

// resolution records how an outstanding request left the pending set, so a later
// message about the same id can be told apart: a second response is a duplicate
// completion, a late cancellation is tolerated.
type resolution int

const (
	resCompleted resolution = iota + 1
	resCancelled
)

type entry struct {
	id           jsonrpc.ID
	owner        string
	method       string
	registeredAt time.Time
}

// dirState is the per-direction correlation state within a session.
type dirState struct {
	pending  map[string]*entry     // key = id.Key(); requests awaiting resolution
	resolved map[string]resolution // bounded recently-resolved ids (duplicate/late detection)
	order    []string              // ring order for bounded eviction of resolved
	cap      int                   // resolved ring capacity
}

func newDirState(cap int) *dirState {
	if cap < 1 {
		cap = 1
	}
	return &dirState{
		pending:  make(map[string]*entry),
		resolved: make(map[string]resolution),
		cap:      cap,
	}
}

// resolve moves key out of pending into the bounded resolved ring, evicting the
// oldest resolved id when full. Bounded memory: the resolved ring can never
// exceed cap regardless of traffic.
func (d *dirState) resolve(key string, r resolution) {
	delete(d.pending, key)
	if _, ok := d.resolved[key]; !ok {
		if len(d.order) >= d.cap {
			oldest := d.order[0]
			d.order = d.order[1:]
			delete(d.resolved, oldest)
		}
		d.order = append(d.order, key)
	}
	d.resolved[key] = r
}
