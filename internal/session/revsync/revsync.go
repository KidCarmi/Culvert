package revsync

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/KidCarmi/Culvert/internal/session"
)

// Priority classes, lowest first.
const (
	classLocal   = iota // a token this node MAC-verified itself
	classAccount        // an account revocation, any origin
	classLearned        // a token learned from the fleet
)

// key is an entry's position in the priority order. Token is unique within
// one list (it is the map key on the DP, and the dedup key of the CP's merge),
// so the order is total and never depends on map iteration.
type key struct {
	class  int
	expiry int64
	token  string
}

func (a key) less(b key) bool {
	if a.class != b.class {
		return a.class < b.class
	}
	if a.expiry != b.expiry {
		return a.expiry > b.expiry // latest expiry first
	}
	return a.token < b.token
}

// Cursor is where the rotating window stopped. It is a KEY rather than an
// index, so entries that expire or arrive between ticks do not shift the
// resume point onto entries that were already sent. The zero value is ready
// and means "no rotation in progress"; a Cursor belongs to exactly one
// (leg, peer) pair and is not safe for concurrent use.
type Cursor struct {
	last key
	set  bool
}

// Active reports whether a rotation is in progress, i.e. the previous message
// was over budget and left entries for a later tick. An owner that keeps one
// Cursor per peer can release an inactive one.
func (c Cursor) Active() bool { return c.set }

type item struct {
	key  key
	e    session.RevocationEntry
	cost int // marshalled bytes, without the separating comma
}

// rank orders entries for plan. classOf assigns the class; it is the only
// thing that differs between the two legs.
func rank(entries []session.RevocationEntry, classOf func(session.RevocationEntry) int) ([]item, error) {
	items := make([]item, 0, len(entries))
	for i := range entries {
		b, err := json.Marshal(entries[i])
		if err != nil {
			return nil, fmt.Errorf("measure revocation entry: %w", err)
		}
		items = append(items, item{
			key:  key{class: classOf(entries[i]), expiry: entries[i].Expiry, token: entries[i].Token},
			e:    entries[i],
			cost: len(b),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key.less(items[j].key) })
	return items, nil
}

// plan chooses the entries whose marshalled JSON ARRAY fits arrayBudget bytes:
// a priority prefix of up to half the budget, then a rotating window over the
// remainder that resumes after cur. items must be sorted by key.less. It
// returns the chosen entries (prefix first) and how many were deferred to a
// later tick, and advances cur.
//
// Nothing here removes anything from anywhere: "deferred" entries are simply
// not in this tick's message.
func plan(items []item, arrayBudget int, cur *Cursor) (send []session.RevocationEntry, deferred int) {
	used := len("[]")
	send = make([]session.RevocationEntry, 0, min(len(items), 1024))
	fits := func(cost, limit int) bool {
		if len(send) > 0 {
			cost++ // the separating comma
		}
		return used+cost <= limit
	}
	take := func(it item) {
		if len(send) > 0 {
			used++
		}
		used += it.cost
		send = append(send, it.e)
	}

	// 1. The priority prefix, strict, up to half the budget.
	h := 0
	for h < len(items) && fits(items[h].cost, arrayBudget/2) {
		take(items[h])
		h++
	}
	rest := items[h:]
	if len(rest) == 0 {
		*cur = Cursor{}
		return send, 0
	}

	// 2. The rotating window, resuming strictly after the last entry the
	// previous tick's window carried (wrapping to the start).
	start := 0
	if cur.set {
		start = sort.Search(len(rest), func(i int) bool { return cur.last.less(rest[i].key) })
		if start == len(rest) {
			start = 0
		}
	}
	carried := 0
	var last key
	advanced := false
	for k := range len(rest) {
		it := rest[(start+k)%len(rest)]
		if !fits(it.cost, arrayBudget) {
			if carried == 0 {
				// An entry larger than the entire window can never ride; step
				// the cursor past it so it cannot jam the rotation for every
				// entry behind it. Unreachable for any entry a cookie can
				// produce (the window is at least half the budget, megabytes),
				// but a jammed rotation would be a silent total stop.
				last, advanced = it.key, true
				continue
			}
			break
		}
		take(it)
		carried++
		last, advanced = it.key, true
	}
	if carried == len(rest) {
		*cur = Cursor{} // everything went out; the next backlog starts fresh
	} else if advanced {
		*cur = Cursor{last: last, set: true}
	}
	return send, len(items) - len(send)
}

// marshalWithinBudget marshals envelope(entries) and, when that exceeds
// budget, re-marshals it carrying the planned subset. It reports how many
// entries were deferred. The envelope's own bytes are measured (an empty
// array in place of the entries), so the array budget is exact.
func marshalWithinBudget(entries []session.RevocationEntry, budget int, cur *Cursor,
	classOf func(session.RevocationEntry) int, envelope func([]session.RevocationEntry) any,
) (body []byte, deferred int, err error) {
	body, err = json.Marshal(envelope(entries))
	if err != nil {
		return nil, 0, fmt.Errorf("marshal revocation sync: %w", err)
	}
	if len(body) <= budget {
		*cur = Cursor{}
		return body, 0, nil
	}
	empty, err := json.Marshal(envelope([]session.RevocationEntry{}))
	if err != nil {
		return nil, 0, fmt.Errorf("measure revocation sync envelope: %w", err)
	}
	items, err := rank(entries, classOf)
	if err != nil {
		return nil, 0, err
	}
	send, deferred := plan(items, budget-(len(empty)-len("[]")), cur)
	if body, err = json.Marshal(envelope(send)); err != nil {
		return nil, 0, fmt.Errorf("marshal budgeted revocation sync: %w", err)
	}
	return body, deferred, nil
}

// Request is the DP→CP SyncRevocations body. The field names are the wire
// contract the CP handler decodes.
type Request struct {
	NodeID  string                    `json:"node_id"`
	Entries []session.RevocationEntry `json:"entries"`
}

// BuildRequest marshals a node's revocation request within budget bytes, local
// logouts first. local and other are the two halves of
// session's ExportRevocationsByOrigin. It reports how many entries were
// deferred to a later tick and advances cur.
func BuildRequest(nodeID string, local, other []session.RevocationEntry, budget int, cur *Cursor) (body []byte, deferred int, err error) {
	all := make([]session.RevocationEntry, 0, len(local)+len(other))
	all = append(all, local...)
	all = append(all, other...)
	isLocal := make(map[string]struct{}, len(local))
	for i := range local {
		isLocal[local[i].Token] = struct{}{}
	}
	classOf := func(e session.RevocationEntry) int {
		if _, ok := isLocal[e.Token]; ok {
			return classLocal
		}
		if e.User != "" {
			return classAccount
		}
		return classLearned
	}
	envelope := func(es []session.RevocationEntry) any { return Request{NodeID: nodeID, Entries: es} }
	return marshalWithinBudget(all, budget, cur, classOf, envelope)
}

// BuildResponse marshals the CP's reply within budget bytes (AU-71). Every
// entry is remote to the requester, so the classes are account first (one
// entry withdraws every session an identity holds), then tokens.
func BuildResponse(entries []session.RevocationEntry, budget int, cur *Cursor) (body []byte, deferred int, err error) {
	classOf := func(e session.RevocationEntry) int {
		if e.User != "" {
			return classAccount
		}
		return classLearned
	}
	envelope := func(es []session.RevocationEntry) any { return map[string]any{"entries": es} }
	return marshalWithinBudget(entries, budget, cur, classOf, envelope)
}
