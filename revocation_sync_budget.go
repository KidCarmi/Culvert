package main

// revocation_sync_budget.go — AU-50 / AU-71. Byte budgets for the two legs of
// SyncRevocations, and the planner that keeps a list larger than a leg's
// budget propagating instead of failing the whole plane.
//
// THE FAILURE. SyncRevocations is bidirectional and its legs are capped
// differently: a Data Plane's REQUEST rides maxClusterInboundMsgSize (16 MiB —
// the DP's MaxCallSendMsgSize and the CP's MaxRecvMsgSize), the CP's REPLY
// rides maxClusterGRPCMsgSize (128 MiB). The DP used to send its whole live
// list, and that list includes every fleet entry it merged from earlier
// replies, so the request grew with the FLEET total. Past 16 MiB every sync
// failed with ResourceExhausted, and that node could neither publish a new
// local logout nor learn a fleet one until enough entries expired (Codex P1,
// PR #1437). The reply leg had the same shape one size up: MergedExcluding
// returns the CP's own list plus every other node's slot, bounded by nothing
// but the 128 MiB frame (AU-71).
//
// THE RULE. A leg that does not fit is DEFERRED, never dropped:
//
//   - Nothing is removed from any revocation list. The planner only chooses
//     which entries ride THIS tick; the rest ride later ones. Dropping an entry
//     from the list to make the request fit would un-revoke a session, which
//     is the fail-open direction this control may not take.
//   - Half of the budget is a strict priority PREFIX, so the entries that
//     matter most go out on the very next tick however large the backlog: on
//     the request leg that is this node's OWN logouts first (no other node can
//     tell the fleet about them — the CP already holds every entry this node
//     learned from it), then account revocations, then learned tokens; each
//     class latest-expiry first, which is the newest session and the longest
//     remaining protection.
//   - The other half is a ROTATING WINDOW over everything the prefix did not
//     carry, resuming where the previous tick stopped. That is what makes
//     "deferred" true rather than a polite word for "dropped": every live entry
//     is sent within ceil(backlog / window) ticks, including the oldest local
//     one, which a fixed prefix (AU-40's HA trim) would starve for as long as
//     the backlog stayed large.
//
// The receiving side needs no change for this to be correct. Both legs MERGE
// additively and persist (mergeAndPersistRevocations), so an entry carried by
// any tick is retained after it rotates out of the window. The CP's per-node
// aggregator slot is REPLACED by each request and so does fluctuate, but the
// same handler merges every request into the CP's own list, which is
// contributed to every reply (UpdateLocal): the fleet learns a rotated entry
// through the CP's slot rather than the requester's.
//
// The common case pays exactly what it did before: one marshal, measured, and
// sent unchanged when it fits. The planner runs only on the over-budget path.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// revocationSyncFrameReserve is the margin between each leg's byte budget and
// its gRPC limit. SyncRevocations rides rawCodec exactly like the HA bundle, so
// the accounting measured for haBundleFrameReserve holds unchanged: grpc-go
// compares the opaque JSON payload alone against the limit, and the 5-byte
// message header, HTTP/2 framing and HPACK are outside that comparison. The
// reserve is defensive headroom, not a framing tax.
const revocationSyncFrameReserve = haBundleFrameReserve // 1 MiB

// maxRevocationSyncRequestBytes is the DP→CP request budget. It is DERIVED
// from the limit that actually bounds this leg (AU-44's rule: a budget for a
// container comes from what holds it), which is the SMALL inbound bound, not
// the 128 MiB frame the reply rides.
const maxRevocationSyncRequestBytes = maxClusterInboundMsgSize - revocationSyncFrameReserve // 15 MiB

// maxRevocationSyncResponseBytes is the CP→DP reply budget (AU-71), derived
// from the frame the DP receives with (clusterClientCallOptions'
// MaxCallRecvMsgSize).
const maxRevocationSyncResponseBytes = maxClusterGRPCMsgSize - revocationSyncFrameReserve // 127 MiB

// The budgets the two legs enforce. Variables only so a gate can exercise the
// over-budget path of the 127 MiB leg without a 127 MiB fixture (the
// snapshotWireBudget precedent); production never reassigns them. The request
// leg's end-to-end gate runs at the REAL 16 MiB limit.
var (
	revocationSyncRequestBudget  = maxRevocationSyncRequestBytes
	revocationSyncResponseBudget = maxRevocationSyncResponseBytes
)

// Priority classes, lowest first.
const (
	revSyncClassLocal   = iota // a token this node MAC-verified itself
	revSyncClassAccount        // an account revocation, any origin
	revSyncClassLearned        // a token learned from the fleet
)

// revSyncKey is an entry's position in the priority order. Token is unique
// within one list (it is the map key on the DP, and the dedup key of the CP's
// merge), so the order is total and never depends on map iteration.
type revSyncKey struct {
	class  int
	expiry int64
	token  string
}

func (a revSyncKey) less(b revSyncKey) bool {
	if a.class != b.class {
		return a.class < b.class
	}
	if a.expiry != b.expiry {
		return a.expiry > b.expiry // latest expiry first
	}
	return a.token < b.token
}

// revSyncCursor is where the rotating window stopped. It is a KEY rather than
// an index, so entries that expire or arrive between ticks do not shift the
// resume point onto entries that were already sent.
type revSyncCursor struct {
	last revSyncKey
	set  bool
}

type revSyncItem struct {
	key  revSyncKey
	e    RevocationEntry
	cost int // marshalled bytes, without the separating comma
}

// revSyncItems ranks entries for planRevocationSync. classOf assigns the
// class; it is the only thing that differs between the two legs.
func revSyncItems(entries []RevocationEntry, classOf func(RevocationEntry) int) ([]revSyncItem, error) {
	items := make([]revSyncItem, 0, len(entries))
	for i := range entries {
		b, err := json.Marshal(entries[i])
		if err != nil {
			return nil, fmt.Errorf("measure revocation entry: %w", err)
		}
		items = append(items, revSyncItem{
			key:  revSyncKey{class: classOf(entries[i]), expiry: entries[i].Expiry, token: entries[i].Token},
			e:    entries[i],
			cost: len(b),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key.less(items[j].key) })
	return items, nil
}

// planRevocationSync chooses the entries whose marshalled JSON ARRAY fits
// arrayBudget bytes: a priority prefix of up to half the budget, then a
// rotating window over the remainder that resumes after cur. items must be
// sorted by revSyncKey.less. It returns the chosen entries (prefix first) and
// how many were deferred to a later tick, and advances cur.
//
// Nothing here removes anything from anywhere: "deferred" entries are simply
// not in this tick's message.
func planRevocationSync(items []revSyncItem, arrayBudget int, cur *revSyncCursor) (send []RevocationEntry, deferred int) {
	used := len("[]")
	send = make([]RevocationEntry, 0, min(len(items), 1024))
	fits := func(cost, limit int) bool {
		if len(send) > 0 {
			cost++ // the separating comma
		}
		return used+cost <= limit
	}
	take := func(it revSyncItem) {
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
		*cur = revSyncCursor{}
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
	var last revSyncKey
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
		*cur = revSyncCursor{} // everything went out; the next backlog starts fresh
	} else if advanced {
		*cur = revSyncCursor{last: last, set: true}
	}
	return send, len(items) - len(send)
}

// marshalWithinBudget marshals envelope(entries) and, when that exceeds
// budget, re-marshals it carrying the planned subset. It reports how many
// entries were deferred. The envelope's own bytes are measured (an empty
// array in place of the entries), so the array budget is exact.
func marshalWithinBudget(entries []RevocationEntry, budget int, cur *revSyncCursor,
	classOf func(RevocationEntry) int, envelope func([]RevocationEntry) any,
) (body []byte, deferred int, err error) {
	body, err = json.Marshal(envelope(entries))
	if err != nil {
		return nil, 0, fmt.Errorf("marshal revocation sync: %w", err)
	}
	if len(body) <= budget {
		*cur = revSyncCursor{}
		return body, 0, nil
	}
	empty, err := json.Marshal(envelope([]RevocationEntry{}))
	if err != nil {
		return nil, 0, fmt.Errorf("measure revocation sync envelope: %w", err)
	}
	items, err := revSyncItems(entries, classOf)
	if err != nil {
		return nil, 0, err
	}
	send, deferred := planRevocationSync(items, budget-(len(empty)-len("[]")), cur)
	if body, err = json.Marshal(envelope(send)); err != nil {
		return nil, 0, fmt.Errorf("marshal budgeted revocation sync: %w", err)
	}
	return body, deferred, nil
}

// revocationSyncRequest is the DP→CP SyncRevocations body. The field names
// are the wire contract the CP handler decodes.
type revocationSyncRequest struct {
	NodeID  string            `json:"node_id"`
	Entries []RevocationEntry `json:"entries"`
}

// buildRevocationSyncRequest marshals this node's revocation request within
// budget, local logouts first. local and other are ExportRevocationsByOrigin.
func buildRevocationSyncRequest(nodeID string, local, other []RevocationEntry, budget int, cur *revSyncCursor) (body []byte, deferred int, err error) {
	all := make([]RevocationEntry, 0, len(local)+len(other))
	all = append(all, local...)
	all = append(all, other...)
	isLocal := make(map[string]struct{}, len(local))
	for i := range local {
		isLocal[local[i].Token] = struct{}{}
	}
	classOf := func(e RevocationEntry) int {
		if _, ok := isLocal[e.Token]; ok {
			return revSyncClassLocal
		}
		if e.User != "" {
			return revSyncClassAccount
		}
		return revSyncClassLearned
	}
	envelope := func(es []RevocationEntry) any { return revocationSyncRequest{NodeID: nodeID, Entries: es} }
	return marshalWithinBudget(all, budget, cur, classOf, envelope)
}

// buildRevocationSyncResponse marshals the CP's reply within budget (AU-71).
// Every entry is remote to the requester, so the classes are account first
// (one entry withdraws every session an identity holds), then tokens.
func buildRevocationSyncResponse(entries []RevocationEntry, budget int, cur *revSyncCursor) (body []byte, deferred int, err error) {
	classOf := func(e RevocationEntry) int {
		if e.User != "" {
			return revSyncClassAccount
		}
		return revSyncClassLearned
	}
	envelope := func(es []RevocationEntry) any { return map[string]any{"entries": es} }
	return marshalWithinBudget(entries, budget, cur, classOf, envelope)
}

// Deferral accounting. Cumulative entry counts per leg — a deferral is a
// successful degradation on a path that runs every few seconds, so the
// magnitude belongs in a counter (culvert_cluster_revocation_sync_deferred_total)
// and the explanation in one rate-limited line, never a line per tick.
var (
	revocationSyncRequestDeferred  atomic.Uint64
	revocationSyncResponseDeferred atomic.Uint64
	revocationSyncDeferLogged      atomic.Int64
)

const revocationSyncDeferLogInterval = time.Minute

// writeRevocationSyncDeferredMetrics emits the deferral counter on /metrics.
// Nothing is dropped on this path, so it is deliberately a separate series
// from culvert_cluster_revocation_drops_total and does not feed the
// session_revocation contract row's dropped branch. Sustained growth means
// the revocation backlog is larger than one message and fleet-wide
// propagation of a deferred entry takes several ticks.
func writeRevocationSyncDeferredMetrics(w *strings.Builder) {
	fmt.Fprintf(w, "\n# HELP culvert_cluster_revocation_sync_deferred_total Revocation entries a SyncRevocations message left for a later tick because the full set exceeded that leg's byte budget (request: this Data Plane to its Control Plane; reply: this Control Plane to a Data Plane). Deferred entries rotate through later ticks and are never removed from any revocation list\n")
	fmt.Fprintf(w, "# TYPE culvert_cluster_revocation_sync_deferred_total counter\nculvert_cluster_revocation_sync_deferred_total{leg=\"request\"} %d\nculvert_cluster_revocation_sync_deferred_total{leg=\"reply\"} %d\n",
		revocationSyncRequestDeferred.Load(), revocationSyncResponseDeferred.Load())
}

// noteRevocationSyncDeferred charges n deferred entries to a leg and emits the
// explanatory line at most once per interval. who and leg are fixed strings
// chosen by the caller; node is peer-supplied on the CP and is sanitized.
func noteRevocationSyncDeferred(counter *atomic.Uint64, who, leg, node string, deferred, budget int) {
	if deferred <= 0 {
		return
	}
	counter.Add(uint64(deferred))
	now := time.Now().UnixNano()
	prev := revocationSyncDeferLogged.Load()
	if prev != 0 && now-prev < int64(revocationSyncDeferLogInterval) {
		return
	}
	if !revocationSyncDeferLogged.CompareAndSwap(prev, now) {
		return
	}
	logger.Printf("%s: SyncRevocations %s for node %q exceeds its %d byte budget; %d revocation entries deferred to later ticks (rotated, not dropped — no revocation was removed)",
		who, leg, sanitizeLog(node), budget, deferred)
}
