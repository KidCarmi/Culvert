package main

// revocation_sync_budget.go — AU-50 / AU-71. Byte budgets for the two legs of
// SyncRevocations, the deferral accounting, and main's bindings to the planner
// (internal/session/revsync) that keeps a list larger than a leg's budget
// propagating instead of failing the whole plane.
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
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/session/revsync"
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

// The planner itself — the priority order, the rotating window and the request
// wire envelope — is owned by internal/session/revsync (IM-015, ADR-0049).
// The names below are main's bindings to it: main owns the budgets above, the
// cursor INSTANCES (DataPlaneClient.revSyncCursor and the Control Plane
// aggregator's per-node respCursor), the deferral accounting below and the
// RPC, and passes the budget and cursor into every call.

// revSyncCursor is where a leg's rotating window stopped.
type revSyncCursor = revsync.Cursor

// revocationSyncRequest is the DP→CP SyncRevocations body. The field names
// are the wire contract the CP handler decodes.
type revocationSyncRequest = revsync.Request

// buildRevocationSyncRequest marshals this node's revocation request within
// budget, local logouts first. local and other are ExportRevocationsByOrigin.
func buildRevocationSyncRequest(nodeID string, local, other []RevocationEntry, budget int, cur *revSyncCursor) (body []byte, deferred int, err error) {
	return revsync.BuildRequest(nodeID, local, other, budget, cur)
}

// buildRevocationSyncResponse marshals the CP's reply within budget (AU-71),
// account revocations first, then tokens.
func buildRevocationSyncResponse(entries []RevocationEntry, budget int, cur *revSyncCursor) (body []byte, deferred int, err error) {
	return revsync.BuildResponse(entries, budget, cur)
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
