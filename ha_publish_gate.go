package main

// ha_publish_gate.go — ADR-0064 part D: the publication safety gate of a
// PROMOTED control plane.
//
// A promoted standby seeds its config version above everything the old leader
// issued and publishes what it holds. A data plane that had applied versions
// the standby never replicated is then handed OLDER content at a HIGHER
// version: a silent rollback. This gate stops that without touching ADR-0005:
// it never blocks a commit into the ConfigStore (a promotion must commit a
// snapshot carrying its new epoch); it decides, per data plane, what is
// DISTRIBUTED, and whether operator mutations are accepted.
//
// Evidence, all of it already on the wire:
//
//	W   the replicated watermark: the highest leader version this node applied
//	    as a standby (replicatedLeaderConfigVersion at promotion).
//	P0  the first version this node committed as leader.
//	k   the version a data plane says it holds: known_version on GetConfig and
//	    GetConfigDelta, config_version on every heartbeat.
//
//	k <= W, or P0 <= k <= current   consistent with this node's lineage: served
//	                                exactly as before. A healthy failover never
//	                                leaves this row.
//	W < k < P0, or k > current      the data plane holds state this node does
//	                                not. It is answered "unchanged" (it keeps
//	                                what it has; it is never rolled back), the
//	                                evidence is recorded, and the gate HOLDS.
//
// While held: data planes consistent with this node keep being served (never
// frozen); a data plane that sends no version gets Unavailable (it keeps its
// last-good); operator mutations of distributed configuration are refused
// (ha_write_gate.go); the status carries the diff and one alert fires. A hold
// ends by reconciliation with the previous leader (ha_publish_reconcile.go) or
// by an explicit, audited operator release.
//
// The gate arms only on an HA promotion and is persisted, so a restart keeps
// both the bounds and the hold. A standalone or never-promoted control plane
// has no gate and behaves exactly as before.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const haPublishGateFile = "ha_publish_gate.json"

// maxPublishGateEvidence bounds the recorded per-node evidence.
const maxPublishGateEvidence = 256

// publishGateEvidence is one data plane's (or the previous leader's) report of
// a version this node cannot account for.
type publishGateEvidence struct {
	Node     string `json:"node"`                // node ID (heartbeat), "peer:<addr>" or "ip:<addr>"
	Version  int64  `json:"version"`             // the version it reports
	Epoch    int64  `json:"epoch,omitempty"`     // highest fencing epoch it observed (heartbeat)
	SyncedFP string `json:"synced_fp,omitempty"` // its blocklist fingerprint (heartbeat)
	Source   string `json:"source"`              // "heartbeat" | "get_config" | "get_config_delta" | "previous_leader"
	SeenAt   string `json:"seen_at"`             // RFC3339, last report
}

// publishGateState is the persisted gate. Guarded by publishGate.mu.
type publishGateState struct {
	Armed bool `json:"armed"`
	// Gaps are the version ranges (exclusive bounds) this lineage cannot
	// account for: one per promotion (its watermark, its first own version),
	// including those inherited from the leader this node replicated. A
	// reported version inside a gap is state this node does not hold.
	Gaps       []publishGateGap      `json:"gaps,omitempty"`
	Watermark  int64                 `json:"watermark"`       // W
	FirstOwn   int64                 `json:"first_own"`       // P0
	Term       uint64                `json:"term"`            // leadership term the gate was armed for
	Epoch      int64                 `json:"epoch,omitempty"` // fencing epoch at arming (0 in legacy mode)
	ArmedAt    string                `json:"armed_at"`
	Held       bool                  `json:"held"`
	HeldSince  string                `json:"held_since,omitempty"`
	HoldReason string                `json:"hold_reason,omitempty"`
	Phase      string                `json:"phase,omitempty"` // "" | "reconciling" | "adopted" (reconciliation journal)
	ReleasedBy string                `json:"released_by,omitempty"`
	ReleasedAt string                `json:"released_at,omitempty"`
	Reconciled int64                 `json:"reconciled_through,omitempty"` // last version adopted from the previous leader
	Evidence   []publishGateEvidence `json:"evidence,omitempty"`
}

// publishGateGap is one unaccounted version range, bounds exclusive.
type publishGateGap struct {
	Above int64  `json:"above"` // the watermark replicated before the promotion
	Below int64  `json:"below"` // the promotion's first own version
	Term  uint64 `json:"term"`
}

// inheritedPublishGate is the gate of the leader this node last replicated
// from (carried in the HASync bundle). A standby that is promoted starts from
// it, so a hold — and every still-open gap — survives a second failover.
var inheritedPublishGate struct {
	mu sync.Mutex
	st *publishGateState
}

func setInheritedPublishGate(st *publishGateState) {
	inheritedPublishGate.mu.Lock()
	inheritedPublishGate.st = st
	inheritedPublishGate.mu.Unlock()
}

func takeInheritedPublishGate() *publishGateState {
	inheritedPublishGate.mu.Lock()
	defer inheritedPublishGate.mu.Unlock()
	return inheritedPublishGate.st
}

var publishGate struct {
	mu sync.Mutex
	st publishGateState
	// loadedFrom is the gate file the in-memory state was read from ("": not
	// loaded). The state follows the file: a different data directory is a
	// different node's gate.
	loadedFrom string
	alerted    bool // fire-once per hold
}

func haPublishGatePath() string {
	return filepath.Join(filepath.Dir(haConfigPath()), haPublishGateFile)
}

// loadPublishGateLocked reads the persisted gate once per process (and again
// after a test reset). A missing file is "not armed"; an unreadable one is
// logged and treated as not armed — the gate is a safety net above the
// existing behaviour, never a reason to stop serving.
func loadPublishGateLocked() {
	path := haPublishGatePath()
	if publishGate.loadedFrom == path {
		return
	}
	publishGate.loadedFrom = path
	publishGate.st = publishGateState{}
	publishGate.alerted = false
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st publishGateState
	if jerr := json.Unmarshal(data, &st); jerr != nil {
		logger.Printf("HA: publication gate state %s is unreadable (%v) — starting without it", haPublishGateFile, jerr)
		return
	}
	publishGate.st = st
}

func savePublishGateLocked() {
	data, err := json.MarshalIndent(publishGate.st, "", "  ")
	if err != nil {
		return
	}
	if werr := atomicWriteFile(haPublishGatePath(), data, 0o600); werr != nil {
		logger.Printf("HA: persisting the publication gate failed: %v", werr)
	}
}

// resetPublishGateForTest forgets the in-memory gate so the next use re-reads
// the (test-scoped) file.
func resetPublishGateForTest() {
	publishGate.mu.Lock()
	publishGate.st = publishGateState{}
	publishGate.loadedFrom = ""
	publishGate.alerted = false
	publishGate.mu.Unlock()
	setInheritedPublishGate(nil)
}

// armPublishGate records the bounds of a promotion. Called by promote() once
// the node leads. watermark is what this node replicated as a standby;
// firstOwn the version its promotion committed. Idempotent for one term.
func armPublishGate(watermark, firstOwn int64, term uint64, epoch int64) {
	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	loadPublishGateLocked()
	if publishGate.st.Armed && publishGate.st.Term == term && publishGate.st.Epoch == epoch {
		return
	}
	next := publishGateState{
		Armed: true, Watermark: watermark, FirstOwn: firstOwn, Term: term, Epoch: epoch,
		ArmedAt: time.Now().UTC().Format(time.RFC3339),
	}
	// Start from the previous leader's gate: its open gaps, and its hold with
	// the evidence, are still true of the fleet.
	if in := takeInheritedPublishGate(); in != nil && in.Armed {
		next.Gaps = append(next.Gaps, in.Gaps...)
		if in.Held {
			next.Held, next.HeldSince = true, in.HeldSince
			next.Evidence = append([]publishGateEvidence(nil), in.Evidence...)
		}
	}
	if firstOwn > watermark+1 {
		next.Gaps = append(next.Gaps, publishGateGap{Above: watermark, Below: firstOwn, Term: term})
	}
	publishGate.st = next
	if next.Held {
		publishGate.st.HoldReason = publishHoldReasonLocked()
	}
	publishGate.alerted = false
	savePublishGateLocked()
	logger.Printf("HA: publication gate armed for term %d (replicated watermark v%d, first own version v%d)", term, watermark, firstOwn)
}

// disarmPublishGate drops the gate when this node stops leading (it re-enters
// standby): the bounds describe a leadership that is over.
func disarmPublishGate() {
	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	loadPublishGateLocked()
	if !publishGate.st.Armed {
		return
	}
	publishGate.st = publishGateState{}
	publishGate.alerted = false
	_ = os.Remove(haPublishGatePath())
}

type publishGateVerdict int

const (
	gateServe       publishGateVerdict = iota // serve as usual
	gateKeepCurrent                           // answer "unchanged": the caller holds state this node lacks
	gateUnavailable                           // held, and the caller's state is unknown
)

// consistentLocked reports whether version k belongs to this node's lineage.
func (st *publishGateState) consistent(k, current int64) bool {
	if k > current {
		return false
	}
	for i := range st.Gaps {
		if k > st.Gaps[i].Above && k < st.Gaps[i].Below {
			return false
		}
	}
	return true
}

// publishGateDecide classifies one data-plane report. node identifies the
// reporter for the diff; k is the version it holds (0: not stated).
func publishGateDecide(node, source string, k, epoch int64, fp string) publishGateVerdict {
	if !publishGateApplies() {
		return gateServe
	}
	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	loadPublishGateLocked()
	st := &publishGate.st
	if !st.Armed {
		return gateServe
	}
	if k <= 0 {
		if st.Held {
			return gateUnavailable
		}
		return gateServe
	}
	if st.consistent(k, globalConfigStore.Version()) {
		return gateServe
	}
	recordGateEvidenceLocked(publishGateEvidence{Node: node, Version: k, Epoch: epoch, SyncedFP: fp, Source: source})
	return gateKeepCurrent
}

// recordGateEvidenceLocked stores (or refreshes) one report and enters HOLD.
func recordGateEvidenceLocked(ev publishGateEvidence) {
	st := &publishGate.st
	ev.SeenAt = time.Now().UTC().Format(time.RFC3339)
	changed := false
	found := false
	for i := range st.Evidence {
		if st.Evidence[i].Node != ev.Node {
			continue
		}
		found = true
		if st.Evidence[i].Version != ev.Version || st.Evidence[i].SyncedFP != ev.SyncedFP {
			changed = true
		}
		if ev.Epoch == 0 {
			ev.Epoch = st.Evidence[i].Epoch
		}
		if ev.SyncedFP == "" {
			ev.SyncedFP = st.Evidence[i].SyncedFP
		}
		st.Evidence[i] = ev
		break
	}
	if !found && len(st.Evidence) < maxPublishGateEvidence {
		st.Evidence = append(st.Evidence, ev)
		changed = true
	}
	if !st.Held {
		st.Held = true
		st.HeldSince = ev.SeenAt
		st.ReleasedBy, st.ReleasedAt = "", ""
		changed = true
		logger.Printf("HA: PUBLICATION HELD — %q reports config version v%d, which this node never replicated "+
			"(watermark v%d, own versions from v%d). It keeps its configuration (answered \"unchanged\"), "+
			"consistent data planes keep being served, and configuration changes are refused until the state "+
			"is reconciled or an operator releases the hold.", sanitizeLog(ev.Node), ev.Version, st.Watermark, st.FirstOwn)
	}
	st.HoldReason = publishHoldReasonLocked()
	if changed {
		savePublishGateLocked()
	}
	if !publishGate.alerted {
		publishGate.alerted = true
		pagePublishHold(st.HoldReason)
	}
}

func publishHoldReasonLocked() string {
	st := &publishGate.st
	maxV := int64(0)
	for i := range st.Evidence {
		if st.Evidence[i].Version > maxV {
			maxV = st.Evidence[i].Version
		}
	}
	return fmt.Sprintf("publication is held: %d node(s) report a configuration version this control plane never "+
		"replicated (up to v%d; replicated watermark v%d, own versions from v%d) — publishing would roll them back",
		len(st.Evidence), maxV, st.Watermark, st.FirstOwn)
}

// haPublishAuthorized is the ONE publishing-authorization predicate (ADR-0064):
// leadership is haLeadershipHeld; this is whether a leader may distribute new
// content and accept configuration changes. The state-authority contract's declared-emptying check
// is to be consulted here as well, not in a second gate.
func haPublishAuthorized() (ok bool, reason string) {
	if reason, refused := haDistributionRefused(); refused {
		return false, reason
	}
	if !publishGateApplies() {
		return true, ""
	}
	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	loadPublishGateLocked()
	if publishGate.st.Armed && publishGate.st.Held {
		return false, publishGate.st.HoldReason
	}
	return true, ""
}

// publishGateSnapshot returns a copy of the gate for status and tests.
func publishGateSnapshot() publishGateState {
	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	loadPublishGateLocked()
	st := publishGate.st
	st.Evidence = append([]publishGateEvidence(nil), st.Evidence...)
	sort.Slice(st.Evidence, func(i, j int) bool { return st.Evidence[i].Node < st.Evidence[j].Node })
	return st
}

// addPublishGateStatus adds the actionable diff to an HA status response.
func addPublishGateStatus(resp map[string]any) {
	st := publishGateSnapshot()
	if !st.Armed || !publishGateApplies() {
		return
	}
	gate := map[string]any{
		"watermark": st.Watermark, "first_own_version": st.FirstOwn, "current_version": globalConfigStore.Version(),
		"term": st.Term, "held": st.Held, "gaps": st.Gaps,
	}
	if st.Reconciled != 0 {
		gate["reconciled_through"] = st.Reconciled
	}
	if st.ReleasedBy != "" {
		gate["released_by"], gate["released_at"] = st.ReleasedBy, st.ReleasedAt
	}
	if st.Held {
		gate["held_since"] = st.HeldSince
		gate["ahead_nodes"] = st.Evidence
		gate["conflict"] = publishGateConflict(st.Evidence)
		gate["action"] = "Automatic: this node keeps trying to adopt the previous leader's committed state. " +
			"If the previous leader is gone for good, release the hold: POST /api/cluster/ha/publish-release " +
			"(the listed nodes are then rolled back to this node's configuration)."
	}
	resp["publish_gate"] = gate
}

// publishGateConflict names an evidence set no single previous-leader state
// can explain: two blocklist fingerprints reported for one version.
func publishGateConflict(evs []publishGateEvidence) string {
	fps := map[int64]string{}
	for i := range evs {
		if evs[i].SyncedFP == "" {
			continue
		}
		if prev, ok := fps[evs[i].Version]; ok && prev != evs[i].SyncedFP {
			return fmt.Sprintf("two different blocklist fingerprints are reported for version v%d", evs[i].Version)
		}
		fps[evs[i].Version] = evs[i].SyncedFP
	}
	return ""
}

// publishGateForBundle is the gate as a standby must inherit it (nil: no gate).
func publishGateForBundle() *publishGateState {
	st := publishGateSnapshot()
	if !st.Armed {
		return nil
	}
	return &st
}

// releasePublishHold is the operator's exception path: accept THIS node's
// state as authoritative. The nodes ahead of it are then served and roll back.
// Idempotent: releasing a gate that is not held changes nothing.
func releasePublishHold(actor string) (released bool, st publishGateState, err error) {
	publishGate.mu.Lock()
	loadPublishGateLocked()
	if !publishGate.st.Armed || !publishGate.st.Held {
		st = publishGate.st
		publishGate.mu.Unlock()
		return false, st, nil
	}
	maxV := int64(0)
	for i := range publishGate.st.Evidence {
		if publishGate.st.Evidence[i].Version > maxV {
			maxV = publishGate.st.Evidence[i].Version
		}
	}
	publishGate.mu.Unlock()

	// A data plane ignores a snapshot whose version is not above its own, so
	// the release publishes ABOVE every reported version. Outside the gate lock:
	// the publish marshals a snapshot.
	globalConfigStore.raiseVersionAtLeast(maxV)
	if perr := publishCurrentConfigSnapshot(); perr != nil {
		return false, publishGateSnapshot(), fmt.Errorf("publishing this node's configuration as authoritative failed: %w", perr)
	}

	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	g := &publishGate.st
	// Everything reported so far is now BELOW this node's own range: the
	// watermark moves up to it, and the own range restarts at the release.
	g.Watermark, g.FirstOwn = maxV, globalConfigStore.Version()
	g.Gaps = nil // every earlier version is superseded by this node's release
	g.Held, g.HoldReason, g.HeldSince, g.Phase = false, "", "", ""
	g.Evidence = nil
	g.ReleasedBy, g.ReleasedAt = actor, time.Now().UTC().Format(time.RFC3339)
	publishGate.alerted = false
	savePublishGateLocked()
	return true, *g, nil
}

// publishGateArming carries a promotion's bounds from its start to its end.
type publishGateArming struct {
	active    bool
	watermark int64
}

// beginPublishGateArming is called at the start of promote(): it captures the
// replicated watermark and asks the store to remember the promotion's first
// commit. Only the process's own HA state arms the gate.
func (h *HAState) beginPublishGateArming() publishGateArming {
	if h != haTopologySource() {
		return publishGateArming{}
	}
	globalConfigStore.markNextCommit()
	return publishGateArming{active: true, watermark: replicatedLeaderConfigVersion.Load()}
}

// arm completes the arming once the node leads.
func (a publishGateArming) arm(term uint64, epoch int64) {
	if !a.active {
		return
	}
	first := globalConfigStore.markedCommitVersion()
	if first == 0 {
		first = globalConfigStore.Version() + 1 // the promotion committed nothing: own versions start with the next commit
	}
	armPublishGate(a.watermark, first, term, epoch)
}

// publishGateForDataPlane applies the gate to one config request. It returns
// keep=true when the caller must be told to keep what it has, or a non-nil
// error when the caller's state is unknown during a hold.
func publishGateForDataPlane(node, source string, k int64) (keep bool, err error) {
	switch publishGateDecide(node, source, k, 0, "") {
	case gateKeepCurrent:
		return true, nil
	case gateUnavailable:
		return false, status.Errorf(codes.Unavailable, "configuration distribution is held on this control plane and this "+
			"request states no version — keeping the node on its current configuration")
	}
	return false, nil
}

// apiClusterHAPublishRelease handles POST /api/cluster/ha/publish-release: the
// operator accepts THIS node's configuration as authoritative and ends a
// publication hold. It is the exception path: the response and the audit entry
// carry the diff (which nodes were ahead, at which versions), it is idempotent,
// and it is refused while automatic reconciliation is still possible unless
// the request sets "force".
func apiClusterHAPublishRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // an empty body is "not forced"
	}
	before := publishGateSnapshot()
	if !before.Armed || !before.Held {
		jsonOK(w, map[string]any{"ok": true, "released": false, "held": false, "detail": "publication is not held"})
		return
	}
	if !haLeadershipHeld() {
		http.Error(w, "release refused: this node does not hold HA leadership", http.StatusConflict)
		return
	}
	if !req.Force && haPreviousLeaderReachable() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "the previous leader is reachable, so its newer configuration can still be adopted automatically; " +
				"releasing now discards it. Repeat with {\"force\": true} to release anyway.",
			"code": "ha_reconciliation_possible", "ahead_nodes": before.Evidence,
		})
		return
	}
	released, after, err := releasePublishHold(sessionAdmin(r))
	if err != nil {
		http.Error(w, "release failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"ok": true, "released": released, "held": after.Held, "rolled_back_nodes": before.Evidence,
		"published_version": globalConfigStore.Version(),
	})
	if !released {
		return
	}
	diff, _ := json.Marshal(before.Evidence)
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.ha-publish-release",
		Object: "self",
		Detail: fmt.Sprintf("operator released the publication hold (force=%v): this node's configuration was published as "+
			"authoritative at v%d; nodes rolled back: %s", req.Force, globalConfigStore.Version(), auditCutString(string(diff), 1500)),
	})
}

// auditCutString bounds a detail fragment.
func auditCutString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// haPreviousLeaderReachable reports whether the leader this node replaced
// answers on the cluster port — reconciliation with it is then still possible.
// Test seam.
var haPreviousLeaderReachable = func() bool {
	addr := globalHA.Status().PeerAddr
	if addr == "" {
		return false
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// haDistributionRefused reports whether this node must hand out NO
// configuration at all — to data planes or to a standby. That is narrower than
// "not publish-authorized": during a publication hold the gate answers each
// data plane itself (consistent ones are served, ahead ones keep their state)
// and HASync stays served. Here the node has no authority to distribute
// anything: it holds the leader ROLE without the fencing lease (a resume the
// lease denied, with no standby to join — the ADR-0005 S2 stance). The lease
// is the authority, so a node without it is a stale leader as far as anyone
// else can tell, and its configuration must not reach the fleet. Data planes
// keep their last-good configuration, as on any failed poll.
//
// The listener's blanket CULVERT_PUBLISH_NOT_AUTHORIZED refusal keys on THIS
// predicate, not on haPublishAuthorized.
func haDistributionRefused() (reason string, refused bool) {
	if globalHA.unfencedLeader() {
		return "this node holds the HA leader role without the fencing lease, so it is not authorized to distribute configuration", true
	}
	return "", false
}

// refuseDistributionIfUnauthorized is the check GetConfig, GetConfigDelta and
// HASync make before serving.
func refuseDistributionIfUnauthorized(method string) error {
	if reason, refused := haDistributionRefused(); refused {
		return status.Errorf(codes.Unavailable, "%s: %s; %s is not served", haPublishNotAuthorizedMark, reason, method)
	}
	return nil
}

// pagePublishHold pages a publication hold once. A promotion (and so a hold)
// can precede the load of the persisted webhooks at start-up, so before the
// startup flush the page queues and is delivered only while the hold is still
// in force; afterwards it is dispatched off the caller's goroutine.
func pagePublishHold(reason string) {
	payload := AlertPayload{Event: "ha_resume_unfenced", Source: "ha",
		Detail: "publication held on the promoted control plane: " + reason}
	if !startupAlertsFlushed() {
		deferStartupAlertWhile("ha_resume_unfenced", payload, publishHoldInForce)
		return
	}
	go fireAlert("ha_resume_unfenced", payload)
}

// publishHoldInForce reports whether a gate hold is active. It must not take
// the gate lock's caller path: it is called by the startup alert flush.
func publishHoldInForce() bool {
	st := publishGateSnapshot()
	return st.Armed && st.Held
}

// publishGateApplies reports whether the gate is in force: only while this
// node is an HA LEADER. A gate file left by an earlier leadership does nothing
// on a node that is now standalone or a standby. Read before, never under, the
// gate lock (lock order: the gate lock is a leaf).
func publishGateApplies() bool {
	return haTopologySource().Status().Role == "leader"
}
