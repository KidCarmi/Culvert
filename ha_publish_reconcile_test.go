package main

// ha_publish_reconcile_test.go — ADR-0064 part D: a publication hold is
// reconciled automatically from the previous leader's PRESERVED configuration
// when that is verifiable, and only then; a demoted leader preserves its
// configuration before a resync overwrites it.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	reconNewerRule = "ha-recon-old-leader-newer-rule"
	reconAhead     = gateWatermark + 3
)

// previousLeaderPreserved is what the old leader (term 7) committed after the
// standby's last sync: the replicated rule plus one more, at v4245.
func previousLeaderPreserved(t *testing.T) *haPreservedSnapshot {
	t.Helper()
	snap := globalConfigStore.Get()
	snap.IdPProfiles = nil
	snap.PolicyRules = append(append([]PolicyRule(nil), snap.PolicyRules...),
		PolicyRule{Priority: 2, Name: reconNewerRule, DestFQDN: "newer.ha-recon.example", Action: ActionBlockPage})
	snap.Version = reconAhead
	return &haPreservedSnapshot{Version: reconAhead, Term: 7, SavedAt: time.Now().UTC().Format(time.RFC3339), Snapshot: snap}
}

// heldPair is a promoted node with one data plane ahead at v4245 (a hold) and
// a previous leader that answers with rec.
func heldPair(t *testing.T) (*eligPair, *haPreservedSnapshot) {
	t.Helper()
	p := promotedPair(t)
	rec := previousLeaderPreserved(t)
	haFetchPeerSnapshot = func(context.Context) (*haPreservedSnapshot, error) { return rec, nil }
	if unchanged, _, _ := dpGetConfig(t, reconAhead); !unchanged {
		t.Fatal("setup: the ahead data plane must be kept and the gate held")
	}
	return p, rec
}

func servedRuleNames(t *testing.T, k int64) (version int64, names string) {
	t.Helper()
	unchanged, snap, err := dpGetConfig(t, k)
	if err != nil || unchanged {
		t.Fatalf("k=%d: want a served snapshot (unchanged=%v err=%v)", k, unchanged, err)
	}
	return snap.Version, ruleNamesOf(snap.PolicyRules)
}

// The verifiable case: no operator. The previous leader's configuration is
// adopted, published above every reported version, and the hold is released.
func TestPublishReconcile_AdoptsThePreviousLeadersConfigurationAutomatically(t *testing.T) {
	heldPair(t)
	if !reconcilePublishHoldOnce(context.Background()) {
		t.Fatalf("a verifiable hold must reconcile without an operator; note=%q", publishGateSnapshot().ReconcileNote)
	}
	st := publishGateSnapshot()
	if st.Held || st.Reconciled != reconAhead || len(st.Gaps) != 0 {
		t.Fatalf("gate after reconciliation = %+v", st)
	}
	if ok, why := haPublishAuthorized(); !ok {
		t.Fatalf("publishing must be authorized again: %s", why)
	}
	// The node that was ahead is served ABOVE its version, with the newer rule.
	v, names := servedRuleNames(t, reconAhead)
	if v <= reconAhead || !strings.Contains(names, reconNewerRule) || !strings.Contains(names, eligLeaderRule) {
		t.Fatalf("served v%d rules=[%s]; want > v%d with %q", v, names, reconAhead, reconNewerRule)
	}
	// So is a node that was behind.
	if _, names := servedRuleNames(t, gateWatermark); !strings.Contains(names, reconNewerRule) {
		t.Errorf("a node at the watermark must receive the adopted configuration; got [%s]", names)
	}
	if d := findAuditEntry(t, "cluster.ha-auto-reconcile", "self").Detail; !strings.Contains(d, "ha_auto_reconcile") || !strings.Contains(d, `"version":4245`) {
		t.Errorf("audit detail must carry the diff; got %q", d)
	}
	// Idempotent: nothing left to do, nothing published again.
	published := globalConfigStore.Version()
	if reconcilePublishHoldOnce(context.Background()) || globalConfigStore.Version() != published {
		t.Error("a repeated attempt must change nothing")
	}
	if w := haGateRequest("POST", "/api/policy"); w.Code == 503 {
		t.Error("configuration changes must be accepted after reconciliation")
	}
}

// The conflicting / ambiguous / unrecoverable branch: the hold stays, with the
// reason, and nothing of the previous leader's is installed.
func TestPublishReconcile_KeepsTheHoldWhenNotVerifiable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, rec *haPreservedSnapshot)
		want   string
	}{
		{"previous leader unreachable", func(_ *testing.T, _ *haPreservedSnapshot) {
			haFetchPeerSnapshot = func(context.Context) (*haPreservedSnapshot, error) { return nil, errors.New("connection refused") }
		}, "could not be fetched"},
		{"preserved configuration older than a reported version", func(_ *testing.T, rec *haPreservedSnapshot) {
			rec.Version = reconAhead - 1
		}, "older than a version a data plane reports"},
		{"lineage: not an older term", func(_ *testing.T, rec *haPreservedSnapshot) {
			rec.Term = 99
		}, "lineage"},
		{"both leaders wrote", func(t *testing.T, _ *haPreservedSnapshot) {
			policyStore.ReplaceAll(append(policyStore.List(), PolicyRule{Priority: 9, Name: "new-leader-own-edit", DestFQDN: "own.example", Action: ActionAllow}))
			if err := publishCurrentConfigSnapshot(); err != nil {
				t.Fatalf("own commit: %v", err)
			}
		}, "both sides hold changes"},
		{"preserved configuration fails the shared validation", func(_ *testing.T, rec *haPreservedSnapshot) {
			rec.Snapshot.PolicyRules = append(rec.Snapshot.PolicyRules, subjectMatchRule("ha-recon-unenforceable"))
		}, "refused by validation"},
		{"two fingerprints for one version", func(_ *testing.T, _ *haPreservedSnapshot) {
			publishGateDecide("dp-x", "heartbeat", reconAhead-1, 0, "fp-1")
			publishGateDecide("dp-y", "heartbeat", reconAhead-1, 0, "fp-2")
		}, "conflicting generations"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rec := heldPair(t)
			c.mutate(t, rec)
			before := ruleNamesOf(policyStore.List())
			if reconcilePublishHoldOnce(context.Background()) {
				t.Fatal("reconciled a state that is not verifiable")
			}
			st := publishGateSnapshot()
			if !st.Held || !strings.Contains(st.ReconcileNote, c.want) {
				t.Fatalf("want the hold kept with a note containing %q; held=%v note=%q", c.want, st.Held, st.ReconcileNote)
			}
			if got := ruleNamesOf(policyStore.List()); got != before || strings.Contains(got, reconNewerRule) {
				t.Fatalf("the running policy changed: [%s] → [%s]", before, got)
			}
			if unchanged, _, _ := dpGetConfig(t, reconAhead); !unchanged {
				t.Fatal("the ahead data plane was rolled back")
			}
			gate, _ := haStatusJSON(t)["publish_gate"].(map[string]any)
			if note, _ := gate["reconcile_note"].(string); !strings.Contains(note, c.want) {
				t.Errorf("the status must say why; got %v", gate["reconcile_note"])
			}
		})
	}
}

// A crash at either point of an adoption converges on the same single result.
func TestPublishReconcile_RestartMidReconciliationConverges(t *testing.T) {
	for _, crashAfter := range []string{"apply", "publish"} {
		t.Run("crash after "+crashAfter, func(t *testing.T) {
			_, rec := heldPair(t)
			// The interrupted attempt: journal, apply, (publish), then the process dies
			// before the gate is released.
			setPublishGatePhase("reconciling", rec.Version)
			if err := applyConfigSnapshot(rec.Snapshot); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if crashAfter == "publish" {
				if err := publishCurrentConfigSnapshot(); err != nil {
					t.Fatalf("publish: %v", err)
				}
			}
			publishGate.mu.Lock() // the restart: memory gone, file kept
			publishGate.st, publishGate.loadedFrom, publishGate.alerted = publishGateState{}, "", false
			publishGate.mu.Unlock()
			if st := publishGateSnapshot(); !st.Held || st.Phase != "reconciling" {
				t.Fatalf("after the restart the gate must still be held, mid-reconciliation; got %+v", st)
			}

			if !reconcilePublishHoldOnce(context.Background()) {
				t.Fatalf("the resumed reconciliation must complete; note=%q", publishGateSnapshot().ReconcileNote)
			}
			st := publishGateSnapshot()
			if st.Held || st.Phase != "" || st.Reconciled != reconAhead {
				t.Fatalf("gate = %+v", st)
			}
			v, names := servedRuleNames(t, reconAhead)
			if v <= reconAhead || strings.Count(names, reconNewerRule) != 1 || strings.Count(names, eligLeaderRule) != 1 {
				t.Fatalf("want exactly the adopted configuration once, above v%d; got v%d [%s]", reconAhead, v, names)
			}
		})
	}
}

// Preserve before overwrite: a leader that is demoted writes its committed
// configuration to disk before it enters standby; a resync from the new leader
// does not delete it; and it is handed to the new leader over HAPeerSnapshot —
// to a holder of the HA token only, by a node that is NOT the leader.
func TestPublishReconcile_DemotedLeaderPreservesAndServesItsConfiguration(t *testing.T) {
	p := promotedPair(t)
	led := globalConfigStore.Get()
	p.h.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
	p.h.mu.Lock()
	p.h.standbyAddr = "new-leader.ha-recon.example:50051"
	p.h.mu.Unlock()
	if !p.h.enterStandbyResync("self-fence") {
		t.Fatal("setup: demotion")
	}
	rec, err := loadPreservedSnapshot()
	if err != nil || rec.Version != led.Version || !snapHasLeaderConfig(rec.Snapshot) {
		t.Fatalf("the demoted leader must preserve its committed configuration v%d; got %+v err=%v", led.Version, rec, err)
	}

	// The resync from the new leader overwrites the stores — not the file.
	p.s = newEligLoop(p.h, p.leader)
	p.leader.serve(eligBundle(t, []PolicyRule{{Priority: 1, Name: "new-leader-rule", DestFQDN: "x.example", Action: ActionAllow}}))
	p.s.guardedSyncOnce()
	if got := ruleNamesOf(policyStore.List()); got != "new-leader-rule" {
		t.Fatalf("setup: the resync must have replaced the running policy; got [%s]", got)
	}
	if after, err := loadPreservedSnapshot(); err != nil || after.Version != led.Version {
		t.Fatalf("a resync discarded the preserved configuration (err=%v)", err)
	}

	// Served by this (standby) node to the new leader.
	h := gatedUnary("HAPeerSnapshot", (&controlPlaneServer{}).HAPeerSnapshot)
	call := func(token string) (json.RawMessage, error) {
		req, _ := json.Marshal(map[string]string{"token": token})
		out, err := h(nil, context.Background(), func(v any) error { *(v.(*json.RawMessage)) = req; return nil }, nil)
		if err != nil {
			return nil, err
		}
		return out.(json.RawMessage), nil
	}
	if _, err := call("not-the-token"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("HAPeerSnapshot without the HA token: %v, want PermissionDenied", err)
	}
	raw, err := call(eligSharedSecret)
	if err != nil {
		t.Fatalf("HAPeerSnapshot from a standby must be served (it is not leader-gated): %v", err)
	}
	var got haPreservedSnapshot
	if json.Unmarshal(raw, &got) != nil || got.Version != led.Version || !snapHasLeaderConfig(got.Snapshot) {
		t.Fatalf("served snapshot = v%d", got.Version)
	}
	// A node that never led has nothing to serve.
	_ = os.Remove(haPreservedSnapshotPath())
	if _, err := call(eligSharedSecret); status.Code(err) != codes.NotFound {
		t.Errorf("no preserved snapshot: %v, want NotFound", err)
	}
}

// The promotion's first own version is unmistakably above the previous
// leader's lineage even when the wall clock gives no help (no clock seed runs
// in this fixture): a data plane on the old leader's NEXT version is detected.
func TestPublishGate_PromotionVersionJumpMakesTheGapClockIndependent(t *testing.T) {
	p := newEligPair(t) // onPromote publishes without the wall-clock version seed
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	if !p.outage(haStandbyMaxFail) {
		t.Fatal("setup: promote")
	}
	st := publishGateSnapshot()
	if st.FirstOwn < gateWatermark+haPromotionVersionJump || len(st.Gaps) != 1 {
		t.Fatalf("first own version v%d must be at least the watermark + %d; gate=%+v", st.FirstOwn, haPromotionVersionJump, st)
	}
	if unchanged, snap, _ := dpGetConfig(t, gateWatermark+1); !unchanged {
		t.Fatalf("a data plane on the old leader's next version (v%d) was handed v%d: version collision", gateWatermark+1, snap.Version)
	}
}

// Heartbeat evidence through the real PushMetrics handler.
func TestPublishGate_HeartbeatThroughPushMetricsHoldsPublication(t *testing.T) {
	promotedPair(t)
	nodeMetricsMu.Lock()
	orig := nodeMetrics
	nodeMetrics = map[string]MetricsReport{}
	nodeMetricsMu.Unlock()
	t.Cleanup(func() { nodeMetricsMu.Lock(); nodeMetrics = orig; nodeMetricsMu.Unlock() })
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-hb", Status: "connected", CertSerial: "s-hb"})
	origInsecure := clusterInsecure
	clusterInsecure = true // no mTLS peer in the test context
	t.Cleanup(func() { clusterInsecure = origInsecure })

	push := func(v int64) {
		raw, _ := json.Marshal(MetricsReport{NodeID: "dp-hb", ConfigVersion: v, Epoch: 0, SyncedFP: "fp-hb"})
		if _, err := (&controlPlaneServer{}).PushMetrics(context.Background(), raw); err != nil {
			t.Fatalf("PushMetrics: %v", err)
		}
	}
	push(gateWatermark)
	if st := publishGateSnapshot(); st.Held {
		t.Fatal("a heartbeat at the watermark must not hold publication")
	}
	push(reconAhead)
	st := publishGateSnapshot()
	if !st.Held || len(st.Evidence) != 1 || st.Evidence[0].Node != "dp-hb" || st.Evidence[0].Source != "heartbeat" || st.Evidence[0].SyncedFP != "fp-hb" {
		t.Fatalf("a heartbeat reporting an unreplicated version must hold publication and name the node; got %+v", st)
	}
}
