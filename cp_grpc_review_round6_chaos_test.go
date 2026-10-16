package main

// cp_grpc_review_round6_chaos_test.go — CHAOS-71 gates for the sixth review
// round on #1556: leader-gating of every ConfigService RPC (Codex P1
// 4294985681) and startup-ordered listener alerts (Codex P2 4294985690).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// cpGRPCProductionAlert is the production alert sink, captured at package init
// before any gate swaps the seam.
var cpGRPCProductionAlert = fireCPGRPCListenerAlert

// TestChaos71_SelfFencedStandbyRefusesConfigAndTheDPFailsOver — Codex P1
// (4294985681). After a self-fence the CP supervisor keeps running (ADR-0005:
// a demoted leader's server is not stopped) and can rebind. A Data Plane at an
// old version asking that standby for config used to get "unchanged" forever —
// standby resync does not advance ConfigStore.version — and never fail over.
// The standby now refuses with a retriable Unavailable, the DP counts it as a
// poll failure, and its address failover runs. Driven through the real gRPC
// server and the real DP poll/failover code; the DP's backoff sleep is skipped
// by a cancelled poll context (the RPC itself uses a live context).
func TestChaos71_SelfFencedStandbyRefusesConfigAndTheDPFailsOver(t *testing.T) {
	_ = cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	const peer = "127.0.0.1:1" // the new leader's address in the DP's list; never dialled successfully
	// The node self-fenced: HA role is standby while its supervisor rebinds.
	cpWithGlobalHARole(t, "standby", peer)

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	cpWaitFor(t, 10*time.Second, "the rebound listener to serve", func() bool { return cpGRPCListenerState().Serving })

	c := &DataPlaneClient{nodeID: "dp-old", addrs: []string{addr, peer}}
	c.lastVersion.Store(1) // an old version the standby would have called "unchanged"
	if err := c.connect(addr); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	c.callForTest = func(_ context.Context, method string, req json.RawMessage) (json.RawMessage, error) {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var resp json.RawMessage
		err := conn.Invoke(ctx, method, req, &resp)
		return resp, err
	}

	// The refusal itself: retriable, and not "unchanged".
	body, _ := json.Marshal(getConfigRequest{KnownVersion: 1})
	if _, err := c.call(t.Context(), methodGetConfig, body); status.Code(err) != codes.Unavailable {
		t.Fatalf("GetConfig on a self-fenced standby = %v, want codes.Unavailable (retriable, counted as a poll failure)", err)
	}

	pollCtx, cancel := context.WithCancel(context.Background())
	cancel() // skip the DP's backoff sleeps
	for i := 0; i < 6; i++ {
		_, _ = c.pollConfig(pollCtx)
		c.mu.Lock()
		idx := c.activeIdx
		c.mu.Unlock()
		if idx == 1 {
			return // failed over to the leader's address
		}
	}
	t.Fatal("the DP never failed over away from a standby that refuses config — it would stay on stale policy")
}

// TestChaos71_StandaloneCPStillServesConfig is the control: with HA off the
// leader gate is open, so a standalone Control Plane serves as before.
func TestChaos71_StandaloneCPStillServesConfig(t *testing.T) {
	_ = cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	cpWithGlobalHARole(t, "", "")
	if ok, reason := haServingAllowed(); !ok {
		t.Fatalf("a standalone CP is gated: %s", reason)
	}
	cpWithGlobalHARole(t, "leader", "10.0.0.9:50051")
	if ok, reason := haServingAllowed(); !ok {
		t.Fatalf("the HA leader is gated: %s", reason)
	}
	cpWithGlobalHARole(t, "standby", "10.0.0.9:50051")
	if ok, _ := haServingAllowed(); ok {
		t.Fatal("a standby is not gated")
	}
}

// TestChaos71_Wall_EveryCPRPCHasAnHAServingPolicy: every method registered on
// ConfigService must be registered through gatedUnary under its own name and
// have an explicit entry in cpRPCPolicies (leader-gated, or deliberately
// ungated with a reason) — and every policy must name a registered method.
func TestChaos71_Wall_EveryCPRPCHasAnHAServingPolicy(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "controlplane_server.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	reg := regexp.MustCompile(`\{MethodName: "([A-Za-z]+)", Handler: ([A-Za-z]+)\(([^)]*)\)\}`)
	matches := reg.FindAllStringSubmatch(body, -1)
	if len(matches) < 9 {
		t.Fatalf("found only %d ConfigService registrations — the wall is not reading registerConfigService", len(matches))
	}
	registered := map[string]bool{}
	for _, m := range matches {
		name, wrapper, args := m[1], m[2], m[3]
		registered[name] = true
		if wrapper != "gatedUnary" {
			t.Errorf("%s is registered through %s, not gatedUnary — it bypasses the HA serving policy", name, wrapper)
			continue
		}
		if !strings.HasPrefix(args, fmt.Sprintf("%q,", name)) {
			t.Errorf("%s is registered with a mismatched policy name (%s)", name, args)
		}
		p, ok := cpRPCPolicies[name]
		if !ok {
			t.Errorf("%s has no entry in cpRPCPolicies", name)
			continue
		}
		if strings.TrimSpace(p.why) == "" {
			t.Errorf("%s's policy carries no reason", name)
		}
	}
	for name := range cpRPCPolicies {
		if !registered[name] {
			t.Errorf("cpRPCPolicies names %s, which is not a registered ConfigService method", name)
		}
	}
}

// TestChaos71_ListenerAlertBeforeWebhooksLoadIsQueued — Codex P2 (4294985690).
// The supervisor starts in initCluster, before initPersistentAdminState loads
// the webhooks, and its alert latches are fire-once: a page raised before the
// load must queue through the startup-alert queue and be delivered at the
// flush, not latch and vanish.
func TestChaos71_ListenerAlertBeforeWebhooksLoadIsQueued(t *testing.T) {
	startupAlertMu.Lock()
	prevQueue, prevFlushed := startupAlertQueue, startupAlertFlushed
	startupAlertQueue, startupAlertFlushed = nil, false
	startupAlertMu.Unlock()
	var delivered []string
	prevFire := startupAlertFire
	startupAlertFire = func(event string, p AlertPayload) { delivered = append(delivered, event+": "+p.Detail) }
	t.Cleanup(func() {
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = prevQueue, prevFlushed
		startupAlertMu.Unlock()
		startupAlertFire = prevFire
	})

	cpGRPCProductionAlert("supervisor stopped (reason: role_conflict)")
	if len(delivered) != 0 {
		t.Fatal("the alert was delivered before the webhooks loaded")
	}
	startupAlertMu.Lock()
	queued := len(startupAlertQueue)
	startupAlertMu.Unlock()
	if queued != 1 {
		t.Fatalf("the pre-load alert was not queued (queue length %d) — a fire-once latch would drop it", queued)
	}
	flushStartupAlerts()
	if len(delivered) != 1 || !strings.HasPrefix(delivered[0], "cp_grpc_listener_down: ") {
		t.Errorf("the queued alert was not delivered at the flush: %v", delivered)
	}
}
