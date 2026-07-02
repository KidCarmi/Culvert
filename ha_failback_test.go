package main

// ha_failback_test.go — ADR-0005 S0: the leader records the standby's advertised
// address (from the HASync request) as the failback target. This is the
// prerequisite that unblocks the etcd-lease failover work — without it a
// demoted leader has nowhere to resync from (the ADR-0004 peer-address
// asymmetry).

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/peer"
)

func leaderForS0(t *testing.T) *HAState {
	t.Helper()
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.token = "tok"
	h.peerAddr = "cp-self:50051"
	h.term = 1
	h.stopCh = make(chan struct{})
	h.mu.Unlock()
	return h
}

func TestS0_RecordStandbyAddr_LeaderRecordsAndPersists(t *testing.T) {
	h := leaderForS0(t)
	h.RecordStandbyAddr("cp-standby:50051")
	if got := h.StandbyAddr(); got != "cp-standby:50051" {
		t.Fatalf("StandbyAddr = %q, want cp-standby:50051", got)
	}
	if got := h.Status().StandbyAddr; got != "cp-standby:50051" {
		t.Errorf("Status().StandbyAddr = %q, want cp-standby:50051", got)
	}
	// Persisted for restart durability.
	cfg, err := loadHAConfig()
	if err != nil {
		t.Fatalf("loadHAConfig: %v", err)
	}
	if cfg.StandbyAddr != "cp-standby:50051" {
		t.Errorf("persisted StandbyAddr = %q, want cp-standby:50051", cfg.StandbyAddr)
	}
}

func TestS0_RecordStandbyAddr_IgnoredWhenNotLeader(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.mu.Unlock()
	h.RecordStandbyAddr("cp-standby:50051")
	if got := h.StandbyAddr(); got != "" {
		t.Errorf("a standby must not record a standby address, got %q", got)
	}
}

func TestS0_RecordStandbyAddr_IgnoresEmpty(t *testing.T) {
	h := leaderForS0(t)
	h.RecordStandbyAddr("")
	if got := h.StandbyAddr(); got != "" {
		t.Errorf("empty address must be ignored, got %q", got)
	}
}

// The failback target survives a leader restart (persisted in ha_config.json,
// restored by ResumeAsLeader).
func TestS0_StandbyAddr_SurvivesRestart(t *testing.T) {
	h := leaderForS0(t)
	h.RecordStandbyAddr("cp-standby:50051")
	cfg, err := loadHAConfig()
	if err != nil {
		t.Fatalf("loadHAConfig: %v", err)
	}

	// Simulate a restart: a fresh HAState resumes from the persisted config.
	h2 := &HAState{}
	h2.ResumeAsLeader(cfg)
	if got := h2.StandbyAddr(); got != "cp-standby:50051" {
		t.Errorf("ResumeAsLeader did not restore the failback target: got %q", got)
	}
}

// advertiseAddr surfaces this node's own gRPC address (captured at
// StartAsStandby) — what the standby sends in the HASync request.
func TestS0_AdvertiseAddr_FromPromoteContext(t *testing.T) {
	h := &HAState{}
	h.mu.Lock()
	h.pc = promoteContext{grpcAddr: "cp-standby:50051", set: true}
	h.mu.Unlock()
	if got := h.advertiseAddr(); got != "cp-standby:50051" {
		t.Errorf("advertiseAddr = %q, want cp-standby:50051", got)
	}
}

// PR #529 review (Codex P2): a standby launched from the HA deploy command
// advertises its BIND address (":50051" / "0.0.0.0:50051"), which the leader
// cannot dial. The leader normalises it against the OBSERVED peer of the
// HASync connection, keeping the advertised port.
func TestS0_NormalizeAdvertisedAddr(t *testing.T) {
	peerCtx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 33445},
	})
	noPeer := context.Background()

	cases := []struct {
		name string
		ctx  context.Context
		adv  string
		want string
	}{
		{"concrete host passes verbatim", peerCtx, "cp-standby.internal:50051", "cp-standby.internal:50051"},
		{"empty-host bind → peer IP + advertised port", peerCtx, ":50051", "198.51.100.7:50051"},
		{"ipv4 wildcard → peer IP + advertised port", peerCtx, "0.0.0.0:50051", "198.51.100.7:50051"},
		{"ipv6 wildcard → peer IP + advertised port", peerCtx, "[::]:50051", "198.51.100.7:50051"},
		{"wildcard with NO observed peer → record nothing", noPeer, ":50051", ""},
		{"empty stays empty", peerCtx, "", ""},
		{"non-host:port passes verbatim", peerCtx, "cp-standby.internal", "cp-standby.internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeAdvertisedAddr(c.ctx, c.adv); got != c.want {
				t.Errorf("normalizeAdvertisedAddr(%q) = %q, want %q", c.adv, got, c.want)
			}
		})
	}
}
