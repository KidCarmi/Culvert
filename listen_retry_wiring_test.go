package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
	"time"
)

// IM-027 / ADR-0064. The Control Plane gRPC and scan-sidecar rebind ladders
// and the Control Plane gRPC and SOCKS5 sleep clamps are bindings to
// internal/listenretry. This file pins what each binding answers, with the
// listener's own constants, over a fixed input grid.
//
// The digests below were captured by running this test against main
// (46b4ffa6e) BEFORE the four functions were bound, when each still carried
// its own copy of the rule, and the test passed there. A digest that changes
// means a listener's retry cadence or its page latency changed.

// listenRetryGrid is the fixed set of durations the verdict tables walk: the
// boundaries of every constant the four functions read (1 s initial, 30 s
// ceiling and threshold, 100 ms floor), the jittered ceiling (36 s), both
// signs, zero, and the int64 limits where the doubling and the subtraction
// wrap. A deterministic generator adds values spread over nanoseconds to
// minutes so the table does not only hold hand-picked points.
func listenRetryGrid() []time.Duration {
	grid := []time.Duration{
		math.MinInt64, math.MinInt64 + 1, -time.Hour, -30 * time.Second, -time.Second, -1,
		0, 1, time.Microsecond, time.Millisecond,
		99 * time.Millisecond, 100*time.Millisecond - 1, 100 * time.Millisecond, 100*time.Millisecond + 1,
		500 * time.Millisecond, time.Second - 1, time.Second, time.Second + 1,
		2 * time.Second, 4 * time.Second, 8 * time.Second,
		15*time.Second - 1, 15 * time.Second, 15*time.Second + 1, 16 * time.Second,
		24 * time.Second, 29 * time.Second, 30*time.Second - 100*time.Millisecond,
		30*time.Second - 1, 30 * time.Second, 30*time.Second + 1,
		31 * time.Second, 36 * time.Second, time.Minute, time.Hour,
		math.MaxInt64 / 2, math.MaxInt64/2 + 1, math.MaxInt64 - 1, math.MaxInt64,
	}
	// SplitMix64: fixed seed, no dependency on math/rand's algorithm.
	state := uint64(0x1F2E3D4C5B6A7988)
	next := func() uint64 {
		state += 0x9E3779B97F4A7C15
		z := state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	for i := 0; i < 160; i++ {
		// Up to ~70 s, the range the supervisors live in.
		grid = append(grid, time.Duration(next()%uint64(70*time.Second)))
	}
	for i := 0; i < 20; i++ {
		grid = append(grid, time.Duration(int64(next()))) // #nosec G115 -- the wrap is wanted: any int64 of either sign
	}
	return grid
}

func ladderDigest(next func(time.Duration) time.Duration) (digest string, rows int) {
	h := sha256.New()
	for _, cur := range listenRetryGrid() {
		fmt.Fprintf(h, "%d>%d\n", int64(cur), int64(next(cur)))
		rows++
	}
	return hex.EncodeToString(h.Sum(nil)), rows
}

func clampDigest(clamp func(wait, failingFor time.Duration) time.Duration) (digest string, rows int) {
	h := sha256.New()
	grid := listenRetryGrid()
	for _, wait := range grid {
		for _, failingFor := range grid {
			fmt.Fprintf(h, "%d,%d>%d\n", int64(wait), int64(failingFor), int64(clamp(wait, failingFor)))
			rows++
		}
	}
	return hex.EncodeToString(h.Sum(nil)), rows
}

func TestListenRetryWiring_LadderVerdictsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		next func(time.Duration) time.Duration
		want string
	}{
		{"cp_grpc", nextCPGRPCBindBackoff, "5b9aa4107c6f3605a4dc41dddb8e8f7e447f65b2488bab86820b88003e7b9d32"},
		{"scan_svc", nextScanSvcBindBackoff, "5b9aa4107c6f3605a4dc41dddb8e8f7e447f65b2488bab86820b88003e7b9d32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, rows := ladderDigest(tc.next)
			if rows != 219 {
				t.Fatalf("walked %d inputs, want 219: the grid changed, so the digest is not comparable", rows)
			}
			if got != tc.want {
				t.Fatalf("ladder verdict digest = %s, want %s (captured from main before the bind)", got, tc.want)
			}
		})
	}
}

func TestListenRetryWiring_ClampVerdictsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clamp func(wait, failingFor time.Duration) time.Duration
		want  string
	}{
		{"cp_grpc", clampCPGRPCBindSleep, "54dc68e46d2a6d4958e2f3409e3daf5cc0240e468ec6c5923ac7ce44767a551e"},
		{"socks5", clampSOCKS5BindSleep, "54dc68e46d2a6d4958e2f3409e3daf5cc0240e468ec6c5923ac7ce44767a551e"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, rows := clampDigest(tc.clamp)
			if rows != 219*219 {
				t.Fatalf("walked %d inputs, want %d: the grid changed, so the digest is not comparable", rows, 219*219)
			}
			if got != tc.want {
				t.Fatalf("clamp verdict digest = %s, want %s (captured from main before the bind)", got, tc.want)
			}
		})
	}
}

// The digests would not notice a binding handed another listener's constants
// if the two listeners' constants happened to be equal, which today they are
// (1 s, 30 s, 30 s, 100 ms everywhere). These name each listener's own
// constants, so a later change to one listener's ceiling or threshold moves
// that listener and only that listener.
func TestListenRetryWiring_EachBindingReadsItsOwnConstants(t *testing.T) {
	if got := nextCPGRPCBindBackoff(0); got != cpGRPCBindBackoffInitial {
		t.Errorf("Control Plane first rung = %s, want cpGRPCBindBackoffInitial %s", got, cpGRPCBindBackoffInitial)
	}
	if got := nextCPGRPCBindBackoff(cpGRPCBindBackoffMax); got != cpGRPCBindBackoffMax {
		t.Errorf("Control Plane rung above the ceiling = %s, want cpGRPCBindBackoffMax %s", got, cpGRPCBindBackoffMax)
	}
	if got := nextScanSvcBindBackoff(0); got != scanSvcBindBackoffInitial {
		t.Errorf("scan sidecar first rung = %s, want scanSvcBindBackoffInitial %s", got, scanSvcBindBackoffInitial)
	}
	if got := nextScanSvcBindBackoff(scanSvcBindBackoffMax); got != scanSvcBindBackoffMax {
		t.Errorf("scan sidecar rung above the ceiling = %s, want scanSvcBindBackoffMax %s", got, scanSvcBindBackoffMax)
	}

	// One nanosecond short of the threshold: the remaining time is below the
	// floor, so the sleep is the floor. At the threshold the clamp is off.
	if got := clampCPGRPCBindSleep(time.Hour, cpGRPCUnavailableAfter-1); got != cpGRPCBindClampFloor {
		t.Errorf("Control Plane clamp just short of the threshold = %s, want cpGRPCBindClampFloor %s", got, cpGRPCBindClampFloor)
	}
	if got := clampCPGRPCBindSleep(time.Hour, cpGRPCUnavailableAfter); got != time.Hour {
		t.Errorf("Control Plane clamp at the threshold = %s, want the sleep unchanged", got)
	}
	if got := clampSOCKS5BindSleep(time.Hour, socks5BindUnavailableAfter-1); got != socks5BindClampFloor {
		t.Errorf("SOCKS5 clamp just short of the threshold = %s, want socks5BindClampFloor %s", got, socks5BindClampFloor)
	}
	if got := clampSOCKS5BindSleep(time.Hour, socks5BindUnavailableAfter); got != time.Hour {
		t.Errorf("SOCKS5 clamp at the threshold = %s, want the sleep unchanged", got)
	}
}
