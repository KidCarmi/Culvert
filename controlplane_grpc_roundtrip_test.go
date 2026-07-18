package main

// controlplane_grpc_roundtrip_test.go — P0-4: REAL CP↔DP gRPC coverage.
//
// Every other cluster test drives the RPCs through the callForTest mock, so the
// actual wire path (service registration, the hand-rolled JSON codec, the
// 128 MiB frame, and gzip) had ZERO coverage. That gap hid a startup panic:
// StartControlPlaneGRPC passed a non-nil *controlPlaneServer as the impl to
// grpc.RegisterService, whose reflect.Implements check panics on a concrete
// (non-interface) HandlerType — so the CP gRPC server could never start. These
// tests stand up the EXACT production registration over an in-memory bufconn
// and prove: (1) the server starts, (2) a >4 MiB snapshot round-trips through
// the raised frame that the old 4 MiB default would have rejected, (3) the
// frame bound is actually enforced on the received message, and (4) the opt-in
// gzip path round-trips.

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startBufconnCP brings up a real gRPC server using the production
// registerConfigService + frame budget over an in-memory listener. The returned
// dialer builds client connections against it. Registration alone guards the
// startup panic — if registerConfigService ever regresses to a non-nil impl,
// grpc.NewServer.RegisterService panics here and the test fails loudly.
func startBufconnCP(t *testing.T) func(t *testing.T, callOpts ...grpc.CallOption) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxClusterGRPCMsgSize),
		grpc.MaxSendMsgSize(maxClusterGRPCMsgSize),
	)
	registerConfigService(srv) // exact production registration (nil impl)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return func(t *testing.T, callOpts ...grpc.CallOption) *grpc.ClientConn {
		t.Helper()
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(callOpts...),
		)
		if err != nil {
			t.Fatalf("dial bufconn CP: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
}

// publishLargeSnapshot puts a snapshot of n blocked hosts into the global store
// and returns the version the store assigned. n=300k yields ~6 MiB of JSON —
// comfortably past gRPC's 4 MiB default receive frame.
func publishLargeSnapshot(n int) int64 {
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = "host-" + strconv.Itoa(i) + ".malware.example"
	}
	globalConfigStore.Update(ConfigSnapshot{BlockedHosts: hosts})
	return globalConfigStore.Get().Version
}

// TestCPGRPC_LargeSnapshotRoundTrip is the core P0-4 proof: a >4 MiB snapshot
// travels CP→DP through the real service over the raised frame, and the SAME
// payload fails against a client pinned to the OLD 4 MiB default — proving the
// frame increase is load-bearing, not cosmetic.
func TestCPGRPC_LargeSnapshotRoundTrip(t *testing.T) {
	dial := startBufconnCP(t)
	const n = 300_000
	wantVer := publishLargeSnapshot(n)

	// New client with the exact production option set (raw codec + 128 MiB
	// frame): must succeed.
	conn := dial(t, clusterClientCallOptions()...)
	var resp json.RawMessage
	if err := conn.Invoke(context.Background(), methodGetConfig, json.RawMessage("{}"), &resp); err != nil {
		t.Fatalf("GetConfig with 128 MiB frame failed: %v", err)
	}
	if len(resp) < 4<<20 {
		t.Fatalf("test payload only %d bytes; must exceed the old 4 MiB default to be meaningful", len(resp))
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if got.Version != wantVer {
		t.Errorf("round-tripped version = %d, want %d", got.Version, wantVer)
	}
	if len(got.BlockedHosts) != n {
		t.Errorf("round-tripped %d hosts, want %d", len(got.BlockedHosts), n)
	}

	// Old-style client pinned to the 4 MiB default: the same response must be
	// rejected with ResourceExhausted. This is the regression the frame bump
	// fixed (and the failure an un-upgraded DP would still see — a CLEAN,
	// per-call error, unlike the gzip-blackout the opt-in default prevents).
	oldConn := dial(t, grpc.ForceCodecV2(rawCodec{}), grpc.MaxCallRecvMsgSize(4<<20))
	var oldResp json.RawMessage
	err := oldConn.Invoke(context.Background(), methodGetConfig, json.RawMessage("{}"), &oldResp)
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("old 4 MiB client: got err=%v (code %s), want ResourceExhausted", err, status.Code(err))
	}
}

// TestCPGRPC_FrameBoundEnforced proves the frame is a real bound: a client with
// a deliberately tiny receive limit rejects a large response. grpc-go enforces
// the limit on the RECEIVED (decompressed) message, so this is also the guard
// that a gzip decompression bomb cannot exceed maxClusterGRPCMsgSize.
func TestCPGRPC_FrameBoundEnforced(t *testing.T) {
	dial := startBufconnCP(t)
	publishLargeSnapshot(50_000) // ~1 MiB, over a 64 KiB limit
	conn := dial(t, grpc.ForceCodecV2(rawCodec{}), grpc.MaxCallRecvMsgSize(64<<10))
	var resp json.RawMessage
	err := conn.Invoke(context.Background(), methodGetConfig, json.RawMessage("{}"), &resp)
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("tiny-limit client: got err=%v (code %s), want ResourceExhausted", err, status.Code(err))
	}
}

// TestCPGRPC_CompressionRoundTrip exercises the opt-in gzip path: a DP that has
// enabled compression sends gzip-encoded requests, and the server (which always
// registers the gzip codec) decompresses and echoes gzip. Proves compression is
// functionally correct when a uniform fleet opts in.
func TestCPGRPC_CompressionRoundTrip(t *testing.T) {
	dial := startBufconnCP(t)
	wantVer := publishLargeSnapshot(100_000)
	conn := dial(t,
		grpc.ForceCodecV2(rawCodec{}),
		grpc.MaxCallRecvMsgSize(maxClusterGRPCMsgSize),
		grpc.UseCompressor(gzip.Name),
	)
	var resp json.RawMessage
	if err := conn.Invoke(context.Background(), methodGetConfig, json.RawMessage("{}"), &resp); err != nil {
		t.Fatalf("gzip GetConfig failed: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal gzip snapshot: %v", err)
	}
	if got.Version != wantVer {
		t.Errorf("gzip round-tripped version = %d, want %d", got.Version, wantVer)
	}
}
