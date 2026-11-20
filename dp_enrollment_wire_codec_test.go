package main

// dp_enrollment_wire_codec_test.go — `culvert --enroll <url>` must be able to
// enroll against a real Control Plane over the real gRPC wire.
//
// Every Data Plane enrollment path ends in callEnrollRPC (dp_enrollment.go):
// the GUI's "enroll_cmd" (`./culvert -enroll ...`, ui_cluster.go), the
// bootstrap compose document (bootstrap.go) and docker-compose.ha.yml's `dp`
// service (`--enroll $ENROLL_URL`). The ConfigService is JSON over gRPC with
// json.RawMessage request/response values, which gRPC's DEFAULT (protobuf)
// codec cannot marshal — controlplane_codec.go exists for exactly that, and
// the long-lived DP client forces it through clusterClientCallOptions()
// (controlplane_client.go connect()). callEnrollRPC dialed WITHOUT those call
// options, so the request failed client-side before it ever left the node:
//
//	enrollment RPC failed: rpc error: code = Internal desc = grpc: error while
//	marshaling: proto: failed to marshal, message is jsontext.Value, want proto.Message
//
// runEnrollmentMode turns that into log.Fatalf, so no DP could enroll at all.
// The existing enrollment tests drive admitEnrollment/Enroll in-process or
// point runEnrollment at a closed port, so none of them ever marshaled a
// request; this one stands up the production ConfigService registration on a
// loopback TCP listener and enrolls through the real client.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// startLoopbackEnrollCP serves the production ConfigService (Enroll included)
// on a real 127.0.0.1 TCP listener, against the fresh cluster store and CA
// that swapEnrollFixture installs. Returns the CP's host:port.
func startLoopbackEnrollCP(t *testing.T) string {
	t.Helper()
	swapEnrollFixture(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Same server bounds as StartControlPlaneGRPC.
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxClusterInboundMsgSize),
		grpc.MaxSendMsgSize(maxClusterGRPCMsgSize),
	)
	registerConfigService(srv)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

// enrollURLForLoopbackCP mints a single-use token on the fixture's cluster
// store and returns the enrollment URL the CP GUI hands an operator, CA
// fingerprint included (the same format ui_cluster.go and bootstrap.go emit).
func enrollURLForLoopbackCP(t *testing.T, cpAddr string) string {
	t.Helper()
	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	block, _ := pem.Decode(globalClusterCA.CACertPEM())
	if block == nil {
		t.Fatal("fixture CA has no PEM block")
	}
	fp := sha256.Sum256(block.Bytes)
	return "culvert://enroll/" + cpAddr + "/" + token + "?ca-fp=sha256:" + hex.EncodeToString(fp[:])
}

func TestRunEnrollment_EnrollsOverRealGRPCWire(t *testing.T) {
	t.Chdir(t.TempDir()) // persistEnrollCerts writes next to the process CWD
	cpAddr := startLoopbackEnrollCP(t)
	url := enrollURLForLoopbackCP(t, cpAddr)

	ec, err := runEnrollment(url)
	if err != nil {
		t.Fatalf("enrollment against a live Control Plane with a fresh, valid token failed: %v", err)
	}

	// The CP registered exactly this node and spent the token.
	node, ok := globalClusterStore.GetNode(ec.NodeID)
	if !ok {
		t.Fatalf("CP has no registration for enrolled node %q", ec.NodeID)
	}
	if node.Status != "connected" || node.CertSerial == "" {
		t.Errorf("registration = status %q serial %q, want connected with a serial", node.Status, node.CertSerial)
	}
	if _, err := runEnrollment(enrollURLForLoopbackCP(t, cpAddr)); err == nil {
		t.Error("a second enrollment of a live, registered node ID was accepted")
	}

	// The DP persisted the CP-issued material it will dial with.
	if ec.CPAddr != cpAddr {
		t.Errorf("saved CP address = %q, want %q", ec.CPAddr, cpAddr)
	}
	for _, p := range []string{ec.CertFile, ec.KeyFile, ec.CAFile, enrollmentConfigFile} {
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("enrollment did not persist %s: %v", p, err)
		}
	}
	saved, err := loadEnrollmentConfig()
	if err != nil {
		t.Fatalf("load saved enrollment config: %v", err)
	}
	if *saved != *ec {
		t.Errorf("saved enrollment config %+v differs from the returned one %+v", *saved, *ec)
	}
	ca, err := os.ReadFile(ec.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, globalClusterCA.CACertPEM()) {
		t.Error("persisted cluster CA is not the Control Plane's CA")
	}
}
