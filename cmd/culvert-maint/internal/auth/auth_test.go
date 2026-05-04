package auth

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewPolicy_AcceptsUIDsAndUsernames(t *testing.T) {
	// Resolve current user; should always succeed.
	myUID := strconv.Itoa(os.Geteuid())
	p, err := NewPolicy([]string{myUID})
	if err != nil {
		t.Fatalf("NewPolicy(uid): %v", err)
	}
	if err := p.Allow(PeerInfo{UID: uint32(os.Geteuid())}); err != nil { //nolint:gosec // uid range fits uint32 on Linux
		t.Errorf("self-UID should be allowed: %v", err)
	}
}

func TestNewPolicy_RejectsEmptyAllowlist(t *testing.T) {
	if _, err := NewPolicy(nil); err == nil {
		t.Error("empty allowlist should error")
	}
	if _, err := NewPolicy([]string{}); err == nil {
		t.Error("empty allowlist should error")
	}
	if _, err := NewPolicy([]string{""}); err == nil {
		t.Error("only-blank entries should error (effectively empty)")
	}
}

func TestNewPolicy_RejectsUnknownUsername(t *testing.T) {
	_, err := NewPolicy([]string{"definitely_not_a_real_user_xyz_123"})
	if err == nil {
		t.Error("unknown username should error")
	}
}

func TestPolicy_Allow_RejectsForeignUID(t *testing.T) {
	myUID := strconv.Itoa(os.Geteuid())
	p, err := NewPolicy([]string{myUID})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	// 99999 is almost certainly not the current process UID.
	err = p.Allow(PeerInfo{UID: 99999, Username: "interloper"})
	if err == nil {
		t.Error("expected ErrUnauthorized for foreign UID")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("error should wrap ErrUnauthorized, got: %v", err)
	}
	if !strings.Contains(err.Error(), "interloper") {
		t.Errorf("error should mention foreign username, got: %v", err)
	}
}

func TestPeerInfo_String(t *testing.T) {
	if got := (PeerInfo{UID: 1234, Username: "culvert-cp"}).String(); got != "uid=1234,user=culvert-cp" {
		t.Errorf("got %q", got)
	}
	if got := (PeerInfo{UID: 1234}).String(); got != "uid=1234" {
		t.Errorf("got %q", got)
	}
}

// TestPeer_OnUDS_ReturnsCallingProcessUID validates the SO_PEERCRED
// integration by setting up a UDS listener in the same process and
// connecting to it from the same process. The peer's UID must match the
// test process's effective UID.
func TestPeer_OnUDS_ReturnsCallingProcessUID(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", sock) //nolint:noctx // test fixture; ListenConfig adds no value here
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	var (
		serverPeer PeerInfo
		serverErr  error
		wg         sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer func() { _ = conn.Close() }()
		serverPeer, serverErr = Peer(conn)
	}()

	// Connect.
	c, err := net.DialTimeout("unix", sock, 2*time.Second) //nolint:noctx // test fixture
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Peer: %v", serverErr)
	}
	if serverPeer.UID != uint32(os.Geteuid()) { //nolint:gosec // uid range fits uint32 on Linux
		t.Errorf("peer UID: got %d want %d", serverPeer.UID, os.Geteuid())
	}
}

func TestPeer_RejectsNonUDSConnection(t *testing.T) {
	// Set up a TCP listener in this process.
	tcp, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test fixture
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer func() { _ = tcp.Close() }()

	var serverErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := tcp.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer func() { _ = conn.Close() }()
		_, serverErr = Peer(conn)
	}()

	c, err := net.DialTimeout("tcp", tcp.Addr().String(), 2*time.Second) //nolint:noctx // test fixture
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	_ = c.Close()
	<-done
	if serverErr == nil {
		t.Fatal("Peer must reject TCP connection (UDS only)")
	}
	if !strings.Contains(serverErr.Error(), "UnixConn") {
		t.Errorf("error should mention UnixConn, got: %v", serverErr)
	}
}
