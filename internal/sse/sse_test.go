package sse

// Engine tests, moved in-package from package main's coverage_test.go and
// events_livefeed_test.go with the extraction (ADR-0002).

import (
	"bytes"
	"testing"
)

func TestHub_RegisterUnregister(t *testing.T) {
	h := NewHub()
	ch := make(chan []byte, 4)

	if h.ClientCount() != 0 {
		t.Error("fresh hub should have 0 clients")
	}
	h.Register(ch)
	if h.ClientCount() != 1 {
		t.Errorf("ClientCount = %d, want 1 after register", h.ClientCount())
	}
	h.Unregister(ch)
	if h.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0 after unregister", h.ClientCount())
	}
}

func TestHub_Broadcast(t *testing.T) {
	h := NewHub()
	ch := make(chan []byte, 4)
	h.Register(ch)

	msg := []byte(`{"test":1}`)
	h.Broadcast(msg)

	select {
	case received := <-ch:
		if !bytes.Equal(received, msg) {
			t.Errorf("broadcast received %q, want %q", received, msg)
		}
	default:
		t.Error("broadcast message not received")
	}
	h.Unregister(ch)
}

func TestHub_Broadcast_SlowClient(_ *testing.T) {
	// A full channel (no buffer space) should be skipped gracefully.
	h := NewHub()
	ch := make(chan []byte) // unbuffered — will always be "full"
	h.Register(ch)
	// Broadcast should not block.
	done := make(chan struct{})
	go func() {
		h.Broadcast([]byte("msg"))
		close(done)
	}()
	<-done
	h.Unregister(ch)
}

func TestHub_Broadcast_EvictionCounted(t *testing.T) {
	h := NewHub()
	ch := make(chan []byte) // unbuffered — always "full", triggers eviction
	h.Register(ch)

	before := h.Evicted()
	h.Broadcast([]byte("x"))
	if got := h.Evicted(); got != before+1 {
		t.Errorf("Evicted = %d, want %d", got, before+1)
	}
	if h.ClientCount() != 0 {
		t.Error("evicted client should be removed from the hub")
	}
}

func TestHub_RegisterCap(t *testing.T) {
	h := NewHub()
	h.SetMaxClients(1)
	if !h.Register(make(chan []byte, 1)) {
		t.Fatal("first register under the cap should succeed")
	}
	if h.Register(make(chan []byte, 1)) {
		t.Error("register at the cap should be rejected")
	}
	if h.MaxClients() != 1 {
		t.Errorf("MaxClients = %d, want 1", h.MaxClients())
	}

	// Rejected is handler-owned: it only moves via AddRejected.
	if h.Rejected() != 0 {
		t.Errorf("Rejected = %d before AddRejected, want 0", h.Rejected())
	}
	h.AddRejected()
	if h.Rejected() != 1 {
		t.Errorf("Rejected = %d, want 1", h.Rejected())
	}

	// Cap 0 disables the limit.
	h.SetMaxClients(0)
	if !h.Register(make(chan []byte, 1)) {
		t.Error("register with cap 0 (uncapped) should succeed")
	}
}

func TestHub_EvictForTest(t *testing.T) {
	h := NewHub()
	ch := make(chan []byte, 1)
	h.Register(ch)
	h.EvictForTest(ch)
	if h.ClientCount() != 0 {
		t.Error("EvictForTest should remove the client")
	}
	if _, open := <-ch; open {
		t.Error("EvictForTest should close the channel")
	}
	// Evicting an unknown channel is a no-op (no panic, no double close).
	h.EvictForTest(ch)
}
