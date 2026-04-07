package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"
)

// ── Leader Election via flock() ─────────────────────────────────────────────
//
// Active/Passive HA for the Control Plane. Both CP instances share the same
// storage directory (NFS, EFS, GlusterFS, etc.). Leadership is determined by
// an exclusive file lock (flock) on a lock file — the kernel guarantees only
// one process can hold the lock at any time, eliminating split-brain.
//
// When the active CP crashes, the OS releases the flock automatically. The
// standby CP acquires it within seconds and promotes itself to leader.

// HAState tracks the HA status of this Control Plane instance.
type HAState struct {
	mu       sync.RWMutex
	role     string    // "leader", "standby", or "" (HA disabled)
	lockFile *os.File  // held while leader
	lockPath string    // path to the lock file
	peerAddr string    // optional: address of the other CP for display
	since    time.Time // when current role was acquired
	stopCh   chan struct{}
}

var globalHA = &HAState{}

// HAStatus returns a snapshot of the current HA state for API/UI consumption.
type HAStatus struct {
	Enabled  bool   `json:"enabled"`
	Role     string `json:"role"`               // "leader", "standby", or ""
	Since    string `json:"since,omitempty"`     // RFC3339
	PeerAddr string `json:"peer_addr,omitempty"` // other CP address
	LockPath string `json:"lock_path,omitempty"` // lock file path
}

func (h *HAState) Status() HAStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := HAStatus{
		Enabled:  h.role != "",
		Role:     h.role,
		PeerAddr: h.peerAddr,
		LockPath: h.lockPath,
	}
	if !h.since.IsZero() {
		s.Since = h.since.Format(time.RFC3339)
	}
	return s
}

// IsLeader returns true if this CP holds the leader lock.
func (h *HAState) IsLeader() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.role == "leader"
}

// tryAcquireLock attempts a non-blocking flock on the lock file.
// Returns true if the lock was acquired (this instance is now leader).
func (h *HAState) tryAcquireLock() (bool, error) {
	if h.lockFile != nil {
		return true, nil // already holding the lock
	}
	f, err := os.OpenFile(h.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, fmt.Errorf("open lock file: %w", err)
	}
	// LOCK_EX | LOCK_NB: exclusive, non-blocking.
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		f.Close()
		// EWOULDBLOCK means another process holds the lock.
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return false, nil
		}
		return false, fmt.Errorf("flock: %w", err)
	}
	// Write our PID + timestamp into the lock file for debugging.
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	info := map[string]any{
		"pid":       os.Getpid(),
		"acquired":  time.Now().Format(time.RFC3339),
		"grpc_addr": clusterRole.grpcAddr,
	}
	enc, _ := json.Marshal(info)
	_, _ = f.Write(enc)
	_ = f.Sync()

	h.lockFile = f
	return true, nil
}

// releaseLock releases the flock and closes the lock file.
func (h *HAState) releaseLock() {
	if h.lockFile != nil {
		_ = syscall.Flock(int(h.lockFile.Fd()), syscall.LOCK_UN)
		_ = h.lockFile.Close()
		h.lockFile = nil
	}
}

// StartLeaderElection begins the leader election loop. It tries to acquire
// the flock immediately. If successful, onPromote is called to start the gRPC
// server. If not, it retries every pollInterval until the lock is acquired.
//
// When the leader lock is lost (e.g. lock file deleted), the CP demotes
// itself and calls onDemote.
func (h *HAState) StartLeaderElection(lockPath, peerAddr string, pollInterval time.Duration,
	onPromote func() error, onDemote func()) {
	h.mu.Lock()
	h.lockPath = lockPath
	h.peerAddr = peerAddr
	h.role = "standby"
	h.since = time.Now()
	h.stopCh = make(chan struct{})
	h.mu.Unlock()

	logger.Printf("HA: starting leader election (lock=%s, poll=%s)", lockPath, pollInterval)

	go h.electionLoop(pollInterval, onPromote, onDemote)
}

func (h *HAState) electionLoop(interval time.Duration, onPromote func() error, onDemote func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Try immediately on startup.
	h.tryPromote(onPromote)

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.mu.RLock()
			role := h.role
			h.mu.RUnlock()

			if role == "leader" {
				// Verify we still hold the lock by re-checking.
				// If someone deleted the lock file, we need to re-acquire.
				if _, err := os.Stat(h.lockPath); os.IsNotExist(err) {
					logger.Printf("HA: lock file disappeared — demoting")
					h.demote(onDemote)
				}
			} else {
				h.tryPromote(onPromote)
			}
		}
	}
}

func (h *HAState) tryPromote(onPromote func() error) {
	acquired, err := h.tryAcquireLock()
	if err != nil {
		logger.Printf("HA: lock attempt error: %v", err)
		return
	}
	if !acquired {
		return
	}
	// We got the lock — promote to leader.
	logger.Printf("HA: acquired leader lock — promoting to active CP")
	if err := onPromote(); err != nil {
		logger.Printf("HA: promote callback failed: %v — releasing lock", err)
		h.releaseLock()
		return
	}
	h.mu.Lock()
	h.role = "leader"
	h.since = time.Now()
	h.mu.Unlock()
	logger.Printf("HA: now serving as leader")
}

func (h *HAState) demote(onDemote func()) {
	h.mu.Lock()
	h.role = "standby"
	h.since = time.Now()
	h.mu.Unlock()
	h.releaseLock()
	onDemote()
	logger.Printf("HA: demoted to standby")
}

// Stop terminates the election loop and releases the lock.
func (h *HAState) Stop() {
	h.mu.Lock()
	if h.stopCh != nil {
		close(h.stopCh)
		h.stopCh = nil
	}
	h.mu.Unlock()
	h.releaseLock()
}

// ── Health Endpoint ─────────────────────────────────────────────────────────

// apiHealthz is an unauthenticated health-check endpoint for load balancers.
// Returns 200 if this CP is the leader (or if HA is disabled), 503 otherwise.
// Load balancers should route DP traffic only to the 200-returning CP.
func apiHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := globalHA.Status()
	// If HA is not enabled, this node is standalone — always healthy.
	if !status.Enabled {
		jsonOK(w, map[string]any{"status": "ok", "role": "standalone", "leader": true})
		return
	}
	if status.Role == "leader" {
		jsonOK(w, map[string]any{"status": "ok", "role": "leader", "leader": true, "since": status.Since})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	resp, _ := json.Marshal(map[string]any{"status": "standby", "role": "standby", "leader": false})
	_, _ = w.Write(resp)
}

// apiClusterHA returns the HA status for the admin UI.
func apiClusterHA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, globalHA.Status())
}
