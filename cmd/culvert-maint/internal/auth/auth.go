// Package auth implements the agent's local-socket authentication gate.
//
// Default transport is the Unix domain socket at /run/culvert-maint/culvert-maint.sock.
// On Linux the gate uses SO_PEERCRED to read the connecting peer's UID
// and gates against an operator-configured allowlist of UIDs / usernames.
// Anyone not on the allowlist is rejected with HTTP 403.
//
// On non-Linux build targets, the SO_PEERCRED path is unimplemented and
// the gate fails closed by default — the agent intentionally does not
// support deployment outside Linux per the D1.6 design.
package auth

import (
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
)

// PeerInfo describes the connecting peer at the OS level.
type PeerInfo struct {
	UID      uint32
	GID      uint32
	Username string // resolved from UID via os/user; "" if unresolvable
}

// String renders an audit-stable peer identity, e.g. "uid=1000,user=culvert-cp".
func (p PeerInfo) String() string {
	if p.Username != "" {
		return fmt.Sprintf("uid=%d,user=%s", p.UID, p.Username)
	}
	return fmt.Sprintf("uid=%d", p.UID)
}

// ErrUnauthorized is returned by Allow when a peer is not on the
// allowlist. Server maps this to HTTP 403.
var ErrUnauthorized = errors.New("auth: peer not in allowlist")

// Policy gates a connecting peer.
type Policy struct {
	uids  map[uint32]struct{}
	users map[string]struct{}
}

// NewPolicy compiles the operator-configured allowlist from a list of
// UID-or-username tokens. Pure numeric entries are treated as UIDs;
// everything else is treated as a username and resolved at policy-build
// time.
func NewPolicy(entries []string) (*Policy, error) {
	p := &Policy{
		uids:  map[uint32]struct{}{},
		users: map[string]struct{}{},
	}
	for _, raw := range entries {
		if raw == "" {
			continue
		}
		if uid, err := strconv.ParseUint(raw, 10, 32); err == nil {
			p.uids[uint32(uid)] = struct{}{}
			continue
		}
		// Username — resolve to a UID at policy-build time.
		u, err := user.Lookup(raw)
		if err != nil {
			return nil, fmt.Errorf("auth: cannot resolve user %q: %w", raw, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("auth: cannot parse uid for %q: %w", raw, err)
		}
		p.uids[uint32(uid)] = struct{}{}
		p.users[u.Username] = struct{}{}
	}
	if len(p.uids) == 0 {
		return nil, errors.New("auth: allowlist is empty (specify CP UID or username)")
	}
	return p, nil
}

// Allow checks the peer against the allowlist. Returns nil iff allowed,
// ErrUnauthorized otherwise.
func (p *Policy) Allow(peer PeerInfo) error {
	if _, ok := p.uids[peer.UID]; ok {
		return nil
	}
	return fmt.Errorf("%w (uid=%d, user=%q)", ErrUnauthorized, peer.UID, peer.Username)
}

// Peer returns the PeerInfo for a UDS connection, looking up SO_PEERCRED
// on Linux. On other platforms, returns an error and the caller should
// fail closed.
func Peer(conn net.Conn) (PeerInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerInfo{}, errors.New("auth: connection is not a UnixConn (UDS only)")
	}
	return peerCredOS(uc)
}
