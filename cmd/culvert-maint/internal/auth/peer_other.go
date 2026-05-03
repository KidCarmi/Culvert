//go:build !linux

package auth

import (
	"errors"
	"net"
)

// peerCredOS on non-Linux platforms always fails closed. The agent is
// Linux-only by design (D1.6 plan § 1).
func peerCredOS(_ *net.UnixConn) (PeerInfo, error) {
	return PeerInfo{}, errors.New("auth: SO_PEERCRED is Linux-only; agent does not support this platform")
}
