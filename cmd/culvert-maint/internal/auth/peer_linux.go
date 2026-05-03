//go:build linux

package auth

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"syscall"
)

// peerCredOS reads SO_PEERCRED from the underlying Unix socket and
// resolves the UID to a username (best effort).
func peerCredOS(uc *net.UnixConn) (PeerInfo, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerInfo{}, fmt.Errorf("auth: SyscallConn: %w", err)
	}
	var ucred *syscall.Ucred
	var ucredErr error
	cerr := raw.Control(func(fd uintptr) {
		ucred, ucredErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil {
		return PeerInfo{}, fmt.Errorf("auth: control: %w", cerr)
	}
	if ucredErr != nil {
		return PeerInfo{}, fmt.Errorf("auth: SO_PEERCRED: %w", ucredErr)
	}
	pi := PeerInfo{UID: ucred.Uid, GID: ucred.Gid}
	if u, err := user.LookupId(strconv.FormatUint(uint64(ucred.Uid), 10)); err == nil {
		pi.Username = u.Username
	}
	return pi, nil
}
