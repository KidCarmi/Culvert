// m2probe runs INSIDE an appliance container (docker exec) and reports what
// the kernel lets that process do, for the #1528 M2 hardening checks:
//
//	afpacket   socket(AF_PACKET, SOCK_RAW): needs CAP_NET_RAW
//	io_uring   io_uring_setup(2): Docker's default seccomp profile refuses it
//	userns     clone(CLONE_NEWUSER): the default profile refuses namespace
//	           creation without CAP_SYS_ADMIN, so a process cannot get
//	           NET_RAW back in a user namespace of its own
//	netns      clone(CLONE_NEWNET): same rule
//
// The namespace requests are made by starting a child (this binary with
// -noop, which exits at once) with the flag on its clone. unshare(2) would
// not do: CLONE_NEWUSER is EINVAL in any multithreaded process, and a Go
// program always is, so it would "refuse" with or without a policy.
//
// It only asks; a socket or ring that does open is closed at once, and a
// child that does start exits immediately, so nothing persists in the
// container. One line on stdout; exit 0 when every request was refused,
// 1 otherwise.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const sysIoUringSetup = 425 // amd64 and arm64

func verdict(err error) string {
	if err == nil {
		return "opened"
	}
	var e syscall.Errno
	if errors.As(err, &e) {
		switch e {
		case syscall.EPERM:
			return "errno:EPERM"
		case syscall.EACCES:
			return "errno:EACCES"
		case syscall.ENOSYS:
			return "errno:ENOSYS"
		case syscall.EINVAL:
			return "errno:EINVAL"
		case syscall.EAFNOSUPPORT:
			return "errno:EAFNOSUPPORT"
		}
		return fmt.Sprintf("errno:%d", int(e))
	}
	return "error:" + err.Error()
}

func status() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "status=unreadable"
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch k {
		case "CapEff", "CapBnd", "Seccomp", "NoNewPrivs":
			out = append(out, strings.ToLower(k)+"="+strings.TrimSpace(v))
		}
	}
	return strings.Join(out, " ")
}

func inNewNamespace(flag uintptr) string {
	cmd := exec.Command("/proc/self/exe", "-noop")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flag}
	return verdict(cmd.Run())
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-noop" {
		return
	}
	res := map[string]string{}

	// ETH_P_ALL (0x0003) in network byte order.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
	if err == nil {
		syscall.Close(fd)
	}
	res["afpacket"] = verdict(err)

	var params [120]byte // struct io_uring_params
	r, _, e := syscall.Syscall(sysIoUringSetup, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if e == 0 {
		syscall.Close(int(r))
		res["io_uring"] = "opened"
	} else {
		res["io_uring"] = verdict(e)
	}

	res["netns"] = inNewNamespace(syscall.CLONE_NEWNET)
	res["userns"] = inNewNamespace(syscall.CLONE_NEWUSER)

	ok := true
	for _, k := range []string{"afpacket", "io_uring", "netns", "userns"} {
		if res[k] == "opened" {
			ok = false
		}
	}
	fmt.Printf("uid=%d afpacket=%s io_uring=%s netns=%s userns=%s %s\n",
		os.Getuid(), res["afpacket"], res["io_uring"], res["netns"], res["userns"], status())
	if !ok {
		os.Exit(1)
	}
}
