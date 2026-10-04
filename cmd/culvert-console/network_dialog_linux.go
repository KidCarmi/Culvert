//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/appliancehost"
)

func networkDialog(ctx context.Context) error {
	if runProbe(ctx, []string{"/usr/bin/systemctl", "is-active", "culvert-console-host.service"}) != "active\n" {
		return errors.New("network recovery worker is not active; no changes queued")
	}
	var id, phase string
	if err := hostSession(func(s *appliancehost.Session) error {
		if t := s.State.Network; t != nil && t.Phase != "confirmed" && t.Phase != "rolled_back" {
			id, phase = t.ID, t.Phase
		}
		return nil
	}); err != nil {
		return err
	}
	if phase == "conflict" {
		return errors.New("network files changed externally; backup preserved in private/state.json; recover through the root shell")
	}
	if id == "" {
		var err error
		id, err = queueNetwork(ctx)
		if err != nil || id == "" {
			return err
		}
	}
	fmt.Println("Network operation:", id)
	fmt.Println("Verify access from another client. Reopen this menu after reconnecting to confirm.")
	return confirmNetwork(ctx, id)
}

func queueNetwork(ctx context.Context) (string, error) {
	request, err := readNetworkRequest(ctx)
	if err != nil {
		return "", err
	}
	candidate, err := appliancehost.Candidate(request)
	if err != nil {
		return "", err
	}
	fmt.Printf("Interface %s, mode %s, address %s, gateway %s, DNS %s\n", request.Interface, request.Mode, request.Address, request.Gateway, strings.Join(request.DNS, ","))
	answer, err := confirm(ctx, "Type APPLY to test for 120 seconds (disconnect or timeout rolls back): ")
	if err != nil || answer != "APPLY" {
		return "", err
	}
	var id string
	err = hostSession(func(s *appliancehost.Session) error {
		if err := networkPrerequisites(request.Interface); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		id, err = s.Stage(candidate)
		return err
	})
	return id, err
}

func readNetworkRequest(ctx context.Context) (appliancehost.NetworkRequest, error) {
	var r appliancehost.NetworkRequest
	var err error
	r.Interface, err = confirm(ctx, "Physical interface name (for example ens160): ")
	if err != nil {
		return r, err
	}
	r.Mode, err = confirm(ctx, "Mode (dhcp or static): ")
	if err != nil || r.Mode != "static" {
		return r, err
	}
	r.Address, err = confirm(ctx, "IPv4 address/prefix: ")
	if err != nil {
		return r, err
	}
	r.Gateway, err = confirm(ctx, "IPv4 gateway: ")
	if err != nil {
		return r, err
	}
	dns, err := confirm(ctx, "IPv4 DNS servers, comma separated (1-3): ")
	if err != nil {
		return r, err
	}
	r.DNS = strings.Split(dns, ",")
	return r, nil
}

func networkPrerequisites(iface string) error {
	const interfaces = "/sys/class/net"
	st, err := os.Lstat("/var/lib/culvert-appliance/state/ovf.done")
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("first-boot network configuration has not completed")
	}
	if _, err := os.Stat(filepath.Join(interfaces, iface, "device")); err != nil {
		return errors.New("selected interface is not a physical device")
	}
	return hostNetplan().Preflight(iface)
}

func confirmNetwork(ctx context.Context, id string) error {
	wait, cancel := context.WithTimeout(ctx, 125*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		phase := ""
		err := hostSession(func(s *appliancehost.Session) error {
			if t := s.State.Network; t != nil && t.ID == id {
				phase = t.Phase
			}
			return nil
		})
		if err == nil {
			if phase == "testing" {
				break
			}
			if phase == "rolled_back" || phase == "confirmed" || phase == "conflict" || phase == "" {
				return fmt.Errorf("network operation state: %s", phase)
			}
		}
		select {
		case <-wait.Done():
			return errors.New("confirmation unavailable; worker retains responsibility for rollback")
		case <-ticker.C:
		}
	}
	answer, err := confirm(ctx, "Type CONFIRM after verifying the new connection (anything else leaves rollback armed): ")
	if err != nil {
		return err
	}
	if answer != "CONFIRM" {
		return nil
	}
	if err := hostSession(func(s *appliancehost.Session) error { return s.Confirm(id) }); err != nil {
		return err
	}
	fmt.Println("Network configuration confirmed.")
	return nil
}
