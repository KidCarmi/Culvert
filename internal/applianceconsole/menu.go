package applianceconsole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

func canRetry(s Snapshot) bool {
	state := s.Firstboot["ActiveState"]
	return (state == "failed" || state == "inactive") && !s.recorded("complete")
}

// ActionDependencies are supplied by the authenticated terminal process.
// Run and Confirm are synchronous: they exclusively own terminal input while
// called, and must finish before the caller redraws or starts another action.
type ActionDependencies struct {
	Authorized func() bool
	Collect    func(context.Context) Snapshot
	Run        func([]string) error
	Confirm    func(string) (string, error)
	Out        io.Writer
}

// Actions owns recovery policy, not terminal I/O, process lifetime or sudo rules.
type Actions struct {
	deps ActionDependencies
}

// NewActions copies dependencies once; no recovery action runs at construction.
func NewActions(deps ActionDependencies) Actions {
	return Actions{deps: deps}
}

// Apply checks the effective identity before dispatching any fixed command.
func (a Actions) Apply(ctx context.Context, choice string) error {
	if !a.deps.Authorized() {
		return errors.New("sign in as culvert before using recovery actions")
	}
	const bin = "/opt/culvert-appliance/bin/"
	switch choice {
	case "1":
		if err := a.deps.Run([]string{bin + "culvert-net", "show"}); err != nil {
			return fmt.Errorf("show network: %w", err)
		}
		_, err := fmt.Fprintln(a.deps.Out, "\nUse the recovery shell to change network settings with culvert-net.")
		return err
	case "2":
		return a.deps.Run([]string{"/usr/bin/sudo", "--", bin + "culvert-status"})
	case "4":
		return a.retry(ctx)
	case "5":
		return a.power()
	case "6":
		if _, err := fmt.Fprintln(a.deps.Out, "Recovery shell. Type exit to return to the menu."); err != nil {
			return fmt.Errorf("display shell instructions: %w", err)
		}
		return a.deps.Run([]string{"/bin/bash", "--noprofile", "--norc"})
	default:
		return errors.New("unknown recovery action")
	}
}

func (a Actions) retry(ctx context.Context) error {
	if !canRetry(a.deps.Collect(ctx)) {
		return errors.New("retry refused: provisioning is running, complete, or unknown")
	}
	answer, err := a.deps.Confirm("Type RETRY to resume incomplete provisioning: ")
	if err != nil {
		return fmt.Errorf("confirm retry: %w", err)
	}
	if answer != "RETRY" {
		return nil
	}
	if !canRetry(a.deps.Collect(ctx)) {
		return errors.New("state changed; no retry dispatched")
	}
	if err := a.deps.Run([]string{"/usr/bin/sudo", "--", "/usr/bin/systemctl", "reset-failed", "culvert-firstboot.service"}); err != nil {
		return fmt.Errorf("clear failed provisioning: %w", err)
	}
	if err := a.deps.Run([]string{"/usr/bin/sudo", "--", "/usr/bin/systemctl", "start", "--no-block", "culvert-firstboot.service"}); err != nil {
		return fmt.Errorf("start provisioning: %w", err)
	}
	return nil
}

func (a Actions) power() error {
	answer, err := a.deps.Confirm("Type REBOOT or POWEROFF (anything else cancels): ")
	if err != nil {
		return fmt.Errorf("confirm power action: %w", err)
	}
	if answer != "REBOOT" && answer != "POWEROFF" {
		return nil
	}
	if err := a.deps.Run([]string{"/usr/bin/sudo", "--", "/usr/bin/systemctl", strings.ToLower(answer)}); err != nil {
		return fmt.Errorf("request power action: %w", err)
	}
	return nil
}
