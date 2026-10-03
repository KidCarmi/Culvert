package applianceconsole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Lines is shared by plain text output and the interactive display.
func Lines(s Snapshot) []string {
	lines := []string{"CULVERT APPLIANCE", "Version: " + Clean(s.Version, 70), ""}
	if s.Candidate {
		lines = append(lines, "CANDIDATE BUILD - not qualified for production", "")
	}
	lines = append(lines, Clean(s.Message, 120), "")
	if len(s.ManagementURLs) > 0 {
		lines = append(lines, "Management URL (available when application starts):")
		lines = append(lines, s.ManagementURLs...)
	} else {
		lines = append(lines, "No IPv4 address. Check VM network/DHCP or sign in for recovery.")
	}
	lines = append(lines, "", "Provisioning checkpoints (not application health):")
	for _, step := range s.Steps {
		prefix := "  [ ] "
		if step.State == "recorded" {
			prefix = "  [x] "
		}
		lines = append(lines, prefix+step.Label)
	}
	return append(lines, "", "Client traffic: not verified by this console")
}

// Display clips sanitized status and action hints to the current terminal size.
func Display(s Snapshot, admin, diagnostics bool, height, width int) []string {
	body := Lines(s)
	if diagnostics {
		body = []string{"CULVERT DIAGNOSTICS (no credentials)", "", "Reason: " + s.Reason}
		for _, key := range unitKeys {
			if value, ok := s.Firstboot[key]; ok {
				body = append(body, key+": "+value)
			}
		}
		body = append(body, "", "Check VM network mapping if no address is shown.", "A failed firstboot may need a corrected appliance image.", "A retry does not repair missing image content.")
	}
	footer := []string{"", "[F2 / 2] Sign in  [F4 / 4] Diagnostics  [R] Refresh", "Key-only account? Use SSH with your imported key.", "Console password can be set from authenticated SSH."}
	if admin {
		footer = []string{"", "[1] Network info  [2] Setup access  [3] Diagnostics", "[4] Retry provisioning  [5] Restart/shutdown", "[6] Recovery shell  [Q] Log out"}
	}
	lines := body[:min(len(body), max(0, height-len(footer)-1))]
	lines = append(lines, footer...)
	lines = lines[:min(len(lines), max(0, height-1))]
	for i := range lines {
		lines[i] = Clean(lines[i], max(0, width-1))
	}
	return lines
}

// DecodeKey accepts Linux console and common xterm function-key sequences.
// Unknown/partial escape sequences cannot become a numeric recovery action.
func DecodeKey(raw string) string {
	switch raw {
	case "\x1b[[B", "\x1bOQ", "\x1b[12~":
		return "F2"
	case "\x1b[[D", "\x1bOS", "\x1b[14~":
		return "F4"
	}
	if len(raw) == 1 && raw[0] >= 32 && raw[0] <= 126 {
		return strings.ToUpper(raw)
	}
	if raw == "\x03" || raw == "\x04" {
		return "EXIT"
	}
	return ""
}

// Choice maps a decoded key to an action allowed by the current menu.
func Choice(key string, admin bool) string {
	if key == "R" {
		return "refresh"
	}
	if !admin {
		switch key {
		case "2", "F2":
			return "login"
		case "4", "F4":
			return "diagnostics"
		}
		return ""
	}
	switch key {
	case "Q", "EXIT":
		return "logout"
	case "3":
		return "diagnostics"
	case "1", "2", "4", "5", "6":
		return key
	}
	return ""
}

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
