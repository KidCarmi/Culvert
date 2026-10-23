//go:build linux

// culvert-console is the appliance's Docker-independent local console.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

func main() {
	os.Exit(run())
}

// consoleShutdownGrace bounds how long culvert-console may take to exit after it
// is asked to stop (SIGTERM/SIGHUP/SIGINT). The interactive boot console blocks
// on terminal I/O, and a write to tty1 is NOT interruptible once plymouth takes
// the VT during shutdown — ctx cancellation cannot unblock an in-progress
// write(2) (ASTRA bound PID 6427 to session-2.scope on tty1, SIGTERM→SIGKILL 90s
// apart). systemd's session scope would otherwise wait its DefaultTimeoutStopSec
// (90s) and SIGKILL us, stalling the whole shutdown/reboot. A console carries no
// durable state — exiting promptly on a terminating signal IS correct shutdown
// behaviour, so this makes us honour systemd's contract rather than lowering its
// timeout or waiving the result. The grace sits above interactiveCommand's 2s
// child-kill WaitDelay plus terminal restore, so a clean stop unwinds and exits
// first and never reaches the timer; the timer is the backstop for a write(2)
// caught mid-syscall against a VT that stopped draining.
const consoleShutdownGrace = 5 * time.Second

// machineReadableAdvisoryBudget bounds how long the --json/--text snapshot waits
// for the advisory prerequisites before reporting them not_collected. These
// outputs are read over SSH under a 3s operator-status gate (the QEMU
// controller and culvert-access buffer the whole response until the command
// exits), and the advisory probes are permitted up to 4s on their own — so
// without this bound a slow advisory probe pushes the machine-readable status
// past the gate and the operator reads as "not ready" even while mandatory
// readiness is fine (ASTRA deadline-mismatch finding, PR #1528). The mandatory
// readiness observations have their own 2s bounds and stay live and fail-closed;
// this only caps the advisory wait, it does not increase any timeout.
const machineReadableAdvisoryBudget = 2 * time.Second

// shutdownExitFunc is os.Exit in production; a test replaces it to observe the
// backstop firing without terminating the test binary.
var shutdownExitFunc = os.Exit

// armShutdownExit guarantees the process exits within grace of ctx cancellation
// regardless of which blocking syscall (write, read, or child wait) it is parked
// in. It does NOT touch the terminal: a second goroutine poking tty state would
// race the main goroutine's own deferred restore, and the VT is being torn down
// regardless. The clean path exits before the timer in the common case.
func armShutdownExit(ctx context.Context, grace time.Duration) {
	go func() {
		<-ctx.Done()
		timer := time.NewTimer(grace)
		defer timer.Stop()
		<-timer.C
		shutdownExitFunc(0)
	}()
}

func run() int {
	login := flag.Bool("login", false, "boot console; root on tty1 only")
	admin := flag.Bool("admin", false, "authenticated culvert account menu")
	jsonOutput := flag.Bool("json", false, "read-only status without credentials")
	textOutput := flag.Bool("text", false, "read-only plain text status")
	report := flag.Bool("report", false, "bounded public diagnostic report on stdout; no upload")
	host := flag.String("host", "", "root-only worker or recovery action")
	flag.Parse()
	count := 0
	for _, selected := range []bool{*login, *admin, *jsonOutput, *textOutput, *report, *host != ""} {
		if selected {
			count++
		}
	}
	if count != 1 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "select exactly one of --login, --admin, --json, --text, --report, --host")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	armShutdownExit(ctx, consoleShutdownGrace)
	sources := applianceconsole.Sources{
		Prerequisites: collectPrerequisites, RecoveryFile: hostPublic,
		StateDir: "/var/lib/culvert-appliance/state", BuildFile: "/var/lib/culvert-appliance/build-info.json", NetDir: "/sys/class/net", Probe: runProbe, HostnameFile: "/etc/hostname", ResolverFile: "/run/systemd/resolve/resolv.conf",
	}
	collector := applianceconsole.NewCollector(sources)
	if *host != "" {
		if err := runHost(ctx, *host, collector); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if *report {
		if err := applianceconsole.WriteReport(os.Stdout, collector.Collect(ctx)); err != nil {
			fmt.Fprintln(os.Stderr, "Diagnostic export failed:", err)
			return 1
		}
		return 0
	}
	if *jsonOutput || *textOutput {
		// Machine-readable status is read over SSH under the 3s operator gate;
		// bound the advisory diagnostics so a slow/hung advisory probe cannot
		// push the snapshot past the gate. Mandatory readiness stays live.
		machineReadable := sources
		machineReadable.AdvisoryBudget = machineReadableAdvisoryBudget
		snapshot := applianceconsole.NewCollector(machineReadable).Collect(ctx)
		if *jsonOutput {
			if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
				return 1
			}
		} else {
			fmt.Println(strings.Join(applianceconsole.Lines(snapshot), "\n"))
		}
		return 0
	}
	actions := applianceconsole.NewActions(applianceconsole.ActionDependencies{Authorized: adminIdentity, Collect: collector.Collect, Run: func(args []string) error { return execute(ctx, args) }, Confirm: func(prompt string) (string, error) { return confirm(ctx, prompt) }, Out: os.Stdout})
	if err := runTerminal(ctx, collector, actions, *admin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
