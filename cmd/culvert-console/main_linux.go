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

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

func main() {
	os.Exit(run())
}

func run() int {
	login := flag.Bool("login", false, "boot console; root on tty1 only")
	admin := flag.Bool("admin", false, "authenticated culvert account menu")
	jsonOutput := flag.Bool("json", false, "read-only status without credentials")
	textOutput := flag.Bool("text", false, "read-only plain text status")
	flag.Parse()
	count := 0
	for _, selected := range []bool{*login, *admin, *jsonOutput, *textOutput} {
		if selected {
			count++
		}
	}
	if count != 1 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "select exactly one of --login, --admin, --json, --text")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	collector := applianceconsole.NewCollector(applianceconsole.Sources{
		StateDir: "/var/lib/culvert-appliance/state", BuildFile: "/var/lib/culvert-appliance/build-info.json", NetDir: "/sys/class/net", Probe: runProbe,
	})
	if *jsonOutput || *textOutput {
		snapshot := collector.Collect(ctx)
		if *jsonOutput {
			if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
				return 1
			}
		} else {
			fmt.Println(strings.Join(applianceconsole.Lines(snapshot), "\n"))
		}
		return 0
	}
	actions := applianceconsole.NewActions(applianceconsole.ActionDependencies{Authorized: adminIdentity, Collect: collector.Collect, Run: func(args []string) error { return execute(ctx, args) }, Confirm: confirm, Out: os.Stdout})
	if err := runTerminal(ctx, collector, actions, *admin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
