//go:build linux

package main

import (
	"context"
	"io"
	"os/exec"
	"time"
)

const maxOutput = 65536

// probeEnvironment is an explicit child environment, never inherited credentials or proxies.
func probeEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
}

type limitedOutput struct {
	data     []byte
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if n > maxOutput-len(b.data) {
		b.overflow = true
	}
	if remaining := maxOutput - len(b.data); remaining > 0 {
		b.data = append(b.data, p[:min(len(p), remaining)]...)
	}
	return n, nil
}

// runProbe bounds both elapsed time and retained output. Failure is unknown,
// not an empty successful response. Arbitrary stderr never enters status output.
func runProbe(parent context.Context, args []string) string {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	// #nosec G204 -- argv comes only from fixed collector probes, never keyboard or metadata.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = probeEnvironment()
	cmd.WaitDelay = 250 * time.Millisecond
	var output limitedOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if cmd.Run() != nil || output.overflow {
		return ""
	}
	return string(output.data)
}
