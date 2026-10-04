//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceaccess"
)

func TestDispatchCannotExecuteInvalidOrPrivilegedCommand(t *testing.T) {
	for _, command := range []applianceaccess.Command{applianceaccess.Invalid, applianceaccess.Interactive, 255} {
		var out bytes.Buffer
		if err := dispatch(t.Context(), command, &out); err == nil || out.Len() != 0 {
			t.Fatal("non-public command dispatched")
		}
	}
	var out bytes.Buffer
	if err := dispatch(t.Context(), applianceaccess.Help, &out); err != nil || !strings.Contains(out.String(), "read-only") {
		t.Fatal("help requires a host probe")
	}
}

func TestOutputIsBoundedWithoutPartialSuccessfulReport(t *testing.T) {
	var output boundedOutput
	want := strings.Repeat("x", outputLimit+10)
	n, err := output.Write([]byte(want))
	if err != nil || n != len(want) || !output.overflow || len(output.data) != outputLimit {
		t.Fatal("output bound was not enforced")
	}
}

func TestTerminalInputRejectsOverlongControlAndHonorsCancellation(t *testing.T) {
	for _, raw := range []string{"status\n", "status\x00\n", "status\x1b\n", strings.Repeat("x", 97) + "\n"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(raw); err != nil {
			t.Fatal(err)
		}
		got, err := terminalLine(t.Context(), int(r.Fd()))
		r.Close()
		w.Close()
		if raw == "status\n" {
			if err != nil || got != "status" {
				t.Fatal("ordinary command rejected")
			}
		} else if err == nil || got != "" {
			t.Fatal("unsafe line accepted")
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := terminalLine(ctx, int(r.Fd())); err == nil {
		t.Fatal("idle input ignored cancellation")
	}
}
