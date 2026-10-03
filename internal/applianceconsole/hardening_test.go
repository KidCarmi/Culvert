package applianceconsole

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetryRequiresKnownIncompleteState(t *testing.T) {
	for _, step := range []string{"", "unknown", "recorded"} {
		s := retrySnapshot("inactive")
		s.Steps[0].State = step
		if canRetry(s) {
			t.Fatalf("retry accepted completion state %q", step)
		}
	}
	for _, load := range []string{"", "not-found", "masked", "error"} {
		s := retrySnapshot("failed")
		s.Firstboot["LoadState"] = load
		if canRetry(s) {
			t.Fatalf("retry accepted unit state %q", load)
		}
	}
	c, _ := fixture(t)
	if err := os.Mkdir(filepath.Join(c.sources.StateDir, "complete.done"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := retrySnapshot("inactive")
	s.Steps = c.steps()
	if canRetry(s) || s.recorded("complete") {
		t.Fatal("nonregular completion marker accepted")
	}
}

func TestActionsRecheckCancellationAndIdentity(t *testing.T) {
	for _, choice := range []string{"1", "2", "4", "5", "6"} {
		a, calls := actionFixture()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if a.Apply(ctx, choice) == nil || len(*calls) != 0 {
			t.Fatalf("cancelled action %s dispatched", choice)
		}
	}
	for _, choice := range []string{"4", "5"} {
		for _, change := range []string{"cancel", "identity"} {
			a, calls := actionFixture()
			authorized := true
			a.deps.Authorized = func() bool { return authorized }
			ctx, cancel := context.WithCancel(context.Background())
			a.deps.Confirm = func(string) (string, error) {
				if change == "cancel" {
					cancel()
				} else {
					authorized = false
				}
				if choice == "4" {
					return "RETRY", nil
				}
				return "REBOOT", nil
			}
			err := a.Apply(ctx, choice)
			cancel()
			if err == nil || len(*calls) != 0 {
				t.Fatalf("%s after confirmation dispatched %s", change, choice)
			}
		}
	}
}

func TestRetryCancellationBetweenCommands(t *testing.T) {
	a, calls := actionFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.deps.Run = func(args []string) error {
		*calls = append(*calls, args)
		cancel()
		return nil
	}
	if a.Apply(ctx, "4") == nil || len(*calls) != 1 {
		t.Fatal("start dispatched after cancellation")
	}
}

func TestUnusableKernelAddressesRejected(t *testing.T) {
	for _, address := range []string{
		`{"family":"inet","local":"192.0.2.1"}`,
		`{"family":"inet6","local":"192.0.2.1","prefixlen":24}`,
		`{"family":"inet","local":"2001:db8::1","prefixlen":24}`,
		`{"family":"inet6","local":"::ffff:192.0.2.1","prefixlen":120}`,
		`{"family":"inet6","local":"2001:db8::1","prefixlen":64,"tentative":true}`,
		`{"family":"inet6","local":"2001:db8::1","prefixlen":64,"dadfailed":true}`,
		`{"family":"inet6","local":"2001:db8::1","prefixlen":64,"deprecated":true}`,
		`{"family":"inet6","local":"2001:db8::1","prefixlen":64,"flags":["tentative"]}`,
		`{"family":"inet","local":"192.0.2.1","prefixlen":33}`,
	} {
		var nic kernelInterface
		if err := json.Unmarshal([]byte(`{"addr_info":[`+address+`]}`), &nic); err != nil {
			t.Fatal(err)
		}
		cidrs, ips := kernelAddresses(nic)
		if len(cidrs) != 0 || len(ips) != 0 {
			t.Fatalf("invalid address advertised: %s", address)
		}
	}
}

func TestHomeAddressBelongsToDisplayedInterface(t *testing.T) {
	s := Snapshot{Addresses: []string{"192.0.2.1"}, Interfaces: []Interface{
		{Name: "ens160", Link: "DOWN", Addresses: []string{"198.51.100.1/24"}},
		{Name: "ens192", Link: "UP", Addresses: []string{"192.0.2.1/24"}},
	}}
	text := Render(identityRows(s, 79), false)
	if strings.Contains(text, "ens160") || !strings.Contains(text, "ens192") || !strings.Contains(text, "192.0.2.1") {
		t.Fatal(text)
	}
}

func FuzzFrameBounds(f *testing.F) {
	f.Add(25, 80, 0, "host")
	f.Add(math.MinInt, math.MaxInt, math.MinInt, "\x1b[2J")
	f.Add(24, 80, math.MaxInt, "\n")
	f.Fuzz(func(t *testing.T, height, width, offset int, host string) {
		v := NewView(false)
		v.open("report")
		v.offset = offset
		v.Handle("PAGEDOWN")
		rows := v.Frame(Snapshot{Hostname: Clean(host, 253)}, height, width)
		if len(rows) > max(0, max(0, min(height, 25))-1) {
			t.Fatal("frame exceeds terminal")
		}
		for _, row := range rows {
			if len(row.Text) > max(0, max(0, min(width, 80))-1) || strings.ContainsAny(row.Text, "\x1b\r\n") {
				t.Fatalf("invalid cell: %q", row.Text)
			}
		}
	})
}
