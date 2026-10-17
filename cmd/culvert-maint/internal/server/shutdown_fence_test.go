package server

import (
	"strings"
	"testing"
)

func TestShutdownFenceContract(t *testing.T) {
	const boot = "9ebf0252-80fb-433c-aed4-d764cb293a62"
	for _, action := range []string{"reboot", "poweroff"} {
		for _, phase := range []string{"pending", "aborted"} {
			data := "culvert-shutdown-v1 " + boot + " " + action + " " + phase + "\n"
			if got, err := parseShutdownFence([]byte(data)); err != nil || got != boot {
				t.Fatalf("valid shell contract rejected: %q %v", got, err)
			}
		}
	}
	valid := "culvert-shutdown-v1 " + boot + " reboot pending\n"
	for _, data := range []string{
		"", strings.TrimSuffix(valid, "\n"), valid + "\n", valid + "extra",
		strings.Replace(valid, "v1", "v2", 1), strings.Replace(valid, "pending", "complete", 1),
		strings.Replace(valid, "reboot", "halt", 1), strings.Replace(valid, boot, "missing-boot", 1),
		strings.Replace(valid, boot, strings.ToUpper(boot), 1), strings.Replace(valid, " ", "  ", 1),
		strings.Replace(valid, "pending", "pend\x00ing", 1), strings.Repeat("x", 129),
	} {
		if _, err := parseShutdownFence([]byte(data)); err == nil {
			t.Fatalf("malformed or unknown fence accepted: %q", data)
		}
	}
}
