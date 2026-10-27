package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ─── CWE-117 — peer-supplied CP addresses in the Data Plane's process log ───
//
// applyAddressesLocked adopts the CP config snapshot's cp_addresses verbatim
// into c.addrs and states, in as many words, that both lists "are peer-supplied
// … so they are untrusted log values under the CWE-117 rule". Four older sinks
// in the same file printed an address from that same list with a bare %s:
// connect's two lines and failover's two. validateConfigSnapshot count-caps
// cp_addresses at 100 but never validates an entry as host:port, so a newline
// in one forges records in the DP's process log and in every downstream
// syslog/OTLP consumer.
//
// This is a source gate rather than a behavioural one because the value reaches
// the sink only from a live CP snapshot; the barrier's presence at every sink is
// the property, and it is the property CodeQL checks too.
func TestCWE117_CPAddressLogSinksAreSanitized(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "controlplane_client.go"))
	if err != nil {
		t.Fatalf("read controlplane_client.go: %v", err)
	}

	// Any log line carrying one of the address identifiers must wrap it in the
	// recognised barrier. `%v`/`%s` on a bare identifier is the defect shape.
	bare := regexp.MustCompile(`%[vsq]?",?\s*(addr|nextAddr)\b|%[vs]", (addr|nextAddr)\b`)
	wrapped := regexp.MustCompile(`sanitizeLog\((addr|nextAddr)\)`)

	var bad []string
	checked := 0
	for i, line := range strings.Split(string(src), "\n") {
		if !strings.Contains(line, "logger.Printf(") {
			continue
		}
		if !regexp.MustCompile(`\b(addr|nextAddr)\b`).MatchString(line) {
			continue
		}
		checked++
		if !wrapped.MatchString(line) && bare.MatchString(line) {
			bad = append(bad, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(line)))
		}
	}
	if checked == 0 {
		t.Fatal("found no log line carrying a CP address at all — the pattern drifted and this gate is vacuous")
	}
	if len(bad) > 0 {
		t.Errorf("%d of %d CP-address log sinks print a peer-supplied value without sanitizeLog:\n%s",
			len(bad), checked, strings.Join(bad, "\n"))
	}
}
