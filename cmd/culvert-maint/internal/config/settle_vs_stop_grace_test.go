package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// TestInterruptedSettleDefault_OutlastsTheShippedStopGrace is a cross-artifact
// contract. The settle window is sound only if it is longer than the time
// Docker gives the proxy to stop: a container stop that the previous agent
// process requested can stay pending for the whole stop_grace_period, and
// until it is over a running proxy container proves nothing.
//
// The agent cannot check this at run time (it does not read the compose
// file), so the two shipped defaults are pinned against each other here: the
// agent's default interrupted_settle and every stop_grace_period in the
// repository's docker-compose.yml, which is the file the agent drives.
// Changing either so that this fails brings back the false success of
// ADR-0061's addendum; raise interrupted_settle with it.
func TestInterruptedSettleDefault_OutlastsTheShippedStopGrace(t *testing.T) {
	settle, err := time.ParseDuration(defaultInterruptedSettle)
	if err != nil {
		t.Fatalf("defaultInterruptedSettle %q: %v", defaultInterruptedSettle, err)
	}
	compose := filepath.Join("..", "..", "..", "..", "docker-compose.yml")
	data, err := os.ReadFile(compose) // #nosec G304 -- fixed path inside the repository
	if err != nil {
		t.Fatalf("reading the repository's compose file: %v", err)
	}
	found := regexp.MustCompile(`(?m)^\s*stop_grace_period:\s*"?([0-9a-z.]+)"?`).FindAllSubmatch(data, -1)
	if len(found) == 0 {
		t.Fatal("docker-compose.yml declares no stop_grace_period: Docker's default (10s) would apply and this contract would be checking nothing")
	}
	// The unit restarts the agent RestartSec (5s) after it dies, so a stop
	// requested just before the death has at most stop_grace_period left to
	// run; the margin asked for here is on top of that.
	const margin = 5 * time.Second
	for _, m := range found {
		grace, perr := time.ParseDuration(string(m[1]))
		if perr != nil {
			t.Fatalf("stop_grace_period %q in docker-compose.yml: %v", m[1], perr)
		}
		if settle < grace+margin {
			t.Errorf("default interrupted_settle (%s) must exceed stop_grace_period (%s) by at least %s: a pending container stop could outlast the settle window", settle, grace, margin)
		}
	}
}
