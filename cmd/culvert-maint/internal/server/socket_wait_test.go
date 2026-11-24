package server

import (
	"context"
	"net"
	"time"
)

// waitSocketAccepting waits (up to ~1s, like the loops it replaces) until a
// test server's unix socket ACCEPTS a connection. Waiting for the socket file
// to exist is not enough: the file appears at bind(2), before listen(2), and a
// dial in between is refused (seen in CI as "connect: connection refused" in
// TestCleanup_ArgvCanonicalOrdering).
func waitSocketAccepting(path string) {
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", path)
		cancel()
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
