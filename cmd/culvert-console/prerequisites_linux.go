//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

// collectPrerequisites only reads local state. Each external operation has an
// output/time bound; the shared deadline also covers sequential hostname/DNS work.
func collectPrerequisites(parent context.Context) []applianceconsole.Check {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	paths := []string{"/", "/var/lib/docker", "/var/lib/culvert-appliance", "/var/log/journal"}
	checks := make([]applianceconsole.Check, len(paths)+3)
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Go(func() { checks[i] = storagePrerequisite(ctx, path) })
	}
	wg.Go(func() {
		checks[4] = applianceconsole.ClockCheck(runProbe(ctx, []string{"/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"}))
	})
	wg.Go(func() { checks[5] = dnsPrerequisite(ctx) })
	wg.Go(func() { checks[6] = certificatePrerequisite(ctx) })
	wg.Wait()
	return checks
}

func storagePrerequisite(ctx context.Context, path string) applianceconsole.Check {
	// stat is a bounded subprocess because an unhealthy mounted filesystem can
	// stall a direct statfs syscall. No shell or operator-supplied path is used.
	raw := runProbe(ctx, []string{"/usr/bin/stat", "--file-system", "--format=%a %b %S %d %c", "--", path})
	return parseStoragePrerequisite(path, raw)
}

func parseStoragePrerequisite(path, raw string) applianceconsole.Check {
	unknown := applianceconsole.Check{ID: "storage:" + path, State: "unknown", Detail: "Filesystem observation unavailable or malformed"}
	fields := strings.Fields(raw)
	if len(fields) != 5 {
		return unknown
	}
	var values [5]uint64
	for i, field := range fields {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return unknown
		}
		values[i] = n
	}
	blockSize := values[2]
	if blockSize == 0 || values[0] > ^uint64(0)/blockSize || values[1] > ^uint64(0)/blockSize {
		return unknown
	}
	return applianceconsole.StorageCheck(unknown.ID, values[0]*blockSize, values[1]*blockSize, values[3], values[4])
}

func dnsPrerequisite(ctx context.Context) applianceconsole.Check {
	c := applianceconsole.Check{ID: "configured_dns", State: "unknown", Detail: "Configured hostname unavailable"}
	raw := runProbe(ctx, []string{"/usr/bin/cat", "--", "/etc/hostname"})
	if raw == "" {
		return c
	}
	host := applianceconsole.ConfiguredFQDN(raw)
	if host == "" {
		c.State, c.Detail = "not_configured", "No valid configured FQDN; no external DNS target queried"
		return c
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resolver := net.Resolver{PreferGo: true}
	addresses, err := resolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil || len(addresses) == 0 {
		c.Detail = "Configured FQDN did not resolve within the observation budget"
		return c
	}
	c.State, c.Detail = "ok", "Configured FQDN resolves via host resolver; address ownership and reachability not verified"
	return c
}

func certificatePrerequisite(ctx context.Context) applianceconsole.Check {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// #nosec G402 -- inspect public certificate metadata from fixed loopback only;
	// no credentials are sent and trust is explicitly not asserted.
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	conn, err := dialer.DialContext(probeCtx, "tcp", "127.0.0.1:9090")
	if err != nil {
		return applianceconsole.CertificateCheck(nil, time.Now())
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return applianceconsole.CertificateCheck(nil, time.Now())
	}
	certificates := tlsConn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return applianceconsole.CertificateCheck(nil, time.Now())
	}
	return applianceconsole.CertificateCheck(certificates[0], time.Now())
}
