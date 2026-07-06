// Package clamav implements a ClamAV CLAMD protocol client (INSTREAM scanning)
// over Unix domain sockets or TCP, with zero external API dependency. It is a
// self-contained leaf (stdlib only, no Culvert coupling) extracted from the flat
// package main per ADR-0002.
//
// Protocol: CLAMD INSTREAM command
//
//  1. Send "zINSTREAM\0" (null-terminated command prefix)
//  2. Stream data as length-prefixed chunks (4-byte big-endian uint32 + bytes)
//  3. Terminate with a zero-length chunk ({0,0,0,0})
//  4. Read null-terminated response:
//     "stream: OK\0"                    → clean
//     "stream: <VirusName> FOUND\0"     → malicious
//     "stream: ... ERROR\0"             → scan error
//
// Reference: https://linux.die.net/man/8/clamd
package clamav

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Client is a ClamAV CLAMD protocol client.
type Client struct {
	network string // "unix" or "tcp"
	addr    string // socket path or host:port
	timeout time.Duration
}

const clamChunkSize = 64 << 10 // 64 KiB per INSTREAM chunk (fewer frames + syscalls than 4 KiB)
const clamMaxConcurrent = 4    // max parallel ClamAV scans

// clamSem limits concurrent ClamAV scans to prevent overwhelming the daemon
// when multiple requests trigger scanning simultaneously.
var clamSem = make(chan struct{}, clamMaxConcurrent)

// New creates a client from an address string.
//
//	"unix:/var/run/clamav/clamd.sock"  → Unix domain socket
//	"tcp:localhost:3310"               → TCP connection
//	""                                 → default Unix socket path
func New(addr string) *Client {
	c := &Client{timeout: 30 * time.Second}
	switch {
	case strings.HasPrefix(addr, "unix:"):
		c.network = "unix"
		c.addr = strings.TrimPrefix(addr, "unix:")
	case strings.HasPrefix(addr, "tcp:"):
		c.network = "tcp"
		c.addr = strings.TrimPrefix(addr, "tcp:")
	case addr == "":
		c.network = "unix"
		c.addr = "/var/run/clamav/clamd.sock"
	default:
		// Treat as bare TCP host:port.
		c.network = "tcp"
		c.addr = addr
	}
	return c
}

// Ping verifies the ClamAV daemon is reachable and responding correctly.
// Returns nil on success, error otherwise.
func (c *Client) Ping() error {
	conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(context.Background(), c.network, c.addr)
	if err != nil {
		return fmt.Errorf("clamav: connect failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout)) //nolint:errcheck // a failed deadline set is surfaced by the subsequent read/write

	if _, err := fmt.Fprintf(conn, "zPING\x00"); err != nil {
		return fmt.Errorf("clamav: ping write: %w", err)
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	resp := strings.TrimRight(string(buf[:n]), "\x00\n\r ")
	if resp != "PONG" {
		return fmt.Errorf("clamav: unexpected ping response: %q", resp)
	}
	return nil
}

// Version queries the ClamAV daemon for its engine and signature-database
// version via the VERSION command. The daemon replies with a single line like:
//
//	ClamAV 0.103.8/26982/Wed Apr 12 09:30:00 2023
//
// where the three "/"-separated fields are the engine version, the signature
// database version (main+daily counter), and the database build date. Older or
// minimally-configured daemons may reply with just the engine string and no
// "/" fields; DBVersion/DBDate are then empty. Raw is always the full reply.
func (c *Client) Version() (Version, error) {
	conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(context.Background(), c.network, c.addr)
	if err != nil {
		return Version{}, fmt.Errorf("clamav: connect failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout)) //nolint:errcheck // a failed deadline set is surfaced by the subsequent read/write

	if _, err := fmt.Fprintf(conn, "zVERSION\x00"); err != nil {
		return Version{}, fmt.Errorf("clamav: version write: %w", err)
	}
	// Responses are short; 256 bytes is ample and bounds a misbehaving daemon.
	resp, err := io.ReadAll(io.LimitReader(conn, 256))
	if err != nil {
		return Version{}, fmt.Errorf("clamav: version read: %w", err)
	}
	raw := strings.TrimRight(string(resp), "\x00\n\r ")
	if raw == "" {
		return Version{}, fmt.Errorf("clamav: empty version response (daemon may have closed connection)")
	}
	return parseClamVersion(raw), nil
}

// Version holds the parsed ClamAV VERSION response.
type Version struct {
	Engine    string `json:"engine"`               // e.g. "ClamAV 0.103.8"
	DBVersion string `json:"db_version,omitempty"` // signature database counter, e.g. "26982"
	DBDate    string `json:"db_date,omitempty"`    // database build date, e.g. "Wed Apr 12 09:30:00 2023"
	Raw       string `json:"raw"`                  // full unparsed reply
}

// parseClamVersion splits a VERSION reply into its "/"-separated fields. A
// reply with no "/" (engine only) leaves DBVersion/DBDate empty.
func parseClamVersion(raw string) Version {
	v := Version{Engine: raw, Raw: raw}
	parts := strings.SplitN(raw, "/", 3)
	switch len(parts) {
	case 3:
		v.Engine = strings.TrimSpace(parts[0])
		v.DBVersion = strings.TrimSpace(parts[1])
		v.DBDate = strings.TrimSpace(parts[2])
	case 2:
		v.Engine = strings.TrimSpace(parts[0])
		v.DBVersion = strings.TrimSpace(parts[1])
	}
	return v
}

// Scan submits data to the ClamAV daemon via the INSTREAM command.
// Returns (virusName, isMalicious, error).
// virusName is non-empty only when isMalicious is true.
// Concurrent scans are limited by clamSem to prevent overwhelming the daemon.
func (c *Client) Scan(data []byte) (virusName string, isMalicious bool, err error) {
	// P6: Non-blocking semaphore with timeout to prevent goroutine backlog.
	select {
	case clamSem <- struct{}{}:
	case <-time.After(5 * time.Second):
		return "", false, fmt.Errorf("clamav: scan queue full (%d concurrent), timed out", clamMaxConcurrent)
	}
	defer func() { <-clamSem }()

	conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(context.Background(), c.network, c.addr)
	if err != nil {
		return "", false, fmt.Errorf("clamav: connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout)) //nolint:errcheck // a failed deadline set is surfaced by the subsequent read/write

	// Send INSTREAM command (null-terminated).
	if _, err := fmt.Fprintf(conn, "zINSTREAM\x00"); err != nil {
		return "", false, fmt.Errorf("clamav: command write: %w", err)
	}

	// Stream data in fixed-size chunks, each prefixed with its 4-byte length.
	// The length prefix and the chunk are written together via net.Buffers
	// (writev), so each chunk costs ONE syscall instead of two. The on-wire
	// framing is unchanged — only the chunk size and the write batching differ.
	for off := 0; off < len(data); off += clamChunkSize {
		end := off + clamChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chunk))) // #nosec G115 -- chunk size is bounded by clamChunkSize (65536), well within uint32 range
		framed := net.Buffers{lenBuf[:], chunk}
		if _, err := framed.WriteTo(conn); err != nil {
			return "", false, fmt.Errorf("clamav: write chunk: %w", err)
		}
	}

	// Terminate the stream with a zero-length chunk.
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", false, fmt.Errorf("clamav: terminate stream: %w", err)
	}

	// Read the null-terminated response (bounded to 256 bytes).
	resp, err := io.ReadAll(io.LimitReader(conn, 256))
	if err != nil {
		return "", false, fmt.Errorf("clamav: read response: %w", err)
	}
	return parseClamResponse(strings.TrimRight(string(resp), "\x00\n\r "))
}

// parseClamResponse parses a CLAMD INSTREAM response.
//
//	"stream: OK"                       → ("", false, nil)
//	"stream: Eicar-Test-Signature FOUND" → ("Eicar-Test-Signature", true, nil)
//	"stream: ... ERROR"                → ("", false, error)
func parseClamResponse(resp string) (virusName string, isMalicious bool, err error) {
	switch {
	case strings.HasSuffix(resp, " OK"):
		return "", false, nil
	case strings.HasSuffix(resp, " FOUND"):
		// Format: "stream: <VirusName> FOUND"
		if i := strings.Index(resp, ": "); i >= 0 {
			name := strings.TrimSuffix(strings.TrimSpace(resp[i+2:]), " FOUND")
			return name, true, nil
		}
		return "Unknown", true, nil
	case strings.HasSuffix(resp, " ERROR"):
		return "", false, fmt.Errorf("clamav: scan error: %s", resp)
	default:
		if resp == "" {
			return "", false, fmt.Errorf("clamav: empty response (daemon may have closed connection)")
		}
		return "", false, fmt.Errorf("clamav: unexpected response: %q", resp)
	}
}
