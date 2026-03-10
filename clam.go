package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ClamAV implements a ClamAV CLAMD protocol client.
// It supports both Unix domain sockets and TCP connections for on-the-fly
// file scanning with zero external API dependency.
//
// Protocol: CLAMD INSTREAM command
//
//	1. Send "zINSTREAM\0" (null-terminated command prefix)
//	2. Stream data as length-prefixed chunks (4-byte big-endian uint32 + bytes)
//	3. Terminate with a zero-length chunk ({0,0,0,0})
//	4. Read null-terminated response:
//	     "stream: OK\0"                    → clean
//	     "stream: <VirusName> FOUND\0"     → malicious
//	     "stream: ... ERROR\0"             → scan error
//
// Reference: https://linux.die.net/man/8/clamd
type ClamAV struct {
	network string        // "unix" or "tcp"
	addr    string        // socket path or host:port
	timeout time.Duration
}

const clamChunkSize = 4096 // bytes per INSTREAM chunk

// NewClamAV creates a client from an address string.
//
//	"unix:/var/run/clamav/clamd.sock"  → Unix domain socket
//	"tcp:localhost:3310"               → TCP connection
//	""                                 → default Unix socket path
func NewClamAV(addr string) *ClamAV {
	c := &ClamAV{timeout: 30 * time.Second}
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
func (c *ClamAV) Ping() error {
	conn, err := net.DialTimeout(c.network, c.addr, c.timeout)
	if err != nil {
		return fmt.Errorf("clamav: connect failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout)) //nolint:errcheck

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

// Scan submits data to the ClamAV daemon via the INSTREAM command.
// Returns (virusName, isMalicious, error).
// virusName is non-empty only when isMalicious is true.
func (c *ClamAV) Scan(data []byte) (string, bool, error) {
	conn, err := net.DialTimeout(c.network, c.addr, c.timeout)
	if err != nil {
		return "", false, fmt.Errorf("clamav: connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout)) //nolint:errcheck

	// Send INSTREAM command (null-terminated).
	if _, err := fmt.Fprintf(conn, "zINSTREAM\x00"); err != nil {
		return "", false, fmt.Errorf("clamav: command write: %w", err)
	}

	// Stream data in fixed-size chunks, each prefixed with its 4-byte length.
	for off := 0; off < len(data); off += clamChunkSize {
		end := off + clamChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chunk)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return "", false, fmt.Errorf("clamav: write chunk length: %w", err)
		}
		if _, err := conn.Write(chunk); err != nil {
			return "", false, fmt.Errorf("clamav: write chunk data: %w", err)
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
func parseClamResponse(resp string) (string, bool, error) {
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
