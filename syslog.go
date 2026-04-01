package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// syslogWriter forwards log lines to a remote syslog server over UDP or TCP
// using BSD syslog format (RFC 3164) — accepted by Splunk, Elastic, QRadar,
// rsyslog, syslog-ng, and every other common SIEM.
//
// Priority: facility=1 (user-level), severity=6 (informational) → PRI=14.
// Audit events are sent at severity=5 (notice) → PRI=13.
//
// Configuration:  -syslog udp://10.0.0.1:514   (UDP, most common)
//                 -syslog tcp://logs.corp.com:601 (TCP, reliable delivery)
type syslogWriter struct {
	mu      sync.Mutex
	network string
	addr    string
	conn    net.Conn
	host    string
	tag     string
}

func newSyslogWriter(network, addr string) (*syslogWriter, error) {
	host, err := os.Hostname()
	if err != nil {
		host = "proxyshield"
	}
	sw := &syslogWriter{
		network: network,
		addr:    addr,
		host:    host,
		tag:     "proxyshield",
	}
	if err := sw.connect(); err != nil {
		return nil, fmt.Errorf("syslog connect %s://%s: %w", network, addr, err)
	}
	return sw, nil
}

func (s *syslogWriter) connect() error {
	conn, err := net.DialTimeout(s.network, s.addr, 5*time.Second)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Write implements io.Writer. Each call is a single syslog message.
func (s *syslogWriter) Write(p []byte) (int, error) {
	s.writeMsg(14, strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

// WriteAudit sends an AuditEntry as a structured JSON syslog message at
// severity=5 (notice), which most SIEMs map to a security-relevant priority.
func (s *syslogWriter) WriteAudit(e AuditEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.writeMsg(13, string(b)) // PRI=13: facility=1 severity=5 (notice)
}

func (s *syslogWriter) writeMsg(pri int, msg string) {
	ts := time.Now().Format("Jan 02 15:04:05")
	line := fmt.Sprintf("<%d>%s %s %s: %s\n", pri, ts, s.host, s.tag, msg)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return // syslog down — swallow, never block the proxy
		}
	}
	if _, err := fmt.Fprint(s.conn, line); err != nil {
		s.conn.Close()
		s.conn = nil
		if err2 := s.connect(); err2 == nil {
			fmt.Fprint(s.conn, line) //nolint:errcheck
		}
	}
}

func (s *syslogWriter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// globalSyslog is the active syslog writer; nil when syslog is not configured.
var globalSyslog *syslogWriter

// InitSyslog parses addr and initialises the global syslog writer.
// Supported formats:
//
//	udp://10.0.0.1:514       (default protocol when scheme is omitted)
//	tcp://logs.corp.com:601
func InitSyslog(addr string) error {
	if addr == "" {
		return nil
	}
	network := "udp"
	target := addr
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		network = "tcp"
		target = strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "udp://"):
		target = strings.TrimPrefix(addr, "udp://")
	}
	sw, err := newSyslogWriter(network, target)
	if err != nil {
		return err
	}
	globalSyslog = sw
	logger.Printf("Syslog   → forwarding to %s://%s", network, sanitizeLog(target))
	return nil
}
