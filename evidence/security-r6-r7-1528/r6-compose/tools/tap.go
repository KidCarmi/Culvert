// tap: a logging relay between a Docker client and dockerd on Unix sockets.
// For every client connection it relays bytes unchanged in both directions
// and logs, from the client->daemon stream: each HTTP/1.x request line, each
// Upgrade header, and whether an HTTP/2 connection preface appears. From the
// daemon->client stream it logs any HTTP/2 preface/SETTINGS seen after an
// upgrade, so a session where the DAEMON speaks HTTP/2 to the client (the
// client acting as an HTTP/2 server) is visible.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

var (
	reqLine = regexp.MustCompile(`^(GET|POST|HEAD|DELETE|PUT|PATCH) (\S+) HTTP/1\.[01]\r?$`)
	upgrade = regexp.MustCompile(`(?i)^upgrade:\s*(\S+)`)
	logMu   sync.Mutex
	logw    *os.File
	connSeq int64
)

func logf(format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(logw, time.Now().UTC().Format("15:04:05.000")+" "+format+"\n", a...)
}

// watch scans one direction of a connection line by line until the stream
// stops being HTTP/1 text, then only counts bytes and looks for an HTTP/2
// preface or frame header.
func watch(id int64, dir string, r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	var n int64
	for {
		line, err := br.ReadBytes('\n')
		n += int64(len(line))
		s := string(bytes.TrimRight(line, "\n"))
		if m := reqLine.FindStringSubmatch(s); m != nil && dir == "c>d" {
			logf("conn=%d %s REQ %s %s", id, dir, m[1], m[2])
		}
		if m := upgrade.FindStringSubmatch(s); m != nil {
			logf("conn=%d %s UPGRADE %s", id, dir, m[1])
		}
		if bytes.HasPrefix(line, []byte("PRI * HTTP/2.0")) {
			logf("conn=%d %s HTTP2-PREFACE", id, dir)
		}
		if err != nil {
			logf("conn=%d %s closed after %d bytes", id, dir, n)
			return
		}
	}
}

func handle(c net.Conn, upstream string) {
	id := atomic.AddInt64(&connSeq, 1)
	d, err := net.Dial("unix", upstream)
	if err != nil {
		logf("conn=%d dial-upstream-failed %v", id, err)
		c.Close()
		return
	}
	logf("conn=%d open", id)
	cr, cw := io.Pipe()
	dr, dw := io.Pipe()
	go watch(id, "c>d", cr)
	go watch(id, "d>c", dr)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(io.MultiWriter(d, cw), c); cw.Close(); d.(*net.UnixConn).CloseWrite() }()
	go func() { defer wg.Done(); io.Copy(io.MultiWriter(c, dw), d); dw.Close(); c.(*net.UnixConn).CloseWrite() }()
	wg.Wait()
	c.Close()
	d.Close()
}

func main() {
	listen, upstream, logPath := os.Args[1], os.Args[2], os.Args[3]
	var err error
	logw, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		panic(err)
	}
	os.Remove(listen)
	ln, err := net.Listen("unix", listen)
	if err != nil {
		panic(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, upstream)
	}
}
