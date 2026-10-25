package clamav

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// clamd answers an INSTREAM it cannot spool to its temporary directory with
// TWO NUL-terminated replies — the error, then a verdict for the (empty)
// stream it did manage to scan. Captured from the pinned clamav/clamav 1.4
// image with /tmp full (EICAR request):
const clamdTempFullReply = "Error writing to temporary file ERROR\x00stream: OK\x00"

// The client read the whole buffer and matched only its SUFFIX, so this was a
// clean verdict: under av_unavailable=closed an EICAR body was delivered while
// the disk was full (appliance lab, 41bd1193, pressure phase "blocks" +0).
func TestScanContext_ErrorThenOKIsAnError(t *testing.T) {
	_, found, err := parseRawClamResponse([]byte(clamdTempFullReply))
	if err == nil {
		t.Fatalf("an ERROR reply followed by OK must be an error, got clean (found=%v)", found)
	}
	if !strings.Contains(err.Error(), "Error writing to temporary file") {
		t.Errorf("the error must carry the daemon's reason, got %v", err)
	}
}

// A FOUND anywhere in the reply set wins: blocking is always the safe reading.
func TestParseRaw_FoundWinsOverError(t *testing.T) {
	name, found, err := parseRawClamResponse([]byte("Something ERROR\x00stream: Eicar-Signature FOUND\x00"))
	if err != nil || !found || name != "Eicar-Signature" {
		t.Fatalf("got name=%q found=%v err=%v; want the detection", name, found, err)
	}
}

// Two verdicts for one stream is not a protocol shape clamd produces for a
// healthy scan; it is refused rather than guessed.
func TestParseRaw_TwoCleanRepliesAreUnexpected(t *testing.T) {
	if _, _, err := parseRawClamResponse([]byte("stream: OK\x00stream: OK\x00")); err == nil {
		t.Fatal("two replies to one INSTREAM must be an error")
	}
}

// Controls: the single-reply shapes keep their meaning.
func TestParseRaw_SingleReplies(t *testing.T) {
	if _, found, err := parseRawClamResponse([]byte("stream: OK\x00")); err != nil || found {
		t.Errorf("OK: found=%v err=%v", found, err)
	}
	if name, found, err := parseRawClamResponse([]byte("stream: Eicar-Signature FOUND\x00")); err != nil || !found || name != "Eicar-Signature" {
		t.Errorf("FOUND: name=%q found=%v err=%v", name, found, err)
	}
	if _, _, err := parseRawClamResponse([]byte("INSTREAM size limit exceeded. ERROR\x00")); err == nil {
		t.Error("ERROR: want an error")
	}
	if _, _, err := parseRawClamResponse(nil); err == nil {
		t.Error("empty: want an error")
	}
}

// End to end through ScanContext against a fake daemon speaking the captured
// bytes: the scan must fail, never come back clean.
func TestScanContext_TempFullDaemonIsNotClean(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		cmd := make([]byte, len("zINSTREAM\x00"))
		if _, err := io.ReadFull(c, cmd); err != nil {
			return
		}
		for {
			var l [4]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(l[:])
			if n == 0 {
				break
			}
			if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
				return
			}
		}
		_, _ = c.Write([]byte(clamdTempFullReply))
	}()
	cl := New("tcp:" + ln.Addr().String())
	_, found, err := cl.Scan([]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))
	if err == nil {
		t.Fatalf("scan against a daemon that could not spool the stream came back clean (found=%v)", found)
	}
}
