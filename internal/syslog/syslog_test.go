package syslog

import (
	"strings"
	"testing"
)

func TestFormatMsg_RFC3164(t *testing.T) {
	sw := &Writer{
		host:   "testhost",
		tag:    "culvert",
		format: "rfc3164",
		pid:    "1234",
	}
	msg := sw.formatMsg(14, "hello world")
	if !strings.HasPrefix(msg, "<14>") {
		t.Fatalf("RFC3164 should start with <14>, got %q", msg)
	}
	if !strings.Contains(msg, "testhost") {
		t.Fatal("should contain hostname")
	}
	if !strings.Contains(msg, "culvert:") {
		t.Fatal("should contain tag with colon")
	}
	if !strings.Contains(msg, "hello world") {
		t.Fatal("should contain message body")
	}
}

func TestFormatMsg_RFC5424(t *testing.T) {
	sw := &Writer{
		host:   "testhost",
		tag:    "culvert",
		format: "rfc5424",
		pid:    "5678",
	}
	msg := sw.formatMsg(13, "audit event")
	// RFC5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	if !strings.HasPrefix(msg, "<13>1 ") {
		t.Fatalf("RFC5424 should start with <13>1, got %q", msg)
	}
	if !strings.Contains(msg, "testhost") {
		t.Fatal("should contain hostname")
	}
	if !strings.Contains(msg, "culvert") {
		t.Fatal("should contain app-name")
	}
	if !strings.Contains(msg, "5678") {
		t.Fatal("should contain PID")
	}
	if !strings.Contains(msg, "audit event") {
		t.Fatal("should contain message body")
	}
	// Should contain RFC3339 timestamp
	if !strings.Contains(msg, "T") {
		t.Fatal("RFC5424 timestamp should be RFC3339 format")
	}
}

func TestFormat_Getter(t *testing.T) {
	sw := &Writer{format: "rfc5424"}
	if sw.Format() != "rfc5424" {
		t.Fatalf("Format() = %q, want rfc5424", sw.Format())
	}
}
