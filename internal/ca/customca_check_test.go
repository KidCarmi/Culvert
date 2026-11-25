package ca

import (
	"errors"
	"testing"
	"time"
)

// CheckCustomCA is the gate package main puts in front of an operator upload
// that replaces the active CA. It must refuse exactly what LoadCustomCA refuses,
// plus a certificate outside its validity window — and say which it was.
func TestCheckCustomCA(t *testing.T) {
	valid := issueTestCA(t, "Customer Root", 365*24*time.Hour, nil)
	expired := issueTestCA(t, "Customer Root", -time.Minute, nil)
	other := issueTestCA(t, "Other Root", 365*24*time.Hour, nil)

	if err := CheckCustomCA(valid.certPEM, valid.keyPEM); err != nil {
		t.Errorf("valid CA refused: %v", err)
	}
	if err := CheckCustomCA(expired.certPEM, expired.keyPEM); !errors.Is(err, ErrCAUnusable) {
		t.Errorf("expired CA: err = %v, want ErrCAUnusable", err)
	}
	// A structural fault is not a validity fault: the caller words them
	// differently for the operator.
	err := CheckCustomCA(valid.certPEM, other.keyPEM)
	if err == nil || errors.Is(err, ErrCAUnusable) {
		t.Errorf("mismatched pair: err = %v, want a non-ErrCAUnusable error", err)
	}
	// Whatever LoadCustomCA refuses, the gate refuses too.
	if loadErr := New().LoadCustomCA(valid.certPEM, other.keyPEM); loadErr == nil {
		t.Error("LoadCustomCA accepted a mismatched pair")
	}
}

// The check is a pure predicate: it must not install the CA it was asked about.
func TestCheckCustomCA_InstallsNothing(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	before := cm.CACertForTest()
	valid := issueTestCA(t, "Customer Root", 365*24*time.Hour, nil)
	if err := CheckCustomCA(valid.certPEM, valid.keyPEM); err != nil {
		t.Fatalf("CheckCustomCA: %v", err)
	}
	if !cm.CACertForTest().Equal(before) {
		t.Fatal("CheckCustomCA changed the installed CA")
	}
}
