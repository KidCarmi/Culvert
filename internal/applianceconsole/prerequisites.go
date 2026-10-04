package applianceconsole

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Check is a read-only prerequisite observation, never a provisioning gate.
// States are ok, warning, unknown and not_configured. Unknown is not success.
type Check struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// StorageCheck reports space available to an unprivileged process. Culvert's
// warning reserve is 2 GiB or 10% free bytes, and 5% free inodes. No data is deleted.
func StorageCheck(id string, available, total, freeInodes, inodes uint64) Check {
	c := Check{ID: id, State: "unknown", Detail: "Filesystem capacity unavailable or inconsistent"}
	if total == 0 || available > total || freeInodes > inodes {
		return c
	}
	c.State = "ok"
	c.Detail = fmt.Sprintf("Available %d MiB / %d MiB", available/(1<<20), total/(1<<20))
	// Floating point ratios avoid overflow from multiplying large byte counts.
	if available < 2<<30 || float64(available)/float64(total) < 0.10 {
		c.State = "warning"
	}
	if inodes == 0 {
		c.Detail += "; inode capacity not reported"
		if c.State == "ok" {
			c.State = "unknown"
		}
		return c
	}
	c.Detail += fmt.Sprintf("; free inodes %d / %d", freeInodes, inodes)
	if float64(freeInodes)/float64(inodes) < 0.05 {
		c.State = "warning"
	}
	return c
}

// ClockCheck distinguishes an observed synchronization state from mere service availability.
func ClockCheck(raw string) Check {
	c := Check{ID: "clock", State: "unknown", Detail: "Clock synchronization unavailable"}
	switch strings.TrimSpace(raw) {
	case "yes":
		c.State, c.Detail = "ok", "Host reports synchronized clock; independent time accuracy not verified"
	case "no":
		c.State, c.Detail = "warning", "Host does not report synchronized clock; certificate and authentication checks may fail"
	}
	return c
}

// ConfiguredFQDN accepts only a configured DNS hostname, never a fallback public target.
// The trailing dot prevents resolver search suffixes from changing the question.
func ConfiguredFQDN(raw string) string {
	name := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if !validDNSLabel(label) {
			return ""
		}
	}
	return strings.ToLower(name) + "."
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '-':
		default:
			return false
		}
	}
	return true
}

// CertificateCheck inspects the leaf validity interval and public fingerprint.
// It deliberately makes no claim about trust, hostname matching or reachability.
func CertificateCheck(cert *x509.Certificate, now time.Time) Check {
	c := Check{ID: "setup_certificate", State: "unknown", Detail: "Setup listener certificate unavailable"}
	if cert == nil || len(cert.Raw) == 0 || !cert.NotAfter.After(cert.NotBefore) {
		return c
	}
	c.State = "ok"
	state := "Valid at host clock"
	switch {
	case now.Before(cert.NotBefore):
		c.State, state = "warning", "Not yet valid at host clock"
	case !now.Before(cert.NotAfter):
		c.State, state = "warning", "Expired at host clock"
	case cert.NotAfter.Sub(now) < 30*24*time.Hour:
		c.State, state = "warning", "Expires within 30 days at host clock"
	}
	c.Detail = fmt.Sprintf("%s; expires %s; SHA256 %x; trust and hostname not verified", state, cert.NotAfter.UTC().Format(time.RFC3339), sha256.Sum256(cert.Raw))
	return c
}
