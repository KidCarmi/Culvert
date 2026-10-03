// Package applianceconsole provides read-only appliance observations and the
// local recovery menu. It does not read credentials or require the Docker API.
package applianceconsole

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxOutput = 65536

var stepNames = []string{"ovf", "console", "images", "install", "agent", "complete"}
var stepLabels = []string{"Network configuration", "Console access", "Application images", "Service installation", "Maintenance agent", "Provisioning complete"}
var unitKeys = []string{"LoadState", "ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts"}

// Clean strips terminal controls, non-ASCII and multiline text before display.
func Clean(value string, limit int) string {
	var out strings.Builder
	for _, ch := range value {
		if out.Len() >= max(0, limit) {
			break
		}
		if ch < ' ' || ch > '~' {
			ch = '?'
		}
		out.WriteByte(byte(ch))
	}
	return out.String()
}

// Step describes an existing marker, never inferred live work or service health.
type Step struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	State string `json:"state"`
}

// Snapshot is the versioned contract shared by CLI and terminal display.
type Snapshot struct {
	Hostname              string            `json:"hostname"`
	Interfaces            []Interface       `json:"interfaces"`
	IPv6Gateway           string            `json:"ipv6_gateway"`
	Gateway               string            `json:"gateway"`
	DNS                   []string          `json:"dns"`
	SetupStatus           string            `json:"setup_status"`
	ManagementAvailable   bool              `json:"management_available"`
	SchemaVersion         int               `json:"schema_version"`
	ObservedAt            string            `json:"observed_at"`
	Version               string            `json:"version"`
	Candidate             bool              `json:"candidate"`
	Addresses             []string          `json:"addresses"`
	ManagementURLs        []string          `json:"management_urls"`
	Network               string            `json:"network"`
	Firstboot             map[string]string `json:"firstboot"`
	Steps                 []Step            `json:"steps"`
	Phase                 string            `json:"phase"`
	Reason                string            `json:"reason"`
	Message               string            `json:"message"`
	ApplicationResponding bool              `json:"application_responding"`
	AdministratorEnrolled bool              `json:"administrator_enrolled"`
	TrafficVerified       bool              `json:"traffic_verified"`
}

type setupStatus struct {
	NeedsSetup *bool `json:"needsSetup"`
}
type readyStatus struct {
	Checks map[string]struct {
		Status string `json:"status"`
	} `json:"checks"`
}

// Sources describes read-only host observations selected by the process owner.
// Probe must honor cancellation and bound output; it is called concurrently.
type Sources struct {
	StateDir, BuildFile, NetDir string
	HostnameFile, ResolverFile  string
	Probe                       func(context.Context, []string) string
}

// Collector owns no persistent state or background workers. Each Collect call
// joins all of its probes before returning; callers own context cancellation.
type Collector struct {
	sources Sources
}

// NewCollector copies dependencies so callers cannot replace a live probe.
func NewCollector(sources Sources) Collector {
	return Collector{sources: sources}
}

func httpBody(raw string) (body, code string) {
	index := strings.LastIndexByte(raw, '\n')
	if index < 0 {
		return "", ""
	}
	return raw[:index], raw[index+1:]
}

func (c Collector) observations(ctx context.Context) map[string]string {
	queries := map[string][]string{
		"unit":    {"/usr/bin/systemctl", "show", "culvert-firstboot.service", "--property=" + strings.Join(unitKeys, ",")},
		"network": {"/usr/sbin/ip", "-j", "address", "show", "scope", "global"},
		"route6":  {"/usr/sbin/ip", "-j", "-6", "route", "show", "default"},
		"route":   {"/usr/sbin/ip", "-j", "route", "show", "default"},
		"health":  {"/usr/bin/curl", "--noproxy", "*", "--silent", "--max-time", "2", "--output", "/dev/null", "--write-out", "%{http_code}", "http://127.0.0.1:8080/health"},
		// Only this fixed loopback read permits the appliance's self-signed TLS.
		"setup": {"/usr/bin/curl", "--noproxy", "*", "--silent", "--insecure", "--max-time", "2", "--max-filesize", "65536", "--write-out", "\n%{http_code}", "https://127.0.0.1:9090/api/setup/status"},
		"ready": {"/usr/bin/curl", "--noproxy", "*", "--silent", "--max-time", "2", "--max-filesize", "65536", "--write-out", "\n%{http_code}", "http://127.0.0.1:8080/ready"},
	}
	raw := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for key, args := range queries {
		wg.Go(func() {
			value := c.sources.Probe(ctx, args)
			mu.Lock()
			raw[key] = value
			mu.Unlock()
		})
	}
	wg.Wait()
	return raw
}

// Collect returns a fresh snapshot without changing provisioning or credentials.
func (c Collector) Collect(ctx context.Context) Snapshot {
	raw := c.observations(ctx)
	s := Snapshot{SchemaVersion: 1, ObservedAt: time.Now().UTC().Format(time.RFC3339), Version: "unknown", Addresses: []string{}, ManagementURLs: []string{}, Firstboot: make(map[string]string)}
	for line := range strings.SplitSeq(raw["unit"], "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && slices.Contains(unitKeys, key) {
			s.Firstboot[key] = Clean(value, 40)
		}
	}
	s.Steps = c.steps()
	s.Interfaces, s.Addresses = c.network(raw["network"])
	s.Hostname = readHostname(c.sources.HostnameFile)
	s.Gateway = readGateway(raw["route"])
	s.IPv6Gateway = readGateway(raw["route6"])
	s.DNS = readDNS(c.sources.ResolverFile)
	for _, ip := range s.Addresses {
		s.ManagementURLs = append(s.ManagementURLs, "https://"+net.JoinHostPort(ip, "9090"))
	}
	s.Network = "address_unavailable"
	if len(s.Addresses) > 0 {
		s.Network = "address_assigned"
	}
	c.readBuild(&s)
	s.summarize(raw["health"], raw["setup"], raw["ready"])
	return s
}

func (c Collector) steps() []Step {
	steps := make([]Step, 0, len(stepNames))
	for i, key := range stepNames {
		state := "not_recorded"
		if st, err := os.Stat(filepath.Join(c.sources.StateDir, key+".done")); err == nil && st.Mode().IsRegular() {
			state = "recorded"
		}
		steps = append(steps, Step{key, stepLabels[i], state})
	}
	return steps
}

func (c Collector) readBuild(s *Snapshot) {
	file, err := os.Open(c.sources.BuildFile)
	if err != nil {
		return
	}
	defer file.Close()
	var build struct {
		Appliance struct {
			Version string `json:"version"`
		} `json:"appliance"`
		Candidate struct {
			Candidate bool `json:"candidate"`
		} `json:"candidate"`
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxOutput+1))
	if readErr == nil && len(data) <= maxOutput && json.Unmarshal(data, &build) == nil {
		if build.Appliance.Version != "" {
			s.Version = Clean(build.Appliance.Version, 70)
		}
		s.Candidate = build.Candidate.Candidate
	}
}

func (s Snapshot) recorded(id string) bool {
	for _, step := range s.Steps {
		if step.ID == id && step.State == "recorded" {
			return true
		}
	}
	return false
}

// summarize never treats missing observations or settings POSTs as readiness.
func (s *Snapshot) summarize(health, setupRaw, readyRaw string) {
	var setup setupStatus
	body, code := httpBody(setupRaw)
	setupKnown := code == "200" && json.Unmarshal([]byte(body), &setup) == nil && setup.NeedsSetup != nil
	s.ManagementAvailable = setupKnown
	s.SetupStatus = enrollmentStatus(setupKnown, setup.NeedsSetup)
	s.ApplicationResponding = health == "200"
	s.AdministratorEnrolled = setupKnown && !*setup.NeedsSetup
	s.TrafficVerified = false
	active, result := s.Firstboot["ActiveState"], s.Firstboot["Result"]
	switch {
	case active == "failed" || (result != "" && result != "success" && result != "unknown"):
		s.Phase, s.Reason, s.Message = "failed", "FIRSTBOOT_FAILED", "Provisioning failed; open diagnostics."
	case s.recorded("complete"):
		s.summarizeProvisioned(setupKnown && *setup.NeedsSetup, readinessPassed(readyRaw))
	case active == "active" || active == "activating" || active == "reloading":
		s.Phase, s.Reason, s.Message = "running", "FIRSTBOOT_RUNNING", "Preparing the appliance..."
	case active == "inactive":
		s.Phase, s.Reason, s.Message = "waiting", "FIRSTBOOT_NOT_RUNNING", "Provisioning is incomplete and is not running."
	default:
		s.Phase, s.Reason, s.Message = "unknown", "FIRSTBOOT_UNKNOWN", "Provisioning status is unavailable."
	}
}

func enrollmentStatus(known bool, needsSetup *bool) string {
	if !known {
		return "unknown"
	}
	if *needsSetup {
		return "pending"
	}
	return "completed"
}

func readinessPassed(raw string) bool {
	var ready readyStatus
	body, code := httpBody(raw)
	if code != "200" || json.Unmarshal([]byte(body), &ready) != nil {
		return false
	}
	for _, key := range []string{"policy_loaded", "policy_posture", "ca", "setup_complete"} {
		if ready.Checks[key].Status != "ok" {
			return false
		}
	}
	return true
}

func (s *Snapshot) summarizeProvisioned(needsSetup, checksOK bool) {
	s.Phase = "provisioned"
	switch {
	case !s.ApplicationResponding:
		s.Reason, s.Message = "APPLICATION_UNAVAILABLE", "Application is not responding."
	case needsSetup:
		s.Reason, s.Message = "SETUP_REQUIRED", "Open the management URL to create your administrator."
	case !s.AdministratorEnrolled:
		s.Reason, s.Message = "SETUP_UNKNOWN", "Administrator setup status is unavailable."
	case checksOK:
		s.Phase, s.Reason, s.Message = "ready", "HEALTH_CHECKS_PASSED", "Health checks passed; verify traffic from a test client."
	default:
		s.Reason, s.Message = "READINESS_INCOMPLETE", "Administrator enrolled; readiness checks are incomplete."
	}
}
