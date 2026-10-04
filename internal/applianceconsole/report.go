package applianceconsole

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"
)

// ReportMaxBytes includes the trailing newline. Oversized reports are rejected
// before the destination writer receives any bytes.
const ReportMaxBytes = 64 * 1024

// These export-only structs deliberately do not embed Snapshot, Check or
// RecoveryRecord: adding an internal field must not expand the export contract.
type diagnosticReport struct {
	SchemaVersion      int                 `json:"schema_version"`
	Kind               string              `json:"kind"`
	GeneratedAt        string              `json:"generated_at"`
	ObservedAt         string              `json:"observed_at"`
	ApplianceVersion   string              `json:"appliance_version"`
	Candidate          bool                `json:"candidate"`
	Hostname           string              `json:"hostname"`
	Status             reportStatus        `json:"status"`
	LocalServices      reportLocalServices `json:"local_services"`
	ClientReachability string              `json:"client_reachability"`
	ClientTraffic      string              `json:"client_traffic"`
	Network            reportNetwork       `json:"network"`
	Firstboot          map[string]string   `json:"firstboot"`
	Steps              []reportStep        `json:"steps"`
	Prerequisites      []reportCheck       `json:"prerequisites"`
	Recovery           reportRecovery      `json:"recovery"`
	Scope              string              `json:"scope"`
}

type reportStatus struct {
	Phase                 string `json:"phase"`
	Reason                string `json:"reason"`
	Message               string `json:"message"`
	Setup                 string `json:"setup"`
	AdministratorEnrolled bool   `json:"administrator_enrolled"`
}

type reportLocalServices struct {
	ManagementResponding  bool `json:"management_responding"`
	ApplicationResponding bool `json:"application_responding"`
}

type reportNetwork struct {
	State          string            `json:"state"`
	Gateway        string            `json:"gateway"`
	IPv6Gateway    string            `json:"ipv6_gateway"`
	DNS            []string          `json:"dns"`
	Addresses      []string          `json:"addresses"`
	ManagementURLs []string          `json:"management_urls"`
	Interfaces     []reportInterface `json:"interfaces"`
}

type reportInterface struct {
	Name      string   `json:"name"`
	Link      string   `json:"link"`
	Addresses []string `json:"addresses"`
}

type reportStep struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type reportCheck struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type reportRecovery struct {
	Available    bool               `json:"available"`
	Version      int                `json:"version"`
	NetworkID    string             `json:"network_id"`
	NetworkPhase string             `json:"network_phase"`
	Records      []reportRecord     `json:"records"`
	Verification reportVerification `json:"verification"`
	Scope        string             `json:"scope"`
}

type reportVerification struct {
	Files        string `json:"files"`
	Apply        string `json:"apply"`
	ClientAccess string `json:"client_access"`
}

type reportFailure struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

type reportRecord struct {
	ID          string         `json:"id"`
	Action      string         `json:"action"`
	Phase       string         `json:"phase"`
	Boot        string         `json:"boot"`
	Machine     string         `json:"machine"`
	At          string         `json:"at"`
	Observation string         `json:"observation"`
	Failure     *reportFailure `json:"failure,omitempty"`
}

type reportBuilder struct{ err error }

func (b *reportBuilder) text(value string, limit int) string {
	if len(value) > limit {
		b.err = errors.New("diagnostic report field exceeds export bounds")
		return ""
	}
	return Clean(value, limit)
}

func (b *reportBuilder) count(length, limit int) bool {
	if length > limit {
		b.err = errors.New("diagnostic report collection exceeds export bounds")
		return false
	}
	return true
}

func (b *reportBuilder) texts(values []string, count, width int) []string {
	out := []string{}
	if !b.count(len(values), count) {
		return out
	}
	for _, value := range values {
		out = append(out, b.text(value, width))
	}
	return out
}

// WriteReport exports only bounded, explicitly selected public observations.
// It does not collect files, logs, credentials or private recovery state. Local
// responses never imply client reachability or verified traffic. It validates
// the complete JSON before one Write; transport errors can still partially write.
func WriteReport(destination io.Writer, snapshot Snapshot) error {
	if destination == nil {
		return errors.New("diagnostic report destination is missing")
	}
	b := &reportBuilder{}
	report := b.build(snapshot)
	if b.err != nil {
		return b.err
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(data)+1 > ReportMaxBytes {
		return errors.New("diagnostic report exceeds total export size limit")
	}
	data = append(data, '\n')
	n, err := destination.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (b *reportBuilder) build(s Snapshot) diagnosticReport {
	return diagnosticReport{
		SchemaVersion: 1, Kind: "culvert-diagnostic-report", GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ObservedAt: b.text(s.ObservedAt, 40), ApplianceVersion: b.text(s.Version, maxVersionLength), Candidate: s.Candidate,
		Hostname:           b.text(s.Hostname, 253),
		Status:             reportStatus{Phase: b.text(s.Phase, 32), Reason: b.text(s.Reason, 64), Message: b.text(s.Message, 256), Setup: b.text(s.SetupStatus, 32), AdministratorEnrolled: s.AdministratorEnrolled},
		LocalServices:      reportLocalServices{ManagementResponding: s.ManagementAvailable, ApplicationResponding: s.ApplicationResponding},
		ClientReachability: "not_verified", ClientTraffic: "not_verified",
		Network: b.network(s), Firstboot: b.firstboot(s.Firstboot), Steps: b.steps(s.Steps), Prerequisites: b.checks(s.Prerequisites), Recovery: b.recovery(s.Recovery),
		Scope: "Read-only local observations; no client connectivity test, security attestation, raw logs, private configuration or automatic upload.",
	}
}

func (b *reportBuilder) network(s Snapshot) reportNetwork {
	n := reportNetwork{
		State: b.text(s.Network, 32), Gateway: b.text(s.Gateway, 80), IPv6Gateway: b.text(s.IPv6Gateway, 80),
		DNS: b.texts(s.DNS, 16, 64), Addresses: b.texts(s.Addresses, 64, 64), ManagementURLs: b.texts(s.ManagementURLs, 64, 128),
		Interfaces: []reportInterface{},
	}
	if !b.count(len(s.Interfaces), 16) {
		return n
	}
	for _, nic := range s.Interfaces {
		n.Interfaces = append(n.Interfaces, reportInterface{Name: b.text(nic.Name, 15), Link: b.text(nic.Link, 16), Addresses: b.texts(nic.Addresses, 16, 64)})
	}
	return n
}

func (b *reportBuilder) firstboot(values map[string]string) map[string]string {
	out := make(map[string]string)
	// A fixed export list excludes arbitrary service properties and future keys.
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts", "Job"} {
		if value, exists := values[key]; exists {
			out[key] = b.text(value, 40)
		}
	}
	return out
}

func (b *reportBuilder) steps(steps []Step) []reportStep {
	out := []reportStep{}
	if !b.count(len(steps), 16) {
		return out
	}
	for _, step := range steps {
		if slices.Contains([]string{"ovf", "console", "images", "install", "agent", "complete"}, step.ID) {
			out = append(out, reportStep{ID: step.ID, State: b.text(step.State, 32)})
		}
	}
	return out
}

func (b *reportBuilder) checks(checks []Check) []reportCheck {
	out := []reportCheck{}
	if !b.count(len(checks), 16) {
		return out
	}
	for _, check := range checks {
		if slices.Contains([]string{"storage:/", "storage:/var/lib/docker", "storage:/var/lib/culvert-appliance", "storage:/var/log/journal", "clock", "configured_dns", "setup_certificate"}, check.ID) {
			out = append(out, reportCheck{ID: check.ID, State: b.text(check.State, 32), Detail: b.text(check.Detail, 256)})
		}
	}
	return out
}

func (b *reportBuilder) recovery(r Recovery) reportRecovery {
	out := reportRecovery{Available: r.Available, Version: r.Version, NetworkID: b.text(r.NetworkID, 32), NetworkPhase: b.text(r.NetworkPhase, 32), Records: []reportRecord{}, Scope: "Persisted observations; worker liveness and successful recovery are not inferred."}
	out.Verification = reportVerification{
		Files:        reportEnum(r.Verification.Files, "verified", "unverified"),
		Apply:        reportEnum(r.Verification.Apply, "succeeded"),
		ClientAccess: reportEnum(r.Verification.ClientAccess, "operator_confirmed", "unverified"),
	}
	if !b.count(len(r.Records), 64) {
		return out
	}
	for _, record := range r.Records {
		entry := reportRecord{
			ID: b.text(record.ID, 32), Action: b.text(record.Action, 48), Phase: b.text(record.Phase, 32),
			Boot: b.text(record.Boot, 36), Machine: b.text(record.Machine, 32), At: b.text(record.At, 40), Observation: b.text(record.Observation, 240),
		}
		if record.Failure != nil {
			entry.Failure = &reportFailure{
				Stage: reportEnum(record.Failure.Stage, "apply_precheck", "apply_write", "apply_command", "apply_verify", "confirm_verify", "rollback_read", "rollback_precheck", "rollback_write", "rollback_command", "rollback_verify", "persist_phase", "persist_failure", "recovery", "netplan_generate", "netplan_apply"),
				Code:  reportEnum(record.Failure.Code, "no_space", "read_only", "permission_denied", "timeout", "cancelled", "configuration_changed", "operation_failed"),
			}
		}
		out.Records = append(out.Records, entry)
	}
	return out
}

func reportEnum(value string, allowed ...string) string {
	if slices.Contains(allowed, value) {
		return value
	}
	return "unknown"
}
