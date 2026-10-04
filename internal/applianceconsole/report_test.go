package applianceconsole

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type reportWriter struct {
	calls int
	data  []byte
	err   error
	short bool
}

func (w *reportWriter) Write(data []byte) (int, error) {
	w.calls++
	n := len(data)
	if w.short {
		n--
	}
	w.data = append(w.data, data[:n]...)
	return n, w.err
}

func reportFixture() Snapshot {
	return Snapshot{
		SchemaVersion: 1, ObservedAt: "2026-10-04T12:00:00Z", Version: "test-build", Hostname: "culvert.example.test", Candidate: true,
		Phase: "ready", Reason: "HEALTH_CHECKS_PASSED", Message: "Verify client traffic", SetupStatus: "completed",
		ManagementAvailable: true, ApplicationResponding: true, AdministratorEnrolled: true, TrafficVerified: true,
		Network: "address_assigned", Gateway: "192.0.2.1 (ens160)", IPv6Gateway: "2001:db8::1 (ens160)",
		DNS: []string{"192.0.2.53"}, Addresses: []string{"192.0.2.10"}, ManagementURLs: []string{"https://192.0.2.10:9090"},
		Interfaces:    []Interface{{Name: "ens160", Link: "UP", Addresses: []string{"192.0.2.10/24"}}},
		Firstboot:     map[string]string{"LoadState": "loaded", "ActiveState": "active", "Result": "success", "Environment": "TOKEN=PRIVATE_CANARY"},
		Steps:         []Step{{ID: "ovf", State: "recorded", Label: "PRIVATE_LABEL"}, {ID: "private", State: "PRIVATE_STEP"}},
		Prerequisites: []Check{{ID: "clock", State: "ok", Detail: "Host reports synchronized"}, {ID: "arbitrary_secret", State: "ok", Detail: "PRIVATE_CHECK"}},
		Recovery:      Recovery{Version: 1, Available: true, NetworkID: strings.Repeat("a", 32), NetworkPhase: "rolled_back", Records: []RecoveryRecord{{ID: strings.Repeat("a", 32), Action: "network", Phase: "rolled_back", At: "2026-10-04T11:00:00Z", Observation: "coarse checkpoint"}}},
	}
}

func TestDiagnosticReportExportsPublicAllowlistAndLocalEvidenceOnly(t *testing.T) {
	snapshot := reportFixture()
	var output reportWriter
	if err := WriteReport(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	if output.calls != 1 || len(output.data) > ReportMaxBytes || !bytes.HasSuffix(output.data, []byte{'\n'}) {
		t.Fatal("report not emitted in one bounded write")
	}
	var report diagnosticReport
	if err := json.Unmarshal(output.data, &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Kind != "culvert-diagnostic-report" || report.ObservedAt != snapshot.ObservedAt || report.ApplianceVersion != snapshot.Version || !report.Candidate {
		t.Fatalf("missing report identity: %+v", report)
	}
	if _, err := time.Parse(time.RFC3339, report.GeneratedAt); err != nil {
		t.Fatal("invalid report timestamp", err)
	}
	if !report.LocalServices.ManagementResponding || !report.LocalServices.ApplicationResponding || report.ClientReachability != "not_verified" || report.ClientTraffic != "not_verified" {
		t.Fatalf("local service results imply client verification: %+v", report)
	}
	if report.Firstboot["Result"] != "success" || report.Network.Interfaces[0].Addresses[0] != "192.0.2.10/24" || len(report.Prerequisites) != 1 || len(report.Steps) != 1 || report.Recovery.Records[0].Action != "network" {
		t.Fatal("expected public evidence missing")
	}
	for _, excluded := range []string{"PRIVATE_CANARY", "Environment", "PRIVATE_LABEL", "PRIVATE_STEP", "PRIVATE_CHECK", "arbitrary_secret", "traffic_verified"} {
		if bytes.Contains(output.data, []byte(excluded)) {
			t.Errorf("unapproved evidence exported: %s", excluded)
		}
	}
	if snapshot.Firstboot["Environment"] != "TOKEN=PRIVATE_CANARY" || len(snapshot.Prerequisites) != 2 {
		t.Fatal("export modified source snapshot")
	}
}

func TestDiagnosticReportRejectsOversizedFieldsAndCollectionsBeforeWriting(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*Snapshot)
	}{
		{"hostname", func(s *Snapshot) { s.Hostname = strings.Repeat("a", 254) }},
		{"build", func(s *Snapshot) { s.Version = strings.Repeat("a", 65) }},
		{"unit field", func(s *Snapshot) { s.Firstboot["Result"] = strings.Repeat("a", 41) }},
		{"recovery field", func(s *Snapshot) { s.Recovery.Records[0].Observation = strings.Repeat("a", 241) }},
		{"check detail", func(s *Snapshot) { s.Prerequisites[0].Detail = strings.Repeat("a", 257) }},
		{"interface count", func(s *Snapshot) { s.Interfaces = make([]Interface, 17) }},
		{"interface addresses", func(s *Snapshot) { s.Interfaces[0].Addresses = make([]string, 17) }},
		{"global addresses", func(s *Snapshot) { s.Addresses = make([]string, 65) }},
		{"URLs", func(s *Snapshot) { s.ManagementURLs = make([]string, 65) }},
		{"DNS", func(s *Snapshot) { s.DNS = make([]string, 17) }},
		{"steps", func(s *Snapshot) { s.Steps = make([]Step, 17) }},
		{"checks", func(s *Snapshot) { s.Prerequisites = make([]Check, 17) }},
		{"history", func(s *Snapshot) { s.Recovery.Records = make([]RecoveryRecord, 65) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := reportFixture()
			tt.edit(&snapshot)
			var output reportWriter
			if err := WriteReport(&output, snapshot); err == nil {
				t.Fatal("oversized export accepted")
			}
			if output.calls != 0 || len(output.data) != 0 {
				t.Fatal("oversized export partially written")
			}
		})
	}
}

func TestDiagnosticReportChecksEncodedSizeIncludingJSONEscaping(t *testing.T) {
	snapshot := reportFixture()
	snapshot.Recovery.Records = make([]RecoveryRecord, 64)
	for i := range snapshot.Recovery.Records {
		snapshot.Recovery.Records[i] = RecoveryRecord{ID: strings.Repeat("a", 32), Action: "network", Phase: "conflict", Observation: strings.Repeat("<", 240)}
	}
	var output reportWriter
	err := WriteReport(&output, snapshot)
	if err == nil || !strings.Contains(err.Error(), "total export size limit") || output.calls != 0 {
		t.Fatalf("encoded size not enforced before write: error=%v calls=%d", err, output.calls)
	}
}

func TestDiagnosticReportPropagatesWriterFailureAndShortWrites(t *testing.T) {
	injected := errors.New("destination unavailable")
	for _, tt := range []struct {
		name  string
		out   reportWriter
		cause error
	}{
		{"write error", reportWriter{err: injected}, injected},
		{"partial write error", reportWriter{err: injected, short: true}, injected},
		{"short write", reportWriter{short: true}, io.ErrShortWrite},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := WriteReport(&tt.out, reportFixture()); !errors.Is(err, tt.cause) {
				t.Fatalf("lost output failure: %v", err)
			}
			if tt.out.calls != 1 {
				t.Fatal("export retried partially written output")
			}
		})
	}
	if err := WriteReport(nil, Snapshot{}); err == nil {
		t.Fatal("missing destination accepted")
	}
}

func TestDiagnosticReportSanitizesControlsAndVerificationEnums(t *testing.T) {
	snapshot := reportFixture()
	snapshot.Hostname = "host\x1b[2J\nname"
	snapshot.Recovery.Verification = RecoveryVerification{Files: "verified", Apply: "succeeded", ClientAccess: "operator_confirmed"}
	snapshot.Recovery.Records[0].Failure = &RecoveryFailure{Stage: "rollback_command", Code: "timeout"}
	var output bytes.Buffer
	if err := WriteReport(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	var report diagnosticReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Hostname != "host?[2J?name" || report.Recovery.Verification.Files != "verified" || report.Recovery.Records[0].Failure.Code != "timeout" || report.ClientReachability != "not_verified" {
		t.Fatalf("unsafe or missing evidence: %+v", report)
	}
	snapshot.Recovery.Verification = RecoveryVerification{Files: "SECRET_VALUE", Apply: "", ClientAccess: "verified"}
	snapshot.Recovery.Records[0].Failure = &RecoveryFailure{Stage: "SECRET_STAGE", Code: "SECRET_CODE"}
	output.Reset()
	if err := WriteReport(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "SECRET") || report.Recovery.Verification.Files != "unknown" || report.Recovery.Verification.Apply != "unknown" || report.Recovery.Verification.ClientAccess != "unknown" || report.Recovery.Records[0].Failure.Stage != "unknown" || report.Recovery.Records[0].Failure.Code != "unknown" {
		t.Fatal("unknown verification/failure values were exported or promoted")
	}
}
