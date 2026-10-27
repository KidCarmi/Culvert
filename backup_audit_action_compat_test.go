package main

// backup_audit_action_compat_test.go — T-71 compatibility gate.
//
// `backup.trigger` is the audit action an admin-started on-demand backup has
// recorded since v1.0.254. SIEM rules and saved audit searches match on it,
// so a rename (the original T-64 draft of this change renamed it to
// `backup.create`) silently stops every one of them matching. The decision is
// to keep `backup.trigger` canonical and record `backup.create` (the
// maintenance agent's operation kind) as an alias in the terminology docs.
//
// This gate drives the real handler and then reads the entry back through
// every consumer surface: the in-memory trail, the SIEM forwarder (a real UDP
// syslog writer installed as the live handle), /api/audit JSON, the CSV
// export, and the OpenAPI contract. On each it asserts the shipped name, and
// exactly ONE entry per backup, so no surface double-counts.

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// t71OpID returns a fresh op id the handler accepts (backupOpIDRE), unique
// per run so -count=N and a shuffled suite cannot see a previous run's entry.
func t71OpID(t *testing.T) string {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	b := make([]byte, 25)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	id := []byte{'0'}
	for _, c := range b {
		id = append(id, alphabet[int(c)%len(alphabet)])
	}
	if !backupOpIDRE.Match(id) {
		t.Fatalf("fixture op id %q does not match backupOpIDRE", id)
	}
	return string(id)
}

// t71SIEM installs a real syslog writer aimed at a local UDP listener as the
// live SIEM handle, and restores the previous handle on cleanup.
func t71SIEM(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sw, err := newSyslogWriter("udp", pc.LocalAddr().String(), "rfc3164")
	if err != nil {
		t.Fatalf("newSyslogWriter: %v", err)
	}
	prev := setSyslogHandle(sw)
	t.Cleanup(func() {
		if displaced := setSyslogHandle(prev); displaced != nil {
			_ = displaced.Close()
		}
	})
	return pc
}

// t71SIEMActions reads forwarded audit messages until the deadline and
// returns the action of every one that carries opID.
func t71SIEMActions(t *testing.T, pc net.PacketConn, opID string, wait time.Duration) []string {
	t.Helper()
	var actions []string
	buf := make([]byte, 64*1024)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		_ = pc.SetReadDeadline(deadline)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		msg := string(buf[:n])
		i := strings.IndexByte(msg, '{')
		if i < 0 || !strings.Contains(msg, opID) {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(strings.TrimSpace(msg[i:])), &e); err != nil {
			t.Fatalf("SIEM message is not an audit JSON entry: %v (%q)", err, msg)
		}
		actions = append(actions, e.Action)
		// One entry is expected: keep listening briefly for a second copy.
		if d := time.Now().Add(300 * time.Millisecond); d.Before(deadline) {
			deadline = d
		}
	}
	return actions
}

func TestT71_BackupAuditActionCompat(t *testing.T) {
	resetBackupsCache(t)
	pc := t71SIEM(t)
	opID := t71OpID(t)

	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"op_id":"` + opID + `","kind":"backup.create","state":"pending","deduped":false}`))
	}))
	t.Cleanup(agent.Close)
	t.Setenv(envMaintAgentURL, agent.URL)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/backups", strings.NewReader(`{"encrypt":false}`))
	req.RemoteAddr = "198.51.100.71:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiBackups(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/backups status = %d (body=%s)", w.Code, w.Body.String())
	}

	// 1. The trail: exactly one entry for this backup, under the shipped name.
	var trail []string
	for _, e := range auditGet() {
		if strings.Contains(e.Detail, "op_id="+opID) {
			trail = append(trail, e.Action)
		}
	}
	if len(trail) != 1 || trail[0] != "backup.trigger" {
		t.Fatalf("audit trail actions for this backup = %v; want exactly [backup.trigger]", trail)
	}

	// 2. The SIEM forwarder: the JSON a SIEM rule matches on.
	if got := t71SIEMActions(t, pc, opID, 3*time.Second); len(got) != 1 || got[0] != "backup.trigger" {
		t.Fatalf("SIEM-forwarded actions for this backup = %v; want exactly [backup.trigger]", got)
	}

	// 3. /api/audit JSON: what a saved search over the API reads.
	rec := httptest.NewRecorder()
	apiAudit(rec, adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit", http.NoBody)))
	var page struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode /api/audit: %v (status %d)", err, rec.Code)
	}
	var api []string
	for _, e := range page.Entries {
		if strings.Contains(e.Detail, "op_id="+opID) {
			api = append(api, e.Action)
		}
	}
	if len(api) != 1 || api[0] != "backup.trigger" {
		t.Fatalf("/api/audit actions for this backup = %v; want exactly [backup.trigger]", api)
	}

	// 4. The CSV export: what a compliance handoff and an offline filter read.
	rec = httptest.NewRecorder()
	apiAudit(rec, adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit?format=csv&source=memory", http.NoBody)))
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || len(rows) == 0 {
		t.Fatalf("read CSV export: %v (rows=%d)", err, len(rows))
	}
	actionCol, detailCol := -1, -1
	for i, h := range rows[0] {
		switch h {
		case "action":
			actionCol = i
		case "detail":
			detailCol = i
		}
	}
	if actionCol < 0 || detailCol < 0 {
		t.Fatalf("CSV header %v lacks action/detail", rows[0])
	}
	var exported []string
	for _, row := range rows[1:] {
		if strings.Contains(row[detailCol], "op_id="+opID) {
			exported = append(exported, row[actionCol])
		}
	}
	if len(exported) != 1 || exported[0] != "backup.trigger" {
		t.Fatalf("CSV export actions for this backup = %v; want exactly [backup.trigger]", exported)
	}

	// 5. The contract: the published audit event of POST /api/backups.
	raw, err := os.ReadFile("api/openapi/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI bundle: %v", err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("decode OpenAPI bundle: %v", err)
	}
	var op map[string]any
	if err := json.Unmarshal(spec.Paths["/api/backups"]["post"], &op); err != nil {
		t.Fatalf("decode OpenAPI POST /api/backups: %v", err)
	}
	if got := op["x-culvert-audit-event"]; got != "backup.trigger" {
		t.Fatalf("OpenAPI POST /api/backups x-culvert-audit-event = %v; want backup.trigger", got)
	}
}

// TestT71_BackupAuditActionIsTheShippedName is the cheap source-level pin: the
// constant the handler emits is the shipped identifier, and the alias is the
// agent op kind, not a second action.
func TestT71_BackupAuditActionIsTheShippedName(t *testing.T) {
	if backupAuditAction != "backup.trigger" {
		t.Fatalf("backupAuditAction = %q; it shipped as backup.trigger and SIEM rules match it verbatim", backupAuditAction)
	}
	if backupOpKind != "backup.create" {
		t.Fatalf("backupOpKind = %q; the terminology alias of backup.trigger is the agent op kind backup.create", backupOpKind)
	}
}
