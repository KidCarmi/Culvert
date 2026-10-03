package applianceconsole

import (
	"fmt"
	"strings"
)

// Row carries printable text and a semantic style; only the renderer emits ANSI.
type Row struct{ Text, Style string }

// View owns presentation/navigation only, never provisioning or authentication.
type View struct {
	admin            bool
	screen           string
	selected, offset int
}

// NewView starts with the browser handoff selected among four visible choices.
func NewView(admin bool) View { return View{admin: admin, screen: "home", selected: 2} }

// DecodeKey recognizes complete, bounded key sequences. Partial escapes do not
// become actions. The input adapter handles a lone Escape after its deadline.
func DecodeKey(raw string) string {
	keys := map[string]string{
		"\x1b[[B": "F2", "\x1bOQ": "F2", "\x1b[12~": "F2",
		"\x1b[[D": "F4", "\x1bOS": "F4", "\x1b[14~": "F4",
		"\x1b[A": "UP", "\x1bOA": "UP", "\x1b[B": "DOWN", "\x1bOB": "DOWN",
		"\x1b[5~": "PAGEUP", "\x1b[6~": "PAGEDOWN", "\t": "TAB", "\r": "ENTER", "\n": "ENTER",
		"\x03": "EXIT", "\x04": "EXIT",
	}
	if key := keys[raw]; key != "" {
		return key
	}
	if len(raw) == 1 && raw[0] >= 32 && raw[0] <= 126 {
		return strings.ToUpper(raw)
	}
	return ""
}

func (v *View) open(screen string) { v.screen, v.offset = screen, 0 }

func (v View) privileged(action string) string {
	if !v.admin {
		return "login"
	}
	return action
}

// Handle never returns a privileged command for an unauthenticated view.
// Numbers open immediately; arrows/Tab select visible rows, then Enter opens.
func (v *View) Handle(key string) string {
	switch key {
	case "R":
		return "refresh"
	case "L", "F2":
		if !v.admin {
			return "login"
		}
		return ""
	case "Q", "EXIT":
		if v.admin {
			return "logout"
		}
		return ""
	case "B", "ESC":
		v.open("home")
		return ""
	case "F4":
		v.open("diagnostics")
		return ""
	case "PAGEUP":
		v.offset = max(0, v.offset-1)
		return ""
	case "PAGEDOWN":
		v.offset++
		return ""
	}
	return v.handleScreen(key)
}

func (v *View) handleScreen(key string) string {
	if v.screen == "home" {
		return v.handleHome(key)
	}
	if key == "UP" {
		v.offset = max(0, v.offset-1)
		return ""
	}
	if key == "DOWN" {
		v.offset++
		return ""
	}
	switch v.screen + ":" + key {
	case "network:E":
		return v.privileged("6")
	case "access:S":
		return v.privileged("2")
	case "recovery:1":
		return v.privileged("4")
	case "recovery:2":
		return v.privileged("5")
	case "recovery:3":
		return v.privileged("6")
	}
	return ""
}

func (v *View) handleHome(key string) string {
	switch key {
	case "UP":
		v.selected = (v.selected+2)%4 + 1
	case "DOWN", "TAB":
		v.selected = v.selected%4 + 1
	case "ENTER":
		v.open([]string{"", "network", "access", "diagnostics", "report"}[v.selected])
	case "1", "2", "3", "4":
		v.selected = int(key[0] - '0')
		return v.handleHome("ENTER")
	case "0":
		if !v.admin {
			return "login"
		}
		v.open("recovery")
	}
	return ""
}

func headline(s Snapshot) (label, next, style string) {
	switch {
	case s.Phase == "failed":
		return "[BLOCKED] Provisioning failed.", "Open [3] for diagnostics and recovery guidance.", "error"
	case len(s.Addresses) == 0:
		return "[ACTION] No management address observed.", "Open [1] to inspect the network.", "warning"
	case s.ManagementAvailable && s.SetupStatus == "pending":
		return "[SETUP AVAILABLE] Management responds locally.", "Open [2] and continue in your browser.", "cyan"
	case s.Phase == "ready":
		return "[CHECKS PASSED] Local health checks passed.", "Verify proxy traffic from a test client.", "cyan"
	case s.Phase == "running":
		return "[STARTING] Preparing the appliance.", "Open [3] for observed checkpoints.", "warning"
	default:
		return "[UNVERIFIED] " + s.Message, "Open [3] to inspect the status source.", "warning"
	}
}

func setupLabel(s Snapshot) string {
	switch s.SetupStatus {
	case "pending":
		return "NOT COMPLETED"
	case "completed":
		return "COMPLETED"
	default:
		return "UNKNOWN"
	}
}

func first(values []string, fallback string) string {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}

func (v View) home(s Snapshot, width int) []Row {
	label, next, style := headline(s)
	rows := []Row{{label, style}, {"NEXT  " + next, ""}, {"", ""}}
	rows = append(rows, identityRows(s, width)...)
	if s.Candidate {
		rows = append(rows, Row{"CANDIDATE BUILD - not qualified for production", "warning"})
	}
	rows = append(rows, Row{"", ""}, Row{"CONTINUE SETUP", "cyan"})
	url := "Unavailable: management endpoint not verified."
	if s.ManagementAvailable {
		url = first(s.ManagementURLs, "No address observed; inspect [1].")
	}
	rows = append(rows, Row{url, "cyan"}, Row{"Local checks do not prove browser or proxy reachability.", ""}, Row{"", ""})
	for i, name := range []string{"Network information", "Setup access", "Diagnose readiness", "Installation report"} {
		prefix, tone := "  ", ""
		if i+1 == v.selected {
			prefix, tone = "> ", "selected"
		}
		rows = append(rows, Row{fmt.Sprintf("%s[%d] %s", prefix, i+1, name), tone})
	}
	return rows
}

func identityRows(s Snapshot, width int) []Row {
	nic, link := "unknown", "unknown"
	if len(s.Interfaces) > 0 {
		nic, link = s.Interfaces[0].Name, s.Interfaces[0].Link
	}
	left := []string{"APPLIANCE", "Host     " + s.Hostname, "Build    " + s.Version, "Setup    " + setupLabel(s), "Traffic  NOT VERIFIED"}
	right := []string{"MANAGEMENT NETWORK", "Interface  " + nic, "Address    " + first(s.Addresses, "not assigned"), "Link       " + link, "Gateway    " + s.Gateway}
	if width < 76 {
		return []Row{{"Host: " + s.Hostname, ""}, {"Build: " + s.Version, ""}, {"Setup: " + setupLabel(s) + " | Traffic: NOT VERIFIED", ""}, {"Address: " + first(s.Addresses, "not assigned"), ""}}
	}
	rows := []Row{}
	for i := range left {
		style := ""
		if i == 0 {
			style = "cyan"
		}
		rows = append(rows, Row{fmt.Sprintf("%-34s %s", clipped(left[i], 34), right[i]), style})
	}
	return rows
}

func (v View) details(s Snapshot) []Row {
	switch v.screen {
	case "network":
		return networkRows(s)
	case "access":
		return accessRows(s)
	case "diagnostics":
		return diagnosticRows(s)
	case "report":
		return reportRows(s)
	case "recovery":
		return []Row{{"AUTHENTICATED RECOVERY", "cyan"}, {"[1] Retry incomplete provisioning", ""}, {"[2] Restart / shutdown (confirmation required)", ""}, {"[3] Recovery shell", ""}, {"Retry cannot restore missing image content.", "warning"}}
	}
	return nil
}

func networkRows(s Snapshot) []Row {
	rows := []Row{{"NETWORK / OBSERVED STATE", "cyan"}, {"Source: kernel addresses and routes; systemd resolver file.", ""}}
	for _, nic := range s.Interfaces {
		rows = append(rows, Row{nic.Name + "   Link: " + nic.Link, "cyan"})
		for _, address := range nic.Addresses {
			rows = append(rows, Row{"  " + address, ""})
		}
	}
	rows = append(rows, Row{"IPv4 gateway: " + s.Gateway, ""}, Row{"IPv6 gateway: " + s.IPv6Gateway, ""}, Row{"DNS: " + first(s.DNS, "unknown"), ""})
	for _, dns := range s.DNS[min(1, len(s.DNS)):] {
		rows = append(rows, Row{"     " + dns, ""})
	}
	return append(rows, Row{"DHCP/static mode: not inferred from an assigned address.", ""}, Row{"Guided changes unavailable: rollback backend is not implemented.", "warning"}, Row{"[E] Authenticated recovery shell for existing network tools", ""})
}

func accessRows(s Snapshot) []Row {
	rows := []Row{{"SETUP ACCESS / BROWSER HANDOFF", "cyan"}, {"Administrator setup: " + setupLabel(s), ""}}
	if !s.ManagementAvailable {
		rows = append(rows, Row{"Management endpoint has not passed its local check.", "warning"})
	} else {
		for _, url := range s.ManagementURLs {
			rows = append(rows, Row{url, "cyan"})
		}
	}
	return append(rows, Row{"Local response does not prove access from your browser.", ""}, Row{"Use Culvert's existing web onboarding and authentication.", ""}, Row{"[S] Show setup access through authenticated sudo", ""}, Row{"Key-only account? Sign in over SSH with your imported key.", ""}, Row{"Set a console password there with: sudo passwd culvert", ""})
}

func diagnosticRows(s Snapshot) []Row {
	rows := []Row{{"DIAGNOSE READINESS", "cyan"}, {"Observed (UTC): " + s.ObservedAt, ""}, {"Reason: " + s.Reason, "warning"}, {s.Message, ""}, {"Source: systemd + firstboot markers + local HTTP checks.", ""}}
	for _, key := range unitKeys {
		rows = append(rows, Row{key + ": " + s.Firstboot[key], ""})
	}
	rows = append(rows, Row{"CHECKPOINTS (recorded markers, not live progress)", "cyan"})
	for _, step := range s.Steps {
		rows = append(rows, Row{step.Label + ": " + step.State, ""})
	}
	return append(rows, Row{"Missing image content needs repair before retrying startup.", "warning"}, Row{"No address alone does not identify a DHCP, VLAN or link fault.", ""})
}

func reportRows(s Snapshot) []Row {
	rows := []Row{{"INSTALLATION REPORT / CURRENT OBSERVATION", "cyan"}, {"Host: " + s.Hostname, ""}, {"Build: " + s.Version, ""}, {"Observed (UTC): " + s.ObservedAt, ""}, {"Provisioning: " + s.Phase, ""}, {"Administrator setup: " + setupLabel(s), ""}, {fmt.Sprintf("Local management response: %t", s.ManagementAvailable), ""}, {fmt.Sprintf("Application health HTTP 200: %t", s.ApplicationResponding), ""}, {"Client traffic: NOT VERIFIED", "warning"}, {"Unresolved status: " + s.Reason, ""}}
	if s.Candidate {
		rows = append(rows, Row{"Candidate build; full appliance qualification not established.", "warning"})
	}
	return append(rows, Row{"Read-only observation; no security attestation or upload.", ""}, Row{"Same facts available over SSH: culvert-console --json", ""})
}

func clipped(text string, width int) string {
	text = Clean(text, len(text))
	if len(text) <= width {
		return text
	}
	if width < 4 {
		return Clean(text, width)
	}
	return text[:width-3] + "..."
}

// Frame reserves a row to prevent terminal scrolling and paginates long content.
// Home selection stays visible in small terminals; details support PgUp/PgDn.
func (v *View) Frame(s Snapshot, height, width int) []Row {
	capacity, columns := max(0, height-1), max(0, width-1)
	if capacity == 0 || columns == 0 {
		return nil
	}
	if capacity < 6 || columns < 19 {
		return []Row{{clipped("Resize terminal (minimum 20x7).", columns), "warning"}, {clipped("L Sign in | Q Log out", columns), ""}}[:min(2, capacity)]
	}
	header := []Row{{"C U L V E R T                 APPLIANCE / FIRST-TIME SETUP", "cyan"}, {strings.Repeat("-", min(columns, 78)), "cyan"}}
	body := v.details(s)
	if v.screen == "home" {
		body = v.home(s, columns)
	}
	// Wrap details instead of discarding long addresses or report identities.
	if v.screen != "home" {
		body = wrapRows(body, columns)
	}
	room := capacity - len(header) - 2
	v.offset = min(v.offset, max(0, len(body)-room))
	if v.screen == "home" && len(body) > room {
		v.offset = max(0, len(body)-4+v.selected-1-room+1)
	}
	end := min(len(body), v.offset+room)
	rows := header
	rows = append(rows, body[v.offset:end]...)
	for len(rows) < capacity-2 {
		rows = append(rows, Row{})
	}
	help := "B Back | Up/Down/PgUp/PgDn Scroll | R Refresh"
	if v.screen == "home" {
		help = "1-4 Open | Arrows/Tab Select | Enter Open | 0 Recovery"
	}
	auth := "L/F2 Sign in | Read-only public console"
	if v.admin {
		auth = "Q Log out | Authenticated as culvert"
	}
	if v.offset > 0 || end < len(body) {
		auth = fmt.Sprintf("%d-%d/%d | ", v.offset+1, end, len(body)) + auth
	}
	rows = append(rows, Row{help, ""}, Row{auth, ""})
	for i := range rows {
		rows[i].Text = clipped(rows[i].Text, columns)
	}
	return rows
}

func wrapRows(rows []Row, width int) []Row {
	out := []Row{}
	for _, row := range rows {
		text := Clean(row.Text, len(row.Text))
		for len(text) > width {
			out = append(out, Row{text[:width], row.Style})
			text = text[width:]
		}
		out = append(out, Row{text, row.Style})
	}
	return out
}

// Render emits fixed standard ANSI colors only after sanitizing every cell.
func Render(rows []Row, color bool) string {
	lines := make([]string, len(rows))
	styles := map[string]string{"cyan": "\x1b[36m", "warning": "\x1b[33m", "error": "\x1b[31m", "selected": "\x1b[30;46m"}
	for i := range rows {
		lines[i] = Clean(rows[i].Text, len(rows[i].Text))
		if color && styles[rows[i].Style] != "" {
			lines[i] = styles[rows[i].Style] + lines[i] + "\x1b[0m"
		}
	}
	return strings.Join(lines, "\n")
}

// Lines provides a complete plain-text report without a terminal size limit.
func Lines(s Snapshot) []string {
	rows := append(reportRows(s), networkRows(s)...)
	rows = append(rows, diagnosticRows(s)...)
	return strings.Split(Render(rows, false), "\n")
}
