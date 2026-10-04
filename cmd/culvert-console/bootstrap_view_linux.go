//go:build linux

package main

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

// The password is a terminal-only argument, never part of the public Snapshot.
// Keep the credential whole even on small terminals; URLs are whole or omitted.
func bootstrapRows(s applianceconsole.Snapshot, password string, height, width int) []applianceconsole.Row {
	capacity, columns := max(0, min(height, 25)-1), max(0, min(width, 80)-1)
	lines := []string{"INITIAL CONSOLE ACCESS", "User: culvert", "Initial password:", password, "L/F2 Sign in"}
	if height < 6 || width < 18 {
		lines = []string{"Resize to 18x6", "L/F2 Sign in"}
	}
	rows := make([]applianceconsole.Row, capacity)
	for i := range rows {
		if i < len(lines) {
			rows[i].Text = applianceconsole.Clean(lines[i], columns)
		}
	}
	if height < 6 || width < 18 {
		return rows
	}
	full := append([]applianceconsole.Row{{Text: "CULVERT / FIRST START", Style: "cyan"}}, applianceconsole.BootstrapGuidance(s)...)
	full = append(full, applianceconsole.Row{}, applianceconsole.Row{Text: "LOCAL CONSOLE ACCESS", Style: "cyan"})
	for _, text := range lines[1:] {
		full = append(full, applianceconsole.Row{Text: text})
	}
	full = append(full, applianceconsole.Row{Text: "Change this local password at first sign-in."})
	if s.SetupStatus == "completed" {
		full = append(full, applianceconsole.Row{Text: "This local password is separate from your web administrator."})
	} else {
		full = append(full,
			applianceconsole.Row{Text: "The browser setup token is a DIFFERENT credential."},
			applianceconsole.Row{Text: "After local sign-in: [2] Setup access, then [S] Show token."},
			applianceconsole.Row{Text: "Enter the setup token only in the browser setup wizard."},
		)
	}
	full = append(full,
		applianceconsole.Row{Text: "SSH password login is disabled."},
		applianceconsole.Row{Text: "1 Network | 2 Setup | 3 Diagnostics | 4 Report | B Back"},
	)
	full = wrapBootstrapRows(full, columns)
	if len(full) <= capacity {
		copy(rows, full)
		return rows
	}
	// The compact handoff retains the full password and login key. Public
	// details remain navigable; never clip a URL into a plausible wrong address.
	guidance := applianceconsole.BootstrapGuidance(s)
	compact := []string{guidance[0].Text, "URL/token help: [2] Setup access", "1 Network | 3 Diagnostics | B Back", "Resize for full setup guidance."}
	for i := len(lines); i < len(rows) && i-len(lines) < len(compact); i++ {
		rows[i].Text = applianceconsole.Clean(compact[i-len(lines)], columns)
	}
	return rows
}

func wrapBootstrapRows(rows []applianceconsole.Row, width int) []applianceconsole.Row {
	out := make([]applianceconsole.Row, 0, len(rows))
	for _, row := range rows {
		text := applianceconsole.Clean(row.Text, len(row.Text))
		if strings.HasPrefix(text, "https://") && len(text) > width {
			// A split address can be mistaken for a shorter valid URL. Keep
			// the entire URL on one row or omit it until the terminal grows.
			text = "Resize for full management URL."
		}
		for len(text) > width {
			out = append(out, applianceconsole.Row{Text: text[:width], Style: row.Style})
			text = text[width:]
		}
		out = append(out, applianceconsole.Row{Text: text, Style: row.Style})
	}
	return out
}
