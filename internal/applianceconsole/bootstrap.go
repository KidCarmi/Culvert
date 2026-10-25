package applianceconsole

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// BootstrapGuidance reuses the public observation contract. Credentials never
// enter this model; the authorized terminal adapter owns their separate panel.
func BootstrapGuidance(s Snapshot) []Row {
	label, _, style := headline(s)
	recorded := 0
	for _, id := range stepNames {
		if s.recorded(id) {
			recorded++
		}
	}
	rows := []Row{{label, style}, {fmt.Sprintf("Checkpoints recorded: %d/%d (not a progress estimate)", recorded, len(stepNames)), ""}, {"WEB MANAGEMENT", "cyan"}}
	address := observedManagementURL(s)
	if address == "" {
		return append(rows, Row{"URL unavailable: no current management address.", "warning"}, Row{"[1] Inspect network; [3] Inspect provisioning.", ""})
	}
	rows = append(rows, Row{address, "cyan"})
	if !s.ManagementAvailable {
		return append(rows, Row{"Observed address; local management is not ready.", "warning"}, Row{"Wait for setup access; use [3] if provisioning is blocked.", ""})
	}
	rows = append(rows, Row{"Management responds locally; browser access is not verified.", ""})
	if s.SetupStatus == "completed" {
		return append(rows, Row{"Browser administrator exists; use your web sign-in.", ""})
	}
	return append(rows, Row{"Open this address in your browser to create the administrator.", ""})
}

// The appliance collector observes kernel addresses and the shipped 9090
// management endpoint. Never redisplay a URL whose address left that snapshot,
// or accept paths, query strings, credentials, or arbitrary terminal text.
func observedManagementURL(s Snapshot) string {
	for _, raw := range s.Addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			continue
		}
		address := "https://" + net.JoinHostPort(ip.String(), "9090")
		if slices.Contains(s.ManagementURLs, address) {
			return address
		}
	}
	return ""
}
