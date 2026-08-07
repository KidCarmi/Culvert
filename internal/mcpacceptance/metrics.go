package mcpacceptance

import (
	"strconv"
	"strings"
)

// bannedLabels are the high-cardinality label keys that must NEVER appear on any
// culvert_mcp_* series. The MCP metrics use only fixed closed enums.
var bannedLabels = []string{"tenant", "principal", "server", "tool", "event_id", "eventid", "path", "subject", "client"}

// scanHighCardinality returns the first banned label found on a culvert_mcp_*
// series, or "" if the invariant holds. It parses the Prometheus text exposition
// line by line and inspects only MCP series' label sets.
func scanHighCardinality(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "culvert_mcp_") {
			continue
		}
		open := strings.IndexByte(line, '{')
		if open < 0 {
			continue
		}
		closeIdx := strings.IndexByte(line, '}')
		if closeIdx < open {
			continue
		}
		labels := line[open+1 : closeIdx]
		for _, kv := range strings.Split(labels, ",") {
			key := strings.TrimSpace(strings.SplitN(kv, "=", 2)[0])
			for _, banned := range bannedLabels {
				if key == banned {
					return "culvert_mcp series carries label " + banned
				}
			}
		}
	}
	return ""
}

// metricValueAtLeast reports whether any sample of the named metric is >= min.
func metricValueAtLeast(body []byte, name string, min float64) bool {
	prefix := name
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		// The value is the last space-separated field.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		if v >= min {
			return true
		}
	}
	return false
}
