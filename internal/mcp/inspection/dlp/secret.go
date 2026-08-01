package dlp

import "github.com/KidCarmi/Culvert/internal/redaction"

// scanSecretString runs the existing bounded deterministic scrubber over one
// string leaf and turns its detector hits into sanitized findings. The scrubber
// is the credential-shape backstop (RE2/non-backtracking, zero-width-format-rune
// handling, whole-leaf fail-closed over its own caps, precision-first so
// SHAs/UUIDs/ULIDs are NOT treated as secrets by length). The raw matched secret
// is discarded inside the scrubber; only stable detector names cross the boundary.
func (st *scanState) scanSecretString(s, path string) error {
	_, names, n := redaction.ScrubDetailDefault(s)
	if n == 0 || len(names) == 0 {
		return nil
	}
	// Tally per classification so one leaf with N secrets of the same class is one
	// finding with Count=N (bounded, deterministic).
	type agg struct {
		class Classification
		sev   Severity
		id    string
		count int
	}
	order := make([]string, 0, len(names))
	byID := make(map[string]*agg, len(names))
	for _, name := range names {
		class, sev := classifySecretName(name)
		id := "secret." + name
		a, ok := byID[id]
		if !ok {
			a = &agg{class: class, sev: sev, id: id}
			byID[id] = a
			order = append(order, id)
		}
		a.count++
	}
	for _, id := range order {
		a := byID[id]
		st.add(Finding{Class: a.class, Severity: a.sev, Path: path, DetectorID: a.id, Count: a.count})
	}
	return nil
}

// classifySecretName maps a scrubber detector name to a DLP classification +
// severity. It reuses redaction.SecretClass for the coarse family and refines
// severity: private keys and provider secrets are critical, bearer/JWT high,
// password/api-key assignments high, oversized medium.
func classifySecretName(name string) (class Classification, sev Severity) {
	switch redaction.SecretClass(name) {
	case "private_key":
		return ClassPrivateKey, SevCritical
	case "bearer_token":
		return ClassBearerToken, SevHigh
	case "password_or_api_key":
		return ClassPasswordOrAPIKey, SevHigh
	case "oversized_or_unknown":
		return ClassOversizedUnknown, SevMedium
	default: // credential_secret
		return ClassCredentialSecret, SevCritical
	}
}
