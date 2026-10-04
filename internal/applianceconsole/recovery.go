package applianceconsole

import "encoding/json"

// Recovery is a sanitized worker observation, not a current liveness guarantee.
type Recovery struct {
	Version      int              `json:"version"`
	Records      []RecoveryRecord `json:"records,omitempty"`
	NetworkID    string           `json:"network_id,omitempty"`
	NetworkPhase string           `json:"network_phase,omitempty"`
	Available    bool             `json:"available"`
}

// RecoveryRecord deliberately excludes configuration, credentials and raw logs.
type RecoveryRecord struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Phase       string `json:"phase"`
	Boot        string `json:"boot"`
	Machine     string `json:"machine"`
	At          string `json:"at"`
	Observation string `json:"observation,omitempty"`
}

func readRecovery(path string) Recovery {
	var r Recovery
	if path == "" {
		return r
	}
	if err := json.Unmarshal([]byte(readPublicFile(path)), &r); err != nil || r.Version != 1 || len(r.Records) > 64 {
		return Recovery{}
	}
	r.Available = true
	return r
}
