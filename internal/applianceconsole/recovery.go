package applianceconsole

import "encoding/json"

// Recovery is a sanitized worker observation, not a current liveness guarantee.
type Recovery struct {
	Version      int                  `json:"version"`
	Records      []RecoveryRecord     `json:"records,omitempty"`
	NetworkID    string               `json:"network_id,omitempty"`
	NetworkPhase string               `json:"network_phase,omitempty"`
	Available    bool                 `json:"available"`
	Verification RecoveryVerification `json:"verification"`
}

// RecoveryVerification never equates a successful command with client access.
type RecoveryVerification struct {
	Files        string `json:"files"`
	Apply        string `json:"apply"`
	ClientAccess string `json:"client_access"`
}

// RecoveryFailure contains fixed worker classifications, never raw stderr.
type RecoveryFailure struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

// RecoveryRecord deliberately excludes configuration, credentials and raw logs.
type RecoveryRecord struct {
	ID          string           `json:"id"`
	Action      string           `json:"action"`
	Phase       string           `json:"phase"`
	Boot        string           `json:"boot"`
	Machine     string           `json:"machine"`
	At          string           `json:"at"`
	Observation string           `json:"observation,omitempty"`
	Failure     *RecoveryFailure `json:"failure,omitempty"`
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
