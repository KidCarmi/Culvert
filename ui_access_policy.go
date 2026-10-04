package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
)

// Guarded together with uiAllowedNets. Refused loaded data never becomes an
// empty/open policy. A known malformed slice is retained; unknown file contents
// instead block omnibus saves until local recovery can establish authority.
var (
	uiAccessRefused  bool
	uiAccessUnknown  bool
	uiAccessRetained []string
)

func parseUIAllowedCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for i, value := range cidrs {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("entry %d must be an IP address or CIDR; use an empty list to remove restrictions", i+1)
		}
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("entry %d is not a valid IP address or CIDR", i+1)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func canonicalUIAllowedCIDRs(nets []*net.IPNet) []string {
	values := make([]string, len(nets))
	for i, n := range nets {
		values[i] = n.String()
	}
	return values
}

func publishUIAllowedCIDRs(nets []*net.IPNet) {
	uiAllowedNetsMu.Lock()
	defer uiAllowedNetsMu.Unlock()
	uiAllowedNets = nets
	uiAccessRefused, uiAccessUnknown, uiAccessRetained = false, false, nil
}

func refuseLoadedUIAccessPolicy(retained []string) {
	uiAllowedNetsMu.Lock()
	defer uiAllowedNetsMu.Unlock()
	uiAccessRefused, uiAccessUnknown = true, retained == nil
	uiAccessRetained = append([]string(nil), retained...)
}

func uiAccessPolicyRefused() bool {
	uiAllowedNetsMu.RLock()
	defer uiAllowedNetsMu.RUnlock()
	return uiAccessRefused
}

func uiAccessSavePrecondition() error {
	uiAllowedNetsMu.RLock()
	defer uiAllowedNetsMu.RUnlock()
	if uiAccessUnknown {
		return errors.New("management access policy is unknown; repair stored settings locally before saving")
	}
	return nil
}

func noteUIAccessQuarantine(path string) {
	files, err := filepath.Glob(globEscapeLiteral(path) + ".corrupt.*")
	if err != nil || len(files) > 0 {
		refuseLoadedUIAccessPolicy(nil)
	}
}

func decodeAdminSettingsObject(data []byte, s *AdminSettings) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("admin settings must be a JSON object")
	}
	return json.Unmarshal(data, s)
}

func applyAdminUIAccessPolicy(s *AdminSettings) {
	if !s.UIAllowIPsSaved && len(s.UIAllowIPs) == 0 {
		return
	}
	if err := SetUIAllowedCIDRs(s.UIAllowIPs); err != nil {
		refuseLoadedUIAccessPolicy(s.UIAllowIPs)
		logger.Printf("AdminSettings: invalid management access policy; UI access is refused until local recovery (%v)", err)
	}
}

func writeUIAccessRefusal(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

func persistUIAllowedCIDRs(nets []*net.IPNet) error {
	target := canonicalUIAllowedCIDRs(nets)
	return saveAdminSettingsWithOverrides(adminSaveOverrides{
		uiAllowIPs:     &target,
		applyOnSuccess: func() { publishUIAllowedCIDRs(nets) },
	})
}

func appendUIAccessReadinessCheck(checks map[string]*readinessCheck) {
	if uiAccessPolicyRefused() {
		checks["ui_access_policy"] = &readinessCheck{Status: "fail", Detail: "management access policy unavailable; local recovery required"}
	}
}
