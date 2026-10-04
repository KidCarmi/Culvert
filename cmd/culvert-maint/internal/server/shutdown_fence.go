package server

import (
	"errors"
	"strings"
)

const shutdownFenceName = "host-shutdown.pending"
const shutdownFenceLimit = 128

// The shell maintenance owner writes this exact, bounded, versioned format.
// Unknown versions and malformed contents are unavailable, never permission
// to admit destructive work during a potentially pending shutdown.
func parseShutdownFence(data []byte) (string, error) {
	if len(data) == 0 || len(data) > shutdownFenceLimit || data[len(data)-1] != '\n' {
		return "", errors.New("invalid pending shutdown fence")
	}
	parts := strings.Split(string(data[:len(data)-1]), " ")
	if len(parts) != 4 || parts[0] != "culvert-shutdown-v1" || !validBootID(parts[1]) || (parts[2] != "reboot" && parts[2] != "poweroff") || (parts[3] != "pending" && parts[3] != "aborted") {
		return "", errors.New("invalid pending shutdown fence")
	}
	return parts[1], nil
}

func validBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
