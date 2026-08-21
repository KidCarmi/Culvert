package broker

import (
	"errors"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

const mcperrResourceLimit = mcperr.ReasonResourceLimit

func brokerErr(reason mcperr.Reason, detail string) error {
	return mcperr.New(reason, "credentials.broker", detail)
}

func errInvalidMaterial(detail string) error {
	return brokerErr(mcperr.ReasonProviderInvalidMaterial, detail)
}

func errCacheFull(detail string) error {
	return brokerErr(mcperr.ReasonCacheFull, detail)
}

// sanitizeProviderError translates an UNTRUSTED provider error into a stable
// broker error WITHOUT embedding the provider's message text (which may contain a
// secret canary). A provider error implementing provider.Classified contributes
// only its Reason enum; any other error maps to a generic provider-unavailable
// reason. It returns the retryable hint and the sanitized error (its text is always
// a fixed reason code).
func sanitizeProviderError(err error) (retryable bool, out error) {
	var c provider.Classified
	if errors.As(err, &c) {
		return c.Retryable(), brokerErr(c.Reason(), "provider operation failed")
	}
	// Unclassified/untrusted error: never reflect its text.
	return false, brokerErr(mcperr.ReasonProviderUnavailable, "provider operation failed")
}
