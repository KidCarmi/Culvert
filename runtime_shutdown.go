package main

import "github.com/KidCarmi/Culvert/internal/shutdown"

// The registry engine lives in internal/shutdown. Main owns the service hook
// registrations, the phase sequence, and the diagnostic sink (ADR-0036).
type shutdownRegistry = shutdown.Registry

const shutdownHookGrace = shutdown.DefaultGrace

func newShutdownRegistry() *shutdownRegistry {
	return shutdown.New(shutdown.Options{Logf: func(format string, args ...any) {
		logger.Printf(format, args...)
	}})
}
