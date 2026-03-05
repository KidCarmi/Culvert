package main

// AuthProvider is the interface every authentication backend must implement.
// The proxy calls Verify on every request that requires authentication.
// Implementations are expected to be goroutine-safe and to cache results
// internally to avoid expensive round-trips on every proxied request.
type AuthProvider interface {
	// Verify returns true when the supplied credentials are valid.
	Verify(username, password string) bool
	// Name returns a human-readable backend identifier used in logs.
	Name() string
}
