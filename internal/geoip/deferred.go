package geoip

import (
	"fmt"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// Deferred load of a configured GeoIP database whose STARTUP load failed.
//
// The boot path tolerates a failed InitGeoDB: it logs the error and runs with
// GeoIP disabled. Before this file nothing ever opened the configured path
// again, so every destination-country rule stayed unmatchable until an
// operator fixed the file AND restarted the proxy. Opening the configured path
// is exactly what startup already tried; ArmDeferredLoad records that intent
// and TryDeferredLoad re-attempts it.
//
// This is deliberately NOT a reload. GEO-1 (see InitGeoDB) is about closing a
// reader an in-flight lookup may still hold. TryDeferredLoad publishes only
// while NO reader is loaded, re-checked under geoDBMu at the moment of
// publication, so it never replaces a published reader and never closes one.
// The only reader it closes is one it opened itself and did not publish, which
// no lookup can hold.
//
// Refusals: nothing armed, or a database already loaded. The path is always
// the armed one; nothing here picks a different path.
var (
	// deferredMu serializes attempts and guards the armed intent.
	deferredMu   sync.Mutex
	deferredPath string // "" = nothing armed
)

// ArmDeferredLoad records that the configured database at path, whose startup
// InitGeoDB just failed, should be loaded once it becomes readable. It reports
// whether anything was armed: an empty path or an already loaded database arm
// nothing.
func ArmDeferredLoad(path string) bool {
	if path == "" || Enabled() {
		return false
	}
	deferredMu.Lock()
	defer deferredMu.Unlock()
	deferredPath = path
	return true
}

// DeferredLoadPending returns the armed path, or "" when nothing is pending.
func DeferredLoadPending() string {
	deferredMu.Lock()
	defer deferredMu.Unlock()
	return deferredPath
}

// publishIfUnloaded installs r as the live reader only when none is loaded,
// reporting whether it did. The lock is released by defer so a panic cannot
// leave geoDBMu held behind a recovered caller.
func publishIfUnloaded(r *geoip2.Reader, built time.Time) bool {
	geoDBMu.Lock()
	defer geoDBMu.Unlock()
	if geoDB != nil {
		return false
	}
	geoDB = r
	geoDBBuilt = built
	geoLoadErr = ""
	geoLoadAt = time.Now()
	return true
}

// recordLoadError stores a failed attempt for LoadError.
func recordLoadError(err error) {
	geoDBMu.Lock()
	defer geoDBMu.Unlock()
	geoLoadErr = err.Error()
	geoLoadAt = time.Now()
}

// TryDeferredLoad makes one attempt to load the armed path. It returns
// loaded=true with the path once the database is live. loaded=false with a nil
// error means nothing is pending any more (never armed, or a database is
// already loaded) and the caller should stop. A non-nil error means the file
// still cannot be opened; the intent stays armed and the failure is recorded
// for LoadError.
func TryDeferredLoad() (path string, loaded bool, err error) {
	deferredMu.Lock()
	defer deferredMu.Unlock()
	path = deferredPath
	if path == "" {
		return "", false, nil
	}
	if Enabled() {
		deferredPath = ""
		return path, false, nil
	}
	r, err := geoip2.Open(path)
	if err != nil {
		recordLoadError(err)
		return path, false, fmt.Errorf("geoip database open %s: %w", path, err)
	}
	deferredPath = ""
	if !publishIfUnloaded(r, readerBuildTime(r)) {
		// A database was loaded while the open was in flight. r was never
		// published, so no lookup holds it and closing it is safe.
		_ = r.Close()
		return path, false, nil
	}
	return path, true, nil
}

// ResetForTest unloads the database WITHOUT closing it, clears the recorded
// load error, the armed intent and the IP→country cache. Tests only: the
// reader is leaked on purpose, for the GEO-1 reason above.
func ResetForTest() {
	deferredMu.Lock()
	deferredPath = ""
	deferredMu.Unlock()
	geoDBMu.Lock()
	geoDB = nil
	geoDBBuilt = time.Time{}
	geoLoadErr = ""
	geoLoadAt = time.Time{}
	geoDBMu.Unlock()
	geo.mu.Lock()
	geo.cache = make(map[string]*geoResult)
	geo.mu.Unlock()
}
