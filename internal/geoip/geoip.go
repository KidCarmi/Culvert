// Package geoip is the GeoIP country-lookup engine: a local MaxMind GeoLite2
// (.mmdb) reader with an in-memory IP→country cache. It performs no DNS
// resolution and no SSRF/private-range filtering — callers resolve a host to a
// public net.IP first (see resolveHost in package main, which owns the shared
// SSRF check) and then call LookupByIP. This keeps the engine a true leaf with
// no dependency on the rest of Culvert (extracted under ADR-0002, option F).
package geoip

import (
	"math"
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDBMu    sync.RWMutex
	geoDB      *geoip2.Reader // nil = disabled
	geoDBBuilt time.Time      // MaxMind build timestamp of the loaded .mmdb; zero when not loaded
	geoLoadErr string         // "" = no failure on record
	geoLoadAt  time.Time      // when geoLoadErr was last set
)

// InitGeoDB opens the GeoLite2-Country .mmdb file.
//
// **Call once at startup, and only at startup.** A failure is recorded for
// LoadError and left for the caller to log; it is cleared by a subsequent
// successful call so a fixed path stops reporting a stale error.
//
// GEO-1 (CHAOS-57). This function used to claim that "subsequent calls replace
// the open reader atomically". The POINTER swap is atomic; the CLOSE is not
// safe, and the difference is a process kill rather than an error. geoCache.lookup
// copies `db := geoDB` under the read lock, RELEASES it, and only then calls
// db.Country(ip) — while the swap here calls old.Close() immediately after
// releasing the write lock. geoip2's Close reaches maxminddb's, which
// **munmaps the backing buffer** (reader_mmap.go), so an in-flight lookup
// holding the old reader reads unmapped memory: a SIGSEGV/SIGBUS that Go's
// recover() cannot catch, that crashguard.go never sees, and that leaves no log
// line — a total gateway outage with no evidence.
//
// It is NOT reachable today: loadGeoIP (geoip_startup.go) is the only
// production caller and runs during startup, before the proxy listener serves.
// The hazard is that a reload path is a natural next feature — CLAUDE.md
// mandates a GUI surface for every config option — and the old comment told
// whoever adds it that the swap was already safe. It is not. Before adding any
// runtime reload, the reader lifetime must be made safe first: hold the read
// lock across db.Country, or reference-count the reader, or simply never close
// the old one (a leaked mapping is strictly cheaper than a crash). Recorded in
// roadmap/CHAOS-ENGINEERING-REVIEW.md §25.7 rather than fixed here, because
// building unreachable lifetime machinery for a path with no caller is the
// wrong trade — the trap was the claim, and the claim is what is corrected.
func InitGeoDB(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		geoDBMu.Lock()
		geoLoadErr = err.Error()
		geoLoadAt = time.Now()
		geoDBMu.Unlock()
		return err
	}
	epoch := r.Metadata().BuildEpoch
	if epoch > math.MaxInt64 {
		epoch = math.MaxInt64 // implausible (year 292e9); clamp for the G115 conversion bound
	}
	built := time.Unix(int64(epoch), 0).UTC() // #nosec G115 -- clamped above
	geoDBMu.Lock()
	old := geoDB
	geoDB = r
	geoDBBuilt = built
	geoLoadErr = ""
	geoLoadAt = time.Now()
	geoDBMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// LoadError reports the most recent InitGeoDB failure and when it occurred.
// ok is false when no database was ever configured, or the last attempt (if
// any) succeeded — i.e. there is nothing for an operator to act on.
func LoadError() (msg string, at time.Time, ok bool) {
	geoDBMu.RLock()
	defer geoDBMu.RUnlock()
	return geoLoadErr, geoLoadAt, geoLoadErr != ""
}

// Enabled reports whether a GeoIP database is loaded.
func Enabled() bool {
	geoDBMu.RLock()
	ok := geoDB != nil
	geoDBMu.RUnlock()
	return ok
}

// BuildTime returns the loaded database's MaxMind build timestamp — embedded
// in the .mmdb file's own metadata, not the file's mtime — and whether a
// database is currently loaded. Culvert never auto-refreshes this file, and
// GeoLite2 country data degrades in accuracy over time, so callers use this
// to surface staleness to the operator (there is otherwise no signal that
// the loaded database predates a country's IP allocations).
func BuildTime() (built time.Time, ok bool) {
	geoDBMu.RLock()
	defer geoDBMu.RUnlock()
	if geoDB == nil {
		return time.Time{}, false
	}
	return geoDBBuilt, true
}

type geoResult struct {
	CountryCode string
	Country     string
}

type geoCache struct {
	mu    sync.RWMutex
	cache map[string]*geoResult
}

const geoCacheMaxSize = 50_000

var geo = &geoCache{cache: make(map[string]*geoResult)}

func (g *geoCache) lookup(ipStr string) (code, name string) {
	g.mu.RLock()
	if r, ok := g.cache[ipStr]; ok {
		code, name = r.CountryCode, r.Country
		g.mu.RUnlock()
		return
	}
	g.mu.RUnlock()

	geoDBMu.RLock()
	db := geoDB
	geoDBMu.RUnlock()
	if db == nil {
		return "", ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ""
	}
	record, err := db.Country(ip)
	if err != nil {
		return "", ""
	}
	code = record.Country.IsoCode
	name = record.Country.Names["en"]

	g.mu.Lock()
	if len(g.cache) >= geoCacheMaxSize {
		// Evict ~10 % of entries to avoid thrashing (one-at-a-time eviction
		// under sustained load causes a cache miss on nearly every new IP).
		toEvict := geoCacheMaxSize / 10
		if toEvict == 0 {
			toEvict = 1
		}
		evicted := 0
		for k := range g.cache {
			delete(g.cache, k)
			evicted++
			if evicted >= toEvict {
				break
			}
		}
	}
	g.cache[ipStr] = &geoResult{CountryCode: code, Country: name}
	g.mu.Unlock()
	return
}

// lookupCached returns the cached country code for ipStr without ever issuing a
// new database lookup. Safe to call on the hot policy path.
func (g *geoCache) lookupCached(ipStr string) (code string, ok bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if r, hit := g.cache[ipStr]; hit {
		return r.CountryCode, true
	}
	return "", false
}

// LookupByIP returns the ISO country code and full name for an already-resolved
// public IP. Returns ("", "") when GeoIP is disabled, the IP is nil, or the
// lookup fails. Host resolution + SSRF filtering is the caller's responsibility.
func LookupByIP(ip net.IP) (code, name string) {
	if ip == nil {
		return "", ""
	}
	return geo.lookup(ip.String())
}

// LookupCachedByIP returns the country code only if already cached; it never
// triggers a new database lookup. Returns ("", false) on a cache miss or a nil IP.
func LookupCachedByIP(ip net.IP) (code string, ok bool) {
	if ip == nil {
		return "", false
	}
	return geo.lookupCached(ip.String())
}
