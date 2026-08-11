// Package geoip is the GeoIP country-lookup engine: a local MaxMind GeoLite2
// (.mmdb) reader with an in-memory IP→country cache. It performs no DNS
// resolution and no SSRF/private-range filtering — callers resolve a host to a
// public net.IP first (see resolveHost in package main, which owns the shared
// SSRF check) and then call LookupByIP. This keeps the engine a true leaf with
// no dependency on the rest of Culvert (extracted under ADR-0002, option F).
package geoip

import (
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDBMu    sync.RWMutex
	geoDB      *geoip2.Reader // nil = disabled
	geoDBBuilt time.Time      // MaxMind build timestamp of the loaded .mmdb; zero when not loaded
)

// InitGeoDB opens the GeoLite2-Country .mmdb file.
// Call once at startup. Subsequent calls replace the open reader atomically.
func InitGeoDB(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	built := time.Unix(int64(r.Metadata().BuildEpoch), 0).UTC()
	geoDBMu.Lock()
	old := geoDB
	geoDB = r
	geoDBBuilt = built
	geoDBMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
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
