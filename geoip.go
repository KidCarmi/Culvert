package main

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/oschwald/geoip2-golang"
)

// ---------------------------------------------------------------------------
// GeoIP — local MaxMind GeoLite2 database
//
// No external HTTP calls. Lookups are served from the local .mmdb file.
// If no database path is configured, all GeoIP lookups return ("", "")
// and destCountry policy conditions are silently skipped (fail-open for
// country checks only — the rest of the rule still applies).
//
// To enable:
//   1. Download GeoLite2-Country.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
//   2. Place it in /data/ (Docker) or any accessible path
//   3. Pass -geoip-db /data/GeoLite2-Country.mmdb
// ---------------------------------------------------------------------------

var (
	geoDBMu sync.RWMutex
	geoDB   *geoip2.Reader // nil = disabled
)

// InitGeoDB opens the GeoLite2-Country .mmdb file.
// Call once at startup. Subsequent calls replace the open reader atomically.
func InitGeoDB(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	geoDBMu.Lock()
	old := geoDB
	geoDB = r
	geoDBMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// geoEnabled reports whether a GeoIP database is loaded.
func geoEnabled() bool {
	geoDBMu.RLock()
	ok := geoDB != nil
	geoDBMu.RUnlock()
	return ok
}

// ---------------------------------------------------------------------------
// In-memory cache — avoids repeated .mmdb lookups for the same IP
// ---------------------------------------------------------------------------

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
		for k := range g.cache { // evict one random entry
			delete(g.cache, k)
			break
		}
	}
	g.cache[ipStr] = &geoResult{CountryCode: code, Country: name}
	g.mu.Unlock()
	return
}

// ---------------------------------------------------------------------------
// Public API used by proxy.go and policy.go
// ---------------------------------------------------------------------------

// resolveHost returns the first public IP for a given host (or parses it directly).
func resolveHost(host string) net.IP {
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if isPrivateIP(ip) {
			return nil
		}
		return ip
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && !isPrivateIP(ip) {
			return ip
		}
	}
	return nil
}

// Lookup returns the two-letter ISO country code for a host ("" on failure or disabled).
func (g *geoCache) Lookup(host string) string {
	code, _ := g.LookupFull(host)
	return code
}

// LookupFull returns the country code and full name for a host.
func (g *geoCache) LookupFull(host string) (code, name string) {
	if !geoEnabled() {
		return "", ""
	}
	ip := resolveHost(host)
	if ip == nil {
		return "", ""
	}
	return g.lookup(ip.String())
}

// LookupCached returns the country code only if already in cache.
// Never triggers a new lookup — safe to call in the hot policy path.
// Returns ("", false) on cache miss or when GeoIP is disabled.
func (g *geoCache) LookupCached(host string) (code string, ok bool) {
	if !geoEnabled() {
		return "", false
	}
	ip := resolveHost(host)
	if ip == nil {
		return "", false
	}
	ipStr := ip.String()
	g.mu.RLock()
	defer g.mu.RUnlock()
	if r, hit := g.cache[ipStr]; hit {
		return r.CountryCode, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Country traffic stats (dashboard)
// ---------------------------------------------------------------------------

type countryTrafficStore struct {
	mu    sync.RWMutex
	stats map[string]int64
	names map[string]string
}

var countryTraffic = &countryTrafficStore{
	stats: make(map[string]int64),
	names: make(map[string]string),
}

var activeConns int64

func recordActiveConn(delta int64) { atomic.AddInt64(&activeConns, delta) }
func getActiveConns() int64        { return atomic.LoadInt64(&activeConns) }

func (s *countryTrafficStore) Record(code, name string) {
	if code == "" {
		return
	}
	s.mu.Lock()
	s.stats[code]++
	if name != "" {
		s.names[code] = name
	}
	s.mu.Unlock()
}

type CountryCount struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func (s *countryTrafficStore) Top(n int) []CountryCount {
	s.mu.RLock()
	out := make([]CountryCount, 0, len(s.stats))
	for code, cnt := range s.stats {
		out = append(out, CountryCount{Code: code, Name: s.names[code], Count: cnt})
	}
	s.mu.RUnlock()
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Count > out[i].Count {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

