package main

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// ---------------------------------------------------------------------------
// GeoIP host resolution + dashboard counters (package main side)
//
// The GeoIP *lookup engine* (MaxMind .mmdb reader + IP→country cache) lives in
// internal/geoip. This file keeps the parts that depend on package main:
//
//   - resolveHost: host → public net.IP, applying the shared SSRF private-range
//     check (isPrivateIP/privateCIDRs). It stays here because that SSRF backbone
//     is shared by proxy/security/threatfeed/release and must not be forked.
//   - geo: a thin host-based wrapper preserving the LookupFull/Lookup/LookupCached
//     API used by callers (enrollment.go, policy.go, proxy.go), delegating to the
//     internal/geoip engine after resolution.
//   - countryTraffic / activeConns: dashboard/runtime counters, unrelated to the
//     GeoIP engine (deliberately left in main, ADR-0002 option F).
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
	addrs, err := net.LookupHost(host) //nolint:noctx // pre-existing resolver call moved verbatim during the internal/geoip split (ADR-0002); context-aware DNS is a separate, out-of-scope change to this SSRF-adjacent path
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

// geoResolver is the host-based GeoIP facade used across package main. It owns
// host→IP resolution (with the SSRF check) and delegates the actual country
// lookup to the internal/geoip engine.
type geoResolver struct{}

// geo preserves the call-site API (geo.LookupFull/Lookup/LookupCached) that
// existed before the engine was extracted to internal/geoip.
var geo = &geoResolver{}

// Lookup returns the two-letter ISO country code for a host ("" on failure or disabled).
func (geoResolver) Lookup(host string) string {
	code, _ := geo.LookupFull(host)
	return code
}

// LookupFull returns the country code and full name for a host.
func (geoResolver) LookupFull(host string) (code, name string) {
	if !geoip.Enabled() {
		return "", ""
	}
	ip := resolveHost(host)
	if ip == nil {
		return "", ""
	}
	return geoip.LookupByIP(ip)
}

// LookupCached returns the country code only if already in cache.
// Never triggers a new lookup — safe to call in the hot policy path.
// Returns ("", false) on cache miss or when GeoIP is disabled.
func (geoResolver) LookupCached(host string) (code string, ok bool) {
	if !geoip.Enabled() {
		return "", false
	}
	ip := resolveHost(host)
	if ip == nil {
		return "", false
	}
	return geoip.LookupCachedByIP(ip)
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
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
