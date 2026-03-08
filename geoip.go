package main

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// geoResult holds a cached GeoIP lookup result.
type geoResult struct {
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Status      string `json:"status"`
	cachedAt    time.Time
}

// geoCache caches GeoIP lookups keyed by resolved IP address.
type geoCache struct {
	mu    sync.RWMutex
	cache map[string]*geoResult
}

var geo = &geoCache{cache: make(map[string]*geoResult)}

const geoCacheTTL = time.Hour

// CountryTraffic tracks request counts per country code for the dashboard.
type countryTrafficStore struct {
	mu    sync.RWMutex
	stats map[string]int64 // countryCode → count
	names map[string]string // countryCode → full name
}

var countryTraffic = &countryTrafficStore{
	stats: make(map[string]int64),
	names: make(map[string]string),
}

// activeConns tracks the number of open proxy tunnels/connections.
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
	Code    string `json:"code"`
	Name    string `json:"name"`
	Count   int64  `json:"count"`
}

func (s *countryTrafficStore) Top(n int) []CountryCount {
	s.mu.RLock()
	out := make([]CountryCount, 0, len(s.stats))
	for code, cnt := range s.stats {
		out = append(out, CountryCount{Code: code, Name: s.names[code], Count: cnt})
	}
	s.mu.RUnlock()
	// Sort descending by count.
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

// Lookup returns the two-letter ISO country code for a host (empty on failure).
func (g *geoCache) Lookup(host string) string {
	code, _ := g.LookupFull(host)
	return code
}

// LookupFull returns the country code and full country name for a host.
// Results are cached for geoCacheTTL. Private IPs always return ("", "").
func (g *geoCache) LookupFull(host string) (code, name string) {
	ip := resolveHost(host)
	if ip == nil {
		return "", ""
	}
	ipStr := ip.String()

	g.mu.RLock()
	if r, ok := g.cache[ipStr]; ok && time.Since(r.cachedAt) < geoCacheTTL {
		code, name = r.CountryCode, r.Country
		g.mu.RUnlock()
		return
	}
	g.mu.RUnlock()

	// ip-api.com free tier: 45 req/min, HTTP only, no API key.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ipStr + "?fields=status,countryCode,country")
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	var r geoResult
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", ""
	}
	if r.Status != "success" {
		return "", ""
	}
	r.cachedAt = time.Now()

	g.mu.Lock()
	g.cache[ipStr] = &r
	g.mu.Unlock()

	return r.CountryCode, r.Country
}
