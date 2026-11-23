//go:build socks5_e2e

package main

// evidence.go — what Culvert recorded about a probe: the Prometheus metrics
// (scraped before and after, compared as deltas), the persistent request log
// (JSONL, read from the offset it had before the probe), and the LDAP
// directory's own event log.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type metrics map[string]float64

func (c *culvert) scrape() (metrics, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://%s/metrics", c.proxyAddr()), http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.metricsToken)
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/metrics: HTTP %d", resp.StatusCode)
	}
	m := metrics{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		m[line[:i]] = v
	}
	return m, sc.Err()
}

// hasFamily reports whether any series of the metric family is present.
func (m metrics) hasFamily(name string) bool {
	for k := range m {
		if k == name || strings.HasPrefix(k, name+"{") {
			return true
		}
	}
	return false
}

func decisionsKey(mode, verdict, reason string) string {
	return fmt.Sprintf(`culvert_socks5_policy_decisions_total{mode=%q,verdict=%q,reason=%q}`, mode, verdict, reason)
}

func ruleHitsKey(rule string) string {
	return fmt.Sprintf(`culvert_policy_rule_hits_total{rule=%q}`, rule)
}

func authFailKey(reason string) string {
	return fmt.Sprintf(`culvert_socks5_auth_failures_total{reason=%q}`, reason)
}

// ── Request log ─────────────────────────────────────────────────────────────

type reqEntry struct {
	Identity    string `json:"identity"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	Status      string `json:"status"`
	RuleMatched string `json:"ruleMatched"`
	ActionTaken string `json:"actionTaken"`
	AuthSource  string `json:"auth_source"`
	SSLAction   string `json:"sslAction"`
}

func (e reqEntry) String() string {
	return fmt.Sprintf("%s %s status=%s rule=%q action=%q identity=%q auth_source=%q",
		e.Method, e.Host, e.Status, e.RuleMatched, e.ActionTaken, e.Identity, e.AuthSource)
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// readJSONLFrom decodes every complete line written after offset.
func readJSONLFrom[T any](path string, offset int64) []T {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil
	}
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// awaitEntry polls the request log for an entry written after offset that
// satisfies match, for up to 3 s (the log is written asynchronously).
func awaitEntry(path string, offset int64, match func(reqEntry) bool) (reqEntry, []reqEntry, bool) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries := readJSONLFrom[reqEntry](path, offset)
		for _, e := range entries {
			if match(e) {
				return e, entries, true
			}
		}
		if time.Now().After(deadline) {
			return reqEntry{}, entries, false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ── LDAP directory events ───────────────────────────────────────────────────

type ldapEvent struct {
	Op      string `json:"op"`
	DN      string `json:"dn"`
	Filter  string `json:"filter"`
	Entries int    `json:"entries"`
	Result  string `json:"result"`
}

func awaitLDAP(path string, offset int64, match func(ldapEvent) bool) bool {
	deadline := time.Now().Add(3 * time.Second)
	for {
		for _, e := range readJSONLFrom[ldapEvent](path, offset) {
			if match(e) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
