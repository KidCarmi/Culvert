//go:build socks5_e2e

// Command driver is the SOCKS5 real-network end-to-end suite (SWG-901).
//
// It starts the REAL culvert binary (built by run.sh) once per SOCKS5 policy
// mode, with a real LDAP directory process as its identity provider, a locally
// configured threat feed and a policy file, and drives it over real TCP
// sockets with a raw RFC 1928/1929 SOCKS5 client, a raw HTTP CONNECT client,
// golang.org/x/net/proxy and curl. Every SOCKS5 case is repeated as an HTTP
// CONNECT by the same principal to the same destination and the verdicts are
// compared.
//
// Exit status: 0 every row passed; 1 at least one row failed; 2 the harness
// could not set up (nothing was judged).
//
// Run it through run.sh, which provides the private mount namespace the
// hosts override needs. See README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	culvertBin := flag.String("culvert", "", "culvert binary under test")
	ldapBin := flag.String("ldapserver", "", "ldapserver binary (this module)")
	modesFlag := flag.String("modes", "enforce,shadow,legacy", "comma-separated socks5_policy_mode values to run")
	work := flag.String("work", "", "work directory (configs, logs, request logs)")
	upstreamIP := flag.String("upstream-ip", "auto", "local IPv4 the upstream servers bind to (must be outside the SSRF guard's private ranges)")
	label := flag.String("label", "checkout", "label for this run (e.g. the mutant name)")
	results := flag.String("results", "", "write the results table (Markdown) here")
	resultsJSON := flag.String("results-json", "", "write the results (JSON) here")
	curlFlag := flag.String("curl", "auto", "curl binary, \"auto\" to look it up, \"\" to skip")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("[socks5-e2e] ")

	if *culvertBin == "" || *ldapBin == "" || *work == "" {
		log.Print("-culvert, -ldapserver and -work are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*work, 0o700); err != nil {
		harnessFail(err)
	}
	ip, err := pickUpstreamIP(*upstreamIP)
	if err != nil {
		harnessFail(err)
	}
	if err := bindHosts(*work, ip); err != nil {
		harnessFail(err)
	}
	curl := *curlFlag
	if curl == "auto" {
		curl, _ = exec.LookPath("curl")
	}
	log.Printf("run %q: culvert=%s upstream=%s curl=%q", *label, *culvertBin, ip, curl)

	ups, err := startUpstreams(ip)
	if err != nil {
		harnessFail(err)
	}
	defer ups.close()
	ldap, err := startLDAP(*ldapBin, *work)
	if err != nil {
		harnessFail(err)
	}
	defer ldap.stop()
	log.Printf("upstreams: echo=%d http=%d https=%d; LDAP at %s", ups.echoPort, ups.httpPort, ups.tlsPort, ldap.addr)

	var rows []row
	for _, mode := range strings.Split(*modesFlag, ",") {
		mode = strings.TrimSpace(mode)
		dir := filepath.Join(*work, "mode-"+mode)
		_ = os.RemoveAll(dir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			harnessFail(err)
		}
		ldapStart := fileSize(ldap.events)
		c, err := startCulvert(*culvertBin, mode, dir, ldap.addr)
		if err != nil {
			harnessFail(fmt.Errorf("start culvert (%s): %w", mode, err))
		}
		log.Printf("mode %s: proxy=%d socks5=%d ui=%d dir=%s", mode, c.proxyPort, c.socksPort, c.uiPort, dir)
		rn := &runner{c: c, u: ups, l: ldap, ldapStart: ldapStart, pe: probeEnv{upstreamCA: ups.caPool, culvertCA: c.caPool}}
		rn.out = append(rn.out, envChecks(c)...)
		for _, tc := range buildCases() {
			rn.runCase(tc)
		}
		rn.runClientChecks(curl)
		c.stop()
		rn.out = append(rn.out, postRunChecks(c)...)
		rows = append(rows, rn.out...)
	}

	md := renderMarkdown(*label, ip, rows)
	fmt.Print(md)
	if *results != "" {
		_ = os.WriteFile(*results, []byte(md), 0o644)
	}
	if *resultsJSON != "" {
		b, _ := json.MarshalIndent(map[string]any{"label": *label, "time": time.Now().UTC().Format(time.RFC3339), "rows": rows}, "", "  ")
		_ = os.WriteFile(*resultsJSON, b, 0o644)
	}
	for _, r := range rows {
		if r.Result != "PASS" {
			os.Exit(1)
		}
	}
}

func harnessFail(err error) {
	log.Printf("HARNESS ERROR (nothing judged): %v", err)
	os.Exit(2)
}

// envChecks are per-process sanity rows: the mode Culvert announced.
func envChecks(c *culvert) []row {
	b, _ := os.ReadFile(c.logPath)
	logText := string(b)
	r := row{Mode: c.mode, Case: "E1", Title: "startup announces the SOCKS5 policy mode", Protocol: "process log"}
	switch c.mode {
	case modeLegacy:
		r.Expected = "no \"SOCKS5 policy mode:\" line (key absent = legacy default)"
		if strings.Contains(logText, "SOCKS5 policy mode:") {
			r.Observed = "mode line present"
			r.fail("legacy (key absent) printed a SOCKS5 policy mode line")
		} else {
			r.Observed = "absent"
		}
	default:
		want := "SOCKS5 policy mode: " + c.mode
		r.Expected = want
		if strings.Contains(logText, want) {
			r.Observed = "present"
		} else {
			r.Observed = "absent"
			r.fail("missing %q", want)
		}
	}
	(&runner{}).finish(&r)
	return []row{r}
}

// postRunChecks run after the process stopped: no off-box threat-feed sync.
func postRunChecks(c *culvert) []row {
	b, _ := os.ReadFile(c.logPath)
	r := row{Mode: c.mode, Case: "E2", Title: "threat feed served from the local DB only (no public feed sync)", Protocol: "process log",
		Expected: "no URLhaus/OpenPhish sync line"}
	if strings.Contains(string(b), "URLhaus") || strings.Contains(string(b), "OpenPhish") {
		r.Observed = "sync attempted"
		r.fail("Culvert tried to sync the public feeds; test traffic left the box")
	} else {
		r.Observed = "none"
	}
	(&runner{}).finish(&r)
	return []row{r}
}

func renderMarkdown(label, ip string, rows []row) string {
	var b strings.Builder
	pass, fail := 0, 0
	for _, r := range rows {
		if r.Result == "PASS" {
			pass++
		} else {
			fail++
		}
	}
	fmt.Fprintf(&b, "\n## SOCKS5 real-network E2E — %s (%s UTC)\n\n", label, time.Now().UTC().Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "Upstream address: %s. Rows: %d PASS, %d FAIL.\n\n", ip, pass, fail)
	b.WriteString("| Mode | Case | Description | Protocol | Expected | Observed | Also asserted | Result |\n|---|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", r.Mode, r.Case, esc(r.Title), r.Protocol, esc(r.Expected), esc(r.Observed), esc(r.Evidence), r.Result)
	}
	if fail > 0 {
		b.WriteString("\n### Failures\n\n")
		for _, r := range rows {
			if r.Result == "PASS" {
				continue
			}
			fmt.Fprintf(&b, "- **%s %s %s**: %s\n", r.Mode, r.Case, r.Protocol, esc(strings.Join(r.Problems, "; ")))
		}
	}
	return b.String()
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
