package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- CLI flags ----------

var (
	port      = flag.Int("port", 8080, "Proxy port")
	uiPort    = flag.Int("ui-port", 9090, "Web UI port")
	proxyUser = flag.String("user", "", "Basic auth username")
	proxyPass = flag.String("pass", "", "Basic auth password")
	blockFile = flag.String("blocklist", "", "Path to blocklist file")
	logFile   = flag.String("logfile", "", "Path to log file")

	logger *log.Logger
)

// ---------- Stats ----------

var (
	statTotal   int64
	statBlocked int64
	statAuthFail int64
)

// ---------- Request log ring buffer ----------

type LogEntry struct {
	Time    string `json:"time"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Host    string `json:"host"`
	Status  string `json:"status"`
}

const maxLogEntries = 200

var (
	recentLogs   []LogEntry
	recentLogsMu sync.Mutex
)

func addLog(entry LogEntry) {
	recentLogsMu.Lock()
	defer recentLogsMu.Unlock()
	recentLogs = append(recentLogs, entry)
	if len(recentLogs) > maxLogEntries {
		recentLogs = recentLogs[len(recentLogs)-maxLogEntries:]
	}
}

// ---------- Blocklist ----------

var (
	blocklistMu sync.RWMutex
	blocklist   = map[string]bool{}
	blocklistPath string
)

func loadBlocklist(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	newList := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		newList[strings.ToLower(line)] = true
	}
	blocklistMu.Lock()
	blocklist = newList
	blocklistMu.Unlock()
	return scanner.Err()
}

func saveBlocklist() error {
	if blocklistPath == "" {
		return nil
	}
	blocklistMu.RLock()
	defer blocklistMu.RUnlock()
	f, err := os.Create(blocklistPath)
	if err != nil {
		return err
	}
	defer f.Close()
	for host := range blocklist {
		fmt.Fprintln(f, host)
	}
	return nil
}

func isBlocked(host string) bool {
	blocklistMu.RLock()
	defer blocklistMu.RUnlock()
	return blocklist[strings.ToLower(host)]
}

// ---------- Main ----------

func main() {
	flag.Parse()

	// Logger setup.
	writers := []io.Writer{os.Stdout}
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Cannot open log file: %v", err)
		}
		defer f.Close()
		writers = append(writers, f)
	}
	logger = log.New(io.MultiWriter(writers...), "", log.LstdFlags)

	// Blocklist setup.
	if *blockFile != "" {
		blocklistPath = *blockFile
		if err := loadBlocklist(*blockFile); err != nil {
			logger.Fatalf("Cannot load blocklist: %v", err)
		}
		logger.Printf("Loaded %d blocked hosts", len(blocklist))
	}

	// Start Web UI.
	go startUI(*uiPort)
	logger.Printf("Web UI on http://localhost:%d", *uiPort)

	// Start proxy.
	addr := fmt.Sprintf(":%d", *port)
	logger.Printf("Starting proxy on %s", addr)
	server := &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		logger.Fatalf("Proxy failed: %v", err)
	}
}

// ---------- Proxy ----------

func handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&statTotal, 1)
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Basic auth.
	if *proxyUser != "" {
		user, pass, ok := parseProxyAuth(r)
		if !ok || user != *proxyUser || pass != *proxyPass {
			atomic.AddInt64(&statAuthFail, 1)
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			addLog(LogEntry{time.Now().Format("15:04:05"), clientIP, r.Method, r.Host, "AUTH FAIL"})
			logger.Printf("AUTH FAIL %s", clientIP)
			return
		}
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Blocklist.
	if isBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden", http.StatusForbidden)
		addLog(LogEntry{time.Now().Format("15:04:05"), clientIP, r.Method, r.Host, "BLOCKED"})
		logger.Printf("BLOCKED %s -> %s", clientIP, host)
		return
	}

	addLog(LogEntry{time.Now().Format("15:04:05"), clientIP, r.Method, r.Host, "OK"})
	logger.Printf("%s %s %s", clientIP, r.Method, r.Host)

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func parseProxyAuth(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	removeHopHeaders(r.Header)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
	r.RequestURI = ""
	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} }
	go relay(destConn, clientConn)
	go relay(clientConn, destConn)
	<-done
}

func removeHopHeaders(h http.Header) {
	for _, hdr := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade"} {
		h.Del(hdr)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ---------- Web UI ----------

func startUI(p int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/api/stats", handleAPIStats)
	mux.HandleFunc("/api/logs", handleAPILogs)
	mux.HandleFunc("/api/blocklist", handleAPIBlocklist)

	srv := &http.Server{Addr: fmt.Sprintf(":%d", p), Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("UI server failed: %v", err)
	}
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total":    atomic.LoadInt64(&statTotal),
		"blocked":  atomic.LoadInt64(&statBlocked),
		"authFail": atomic.LoadInt64(&statAuthFail),
	})
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	recentLogsMu.Lock()
	logs := make([]LogEntry, len(recentLogs))
	copy(logs, recentLogs)
	recentLogsMu.Unlock()
	// Return newest first.
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}
	json.NewEncoder(w).Encode(logs)
}

func handleAPIBlocklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		blocklistMu.RLock()
		hosts := make([]string, 0, len(blocklist))
		for h := range blocklist {
			hosts = append(hosts, h)
		}
		blocklistMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hosts)

	case http.MethodPost:
		var body struct{ Host string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Host == "" {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		h := strings.ToLower(strings.TrimSpace(body.Host))
		blocklistMu.Lock()
		blocklist[h] = true
		blocklistMu.Unlock()
		saveBlocklist()
		logger.Printf("UI: blocked %s", h)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		h := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
		if h == "" {
			http.Error(w, "missing host", http.StatusBadRequest)
			return
		}
		blocklistMu.Lock()
		delete(blocklist, h)
		blocklistMu.Unlock()
		saveBlocklist()
		logger.Printf("UI: unblocked %s", h)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proxy Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
  header { background: #1e293b; padding: 16px 32px; border-bottom: 1px solid #334155;
           display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.4rem; font-weight: 700; color: #38bdf8; }
  .badge { background: #22c55e; color: #fff; font-size: 0.7rem; padding: 2px 8px;
           border-radius: 999px; font-weight: 600; }
  main { padding: 24px 32px; max-width: 1100px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 28px; }
  .card { background: #1e293b; border-radius: 12px; padding: 20px 24px; border: 1px solid #334155; }
  .card .label { font-size: 0.8rem; color: #94a3b8; margin-bottom: 6px; }
  .card .value { font-size: 2rem; font-weight: 700; }
  .card.total .value { color: #38bdf8; }
  .card.blocked .value { color: #f87171; }
  .card.auth .value { color: #fb923c; }
  section { background: #1e293b; border-radius: 12px; border: 1px solid #334155; margin-bottom: 24px; }
  section h2 { padding: 16px 20px; font-size: 0.95rem; font-weight: 600;
               border-bottom: 1px solid #334155; color: #94a3b8; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px 16px; text-align: right; font-size: 0.85rem; }
  th { color: #64748b; font-weight: 600; background: #1e293b; }
  tr:not(:last-child) td { border-bottom: 1px solid #1e293b; }
  tbody tr:hover { background: #0f172a; }
  .ok { color: #4ade80; font-weight: 600; }
  .blocked-tag { color: #f87171; font-weight: 600; }
  .auth-fail { color: #fb923c; font-weight: 600; }
  .blocklist-body { padding: 16px 20px; }
  .add-row { display: flex; gap: 8px; margin-bottom: 16px; }
  input[type=text] { flex: 1; background: #0f172a; border: 1px solid #334155;
                     color: #e2e8f0; padding: 8px 12px; border-radius: 8px; font-size: 0.9rem; }
  input[type=text]:focus { outline: none; border-color: #38bdf8; }
  button { background: #0284c7; color: #fff; border: none; padding: 8px 16px;
           border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 600; }
  button:hover { background: #0369a1; }
  button.del { background: #dc2626; }
  button.del:hover { background: #b91c1c; }
  .host-list { display: flex; flex-wrap: wrap; gap: 8px; }
  .host-chip { background: #0f172a; border: 1px solid #334155; padding: 5px 12px;
               border-radius: 999px; font-size: 0.82rem; display: flex; gap: 8px; align-items: center; }
  .host-chip span { cursor: pointer; color: #f87171; font-weight: 700; }
  .empty { color: #475569; font-size: 0.85rem; padding: 8px 0; }
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; Proxy Dashboard</h1>
  <div class="badge">LIVE</div>
</header>
<main>
  <div class="cards">
    <div class="card total"><div class="label">סה"כ בקשות</div><div class="value" id="total">-</div></div>
    <div class="card blocked"><div class="label">חסומות</div><div class="value" id="blocked">-</div></div>
    <div class="card auth"><div class="label">כשל אימות</div><div class="value" id="authFail">-</div></div>
  </div>

  <section>
    <h2>ניהול Blocklist</h2>
    <div class="blocklist-body">
      <div class="add-row">
        <input type="text" id="newHost" placeholder="הוסף דומיין (לדוגמה: ads.com)">
        <button onclick="addHost()">+ הוסף</button>
      </div>
      <div class="host-list" id="hostList"></div>
    </div>
  </section>

  <section>
    <h2>לוג בקשות אחרונות</h2>
    <table>
      <thead><tr><th>שעה</th><th>IP</th><th>Method</th><th>Host</th><th>סטטוס</th></tr></thead>
      <tbody id="logBody"></tbody>
    </table>
  </section>
</main>
<script>
async function fetchStats() {
  const r = await fetch('/api/stats');
  const d = await r.json();
  document.getElementById('total').textContent = d.total;
  document.getElementById('blocked').textContent = d.blocked;
  document.getElementById('authFail').textContent = d.authFail;
}

async function fetchLogs() {
  const r = await fetch('/api/logs');
  const logs = await r.json();
  const body = document.getElementById('logBody');
  body.innerHTML = (logs || []).slice(0, 100).map(l => {
    const cls = l.status === 'OK' ? 'ok' : l.status === 'BLOCKED' ? 'blocked-tag' : 'auth-fail';
    return '<tr><td>' + l.time + '</td><td>' + l.ip + '</td><td>' + l.method +
           '</td><td>' + l.host + '</td><td class="' + cls + '">' + l.status + '</td></tr>';
  }).join('');
}

async function fetchBlocklist() {
  const r = await fetch('/api/blocklist');
  const hosts = await r.json();
  const el = document.getElementById('hostList');
  if (!hosts || hosts.length === 0) {
    el.innerHTML = '<div class="empty">אין דומיינים חסומים</div>';
    return;
  }
  hosts.sort();
  el.innerHTML = hosts.map(h =>
    '<div class="host-chip">' + h + '<span onclick="removeHost(\'' + h + '\')">&times;</span></div>'
  ).join('');
}

async function addHost() {
  const input = document.getElementById('newHost');
  const host = input.value.trim();
  if (!host) return;
  await fetch('/api/blocklist', { method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({host}) });
  input.value = '';
  fetchBlocklist();
}

async function removeHost(host) {
  await fetch('/api/blocklist?host=' + encodeURIComponent(host), { method: 'DELETE' });
  fetchBlocklist();
}

document.getElementById('newHost').addEventListener('keydown', e => { if (e.key === 'Enter') addHost(); });

function refresh() { fetchStats(); fetchLogs(); fetchBlocklist(); }
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
`
