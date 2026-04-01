package main

import (
	"bytes"
	"html/template"
	"net/http"
	"time"
)

const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Denied — Culvert</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0b0f1a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.wrap{max-width:580px;width:100%;padding:40px 20px;text-align:center}
.logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:32px}
.logo-icon{width:46px;height:46px;background:#3b82f6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0}
.logo-name{font-size:1.4rem;font-weight:700;letter-spacing:-.02em}
.card{background:#111827;border:1px solid #1f2d45;border-top:4px solid #ef4444;border-radius:12px;padding:40px 32px;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.icon-circle{width:76px;height:76px;background:rgba(239,68,68,.1);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;font-size:36px}
h1{font-size:1.65rem;font-weight:700;color:#f1f5f9;margin-bottom:8px}
.subtitle{color:#64748b;font-size:.9rem;margin-bottom:28px;line-height:1.5}
.grid{display:grid;gap:10px;text-align:left;margin-bottom:28px}
.row{display:flex;background:#1a2235;border-radius:8px;overflow:hidden}
.lbl{padding:11px 14px;background:#0f1929;color:#64748b;font-size:.74rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;min-width:106px;display:flex;align-items:center;flex-shrink:0}
.val{padding:11px 14px;color:#e2e8f0;font-size:.86rem;word-break:break-all;display:flex;align-items:center}
.footer{font-size:.75rem;color:#475569;border-top:1px solid #1f2d45;padding-top:16px}
a{color:#3b82f6;text-decoration:none}
a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">
    <div class="logo-icon">🛡️</div>
    <div class="logo-name">Culvert</div>
  </div>
  <div class="card">
    <div class="icon-circle">🚫</div>
    <h1>Access Denied</h1>
    <p class="subtitle">This website has been blocked by your organisation's<br>security policy.</p>
    <div class="grid">
      <div class="row"><span class="lbl">URL</span><span class="val">{{.URL}}</span></div>
      <div class="row"><span class="lbl">Category</span><span class="val">{{.Category}}</span></div>
      <div class="row"><span class="lbl">Rule</span><span class="val">{{.RuleName}}</span></div>
      <div class="row"><span class="lbl">Timestamp</span><span class="val">{{.Timestamp}}</span></div>
    </div>
    <div class="footer">
      If you believe this is a mistake, please contact your IT administrator.<br>
      Powered by <strong>Culvert Enterprise</strong>
    </div>
  </div>
</div>
</body>
</html>`

var blockPageTmpl = template.Must(template.New("block").Parse(blockPageHTML))

type blockPageData struct {
	URL       string
	Category  string
	RuleName  string
	Timestamp string
}

// serveBlockPage writes a 403 HTML response using the corporate block page template.
func serveBlockPage(w http.ResponseWriter, url, category, ruleName string) {
	data := blockPageData{
		URL:       url,
		Category:  category,
		RuleName:  ruleName,
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
	}
	var buf bytes.Buffer
	if err := blockPageTmpl.Execute(&buf, data); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(buf.Bytes())
}
