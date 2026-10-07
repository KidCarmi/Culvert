// LAB-ONLY (#1528): does a real browser ever present the portal session cookie
// to the proxy on ordinary traffic? Culvert's proxy authenticates browser SSO
// ONLY from the request's own Cookie header (proxy.go readSessionCookie), and
// the SSO callback sets ps_session host-only on the UI host
// (session.go setSessionCookie: Path=/, HttpOnly, SameSite=Lax, no Domain).
//
// A recording forward proxy. ui.test sets a host-only Lax session cookie (as
// setSessionCookie does); then the browser browses dest.test over plain HTTP and
// over HTTPS (CONNECT). Question: does the proxy ever see ps_session on a request
// whose destination is NOT ui.test?
const http = require('http'), net = require('net');
const { chromium } = require('playwright');
const seen = [];
process.on('uncaughtException', () => {});
const proxy = http.createServer((req, res) => {
  const host = (req.headers.host || '').split(':')[0];
  seen.push({ kind: 'http', host, cookie: req.headers.cookie || '' });
  if (host === 'ui.test' && req.url.includes('callback-set')) {
    res.writeHead(302, { 'Set-Cookie': 'ps_session=SESSIONVALUE; Path=/; HttpOnly; SameSite=Lax', Location: 'http://dest.test/after-login' });
    return res.end();
  }
  res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p>ok ' + host + '</p>');
});
proxy.on('connect', (req, sock) => { sock.on('error', () => {}); seen.push({ kind: 'CONNECT', host: req.url, cookie: req.headers.cookie || '' }); sock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); });
proxy.listen(0, '127.0.0.1', async () => {
  const port = proxy.address().port;
  const b = await chromium.launch({ executablePath: process.env.CHROME || undefined, proxy: { server: 'http://127.0.0.1:' + port } , args: ['--proxy-bypass-list=<-loopback>', '--disable-background-networking'] });
  const p = await (await b.newContext()).newPage();
  await p.goto('http://ui.test/auth/saml/callback-set');           // the "callback": sets the cookie, 302 to the relay
  await p.goto('http://dest.test/page');                            // ordinary plain-HTTP browsing
  await p.goto('http://ui.test/whatever');                          // back on the UI host
  try { await p.goto('https://dest.test/secure', { timeout: 5000 }); } catch (e) {}
  await b.close(); proxy.close();
  const rows = seen.filter(s => /^(ui|dest)\.test/.test(s.host));
  for (const s of rows) console.log(s.kind.padEnd(7), s.host.padEnd(16), 'ps_session presented:', /ps_session=/.test(s.cookie));
  const ctl = rows.some(s => s.host === 'ui.test' && /ps_session=/.test(s.cookie));
  const leak = rows.some(s => s.host.startsWith('dest.test') && /ps_session=/.test(s.cookie));
  const dest = rows.filter(s => s.host.startsWith('dest.test')).length;
  console.log(`control (cookie stored, presented to ui.test): ${ctl}; dest.test requests: ${dest}; ps_session presented to dest.test: ${leak}`);
  process.exit(ctl && dest >= 2 && !leak ? 0 : 1);
});
