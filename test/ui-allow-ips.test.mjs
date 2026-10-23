import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Execute the shipped handler with a minimal DOM and a stubbed apiFetch.
// This catches stale success labels and ambiguous transport failures without
// needing a live appliance or treating an API error as a successful write.
const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const start = html.indexOf('function uiAllowIPsFailure(');
const end = html.indexOf('// ── Syslog / SIEM', start);
assert.ok(start >= 0 && end > start, 'shipped allowlist handlers are present');
const source = html.slice(start, end);

// A response as apiFetch returns it: status + a body read once as text.
const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, text: async () => body });
const typed = (code) => JSON.stringify({ code, error: '<script>untrusted</script>' });

for (const [label, respond, expected] of [
  ['503 ui_allow_ips_persistence_uncertain', () => reply(503, typed('ui_allow_ips_persistence_uncertain')), /New policy is active; storage durability is unconfirmed/],
  ['503 ui_allow_ips_not_saved', () => reply(503, typed('ui_allow_ips_not_saved')), /Not saved; the previous policy remains active/],
  ['503 ui_access_policy_unavailable', () => reply(503, typed('ui_access_policy_unavailable')), /Local console recovery is required/],
  ['plain-text 400', () => reply(400, 'entry 0 is not a valid IP address or CIDR\n'), /^Not saved; the previous policy remains active\. entry 0 is not a valid IP address or CIDR$/],
  ['plain-text 403', () => reply(403, 'forbidden\n'), /^Not saved; the previous policy remains active\. forbidden$/],
  ['untyped 503', () => reply(503, 'Service Unavailable'), /Save result is unconfirmed/],
  ['transport uncertainty', () => { throw new Error('Network failed'); }, /Save result is unconfirmed/],
]) {
  test(`allowlist save displays ${label}`, async () => {
    const status = { textContent: '✓ Saved', style: { color: 'var(--green)' } };
    const toasts = [];
    const context = vm.createContext({
      document: { getElementById: () => status },
      _uiAllowIPList: ['192.0.2.0/24'],
      confirmDanger: async () => true,
      apiFetch: async () => respond(),
      toast: (...args) => toasts.push(args),
    });
    vm.runInContext(source, context);
    await vm.runInContext('saveUIAllowIPs()', context);
    assert.match(status.textContent, expected);
    assert.equal(status.style.color, 'var(--amber)');
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0][0], status.textContent);
    assert.equal(toasts[0][1], 'error');
    assert.doesNotMatch(status.textContent, /<script>|✓ Saved/);
    if (/unconfirmed/.test(expected.source)) assert.doesNotMatch(status.textContent, /previous policy remains/);
  });
}

test('a refusal detail is bounded and rendered as text only', async () => {
  const status = { textContent: '', style: {} };
  const context = vm.createContext({
    document: { getElementById: () => status },
    _uiAllowIPList: ['192.0.2.0/24'],
    confirmDanger: async () => true,
    apiFetch: async () => reply(400, 'x'.repeat(500)),
    toast: () => {},
  });
  vm.runInContext(source, context);
  await vm.runInContext('saveUIAllowIPs()', context);
  assert.equal(status.textContent, 'Not saved; the previous policy remains active. ' + 'x'.repeat(200));
});

test('a 401 clears the status (apiFetch shows the login overlay)', async () => {
  const status = { textContent: '', style: {} };
  const toasts = [];
  const context = vm.createContext({
    document: { getElementById: () => status },
    _uiAllowIPList: ['192.0.2.0/24'],
    confirmDanger: async () => true,
    apiFetch: async () => reply(401, ''),
    toast: (...args) => toasts.push(args),
  });
  vm.runInContext(source, context);
  await vm.runInContext('saveUIAllowIPs()', context);
  assert.equal(status.textContent, '');
  assert.equal(toasts.length, 0);
});

test('successful and cancelled allowlist saves preserve their existing contracts', async () => {
  const status = { textContent: '', style: {} };
  let saves = 0;
  let consent = false;
  const context = vm.createContext({
    document: { getElementById: () => status },
    _uiAllowIPList: [],
    confirmDanger: async () => consent,
    apiFetch: async () => { saves++; return reply(200, '{"ok":true,"ips":[]}'); },
    toast: () => {},
  });
  vm.runInContext(source, context);
  await vm.runInContext('saveUIAllowIPs()', context);
  assert.equal(saves, 0);
  assert.equal(status.textContent, '');
  consent = true;
  await vm.runInContext('saveUIAllowIPs()', context);
  assert.equal(saves, 1);
  assert.equal(status.textContent, '✓ Saved');
  assert.equal(status.style.color, 'var(--green)');
});
