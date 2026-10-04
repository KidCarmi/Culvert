import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Execute the shipped handler with a minimal DOM and a refused API promise.
// This catches stale success labels and ambiguous transport failures without
// needing a live appliance or treating an API error as a successful write.
const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const start = html.indexOf('function uiAllowIPsFailure(');
const end = html.indexOf('// ── Syslog / SIEM', start);
assert.ok(start >= 0 && end > start, 'shipped allowlist handlers are present');
const source = html.slice(start, end);

for (const [code, expected] of [
  ['ui_allow_ips_persistence_uncertain', /New policy is active; storage durability is unconfirmed/],
  ['ui_allow_ips_not_saved', /Not saved; the previous policy remains active/],
  ['invalid_ui_allow_ips', /Not saved; the previous policy remains active/],
  ['ui_access_policy_unavailable', /Local console recovery is required/],
  ['', /Save result is unconfirmed/],
]) {
  test(`allowlist save displays ${code || 'transport uncertainty'}`, async () => {
    const status = { textContent: '✓ Saved', style: { color: 'var(--green)' } };
    const toasts = [];
    const context = vm.createContext({
      document: { getElementById: () => status },
      _uiAllowIPList: ['192.0.2.0/24'],
      confirmDanger: async () => true,
      api: async () => { throw new Error(code ? JSON.stringify({ code, error: '<script>untrusted</script>' }) : 'Network failed'); },
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
    if (!code) assert.doesNotMatch(status.textContent, /previous policy remains/);
  });
}

test('successful and cancelled allowlist saves preserve their existing contracts', async () => {
  const status = { textContent: '', style: {} };
  let saves = 0;
  let consent = false;
  const context = vm.createContext({
    document: { getElementById: () => status },
    _uiAllowIPList: [],
    confirmDanger: async () => consent,
    api: async () => { saves++; return { ok: true, ips: [] }; },
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
