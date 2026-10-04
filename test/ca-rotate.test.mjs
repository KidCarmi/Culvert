import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Execute the shipped CA-rotation handlers with a stubbed api(). A confirmed
// rotation whose bundle could not be written (persisted:false) leaves the new
// CA active in memory only: it must never produce a success toast.
const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const start = html.indexOf('function caRotateResultMessage(');
const end = html.indexOf('async function toggleOCSP(', start);
assert.ok(start >= 0 && end > start, 'shipped CA rotation handlers are present');
const source = html.slice(start, end);

async function rotate(confirmed) {
  const toasts = [];
  let reloads = 0;
  const context = vm.createContext({
    api: async (_path, opts) => (opts.body.confirm ? confirmed : { confirmation_token: 't', warning: 'w' }),
    confirmAction: async () => true,
    loadCAMgmt: () => { reloads++; },
    toast: (...args) => toasts.push(args),
  });
  vm.runInContext(source, context);
  await vm.runInContext('forceRotateCA()', context);
  return { toasts, reloads };
}

test('a persisted rotation is a success that says what to do next', async () => {
  const { toasts, reloads } = await rotate({ status: 'ok', persisted: true });
  assert.equal(toasts.length, 1);
  assert.equal(toasts[0][1], 'success');
  assert.match(toasts[0][0], /distribute the new public CA certificate/);
  assert.match(toasts[0][0], /fresh backup/);
  assert.match(toasts[0][0], /passphrase is unchanged/);
  assert.equal(reloads, 1);
});

test('persisted:false is never a success toast and carries the warning', async () => {
  const { toasts, reloads } = await rotate({ status: 'ok', persisted: false, warning: 'exists in memory only' });
  assert.equal(toasts.length, 1);
  assert.equal(toasts[0][1], 'error');
  assert.match(toasts[0][0], /NOT saved/);
  assert.match(toasts[0][0], /exists in memory only/);
  assert.doesNotMatch(toasts[0][0], /successfully/);
  assert.equal(reloads, 1); // the panel still refreshes to show the in-memory CA
});

test('a server error is reported as a failure', async () => {
  const { toasts, reloads } = await rotate({ error: 'rotation failed' });
  assert.deepEqual(toasts, [['Rotation failed: rotation failed', 'error']]);
  assert.equal(reloads, 0);
});
