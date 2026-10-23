import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Execute the shipped Release Management dispatch handler with stubbed DOM and
// apiFetch. An accepted dispatch whose record did not reach disk
// (durable:false) must not be reported as a plain success: the operator keeps
// the resume context the response carries.
const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const start = html.indexOf('function releaseDispatchRecovery(');
const end = html.indexOf('async function releaseResume(', start);
assert.ok(start >= 0 && end > start, 'shipped dispatch handlers are present');
const source = html.slice(start, end);

function element(value = '') {
  return { value, checked: false, disabled: false, textContent: '', style: {}, dataset: {} };
}

async function dispatch(status, payload) {
  const ids = {
    'rel-disp-release': element(''), 'rel-disp-channel': element('recommended'),
    'rel-disp-agent': element('local'), 'rel-disp-prebackup': element(),
    'rel-disp-passphrase': element(''), 'rel-disp-norollback': element(),
    'rel-disp-ack-unknown': element(), 'rel-disp-allow-downgrade': element(),
    'rel-disp-submit': element(), 'rel-disp-recovery': element(),
    'rel-disp-recovery-msg': element(), 'rel-disp-recovery-body': element(),
  };
  const toasts = [];
  let closed = 0;
  const context = vm.createContext({
    document: { getElementById: (id) => ids[id] },
    apiFetch: async () => ({ status, json: async () => payload }),
    toast: (...args) => toasts.push(args),
    releaseDispatchCancel: () => { closed++; },
    releaseCurrentAgent: () => 'local',
    loadReleaseStatus: () => {},
    loadReleaseCurrent: () => {},
    JSON,
  });
  vm.runInContext(source, context);
  await vm.runInContext('releaseDispatchSubmit()', context);
  return { toasts, closed, ids };
}

test('a durable dispatch is a success and closes the dialog', async () => {
  const { toasts, closed, ids } = await dispatch(202, { op_id: 'op1', durable: true, agent: 'local' });
  assert.equal(toasts.length, 1);
  assert.equal(toasts[0][1], 'success');
  assert.equal(closed, 1);
  assert.notEqual(ids['rel-disp-recovery'].style.display, 'block');
  assert.equal(ids['rel-disp-submit'].disabled, false);
});

test('durable:false is never a success and keeps the resume context in view', async () => {
  const rc = { AgentID: 'local', OpID: 'op1', TargetPinnedRef: 'ghcr.io/x@sha256:' + 'a'.repeat(64) };
  const { toasts, closed, ids } = await dispatch(202, {
    op_id: 'op1', durable: false, agent: 'local', warning: 'dispatch_record_not_persisted', resume_context: rc,
  });
  assert.equal(toasts.length, 1);
  assert.equal(toasts[0][1], 'error');
  assert.match(toasts[0][0], /NOT saved/);
  assert.equal(closed, 0, 'the dialog stays open so the recovery context is not lost');
  assert.equal(ids['rel-disp-recovery'].style.display, 'block');
  const shown = JSON.parse(ids['rel-disp-recovery-body'].textContent);
  assert.deepEqual(shown, { agent: 'local', resume_context: rc });
  assert.equal(ids['rel-disp-submit'].disabled, true, 'the running op must not be re-submitted');
});

test('a refusal is unchanged', async () => {
  const { toasts, closed } = await dispatch(409, { status: 'refused', kind: 'downgrade', detail: 'd' });
  assert.equal(toasts[0][1], 'error');
  assert.equal(closed, 0);
});
