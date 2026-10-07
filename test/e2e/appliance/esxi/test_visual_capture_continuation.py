"""Offline screenshot409 continuation tests; no VM or secret material."""
import importlib.util
import json
from pathlib import Path
import subprocess
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
c=load('capture_continuation',HERE/'visual-capture-continuation.py')
fixtures=load('visual_fixtures',HERE/'test_visual_capture.py')

class ConflictTests(unittest.TestCase):
 def setUp(self):
  self.fixture=fixtures.VisualTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.lab=self.fixture.lab;self.fixture.ledger();self.lab.govc='C:/tools/govc.exe';self.lab.c['endpoint']='https://192.0.2.1'
  self.args=SimpleNamespace(label='continuation',seconds=20,interval=1)
  self.visual=SimpleNamespace(identity=fixtures.v.identity,read_json=fixtures.v.read_json,no_identity_reset=fixtures.v.no_identity_reset,
      preflight=mock.Mock(),image_metadata=fixtures.v.image_metadata,MAX_TOTAL=fixtures.v.MAX_TOTAL)
  self.clock=0.;self.calls=0
 def conflict(self, text=None):
  return subprocess.CompletedProcess([],1,b'',text or b'C:\\tools\\govc.exe: download(https://192.0.2.1/screen?id=66): 409 Conflict\n')
 def sleep(self,n):self.clock+=n
 def run_observer(self, outcomes):
  def capture(lab,path,timeout):
   self.calls+=1
   result=outcomes.pop(0) if outcomes else subprocess.CompletedProcess([],0,b'',b'')
   if isinstance(result,Exception):raise result
   if result.returncode==0:path.write_bytes(fixtures.PNG)
   return result
  return c.observe(self.lab,self.args,self.visual,clock=lambda:self.clock,pause=self.sleep,capture=capture)
 def events(self):
  return [json.loads(x) for x in (self.lab.sec/'visual-continuation-continuation/events.jsonl').read_bytes().splitlines()]
 def test_exact_download_409_only(self):
  self.assertTrue(c.screenshot_conflict(self.conflict(),self.lab.govc,self.lab.c['endpoint']))
  for text in [b'409 Conflict',b'govc: download(https://192.0.2.1/screen?id=66): 409 Conflict',
   b'C:/tools/govc.exe: download(https://192.0.2.2/screen?id=66): 409 Conflict',
   b'C:/tools/govc.exe: download(https://192.0.2.1/folder?id=66): 409 Conflict',
   b'C:/tools/govc.exe: download(https://u:p@192.0.2.1/screen?id=66): 409 Conflict',
   b'C:/tools/govc.exe: download(https://192.0.2.1/screen?id=66&x=1): 409 Conflict',
   b'C:/tools/govc.exe: download(https://192.0.2.1/screen?id=66): 409 Conflict\nother error']:
   self.assertFalse(c.screenshot_conflict(self.conflict(text),self.lab.govc,self.lab.c['endpoint']))
 def test_gap_preserved_and_success_does_not_claim_continuity(self):
  frames,gaps=self.run_observer([self.conflict()])
  self.assertEqual(gaps,1);self.assertGreater(frames,0)
  events=self.events();self.assertEqual(events[1]['status'],'http409_gap')
  self.assertEqual(events[-1]['event'],'complete');self.assertFalse(events[-1]['continuous_coverage'])
  self.assertEqual(len(events[1]['stderr_sha256']),64)
  self.assertTrue((self.lab.sec/'visual-continuation-continuation/attempt-0000.stderr').exists())
 def test_five_consecutive_conflicts_stop_and_preserve_every_attempt(self):
  with self.assertRaisesRegex(ValueError,'conflict budget'):self.run_observer([self.conflict() for _ in range(5)])
  self.assertEqual(self.calls,5);self.assertEqual(self.events()[-1]['event'],'blocked')
  self.assertEqual(len(list((self.lab.sec/'visual-continuation-continuation').glob('attempt-*.json'))),5)
 def test_tenth_total_conflict_stops_even_with_success_between(self):
  ok=subprocess.CompletedProcess([],0,b'',b'')
  values=([self.conflict() for _ in range(4)]+[ok])*2+[self.conflict(),self.conflict()]
  with self.assertRaisesRegex(ValueError,'conflict budget'):self.run_observer(values)
  self.assertEqual(self.calls,12);self.assertEqual(self.events()[-1]['http409_gaps'],10)
 def test_nonempty_or_linked_partial_conflict_stops_without_retry(self):
  def partial(lab,path,timeout):
   self.calls+=1;path.write_bytes(b'partial-screenshot');return self.conflict()
  with self.assertRaisesRegex(ValueError,'partial or linked'):
   c.observe(self.lab,self.args,self.visual,clock=lambda:self.clock,pause=self.sleep,capture=partial)
  self.assertEqual(self.calls,1);self.assertEqual(self.events()[-1]['event'],'blocked')
  path=self.lab.sec/'empty-capture.png';path.write_bytes(b'');c.conflict_artifact(path)
  for mode,attributes in [(stat.S_IFLNK,0),(stat.S_IFREG,0x400)]:
   fake=SimpleNamespace(st_mode=mode,st_nlink=1,st_size=0,st_file_attributes=attributes)
   with mock.patch.object(Path,'lstat',return_value=fake):
    with self.assertRaisesRegex(ValueError,'partial or linked'):c.conflict_artifact(path)
 def test_timeout_and_other_error_never_retried(self):
  for name,outcome in [('timeout',subprocess.TimeoutExpired(['govc'],10)),('other',self.conflict(b'401 Unauthorized'))]:
   self.args.label=name;self.calls=0
   with self.assertRaises(ValueError):self.run_observer([outcome])
   self.assertEqual(self.calls,1)
   rows=[json.loads(x) for x in (self.lab.sec/('visual-continuation-'+name)/'events.jsonl').read_bytes().splitlines()]
   self.assertIn(rows[1]['status'],('timeout_no_retry','failure_no_retry'));self.assertEqual(rows[-1]['event'],'blocked')
 def test_ownership_scope_deleted_reset_and_existing_label_refuse(self):
  self.lab.vm.side_effect=ValueError('ownership')
  with self.assertRaises(ValueError):self.run_observer([])
  self.assertEqual(self.calls,0)
  self.lab.vm.side_effect=None
  with self.assertRaises(FileExistsError):self.run_observer([])
  for phase in ('deleted','identity-reset'):
   self.args.label=phase;self.lab.state_file.write_text(json.dumps(dict(self.fixture.state,phase=phase)))
   with self.assertRaises(ValueError):self.run_observer([])
  self.fixture.ledger();self.args.label='scope-change'
  original=self.sleep
  def changed(n):original(n);self.lab.scope_path.write_text('changed')
  self.sleep=changed;self.calls=0
  with self.assertRaisesRegex(ValueError,'scope changed'):self.run_observer([])
  self.assertEqual(self.calls,1)

if __name__=='__main__':unittest.main()
