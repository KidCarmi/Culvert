"""Original session/boot attribution and budget tests; no guest execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('shutdown',Path(__file__).with_name('lifecycle-shutdown.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class ShutdownTests(unittest.TestCase):
    def setUp(self):
        self.before={'source':m.SOURCE,'image':m.IMAGE,'boot':'11111111-1111-4111-8111-111111111111','scope':'session-27.scope','monotonic_us':1000000,'culvert_uid':1000,
                     'ancestors':[{'comm':'culvert-console','uid':1000,'scope':'session-27.scope','tty_nr':1025},{'comm':'sudo','uid':0},{'comm':'bash','uid':0}]}
        self.after={'source':m.SOURCE,'image':m.IMAGE,'boot':'22222222-2222-4222-8222-222222222222','old_boot':self.before['boot'],'scope':self.before['scope'],
                    'journal':{'parsed':2,'wrong_boot':0,'entry_limit_reached':False,'events':[{'kind':'stop_requested','monotonic_us':2000000,'scope':'session-27.scope'},{'kind':'stopped','monotonic_us':7000000,'scope':'session-27.scope'}]}}
        self.rows=[{'event':'dispatch_intent','monotonic_ns':1000000000},{'event':'all_services_returned_after_failure','monotonic_ns':101000000000}]

    def test_success_requires_original_chain_and_new_boot(self):
        self.assertEqual(m.verdict(self.before,self.after,self.rows)['session_teardown_seconds'],5)
        for comm in ('culvert-console','sudo','bash'):
            changed=copy.deepcopy(self.before);changed['ancestors']=[p for p in changed['ancestors'] if p['comm']!=comm]
            with self.assertRaises(ValueError):m.verdict(changed,self.after,self.rows)
        changed=dict(self.after,boot=self.before['boot'])
        with self.assertRaises(ValueError):m.verdict(self.before,changed,self.rows)

    def test_timeout_sigkill_and_overbudget_never_pass(self):
        for kind in ('timeout','sigkill'):
            after=copy.deepcopy(self.after);after['journal']['events'].append({'kind':kind,'monotonic_us':3000000,'scope':'session-27.scope'})
            with self.assertRaises(ValueError):m.verdict(self.before,after,self.rows)
        after=copy.deepcopy(self.after);after['journal']['events'][1]['monotonic_us']=12000001
        with self.assertRaises(ValueError):m.verdict(self.before,after,self.rows)
        self.rows[1]['monotonic_ns']=121000000001
        with self.assertRaises(ValueError):m.verdict(self.before,self.after,self.rows)

    def test_missing_truncated_wrong_session_evidence_refused(self):
        for patch in ({'parsed':0},{'wrong_boot':1},{'entry_limit_reached':True},{'events':[]}):
            after=copy.deepcopy(self.after);after['journal'].update(patch)
            with self.assertRaises(ValueError):m.verdict(self.before,after,self.rows)
        after=copy.deepcopy(self.after);after['journal']['events'][1]['scope']='session-28.scope'
        with self.assertRaises(ValueError):m.verdict(self.before,after,self.rows)

    def test_journal_attribution_excludes_other_sessions_and_raw_messages(self):
        def row(message,unit='session-27.scope',pid='1'):
            return {'MESSAGE':message,'UNIT':unit,'_PID':pid,'_BOOT_ID':self.before['boot'].replace('-',''),'__MONOTONIC_TIMESTAMP':'2000000'}
        rows=[row('Stopping Session 27 of User culvert...'),row('session-27.scope: Deactivated successfully.'),row('session-270.scope: Killing process with signal SIGKILL.','session-270.scope'),row('secret body SIGKILL',pid='42')]
        value=m.journal_events('\n'.join(json.dumps(x) for x in rows),self.before)
        self.assertEqual([x['kind'] for x in value['events']],['stop_requested','stopped'])
        self.assertNotIn('secret',json.dumps(value))

    def test_embedded_payload_compiles_without_running(self):
        for phase in ('before','after'):
            text=m.payload(phase,self.before if phase=='after' else None)
            code=text.split("python3 - <<'CULVERT_SHUTDOWN_PROOF'\n",1)[1].rsplit('\nCULVERT_SHUTDOWN_PROOF',1)[0]
            compile(code,'guest-proof','exec')
            self.assertNotIn('systemctl reboot',code)

    def test_cli_shell_payload_is_exact_lf_bytes(self):
        # Use a real pipe: Windows text stdout translates LF to CRLF even
        # when the in-memory payload and compile-only tests are correct.
        with tempfile.TemporaryDirectory() as directory:
            before=Path(directory)/'before.json'
            before.write_text(json.dumps(self.before),encoding='utf-8')
            for phase in ('before','after'):
                argv=[sys.executable,str(Path(m.__file__)),phase]
                if phase=='after':argv+=['--before',str(before)]
                result=subprocess.run(argv,capture_output=True,timeout=10,check=True)
                self.assertEqual(result.stdout.count(b'\r'),0,phase+' output must contain no CR bytes')
                expected=m.payload(phase,self.before if phase=='after' else None).encode('utf-8')
                self.assertEqual(result.stdout,expected)
                self.assertEqual(result.stderr,b'')

    def test_journal_command_uses_canonical_boot_and_exact_session(self):
        command=m.journal_command(self.before)
        self.assertIn('--boot=11111111111141118111111111111111',command)
        self.assertIn('--unit=session-27.scope',command)
        self.assertIn('--lines=3000',command)

    def test_hooks_stop_and_preserve_nested_reboot(self):
        hooks=Path(__file__).with_name('candidate-hooks.sh').read_text()
        self.assertIn('STOP=1\n      return 90',hooks)
        self.assertNotIn('os.execv',hooks)
        shared=Path(__file__).parents[1]/'lab/appliance-lab.sh'
        self.assertIn('gpriv --nowait > "$EV/07-reboot.txt" 2>&1 <<<\'culvert-os-update reboot\'',shared.read_text(encoding='utf-8'))

if __name__=='__main__':unittest.main()
