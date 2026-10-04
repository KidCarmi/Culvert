"""Offline evidence-oracle tests; never invokes a VM or real guest command."""
import copy
import datetime
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


post = load('postcheck_test', 'independent-postcheck.py')
guest = load('postcheck_guest_test', 'independent-postcheck-guest.py')


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.evidence = Path(directory.name)
        self.source, self.image = 'a' * 40, 'sha256:' + 'b' * 64
        self.before, self.after = '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'
        build = {'source': {'git_commit': self.source, 'git_dirty': False},
                 'console': {'source_git_commit': self.source, 'source_git_dirty': False},
                 'application': {'index_digest': self.image, 'app_version_file': 'v1.0.260-candidate'}}
        markers = ['access.done', 'agent.done', 'complete.done', 'console.done', 'images.done', 'install.done', 'ovf.done']
        values = {'uid': 0, 'boot_id': self.after, 'kernel': '6.8.0-146-generic', 'kernel_version': '#146-Ubuntu SMP',
                  'done_markers': markers, 'build_info': build, 'app_image_id': self.image,
                  'agent_version': 'v1.0.260-candidate', 'agent_active': 'active',
                  'firstboot_unit': {'LoadState': 'loaded', 'ConditionResult': 'no', 'ExecMainStartTimestampMonotonic': '0'},
                  'firstboot_journal': '-- No entries --',
                  'resume_unit': {'LoadState': 'loaded', 'Result': 'success', 'ExecMainStatus': '0', 'ExecMainStartTimestampMonotonic': '125000'},
                  'resume_journal': 'holding os-update and the maintenance agent lock\nstack started after the maintenance reboot',
                  'resume_durable_log': {'boot_start_epoch': int(datetime.datetime(2026, 10, 4, 23, 29, tzinfo=datetime.timezone.utc).timestamp()), 'lines': []},
                  'resume_marker_present': False, 'proc_cmdline': 'console=ttyS0,115200',
                  'docker_package_holds': ['docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin']}
        self.observation = {'schema_version': 1, 'captured_at': '2026-10-04T23:31:00+00:00',
                            'required_fields': sorted(post.REQUIRED), 'values': values, 'errors': {}}
        files = {'esxi-boot-id-before.txt': self.before, 'esxi-boot-id-after.txt': self.after,
                 '03-kernel-before.txt': '6.8.0-142-generic\n#142-Ubuntu SMP',
                 '07-kernel-after.txt': '6.8.0-146-generic\n#146-Ubuntu SMP',
                 '03-state-files.txt': '\n'.join(markers), '03-build-info.json': json.dumps(build),
                 '08-image.txt': self.image, '09-post-backup-mutation-name.txt': 'esxi-post-backup-block-1234-45',
                 '08-policy.json': json.dumps({'rules': [{'name': 'lab-allow-example', 'enabled': True}]}),
                 '08-login.txt': '{}\n200', '08-enforce.txt': 'allowed 200\ndenied 403'}
        for name in ('05-ca-fingerprint.txt', '09-ca-fingerprint.txt', '08-ca-fingerprint.txt'):
            files[name] = ':'.join(['AB'] * 32)
        for name in ('05b-lookups-before.txt', '09-category-lookups.txt', '08-lookups-after.txt'):
            files[name] = 'example.com category=Gambling tier=community matchedBy=example.com\nexample.net category= tier=none matchedBy='
        for name, value in files.items():
            (self.evidence / name).write_text(value, encoding='utf-8')

    def result(self, observation=None, transport_exit=0):
        return {row['check']: row['result'] for row in post.validate(
            observation or self.observation, self.evidence, self.source, self.image, transport_exit)}

    def test_complete_successful_evidence(self):
        self.assertEqual(set(self.result().values()), {'pass'})

    def test_empty_or_error_kernel_cannot_be_a_changed_kernel(self):
        for text in ('', 'Authenticated console transport blocked', '\n#146-Ubuntu SMP'):
            with self.subTest(text=text):
                (self.evidence / '07-kernel-after.txt').write_text(text)
                self.assertEqual(self.result()['kernel-observation'], 'fail')

    def test_unchanged_or_invalid_boot_id_is_refused(self):
        for value in (self.before, 'not-a-boot-id'):
            with self.subTest(value=value):
                observation = copy.deepcopy(self.observation)
                observation['values']['boot_id'] = value
                (self.evidence / 'esxi-boot-id-after.txt').write_text(value)
                self.assertEqual(self.result(observation)['reboot-identity'], 'fail')

    def test_empty_journal_from_failed_command_invalidates_all_claims(self):
        observation = copy.deepcopy(self.observation)
        observation['values']['firstboot_journal'] = ''
        observation['errors']['firstboot_journal'] = 'required command failed'
        self.assertEqual(self.result(observation), {'postcheck-command-integrity': 'fail'})

    def test_transport_failure_invalidates_even_plausible_complete_json(self):
        self.assertEqual(self.result(transport_exit=90), {'postcheck-command-integrity': 'fail'})

    def test_equal_category_errors_do_not_establish_persistence(self):
        for name in ('05b-lookups-before.txt', '09-category-lookups.txt', '08-lookups-after.txt'):
            (self.evidence / name).write_text('example.com error\nexample.net error')
        self.assertEqual(self.result()['meaningful-category-persistence'], 'fail')

    def test_returned_mutation_is_not_restored_policy(self):
        (self.evidence / '08-policy.json').write_text(json.dumps({'rules': [
            {'name': 'lab-allow-example', 'enabled': True}, {'name': 'esxi-post-backup-block-1234-45'}]}))
        self.assertEqual(self.result()['restored-policy-persistence'], 'fail')

    def test_only_current_boot_durable_log_can_fill_a_journal_flush_gap(self):
        observation = copy.deepcopy(self.observation)
        observation['values']['resume_journal'] = 'holding os-update and the maintenance agent lock'
        for stamp, expected in [('23:30:00', 'pass'), ('23:20:00', 'fail'), ('23:40:00', 'fail')]:
            with self.subTest(stamp=stamp):
                observation['values']['resume_durable_log']['lines'] = [
                    '2026-10-04T' + stamp + 'Z [resume-stack] stack started after the maintenance reboot']
                self.assertEqual(self.result(observation)['locked-stack-resume'], expected)

    def test_guest_command_refuses_empty_failed_output(self):
        process = Mock(stdout=io.BytesIO(b''))
        process.wait.return_value = 1
        with patch.object(guest.subprocess, 'Popen', return_value=process), patch.object(guest.threading, 'Timer'):
            with self.assertRaisesRegex(ValueError, 'command failed'):
                guest.command(['journalctl', 'synthetic-only'])

    def test_guest_durable_collection_excludes_old_and_future_entries(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        boot = int(now.timestamp()) - 120
        def line(offset):
            stamp = (now + datetime.timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%SZ')
            return stamp + ' [resume-stack] stack started after the maintenance reboot'
        old, current, future = line(-240), line(-60), line(240)
        with patch.object(guest, 'read_file', side_effect=['btime ' + str(boot), '\n'.join([old, current, future])]):
            self.assertEqual(guest.resume_log(), {'boot_start_epoch': boot, 'lines': [current]})


if __name__ == '__main__':
    unittest.main()
