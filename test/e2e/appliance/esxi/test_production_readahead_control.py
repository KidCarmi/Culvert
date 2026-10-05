"""Offline refusal and payload contracts; no console/guest operations."""
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import unittest
import uuid

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('readahead_control', HERE / 'production-readahead-control.py')
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
GUEST = {}
exec(compile(CONTROL.GUEST, '<read-ahead-guest>', 'exec'), GUEST)
OWNER = '12345678-1234-4567-89ab-123456789abc'
CAMPAIGN = '23456789-2345-4678-9abc-23456789abcd'
TRANSITION = '3456789a-3456-4789-abcd-3456789abcde'


def config(action='set', expect=128, value=1024):
    return dict(schema=1, action=action, owner_uuid=OWNER, campaign_uuid=CAMPAIGN,
                transition_uuid=TRANSITION, expect=expect, value=value,
                source_sha=CONTROL.SOURCE, image_id=CONTROL.IMAGE, generator_sha256='a' * 64)


def observed(value=128):
    return dict(vendor='VMware, Inc.', guest_uuid=OWNER, source_sha=CONTROL.SOURCE, dirty=False,
                image_id=CONTROL.IMAGE, root='/dev/sda1 ext4', disks=['sda'],
                sectors=40 * 1024**3 // 512, scheduler='[mq-deadline] none', effective=value)


def receipt(c, value):
    result = {key: c[key] for key in ('schema', 'owner_uuid', 'campaign_uuid', 'source_sha', 'image_id', 'generator_sha256')}
    result.update(status='complete', new_value=value, rule_sha256=GUEST['sha'](GUEST['rule_bytes'](c, value)))
    return result


class ReadaheadTests(unittest.TestCase):
    def test_first_B_then_owned_return_A_and_readonly_verify(self):
        first = config()
        GUEST['validate'](first, observed(), None, None)
        back = config(expect=1024, value=128)
        GUEST['validate'](back, observed(1024), receipt(first, 1024), GUEST['rule_bytes'](first, 1024))
        verify = config('verify', 128, 128)
        GUEST['validate'](verify, observed(), receipt(back, 128), GUEST['rule_bytes'](back, 128))

    def test_initial_A_rule_establishes_matched_placement_before_B(self):
        initial = config('set', 128, 128)
        CONTROL.generate('set', OWNER, CAMPAIGN, 128, 128, 'a' * 64)
        GUEST['validate'](initial, observed(), None, None)
        GUEST['validate'](config(), observed(), receipt(initial, 128), GUEST['rule_bytes'](initial, 128))
        with self.assertRaises(ValueError):
            GUEST['validate'](initial, observed(), receipt(initial, 128), GUEST['rule_bytes'](initial, 128))

    def test_exact_and_only_deterministic_VMware_UUID_alias(self):
        state = observed()
        state['guest_uuid'] = str(uuid.UUID(bytes_le=uuid.UUID(OWNER).bytes))
        GUEST['validate'](config(), state, None, None)
        for vendor, identity in [('QEMU', OWNER), ('VMware, Inc.', CAMPAIGN), ('VMware, Inc.', OWNER.upper())]:
            state.update(vendor=vendor, guest_uuid=identity)
            with self.assertRaises(ValueError):
                GUEST['validate'](config(), state, None, None)

    def test_product_disk_scheduler_and_effective_guards(self):
        mutations = [('source_sha', 'b' * 40), ('dirty', True), ('dirty', 0), ('image_id', 'sha256:' + 'c' * 64),
                     ('root', '/dev/sdb1 ext4'), ('root', '/dev/sda1 xfs'), ('disks', ['sda', 'sdb']),
                     ('disks', ['sda', 'nvme0n1']), ('sectors', 39 * 1024**3 // 512),
                     ('scheduler', 'mq-deadline [none]'), ('effective', 256), ('effective', 1024)]
        for key, value in mutations:
            state = observed(); state[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                GUEST['validate'](config(), state, None, None)

    def test_preexisting_rule_missing_or_foreign_receipt_never_adopted(self):
        c = config()
        for content in (b'unrelated rule\n', GUEST['rule_bytes'](c, 128)):
            with self.assertRaises(ValueError):
                GUEST['validate'](c, observed(), None, content)
        for key, value in [('status', 'pending'), ('schema', 2), ('campaign_uuid', TRANSITION),
                           ('owner_uuid', CAMPAIGN), ('generator_sha256', 'b' * 64),
                           ('new_value', 1024), ('rule_sha256', '0' * 64)]:
            prior = receipt(c, 128); prior[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                GUEST['validate'](c, observed(), prior, GUEST['rule_bytes'](c, 128))
        with self.assertRaises(ValueError):
            GUEST['validate'](c, observed(), receipt(c, 128), b'unrelated rule\n')

    def test_only_two_values_no_noop_switch_or_mutating_verify(self):
        for action, expected, value in [('verify', 128, 1024), ('set', 128, 256),
                                         ('set', True, 1024), ('remove', 128, 1024)]:
            with self.subTest(action=action, expected=expected, value=value), self.assertRaises(ValueError):
                CONTROL.generate(action, OWNER, CAMPAIGN, expected, value, 'a' * 64)
        with self.assertRaises(ValueError):
            GUEST['validate'](config('verify', 128, 128), observed(), None, None)

    def test_guest_schema_and_uuid_refusals(self):
        for key, value in [('schema', 2), ('owner_uuid', OWNER.upper()), ('campaign_uuid', 'invalid'),
                           ('transition_uuid', ''), ('expect', True)]:
            c = config(); c[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                GUEST['validate'](c, observed(), None, None)

    def test_payload_is_LF_only_pinned_and_python_compiles(self):
        body = CONTROL.generate('set', OWNER, CAMPAIGN, 128, 1024, 'a' * 64)
        self.assertNotIn('\r', body)
        self.assertIn('timeout 60s python3', body)
        self.assertIn('set +x\numask 077', body)
        python_body = body.split("<<'CULVERT_LAB_READ_AHEAD'\n", 1)[1].rsplit('\nCULVERT_LAB_READ_AHEAD\n', 1)[0]
        compile(python_body, '<generated-payload>', 'exec')
        assignment = next(node for node in ast.parse(python_body).body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'configuration' for target in node.targets))
        values = ast.literal_eval(assignment.value)
        self.assertEqual(values['source_sha'], CONTROL.SOURCE)
        self.assertEqual(values['image_id'], CONTROL.IMAGE)
        self.assertEqual(str(uuid.UUID(values['transition_uuid'])), values['transition_uuid'])
        rule = GUEST['rule_bytes'](values, 1024)
        self.assertEqual(rule.count(b'\n'), 3)
        self.assertTrue(rule.endswith(b'ATTR{queue/read_ahead_kb}="1024"\n'))
        self.assertNotIn(b'\\n', rule)
        bash = shutil.which('bash')
        if bash:
            result = subprocess.run([bash, '-n'], input=body.encode(), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_verify_returns_before_any_mutation_and_set_failure_keeps_lock(self):
        tree = ast.parse(CONTROL.GUEST)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'guest_main')
        verify = next(node for node in function.body if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "c['action'] == 'verify'")
        self.assertIsInstance(verify.body[-1], ast.Return)
        remaining = function.body[function.body.index(verify) + 1:]
        self.assertTrue(any('write_new(lock' in ast.unparse(node) for node in remaining))
        self.assertFalse(any(isinstance(node, ast.Try) for node in remaining))
        self.assertEqual(sum('lock.unlink()' in ast.unparse(node) for node in remaining), 1)
        self.assertNotIn('systemctl', CONTROL.GUEST)
        self.assertNotIn('update-initramfs', CONTROL.GUEST)
        self.assertNotIn('udevadm', CONTROL.GUEST)


if __name__ == '__main__':
    unittest.main()
