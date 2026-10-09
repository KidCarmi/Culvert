import errno
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w, g, c = (load('disk-pressure-' + name) for name in ('worker', 'guest', 'control'))


class AllocationProofTests(unittest.TestCase):
    def fixture(self, allocate, changed=None):
        root = Mock()
        root.lstat.return_value = SimpleNamespace(st_dev=1, st_ino=2)
        probe = SimpleNamespace(st_dev=1, st_ino=3, st_uid=0, st_nlink=1,
                                st_mode=stat.S_IFREG | 0o600, st_size=0, st_blocks=0)
        blocks = SimpleNamespace(st_dev=1, st_ino=4, st_uid=0, st_nlink=1,
                                 st_mode=stat.S_IFREG | 0o600, st_size=8192, st_blocks=16)
        if changed:
            setattr(blocks, changed[0], changed[1])
        armed = {'binding': {'root': {'device': 1, 'inode': 2}, 'probe': {'device': 1, 'inode': 3}}}
        filled = dict(binding=armed['binding'], result='exhausted', allocated_bytes=8192,
                      blocks_identity={'device': 1, 'inode': 4})
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(w, 'safe_directory', return_value=10))
        stack.enter_context(patch.object(w, 'root_guard', return_value={
            'bytes_free': 16777216, 'bytes_available': 0, 'block_bytes': 4096, 'inodes_free': 100}))
        stack.enter_context(patch.object(w.os, 'fstat', side_effect=lambda fd: root.lstat() if fd == 10 else probe))
        stack.enter_context(patch.object(w.os, 'stat', side_effect=lambda name, **kw: probe if name == 'probe' else blocks))
        stack.enter_context(patch.object(w.os, 'open', return_value=11))
        stack.enter_context(patch.object(w.os, 'O_NOFOLLOW', 0, create=True))
        stack.enter_context(patch.object(w.os, 'close'))
        truncate = stack.enter_context(patch.object(w.os, 'ftruncate'))
        allocation = stack.enter_context(patch.object(w.os, 'posix_fallocate', create=True, side_effect=allocate))
        return root, armed, filled, allocation, truncate

    def test_internal_reserve_does_not_override_fresh_enospc(self):
        root, armed, filled, allocate, truncate = self.fixture(OSError(errno.ENOSPC, 'synthetic'))
        result = w.pressure_probe(root, armed, filled, 'blocks')
        self.assertTrue(result['exhausted'])
        self.assertEqual(result['filesystem_before']['bytes_free'], 16777216)
        allocate.assert_called_once_with(11, 0, 4096)
        truncate.assert_called_once_with(11, 0)

    def test_freed_capacity_is_not_pressure_and_probe_is_released(self):
        root, armed, filled, allocate, truncate = self.fixture(None)
        self.assertFalse(w.pressure_probe(root, armed, filled, 'blocks')['exhausted'])
        truncate.assert_called_once_with(11, 0)

    def test_quota_io_readonly_errors_are_not_enospc(self):
        for code in (errno.EIO, errno.EDQUOT, errno.EROFS):
            with self.subTest(code=code):
                root, armed, filled, _, truncate = self.fixture(OSError(code, 'synthetic'))
                with self.assertRaises(OSError):
                    w.pressure_probe(root, armed, filled, 'blocks')
                truncate.assert_called_once_with(11, 0)

    def test_removed_truncated_or_replaced_filler_stops_before_probe(self):
        for changed in [('st_nlink', 0), ('st_size', 4096), ('st_blocks', 0), ('st_ino', 99)]:
            with self.subTest(changed=changed):
                root, armed, filled, allocate, _ = self.fixture(None, changed)
                with self.assertRaises(ValueError):
                    w.pressure_probe(root, armed, filled, 'blocks')
                allocate.assert_not_called()

    def test_filler_binding_must_match_armed_directory(self):
        root, armed, filled, allocate, _ = self.fixture(None)
        filled['binding'] = {'root': {'device': 99, 'inode': 2}}
        with self.assertRaises(ValueError):
            w.pressure_probe(root, armed, filled, 'blocks')
        allocate.assert_not_called()

    def test_root_accounting_records_available_and_internal_difference(self):
        value = SimpleNamespace(f_blocks=10000000, f_frsize=4096, f_bfree=4096, f_bavail=0, f_ffree=12)
        with patch.object(w.os, 'statvfs', create=True, return_value=value), \
                patch.object(w.os, 'stat', return_value=SimpleNamespace(st_dev=1)):
            result = w.root_guard(Path('/synthetic'))
        self.assertEqual(result['unavailable_free_bytes'], 16777216)
        self.assertEqual(result['bytes_available'], 0)
        self.assertEqual(result['f_bfree'], 4096)


class ReplenishmentTests(unittest.TestCase):
    def test_capacity_freed_after_initial_enospc_is_replenished_in_same_fd(self):
        now, free, pauses, calls, checks, reports = [0], [0], [0], [], [], []
        def allocate(fd, offset, count):
            calls.append((fd,offset,count));now[0]+=.001
            if count>free[0]:raise OSError(errno.ENOSPC,'synthetic')
            free[0]-=count
        def pause(seconds):
            pauses[0]+=1
            if pauses[0]==1:free[0]=794624
            else:now[0]=11
        result=w.maintain_blocks(77,8192,10,checks.append,reports.append,allocate,
                                 clock=lambda:now[0],pause=pause)
        self.assertEqual(result['added_bytes'],794624)
        self.assertGreaterEqual(result['enospc_checks'],2)
        self.assertEqual(result['state'],'deadline')
        self.assertTrue(all(row[0]==77 for row in calls))
        self.assertEqual(len(checks),len(calls))
        self.assertTrue(all(row[1]+row[2]<=40*w.GIB for row in calls))

    def test_deadline_and_cumulative_cap_prevent_late_allocation(self):
        allocate, check, publish = Mock(), Mock(), Mock()
        result=w.maintain_blocks(77,8192,0,check,publish,allocate,clock=lambda:1)
        allocate.assert_not_called();check.assert_not_called()
        self.assertEqual(result['state'],'deadline')
        result=w.maintain_blocks(77,40*w.GIB-4096,10,check,publish,allocate,clock=lambda:1)
        allocate.assert_called_once_with(77,40*w.GIB-4096,4096)
        self.assertEqual(result['allocated_bytes'],40*w.GIB)
        self.assertEqual(result['state'],'allocation_cap')

    def test_unexpected_errors_or_changed_binding_stop_without_retry(self):
        for code in (errno.EDQUOT,errno.EIO,errno.EROFS):
            allocate=Mock(side_effect=OSError(code,'synthetic'))
            with self.subTest(code=code), self.assertRaises(OSError):
                w.maintain_blocks(77,8192,10,Mock(),Mock(),allocate,clock=lambda:1)
            self.assertEqual(allocate.call_count,1)
        allocate=Mock()
        with self.assertRaises(ValueError):
            w.maintain_blocks(77,8192,10,Mock(side_effect=ValueError('changed inode')),Mock(),allocate,clock=lambda:1)
        allocate.assert_not_called()

    def test_fixed_call_bound_cannot_reset_with_returning_capacity(self):
        allocate=Mock()
        with patch.object(w,'MAX_REFILL_CALLS',3):
            result=w.maintain_blocks(77,8192,10,Mock(),Mock(),allocate,clock=lambda:1)
        self.assertEqual(result['state'],'call_limit')
        self.assertEqual(allocate.call_count,3)
        self.assertEqual(result['added_bytes'],3*65536)

    def test_fill_retains_original_descriptor_and_checks_path_identity_during_refill(self):
        with tempfile.TemporaryDirectory() as temporary:
            control=Path(temporary)
            binding={'root':{'device':1,'inode':2},'probe':{'device':1,'inode':3}}
            (control/'binding.json').write_text(json.dumps(binding))
            root=Mock();root.lstat.return_value=SimpleNamespace(st_dev=1,st_ino=2)
            opened=SimpleNamespace(st_dev=1,st_ino=4,st_uid=0,st_mode=stat.S_IFREG|0o600,
                                   st_nlink=1,st_size=8192,st_blocks=16)
            observed=SimpleNamespace(**vars(opened))
            def maintain(fd,total,deadline,check,publish):
                self.assertEqual(fd,11);self.assertEqual(total,8192)
                closed.assert_not_called()
                check(total)
                observed.st_ino=99
                with self.assertRaises(ValueError):check(total)
            with patch.object(w,'paths',return_value=(root,control)), \
                    patch.object(w,'safe_directory',return_value=10), \
                    patch.object(w,'root_guard',return_value={'inodes_free':100}), \
                    patch.object(w.os,'O_NOFOLLOW',0,create=True), \
                    patch.object(w.os,'open',return_value=11) as opening, \
                    patch.object(w.os,'fstat',side_effect=lambda fd:root.lstat() if fd==10 else opened), \
                    patch.object(w.os,'stat',return_value=observed), \
                    patch.object(w.os,'close') as closed, \
                    patch.object(w,'fill_blocks',return_value={'result':'exhausted','allocated_bytes':8192}), \
                    patch.object(w,'atomic_json') as publish, \
                    patch.object(w,'maintain_blocks',side_effect=maintain):
                w.fill('a'*32,'blocks')
            self.assertEqual(opening.call_count,1)
            self.assertEqual([call.args[0] for call in closed.call_args_list],[11,10])
            self.assertEqual(publish.call_args_list[0].args[0],control/'filled.json')


class CaptureProofTests(unittest.TestCase):
    def test_requires_correlated_deduplicated_scan_response_in_each_window(self):
        probes = [{'kind': kind, 'started_ns': index*10, 'ended_ns': index*10+5,
                   'body_sha256': str(index)*64, 'private_origin_url': 'http://fixture/' + str(index)}
                  for index, kind in enumerate(('eicar', 'clean', 'clean'), 1)]
        def fragment(index):
            return {'response_fragment_hex': (b'stream: signature FOUND\0' if index == 1 else b'stream: OK\0').hex(),
                    'fragment_truncated': False, 'destination_port': 40000+index, 'sequence': 1,
                    'payload_sha256': str(index)*64, 'monotonic_ns': index*10+2}
        for scenario in ('good', 'missing', 'late', 'shared_port', 'error'):
            capture = Mock()
            capture.snapshot.return_value = dict(available=True, error='failed' if scenario == 'error' else None)
            def observations(start, end):
                index = start//10
                if scenario in ('missing', 'late') and index == 2:
                    return []  # actual observer excludes out-of-window receive timestamps
                row = fragment(index)
                if scenario == 'shared_port':
                    row['destination_port'] = 40000
                return [row, dict(row)]  # mirrored bridge duplicate must not count twice
            capture.observations.side_effect = observations
            with self.subTest(scenario=scenario), patch.object(g, 'sample', return_value={'pass': True, 'probes': probes}):
                result = g.prefill_control(capture, Mock(), Mock(), set())
            self.assertEqual(result['pass'], scenario == 'good')
            if scenario == 'good':
                self.assertTrue(all(len(row['fragments']) == 1 for row in result['correlations']))

    def test_failed_capture_control_prevents_allocator_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root, control = Path(directory) / 'root', Path(directory) / 'control'
            worker, capture = Mock(), Mock()
            worker.paths.return_value = root, control
            worker.safe_directory.return_value = 123
            capture.close.return_value = dict(available=True, fragments=0)
            with patch.object(g, 'network_pair', return_value=('192.0.2.1', '192.0.2.2')), \
                    patch.object(g, 'prefill_control', return_value={'pass': False}), \
                    patch.object(g.os, 'close', side_effect=lambda fd, close=g.os.close: None if fd == 123 else close(fd)), \
                    patch.object(g.subprocess, 'Popen') as launched:
                result = g.phase({'operation': 'a'*32}, 'blocks', Mock(), b'# fixture', worker,
                                 Mock(return_value=capture), Mock(), set())
            launched.assert_not_called()
            self.assertFalse(result['allocation_started'])
            self.assertEqual(result['result'], 'fail')
            self.assertEqual(result['capture']['collection_verdict'], 'CAPTURE_INCOMPLETE')


class SampleBracketingTests(unittest.TestCase):
    def test_three_samples_require_all_six_fresh_allocation_proofs(self):
        for allocation_results, expected in [([True]*6, 'pass'), ([True, False, True, True, True, True], 'fail')]:
            with self.subTest(allocation_results=allocation_results), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                root, control = directory/'root', directory/'control'
                root.mkdir()
                worker, supervisor, capture = Mock(), Mock(), Mock()
                worker.paths.return_value = root, control
                worker.safe_directory.return_value = 123
                worker.root_guard.return_value = {'bytes_free': 16777216}
                events, outcomes = [], iter(allocation_results)
                def allocation(*unused):
                    events.append('allocation')
                    return {'exhausted': next(outcomes)}
                worker.pressure_probe.side_effect = allocation
                supervisor.poll.return_value = None
                def launched(*unused, **kwargs):
                    (control/'armed.json').write_text('{}')
                    (control/'filled.json').write_text('{"result":"exhausted"}')
                    return supervisor
                def released(**kwargs):
                    root.rmdir()
                    (control/'released.json').write_text('{"released":true}')
                supervisor.wait.side_effect = released
                capture.snapshot.return_value = {'available': True, 'fragments': 2}
                capture.close.return_value = {'available': True, 'fragments': 2}
                def sampled(*unused, **kwargs):
                    events.append('sample')
                    return {'pass': True}
                with patch.object(g, 'network_pair', return_value=('192.0.2.1', '192.0.2.2')), \
                        patch.object(g, 'prefill_control', return_value={'pass': True}), \
                        patch.object(g.subprocess, 'Popen', side_effect=launched), \
                        patch.object(g, 'sample', side_effect=sampled), \
                        patch.object(g.time, 'monotonic', side_effect=[0, 1, 2, 3, 131]), \
                        patch.object(g.time, 'sleep'), \
                        patch.object(g.os, 'close', side_effect=lambda fd, close=g.os.close: None if fd == 123 else close(fd)):
                    result = g.phase({'operation': 'a'*32, 'lease': {}}, 'blocks', Mock(), b'# fixture',
                                     worker, Mock(return_value=capture), Mock(), set())
                self.assertEqual(events, ['allocation', 'sample', 'allocation']*3)
                self.assertEqual(result['result'], expected)
                self.assertEqual(result['capture']['collection_verdict'], 'NO_PRESSURE_FRAGMENT_OBSERVED_WITH_PREFILL_CONTROL')


class CaptureOnlyTests(unittest.TestCase):
    def test_healthy_capture_has_no_pressure_or_worker_execution_and_restores_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend, backend_module, worker, capture = Mock(), Mock(), Mock(), Mock()
            backend.cleanup_fixture.return_value = True
            worker.safe_directory.return_value = 123
            capture.close.return_value = {'available': True, 'fragments': 3, 'packet_protocol': 'ETH_P_ALL'}
            with patch.object(g.signal, 'signal'), patch.object(g, 'Path', return_value=Path(temporary)), \
                    patch.object(g, 'container_state', return_value={'fixed': 'identity'}), \
                    patch.object(g, 'network_pair', return_value=('192.0.2.1', '192.0.2.2')), \
                    patch.object(g, 'prefill_control', return_value={'pass': True}), \
                    patch.object(g, 'phase') as phase, patch.object(g.subprocess, 'Popen') as popen, \
                    patch.object(g.os, 'close', side_effect=lambda fd, close=g.os.close: None if fd == 123 else close(fd)):
                result = g.run_capture({'operation':'a'*32}, backend, backend_module, worker, Mock(return_value=capture))
            self.assertEqual(result['result'], 'pass')
            self.assertFalse(result['allocation_started'])
            self.assertTrue(result['policy_restored'])
            phase.assert_not_called();popen.assert_not_called();worker.paths.assert_not_called()
            worker.supervise.assert_not_called();worker.fill.assert_not_called()
            backend.cleanup_fixture.assert_called_once()
            backend.close.assert_called_once()

    def test_capture_termination_runs_policy_cleanup_without_claiming_success(self):
        backend, backend_module, worker = Mock(), Mock(), Mock()
        backend.cleanup_fixture.return_value = True
        handlers = []
        def register(sig, handler):
            handlers.append(handler)
        backend.install_fixture.side_effect = lambda: handlers[0]()
        with patch.object(g.signal, 'signal', side_effect=register), \
                patch.object(g, 'container_state', return_value={'fixed':'identity'}), \
                patch.object(g.subprocess, 'Popen') as launched:
            result = g.run_capture({'operation':'a'*32},backend,backend_module,worker,Mock())
        self.assertEqual(result['result'],'fail')
        self.assertEqual(handlers[1],g.signal.SIG_IGN)
        backend.cleanup_fixture.assert_called_once()
        backend.close.assert_called_once()
        launched.assert_not_called()

    def test_v3_requires_successful_identical_capture_helpers_and_exact_admission(self):
        hashes = {'intent':'i','complete':'c','guest-result':'g'}
        helper_hashes = {'disk-pressure-observe.py':'h'}
        intent = {'helper_hashes':helper_hashes,'prior_capture_failure':hashes,'allocation_permitted':False}
        guest = {'result':'pass','scope':'healthy_capture_only','allocation_started':False,
                 'policy_restored':True,'no_restart':True,'capture_positive_control':{'pass':True},
                 'capture':{'packet_protocol':'ETH_P_ALL','collection_verdict':'BOUNDED_FRAGMENTS_RETAINED'}}
        records = {'intent':intent,'complete':{'result':'pass'},'guest-result':guest}
        manifest = {'files':{'test/e2e/appliance/esxi/disk-pressure-observe.py':'h'}}
        admission = {'capture_gate':{'v2':hashes,'preflight':hashes}}
        with patch.object(c, 'prior_capture_failure', return_value=hashes), \
                patch.object(c, 'attempt_records', return_value=(records,hashes)):
            self.assertEqual(c.capture_gate(Mock(),manifest,admission),admission['capture_gate'])
            for change in ({'allocation_started':True},{'result':'fail'},{'policy_restored':False}):
                old = dict(guest)
                guest.update(change)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    c.capture_gate(Mock(),manifest,admission)
                guest.clear();guest.update(old)
            with self.assertRaises(ValueError):c.capture_gate(Mock(),manifest,{})
            manifest['files']['test/e2e/appliance/esxi/disk-pressure-observe.py']='changed'
            with self.assertRaises(ValueError):c.capture_gate(Mock(),manifest,admission)


class ReplenishmentAdmissionTests(unittest.TestCase):
    def safe_prior(self):
        probes=[{'kind':kind,'http_status':403 if kind=='eicar' else 200,
                 'verdict':'eicar_blocked' if kind=='eicar' else 'clean_delivered'}
                for kind in ('eicar','clean','clean')]
        rows=[{'pass':True,'readiness_truthful':True,'pressure_present_across_sample':index==0,
               'probes':copy.deepcopy(probes)} for index in range(64)]
        guest={'result':'fail','policy_restored':True,'no_restart':True,'phases':[
            {'mode':'blocks','result':'fail','fill':{'result':'exhausted','errno':'ENOSPC'},
             'released':True,'root_pressure_directory_absent':True,'no_restart':True,
             'recovered':{'pass':True},'capture_positive_control':{'pass':True},
             'capture':{'collection_verdict':'BOUNDED_FRAGMENTS_RETAINED'},'samples':rows}]}
        return {'complete':{'result':'fail'},'guest-result':guest}

    def test_only_exact_safe_unsustained_failure_can_admit_v4(self):
        original=self.safe_prior()
        hashes={'guest-result':c.V3_PRESSURE_RESULT}
        mutations=[None,lambda g:g.update(policy_restored=False),
                   lambda g:g['phases'][0]['samples'][1].update(**{'pass':False}),
                   lambda g:g['phases'][0]['samples'][1]['probes'][0].update(http_status=200,verdict='eicar_delivered'),
                   lambda g:g['phases'][0]['samples'][1].update(pressure_present_across_sample=True)]
        for mutation in mutations:
            records=copy.deepcopy(original)
            if mutation:mutation(records['guest-result'])
            with self.subTest(mutation=mutation), patch.object(c,'attempt_records',return_value=(records,hashes)):
                if mutation:
                    with self.assertRaises(ValueError):c.prior_replenishment_failure(Mock(),{})
                else:self.assertEqual(c.prior_replenishment_failure(Mock(),{}),hashes)
        with patch.object(c,'attempt_records',return_value=(original,{'guest-result':'changed'})):
            with self.assertRaises(ValueError):c.prior_replenishment_failure(Mock(),{})

    def test_v4_gate_requires_new_preflight_name_and_current_full_helper_hashes(self):
        hashes={'intent':'i','complete':'c','guest-result':'g'}
        records={'intent':{'helper_hashes':{'disk-pressure-worker.py':'new-worker'},
                           'prior_capture_failure':hashes,'allocation_permitted':False},
                 'complete':{'result':'pass'},'guest-result':{'result':'pass','scope':'healthy_capture_only',
                 'allocation_started':False,'policy_restored':True,'no_restart':True,
                 'capture_positive_control':{'pass':True},
                 'capture':{'packet_protocol':'ETH_P_ALL','collection_verdict':'BOUNDED_FRAGMENTS_RETAINED'}}}
        manifest={'files':{'test/e2e/appliance/esxi/disk-pressure-worker.py':'new-worker'}}
        lab=Mock();admission={'capture_gate':{'v3':hashes,'preflight':hashes}}
        with patch.object(c,'prior_replenishment_failure',return_value=hashes), \
                patch.object(c,'prior_capture_failure') as old_gate, \
                patch.object(c,'attempt_records',return_value=(records,hashes)) as record_loader:
            self.assertEqual(c.capture_gate(lab,manifest,admission,'v4'),admission['capture_gate'])
            record_loader.assert_called_with(lab,'disk-pressure-capture-preflight-v4',manifest)
            old_gate.assert_not_called()
            records['intent']['helper_hashes']['disk-pressure-worker.py']='old-worker'
            with self.assertRaises(ValueError):c.capture_gate(lab,manifest,admission,'v4')


class AdmissionTests(unittest.TestCase):
    def test_original_default_compatible_named_requires_admission(self):
        self.assertEqual(c.attempt_admission(Mock(), SimpleNamespace(), {}, {}), ('disk-pressure', None))
        for name in ('disk-pressure-proof-v2', '../disk-pressure', 'disk-pressure/x'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                c.attempt_admission(Mock(), SimpleNamespace(attempt=name), {}, {})

    def admission_fixture(self, directory):
        prior = directory / 'disk-pressure'
        prior.mkdir()
        probe = {'kind': 'eicar', 'http_status': 403, 'verdict': 'av_unavailable'}
        row = {'pass': True, 'readiness_truthful': True, 'pressure_present_across_sample': False, 'probes': [probe]*3}
        guest = {'operation': 'a'*32, 'result': 'fail', 'policy_restored': True, 'no_restart': True,
                 'phases': [{'mode': 'blocks', 'result': 'fail', 'fill': {'result': 'exhausted', 'errno': 'ENOSPC'},
                             'released': True, 'root_pressure_directory_absent': True, 'recovered': {'pass': True},
                             'no_restart': True, 'samples': [row]*64}]}
        raw = json.dumps(guest).encode()
        values = {'intent': {'operation': 'a'*32, 'owner_uuid': 'u', 'source_sha': 's'},
                  'complete': {'operation': 'a'*32, 'result': 'fail', 'guest_result_sha256': c.sha(raw)},
                  'guest-result': guest}
        admission = {'schema': 1, 'attempt': 'disk-pressure-proof-v2', 'decision': 'allow_prospective_pressure',
                     'custody_verified': True, 'owner_uuid': 'u', 'source_sha': 's', 'prior_directory': str(prior)}
        for name, value in values.items():
            data = json.dumps(value).encode()
            (prior / (name + '.json')).write_bytes(data)
            admission['prior_' + name.replace('-', '_') + '_sha256'] = c.sha(data)
        for name in ('custody_receipt', 'custody_archive'):
            path = directory / name
            path.write_bytes(b'synthetic custody')
            admission[name] = {'path': str(path), 'sha256': c.sha(path.read_bytes())}
        custody = {'schema': 1, 'uuid': 'u', 'run': str(directory),
                   'archive': admission['custody_archive']['path'],
                   'ciphertext_sha256': admission['custody_archive']['sha256'],
                   'roundtrip_verified': True, 'source_unchanged': True, 'every_file_verified': True,
                   'original_retained_at_preservation': True}
        receipt = Path(admission['custody_receipt']['path'])
        receipt.write_text(json.dumps(custody))
        admission['custody_receipt']['sha256'] = c.sha(receipt.read_bytes())
        self.original_hash = patch.object(c, 'ORIGINAL_PRESSURE_RESULT', admission['prior_guest_result_sha256'])
        self.original_hash.start()
        self.addCleanup(self.original_hash.stop)
        path = directory / 'admission.json'
        path.write_text(json.dumps(admission))
        return SimpleNamespace(run=directory, sec=directory, state={'uuid': 'u'}), SimpleNamespace(
            attempt='disk-pressure-proof-v2', prior_admission=path), admission, guest

    def test_bound_prior_failure_admits_distinct_attempt_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab, args, admission, guest = self.admission_fixture(Path(temporary))
            self.assertEqual(c.attempt_admission(lab, args, {'source_sha': 's'}, {'external_inputs': [
                {'path': str(args.prior_admission), 'sha256': c.sha(args.prior_admission.read_bytes())}]})[0], 'disk-pressure-proof-v2')
            (Path(admission['custody_archive']['path'])).write_bytes(b'changed')
            with self.assertRaises(ValueError):
                c.attempt_admission(lab, args, {'source_sha': 's'}, {'external_inputs': [
                {'path': str(args.prior_admission), 'sha256': c.sha(args.prior_admission.read_bytes())}]})

    def test_unfrozen_admission_and_unverified_custody_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab, args, admission, guest = self.admission_fixture(Path(temporary))
            with self.assertRaisesRegex(ValueError, 'not frozen'):
                c.attempt_admission(lab, args, {'source_sha': 's'}, {})
            receipt = Path(admission['custody_receipt']['path'])
            custody = json.loads(receipt.read_bytes())
            custody['every_file_verified'] = False
            receipt.write_text(json.dumps(custody))
            admission['custody_receipt']['sha256'] = c.sha(receipt.read_bytes())
            args.prior_admission.write_text(json.dumps(admission))
            with self.assertRaisesRegex(ValueError, 'custody verification incomplete'):
                c.attempt_admission(lab, args, {'source_sha': 's'}, {'external_inputs': [
                    {'path': str(args.prior_admission), 'sha256': c.sha(args.prior_admission.read_bytes())}]})

    def test_failed_enforcement_cannot_be_admitted_even_with_matching_new_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab, args, admission, guest = self.admission_fixture(Path(temporary))
            guest['phases'][0]['samples'][0]['pass'] = False
            data = json.dumps(guest).encode()
            prior = Path(admission['prior_directory'])
            (prior/'guest-result.json').write_bytes(data)
            admission['prior_guest_result_sha256'] = c.sha(data)
            complete = json.loads((prior/'complete.json').read_bytes())
            complete['guest_result_sha256'] = c.sha(data)
            data = json.dumps(complete).encode()
            (prior/'complete.json').write_bytes(data)
            admission['prior_complete_sha256'] = c.sha(data)
            args.prior_admission.write_text(json.dumps(admission))
            self.original_hash.stop()
            self.original_hash = patch.object(c, 'ORIGINAL_PRESSURE_RESULT', admission['prior_guest_result_sha256'])
            self.original_hash.start()
            self.addCleanup(self.original_hash.stop)
            with self.assertRaises(ValueError):
                c.attempt_admission(lab, args, {'source_sha': 's'}, {'external_inputs': [
                {'path': str(args.prior_admission), 'sha256': c.sha(args.prior_admission.read_bytes())}]})


if __name__ == '__main__':
    unittest.main()
