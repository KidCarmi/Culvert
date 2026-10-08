"""Synthetic NetLog regressions; no browser or network operations."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('browser_connect_proof', Path(__file__).with_name('browser-connect-proof.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class BrowserConnectProofTests(unittest.TestCase):
    def fixture(self):
        return {'constants': {'logEventTypes': {p.SEND: 1, p.RECEIVE: 2}}, 'events': [
            {'type': 1, 'source': {'type': 5, 'id': 17}, 'time': '10',
             'params': {'line': 'CONNECT example.com:443 HTTP/1.1\r\n', 'headers': ['Host: example.com:443']}},
            {'type': 2, 'source': {'type': 5, 'id': 17}, 'time': '11',
             'params': {'headers': ['HTTP/1.1 200 Connection Established', 'Set-Cookie: private-never-publish']}}]}

    def test_pairs_actual_connect_and_response_without_emitting_headers(self):
        result = p.extract(self.fixture(), 'example.com:443', 200)
        self.assertTrue(result['pass'])
        self.assertNotIn('private-never-publish', str(result))

    def test_never_confuses_other_source_authority_failure_or_credential_with_success(self):
        for change in ('source', 'authority', '502', 'missing', 'credential', 'ordinary-request'):
            with self.subTest(change=change):
                data = self.fixture()
                if change == 'source': data['events'][1]['source']['id'] = 18
                if change == 'authority': data['events'][0]['params']['line'] = 'CONNECT other.example:443 HTTP/1.1'
                if change == '502': data['events'][1]['params']['headers'][0] = 'HTTP/1.1 502 Bad Gateway'
                if change == 'missing': data['events'].pop()
                if change == 'credential': data['events'][0]['params']['headers'].append('Proxy-Authorization: secret')
                if change == 'ordinary-request': data['events'][0]['params']['line'] = 'GET https://example.com/ HTTP/1.1'
                self.assertFalse(p.extract(data, 'example.com:443', 200)['pass'])

    def test_later_success_does_not_erase_earlier_failure(self):
        data = self.fixture()
        later = copy.deepcopy(data['events'])
        data['events'][1]['params']['headers'][0] = 'HTTP/1.1 502 Bad Gateway'
        data['events'].extend(later)
        result = p.extract(data, 'example.com:443', 200)
        self.assertFalse(result['pass'])
        self.assertEqual([r['status'] for r in result['exchanges']], [502, 200])


if __name__ == '__main__':
    unittest.main()
