import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'src/unifi_technitium_sync/sync.py'


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = dict(UNIFI_NETWORK_HOST='unifi.example.com', UNIFI_API_KEY='test',
                   TECHNITIUM_DNS01_HOST='dns01.example.com', TECHNITIUM_DNS02_HOST='dns02.example.com',
                   DNS01_TOKEN='test', DNS02_TOKEN='test', SYNC_SUBNET='192.0.2.0/24',
                   DNS_SUFFIX='clients.example.com', DB_PATH=self.temp.name+'/state.db')
        self.env = patch.dict(os.environ, env, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        spec = importlib.util.spec_from_file_location('sync_under_test', SOURCE)
        self.s = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.s)
        self.addCleanup(self.s.db.close)
        self.client = dict(mac='02:00:00:00:00:01', fqdn='laptop.clients.example.com', ip='192.0.2.10')
        self.primary = dict(node_type='Primary', host='dns01.example.com', token='test')
        self.records = {}
        self.calls = []
        # A test must never contact a real service, even when a mock is missing.
        guard = patch.object(self.s.urllib.request, 'urlopen', side_effect=AssertionError('Network forbidden in tests'))
        guard.start()
        self.addCleanup(guard.stop)

    def analyses(self):
        s = self.s
        c = self.client
        a = s.analyze_record('A', c['fqdn'], c['ip'], [], 'clients.example.com', c['mac'])
        ptr = s.analyze_record('PTR', s.ptr_name_for_ip(c['ip']), c['fqdn'], [], s.reverse_zone_for_ip(c['ip']), c['mac'])
        return a, ptr

    def reserve(self):
        self.s.DRY_RUN = False
        return self.s.reserve_pair_transaction(self.client, *self.analyses())

    def read(self, primary, kind, name, zone):
        return self.records.get((kind, name), [])[:]

    def post(self, primary, path, params):
        self.calls.append((path, params.copy()))
        kind = params['type']
        name = params['domain']
        value = params['ipAddress'] if kind == 'A' else params['ptrName']
        key = kind, name
        if path.endswith('/add'):
            self.assertEqual(str(params['overwrite']).lower(), 'false')
            self.records.setdefault(key, []).append(value)
        elif path.endswith('/delete'):
            self.records[key].remove(value)
        else:
            raise AssertionError(path)
        return {'status':'ok'}

    def run_tx(self, tx):
        with patch.object(self.s, 'read_record_values', side_effect=self.read), patch.object(self.s, 'technitium_post', side_effect=self.post):
            self.s.process_pair_transaction(self.primary, tx)

    def test_defaults_and_dry_run_blocks_writes_and_reservations(self):
        self.assertTrue(self.s.DRY_RUN)
        self.assertTrue(self.s.UNIFI_VERIFY_SSL)
        self.assertEqual(self.s.TECHNITIUM_SCHEME, 'https')
        with self.assertRaises(RuntimeError):
            self.s.technitium_post(self.primary, '/unused', {})
        with self.assertRaises(RuntimeError):
            self.s.reserve_pair_transaction(self.client, *self.analyses())
        self.assertEqual(self.s.db.execute('SELECT COUNT(*) FROM dns_pair_transactions').fetchone()[0], 0)

    def test_secondary_never_accepts_write(self):
        self.s.DRY_RUN = False
        with self.assertRaisesRegex(RuntimeError, 'Primary'):
            self.s.technitium_post(dict(node_type='Secondary'), '/unused', {})

    def test_external_match_not_adopted(self):
        c=self.client
        result=self.s.analyze_record('A', c['fqdn'], c['ip'], [c['ip']], 'clients.example.com', c['mac'])
        self.assertEqual(result['state'], 'EXTERNAL_MATCH')
        self.assertIsNone(self.s.get_owned_record('A', c['fqdn']))

    def test_add_requires_journal(self):
        self.s.DRY_RUN=False
        with self.assertRaisesRegex(RuntimeError, 'journal'):
            self.s.add_dns_record(self.primary, 'A', self.client['fqdn'], self.client['ip'], 'clients.example.com', 'missing')

    def test_new_pair_completes_with_ownership(self):
        tx=self.reserve()
        self.run_tx(tx)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.s.db.execute('SELECT state FROM dns_pair_transactions').fetchone()[0], 'COMPLETE')
        self.assertEqual(self.s.get_owned_record('A', self.client['fqdn'])['value'], self.client['ip'])

    def test_recovery_after_a_write_before_state_commit(self):
        tx=self.reserve()
        self.records[('A',tx['a_name'])]=[tx['a_value']]
        # Reopen the actual SQLite file to simulate loss of process-local state.
        self.s.db.close()
        self.s.db=self.s.sqlite3.connect(os.environ['DB_PATH'])
        self.addCleanup(self.s.db.close)
        tx=self.s.load_pair_transactions_for_recovery()[0]
        self.run_tx(tx)
        self.assertEqual([p['type'] for _,p in self.calls], ['PTR'])
        self.assertEqual(self.s.db.execute('SELECT state FROM dns_pair_transactions').fetchone()[0], 'COMPLETE')

    def test_unexpected_dns_persists_conflict(self):
        tx=self.reserve()
        self.records[('A',tx['a_name'])]=['192.0.2.99']
        with self.assertRaises(RuntimeError):
            self.run_tx(tx)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.s.db.execute('SELECT state FROM dns_pair_transactions').fetchone()[0], 'CONFLICT')
        self.assertFalse(self.s.recover_dns_journal(self.primary))

    def test_transport_uses_verified_https(self):
        with patch.object(self.s, 'http_json', return_value={'status':'ok'}) as request:
            self.s.technitium_get('dns01.example.com', 'test', '/api/test')
        self.assertTrue(request.call_args.args[0].startswith('https://'))
        self.assertTrue(request.call_args.kwargs['ssl_context'].check_hostname)

    def test_plaintext_http_requires_explicit_opt_in(self):
        os.environ['TECHNITIUM_SCHEME']='http'
        spec=importlib.util.spec_from_file_location('invalid_config', SOURCE)
        module=importlib.util.module_from_spec(spec)
        with self.assertRaisesRegex(RuntimeError, 'Plaintext HTTP'):
            spec.loader.exec_module(module)

    def test_stale_missing_observation_never_deletes(self):
        tx=self.reserve()
        self.run_tx(tx)
        with patch.object(self.s, 'retire_owned_record') as retire:
            self.s.evaluate_stale_records(self.primary, [], True)
        retire.assert_not_called()

    def test_ownership_drift_blocks_update(self):
        tx=self.reserve()
        self.run_tx(tx)
        result=self.s.analyze_record('A', tx['a_name'], '192.0.2.11', ['192.0.2.99'], tx['a_zone'], self.client['mac'])
        self.assertEqual(result['state'], 'DRIFT')

    def test_multiple_scopes_and_overlap_rejection(self):
        scopes=[dict(name='one',subnet='192.0.2.0/24'), dict(name='two',subnet='198.51.100.0/24')]
        os.environ['SYNC_SCOPES_JSON']=json.dumps(scopes)
        self.assertEqual(len(self.s.parse_sync_scopes()),2)
        scopes[1]['subnet']='192.0.2.0/25'
        os.environ['SYNC_SCOPES_JSON']=json.dumps(scopes)
        with self.assertRaisesRegex(RuntimeError, 'overlapping'):
            self.s.parse_sync_scopes()

    def test_invalid_boolean_and_dns_suffix_rejected(self):
        os.environ['DRY_RUN']='treu'
        with self.assertRaises(RuntimeError):
            self.s.env_bool('DRY_RUN','true')
        os.environ['SYNC_SCOPES_JSON']=json.dumps([dict(name='bad',subnet='192.0.2.0/24',dns_suffix='bad/name')])
        with self.assertRaises(RuntimeError):
            self.s.parse_sync_scopes()


if __name__ == '__main__':
    unittest.main()
