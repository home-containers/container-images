"""Stdlib-only acceptance-driver tests: never invoke Docker."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

PATH = Path(__file__).with_name('runtime_smoke.py')


def load():
    if not PATH.exists():
        raise AssertionError('runtime acceptance driver not implemented')
    spec = importlib.util.spec_from_file_location('runtime_smoke', PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StateTests(unittest.TestCase):
    def test_export_requires_exact_cookie_and_localstorage_on_fixture_origin(self):
        m = load()
        state = {'cookies': [{'name': m.COOKIE, 'value': m.VALUE, 'domain': 'fixture'}],
                 'origins': [{'origin': m.ORIGIN, 'localStorage': [
                     {'name': m.STORAGE, 'value': m.VALUE}]}]}
        m.validate_storage(state)
        for field in ('cookies', 'origins'):
            bad = dict(state, **{field: []})
            with self.assertRaises(m.SmokeFailure):
                m.validate_storage(bad)
        for malformed in (None, [], {'cookies': None, 'origins': []},
                          {'cookies': state['cookies'], 'origins': None}):
            with self.assertRaises(m.SmokeFailure):
                m.validate_storage(malformed)
        state['origins'][0]['origin'] = 'http://attacker:8000'
        with self.assertRaises(m.SmokeFailure):
            m.validate_storage(state)


class FixtureTests(unittest.TestCase):
    def test_check_never_writes_state_and_seed_uses_persistent_cookie(self):
        m = load()
        self.assertTrue(hasattr(m, 'fixture_page'), 'fixture renderer missing')
        check = m.fixture_page('/check').decode()
        seed = m.fixture_page('/seed').decode()
        self.assertNotIn('setItem', check)
        self.assertNotIn('document.cookie =', check)
        self.assertIn('setItem', seed)
        self.assertIn('Max-Age=', seed)
        self.assertIn(m.SENTINEL, check)
        self.assertIn(m.BROTLI_SENTINEL, m.fixture_page('/brotli').decode())

    def test_evaluation_rejects_missing_or_wrong_state_and_snapshot(self):
        m = load()
        self.assertTrue(hasattr(m, 'validate_browser'), 'browser validator missing')
        good = {'ok': True, 'result': json.dumps({'cookie': m.COOKIE + '=' + m.VALUE,
                                                'stored': m.VALUE})}
        m.validate_browser(good, {'snapshot': m.SENTINEL})
        for bad in ({}, {'ok': False, 'result': good['result']},
                    {'ok': True, 'result': '{}'}, {'ok': True, 'result': 'not json'}):
            with self.assertRaises(m.SmokeFailure):
                m.validate_browser(bad, {'snapshot': m.SENTINEL})
        with self.assertRaises(m.SmokeFailure):
            m.validate_browser(good, {'snapshot': 'STATE_MISSING'})


class ProtocolTests(unittest.TestCase):
    def test_websocket_upgrade_checks_status_headers_and_accept(self):
        m = load()
        self.assertTrue(hasattr(m, 'validate_upgrade'), 'upgrade validator missing')
        key = 'dGhlIHNhbXBsZSBub25jZQ=='
        good = (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                b'Connection: keep-alive, Upgrade\r\n'
                b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n')
        m.validate_upgrade(good, key)
        for bad in (good.replace(b'101', b'200'), good.replace(b'websocket', b'http'),
                    good.replace(b's3pPL', b'wrong'), good.replace(b'keep-alive, Upgrade', b'close')):
            with self.assertRaises(m.SmokeFailure):
                m.validate_upgrade(bad, key)

    def test_rfb_decodes_fragmented_frames_and_answers_ping_masked(self):
        import io
        m = load()
        self.assertTrue(hasattr(m, 'read_rfb'), 'RFB frame reader missing')

        class Wire:
            def __init__(self, payload):
                self.data = io.BytesIO(payload)
                self.sent = bytearray()

            def recv(self, size):
                return self.data.read(min(2, size))

            def sendall(self, data):
                self.sent.extend(data)

        wire = Wire(b'\x89\x01p\x02\x04RFB \x80\x08003.008\n')
        self.assertEqual(m.read_rfb(wire), b'RFB 003.008\n')
        self.assertEqual(wire.sent[0], 0x8a)
        self.assertTrue(wire.sent[1] & 0x80)
        for payload in (b'\x88\x00', b'\x82\x04nope', b'\x82\x80',
                        b'\x82\x7e\x00\x10short', b'\x80\x0cRFB 003.008\n'):
            with self.assertRaises(m.SmokeFailure):
                m.read_rfb(Wire(payload))
        for size, prefix in ((126, b'\x82\x7e\x00\x7e'),
                             (65536, b'\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x00')):
            self.assertEqual(m.read_rfb(Wire(prefix + b'RFB 003.008\n' + b'x' * (size - 12))),
                             b'RFB 003.008\n')


class SafetyTests(unittest.TestCase):
    def test_run_plan_inherits_entrypoint_and_user_without_secret_arguments(self):
        m = load()
        self.assertTrue(hasattr(m, 'app_arguments'), 'app launch plan missing')
        args = m.app_arguments('image:test', 'ci-test', 'ci-net', 'ci-state')
        self.assertEqual(m.APP_ENV.get('VNC_BIND'), '0.0.0.0')
        self.assertFalse(any('5900' in arg for arg in args))
        self.assertIn('--pull=never', args)
        self.assertIn('--init', args)
        self.assertIn('--shm-size=512m', args)
        self.assertNotIn('--entrypoint', args)
        self.assertNotIn('--user', args)
        self.assertIn('127.0.0.1::9377', args)
        self.assertIn('127.0.0.1::6080', args)
        self.assertIn('CAMOFOX_API_KEY', args)
        self.assertFalse(any('CAMOFOX_API_KEY=' in arg for arg in args))
        self.assertEqual(args[-1], 'image:test')

    def test_port_bindings_require_loopback_and_unambiguous_port(self):
        m = load()
        self.assertTrue(hasattr(m.Acceptance, 'ports'), 'port validator missing')

        def run_ports(payload):
            driver = m.Acceptance('image:test', 'ci')
            driver.docker = lambda *args, **kwargs: subprocess.CompletedProcess(
                ['docker'], 0, stdout=payload, stderr='')
            driver.ports()
            return driver

        dual = json.dumps({
            '9377/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '3911'},
                         {'HostIp': '::1', 'HostPort': '3911'}],
            '6080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '3980'}]})
        driver = run_ports(dual)
        self.assertEqual(driver.port, 3911)
        self.assertEqual(driver.vnc_port, 3980)
        loopback_only = json.dumps({
            '9377/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '3911'}],
            '6080/tcp': [{'HostIp': '::1', 'HostPort': '3980'}]})
        run_ports(loopback_only)
        for bad in ([{'HostIp': '0.0.0.0', 'HostPort': '1'}],
                    [{'HostIp': '::', 'HostPort': '1'}],
                    [{'HostIp': '192.168.1.5', 'HostPort': '1'}],
                    [{'HostIp': '127.0.0.1', 'HostPort': '1'},
                     {'HostIp': '127.0.0.1', 'HostPort': '2'}]):
            payload = json.dumps({'9377/tcp': bad,
                                  '6080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '2'}]})
            with self.assertRaises(m.SmokeFailure):
                run_ports(payload)
        with self.assertRaises((m.SmokeFailure, ValueError, KeyError, TypeError)):
            run_ports(json.dumps({'9377/tcp': None,
                                  '6080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '2'}]}))

    def test_container_state_and_redaction_fail_closed(self):
        m = load()
        self.assertTrue(hasattr(m, 'validate_container_state'), 'container state validator missing')
        m.validate_container_state({'Running': True, 'OOMKilled': False}, running=True)
        m.validate_container_state({'Running': False, 'OOMKilled': False, 'ExitCode': 143}, running=False)
        for state in ({'Running': False, 'OOMKilled': False, 'ExitCode': 0},
                      {'Running': True, 'OOMKilled': True}, {}):
            with self.assertRaises(m.SmokeFailure):
                m.validate_container_state(state, running=True)
        for code in (1, 137):
            with self.assertRaises(m.SmokeFailure):
                m.validate_container_state({'Running': False, 'OOMKilled': False, 'ExitCode': code}, running=False)
        self.assertTrue(hasattr(m, 'redact'), 'log redaction missing')
        self.assertNotIn('a-secret', m.redact('key=a-secret Bearer token', ['a-secret']))
        self.assertNotIn('token', m.redact('Authorization: Bearer token', []))

    def test_cleanup_verification_requires_explicit_missing_resource(self):
        m = load()
        self.assertTrue(hasattr(m, 'validate_absent'), 'cleanup readback validator missing')
        m.validate_absent(1, 'Error: No such container: smoke-app')
        m.validate_absent(1, 'Error response from daemon: network smoke-net not found')
        for code, error in ((0, ''), (1, 'Cannot connect to Docker daemon'), (1, 'permission denied')):
            with self.assertRaises(m.SmokeFailure):
                m.validate_absent(code, error)

    def test_suffix_rejects_shell_and_docker_name_escape(self):
        m = load()
        self.assertTrue(hasattr(m, 'safe_suffix'), 'suffix validation missing')
        self.assertEqual(m.safe_suffix('ci-123'), 'ci-123')
        for value in ('', '-bad', 'UPPER', '../state', 'x y', 'a' * 41):
            with self.assertRaises(Exception):
                m.safe_suffix(value)


if __name__ == '__main__':
    unittest.main()
