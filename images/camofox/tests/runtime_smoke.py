#!/usr/bin/env python3
"""Real image acceptance; stdlib-only host driver. No builds or pulls.

Run: python3 images/camofox/tests/runtime_smoke.py --image IMAGE [--suffix SAFE]
The private --fixture-server mode runs only inside the disposable fixture container.
"""
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import time

ORIGIN = 'http://fixture:8000'
COOKIE = 'overlay_cookie'
STORAGE = 'overlay-ci'
VALUE = 'overlay-persistence-v1'
USER = 'overlay-ci'
SENTINEL = 'OVERLAY_STATE_OK'
BROTLI_SENTINEL = 'OVERLAY_BROTLI_BROWSER_OK'


class SmokeFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def fixture_page(path):
    if path == '/brotli':
        return ('<!doctype html><html><body>' + BROTLI_SENTINEL + '</body></html>').encode()
    seed = ''
    if path == '/seed':
        seed = (f'document.cookie = "{COOKIE}={VALUE}; Path=/; Max-Age=86400; SameSite=Lax";'
                f'localStorage.setItem("{STORAGE}", "{VALUE}");')
    return (f'<!doctype html><html><body><p id="state">STATE_MISSING</p><script>{seed}'
            f'if(document.cookie.split("; ").includes("{COOKIE}={VALUE}") && '
            f'localStorage.getItem("{STORAGE}") === "{VALUE}") '
            f'document.getElementById("state").textContent="{SENTINEL}";'
            '</script></body></html>').encode()


def fixture_server():
    # Use the image\'s real Node Brotli encoder: no optional Python dependencies.
    compressed = subprocess.run(
        ['node', '-e', 'process.stdout.write(require("node:zlib").brotliCompressSync('
         'require("node:fs").readFileSync(0)))'], input=fixture_page('/brotli'),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True).stdout
    require(bool(compressed), 'Brotli encoder returned no bytes')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            if path not in ('/seed', '/check', '/brotli'):
                self.send_error(404)
                return
            payload = compressed if path == '/brotli' else fixture_page(path)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            if path == '/brotli':
                self.send_header('Content-Encoding', 'br')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()


def validate_browser(evaluation, snapshot):
    require(isinstance(evaluation, dict) and evaluation.get('ok') is True,
            'browser evaluation failed')
    try:
        result = json.loads(evaluation.get('result', ''))
        cookies = result.get('cookie', '').split('; ')
        valid = COOKIE + '=' + VALUE in cookies and result.get('stored') == VALUE
    except (ValueError, TypeError, AttributeError):
        valid = False
    require(valid, 'browser cookie/localStorage state missing')
    require(isinstance(snapshot, dict) and isinstance(snapshot.get('snapshot'), str)
            and SENTINEL in snapshot['snapshot'], 'browser state sentinel missing')


def validate_upgrade(headers, key):
    lines = headers.decode('iso-8859-1').split('\r\n')
    require(len(lines[0].split()) >= 2 and lines[0].split()[1] == '101',
            'noVNC did not upgrade WebSocket')
    fields = {}
    for line in lines[1:]:
        if ':' in line:
            name, value = line.split(':', 1)
            fields[name.lower()] = value.strip()
    expected = base64.b64encode(hashlib.sha1(
        (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
    require(fields.get('sec-websocket-accept') == expected,
            'invalid WebSocket accept hash')
    require(fields.get('upgrade', '').lower() == 'websocket' and
            'upgrade' in [v.strip().lower() for v in fields.get('connection', '').split(',')],
            'invalid WebSocket upgrade headers')


def receive_exact(wire, size):
    result = bytearray()
    while len(result) < size:
        chunk = wire.recv(size - len(result))
        require(bool(chunk), 'WebSocket closed before RFB banner')
        result.extend(chunk)
    return bytes(result)


def send_frame(wire, opcode, payload):
    require(len(payload) <= 125, 'oversized control frame')
    mask = secrets.token_bytes(4)
    wire.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask +
                 bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))


def read_rfb(wire):
    banner = bytearray()
    fragmented = False
    for _ in range(128):
        first, second = receive_exact(wire, 2)
        require(not first & 0x70 and not second & 0x80, 'invalid server WebSocket flags')
        opcode = first & 15
        final = bool(first & 0x80)
        length = second & 127
        if length == 126:
            length = struct.unpack('!H', receive_exact(wire, 2))[0]
        elif length == 127:
            length = struct.unpack('!Q', receive_exact(wire, 8))[0]
        require(length <= 1048576, 'oversized WebSocket frame')
        payload = receive_exact(wire, length)
        if opcode in (8, 9, 10):
            require(final and length <= 125, 'invalid WebSocket control frame')
            require(opcode != 8, 'WebSocket closed before RFB banner')
            if opcode == 9:
                send_frame(wire, 10, payload)
            continue
        require(opcode in (0, 2), 'RFB requires binary WebSocket data')
        require((opcode == 0) == fragmented, 'invalid WebSocket continuation')
        fragmented = not final
        banner.extend(payload)
        if len(banner) >= 12:
            require(re.fullmatch(rb'RFB 003\.[0-9]{3}\n', bytes(banner[:12])) is not None,
                    'no actual RFB protocol banner')
            return bytes(banner[:12])
    raise SmokeFailure('too many WebSocket frames before RFB')


def probe_vnc(port, path='/websockify'):
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    with socket.create_connection(('127.0.0.1', port), timeout=10) as wire:
        wire.settimeout(10)
        wire.sendall((f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                      'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                      f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
                      'Sec-WebSocket-Protocol: binary\r\n\r\n').encode())
        headers = bytearray()
        while not headers.endswith(b'\r\n\r\n'):
            require(len(headers) < 16384, 'oversized WebSocket handshake')
            headers.extend(receive_exact(wire, 1))
        validate_upgrade(bytes(headers), key)
        return read_rfb(wire)


def validate_storage(state):
    require(isinstance(state, dict), 'storage state must be an object')
    require(isinstance(state.get('cookies'), list) and isinstance(state.get('origins'), list),
            'storage state cookies/origins must be arrays')
    require(all(isinstance(o, dict) and isinstance(o.get('localStorage'), list)
                for o in state['origins']), 'storage state origins must contain localStorage arrays')
    def cookie_domain(cookie):
        domain = cookie.get('domain', '')
        return domain if isinstance(domain, str) else ''
    require(any(c.get('name') == COOKIE and c.get('value') == VALUE and
                cookie_domain(c).lstrip('.') == 'fixture'
                for c in state.get('cookies', []) if isinstance(c, dict)),
            'expected fixture cookie missing from storage state')
    require(any(o.get('origin') == ORIGIN and any(
        item.get('name') == STORAGE and item.get('value') == VALUE
        for item in o.get('localStorage', []) if isinstance(item, dict))
        for o in state.get('origins', []) if isinstance(o, dict)),
        'expected fixture localStorage missing from storage state')


SECRET_NAMES = ('CAMOFOX_API_KEY', 'CAMOFOX_ACCESS_KEY', 'CAMOFOX_ADMIN_KEY', 'VNC_PASSWORD')
APP_ENV = {
    'ENABLE_VNC': '1', 'VNC_BIND': '0.0.0.0', 'CAMOFOX_DISABLE_DEFAULT_ADDONS': '1',
    'CAMOFOX_CRASH_REPORT_ENABLED': 'false', 'CAMOFOX_PROFILE_DIR': '/state/profiles',
    'CAMOFOX_COOKIES_DIR': '/state/cookies', 'CAMOFOX_UPLOADS_DIR': '/state/uploads',
}


def safe_suffix(value):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', value):
        raise argparse.ArgumentTypeError('suffix must be 1-40 lowercase letters, digits or hyphens')
    return value


def app_arguments(image, name, network, volume):
    args = ['run', '-d', '--pull=never', '--name', name, '--network', network,
            '--init', '--shm-size=512m', '-p', '127.0.0.1::9377',
            '-p', '127.0.0.1::6080', '--mount', f'type=volume,src={volume},dst=/state']
    for key in SECRET_NAMES:
        args.extend(['--env', key])  # Docker reads value from subprocess environment, not argv.
    for key, value in APP_ENV.items():
        args.extend(['--env', f'{key}={value}'])
    return args + [image]  # Deliberately inherit image USER, Entrypoint and Cmd.


def validate_container_state(state, *, running):
    require(state.get('OOMKilled') is False, 'container OOM killed or missing OOM status')
    require(state.get('Running') is running, 'container unexpectedly exited or still running')
    if not running:
        require(state.get('ExitCode') in (0, 143), 'container shutdown had unexpected exit code')


def validate_absent(returncode, stderr):
    require(returncode != 0 and bool(re.search(r'no such|not found', stderr, re.IGNORECASE)),
            'Docker resource absence could not be verified')


def redact(text, values):
    for value in values:
        if value:
            text = text.replace(value, '[REDACTED]')
    return re.sub(r'(?i)Bearer\s+[^\s"\x27,}]+', 'Bearer [REDACTED]', text)


def http_request(port, method, path, *, token=None, data=None, expected=(200,)):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=45)
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if data is not None:
        headers['Content-Type'] = 'application/json'
    try:
        connection.request(method, path, body=json.dumps(data) if data is not None else None,
                           headers=headers)
        response = connection.getresponse()
        payload = response.read(4 * 1024 * 1024 + 1)
        require(response.status in expected, f'{method} {path} returned HTTP {response.status}')
        require(len(payload) <= 4 * 1024 * 1024, 'HTTP response exceeds bound')
        return payload
    finally:
        connection.close()


class Acceptance:
    def __init__(self, image, suffix):
        self.image = image
        # Always add randomness, including when caller supplies a repeatable CI suffix.
        self.prefix = 'camofox-smoke-' + suffix + '-' + secrets.token_hex(4)
        self.app = self.prefix + '-app'
        self.fixture = self.prefix + '-fixture'
        self.network = self.prefix + '-net'
        self.volume = self.prefix + '-state'
        self.keys = {key: secrets.token_hex(4 if key == 'VNC_PASSWORD' else 24)
                     for key in SECRET_NAMES}
        self.environment = dict(os.environ, **self.keys)
        self.owned = []
        self.port = None
        self.vnc_port = None

    def docker(self, *args, timeout=90, check=True):
        try:
            result = subprocess.run(['docker', *args], env=self.environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout, text=True)
        except (OSError, subprocess.TimeoutExpired) as exc:
            # Never stringify subprocess exceptions: they may include sensitive argv/env.
            raise SmokeFailure(f'Docker {args[0]} failed ({type(exc).__name__})') from None
        if check and result.returncode:
            raise SmokeFailure('Docker ' + args[0] + ' failed: ' +
                               redact(result.stderr[-4000:], self.keys.values()))
        return result

    def state(self, name, running=True):
        state = json.loads(self.docker('inspect', '--format', '{{json .State}}', name).stdout)
        validate_container_state(state, running=running)
        return state

    def live(self):
        self.state(self.fixture)
        self.state(self.app)

    def api(self, method, path, data=None):
        return json.loads(http_request(self.port, method, path,
                                      token=self.keys['CAMOFOX_ACCESS_KEY'], data=data))

    def wait(self, description, action, timeout=180):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            self.live()  # Do not mask an OOM or unexpected container exit as readiness delay.
            try:
                return action()
            except (SmokeFailure, OSError, http.client.HTTPException, ValueError) as exc:
                last = type(exc).__name__ + ': ' + str(exc)
                time.sleep(2)
        raise SmokeFailure(description + ' timed out: ' + redact(last or '', self.keys.values()))

    def ports(self):
        bindings = json.loads(self.docker('inspect', '--format',
                                         '{{json .NetworkSettings.Ports}}', self.app).stdout)
        for target in ('9377/tcp', '6080/tcp'):
            entries = bindings.get(target) or []
            # Newer Docker daemons can report one binding per address family.
            # Every entry must be loopback (IPv4 127.0.0.0/8 or IPv6 ::1) with
            # a usable port; wildcard or LAN addresses are rejected.
            require(bool(entries) and
                    all(ipaddress.ip_address(entry['HostIp']).is_loopback
                        for entry in entries),
                    'published port is not exclusively loopback')
            ports = {int(entry['HostPort']) for entry in entries}
            require(len(ports) == 1, 'published port is ambiguous across bindings')
            if target == '9377/tcp':
                self.port = ports.pop()
            else:
                self.vnc_port = ports.pop()

    def start_app(self):
        self.docker(*app_arguments(self.image, self.app, self.network, self.volume))
        self.ports()
        self.wait('public health', lambda: http_request(self.port, 'GET', '/health'))
        # Upstream versions use either global 401 or per-route 403; both deny access.
        http_request(self.port, 'POST', '/tabs', data={
            'userId': USER, 'sessionKey': 'acceptance', 'url': ORIGIN + '/check'},
            expected=(401, 403))

    def new_tab(self, path):
        response = self.api('POST', '/tabs', {
            'userId': USER, 'sessionKey': 'acceptance', 'url': ORIGIN + path})
        tab = response.get('tabId')
        require(isinstance(tab, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]+', tab)),
                'tab creation did not return a safe nonempty tabId')
        return tab

    def snapshot(self, tab):
        return self.api('GET', f'/tabs/{tab}/snapshot?userId={USER}')

    def browser_state(self, tab):
        evaluation = self.api('POST', f'/tabs/{tab}/evaluate', {
            'userId': USER, 'expression': 'JSON.stringify({cookie:document.cookie,'
            f'stored:localStorage.getItem("{STORAGE}")' + '})'})
        validate_browser(evaluation, self.snapshot(tab))
        return True

    def navigation(self, seed=False):
        tab = self.new_tab('/seed' if seed else '/check')
        self.wait('browser persisted state', lambda: self.browser_state(tab))
        self.api('POST', f'/tabs/{tab}/navigate', {'userId': USER, 'url': ORIGIN + '/check'})
        self.wait('real navigation to read-only state fixture', lambda: self.browser_state(tab))
        state = self.api('GET', f'/sessions/{USER}/storage_state')
        validate_storage(state)
        # Verify actual durable state, not merely an API export of live memory.
        persisted = self.docker('exec', self.app, 'python3', '-c',
            'import json,pathlib; p=pathlib.Path("/state/profiles"); '
            'print(json.dumps([json.loads(f.read_text()) for f in p.rglob("storage-state.json")]))')
        candidates = json.loads(persisted.stdout)
        require(bool(candidates), 'no persisted storage-state.json on mounted volume')
        matching = False
        for candidate in candidates:
            try:
                validate_storage(candidate)
                matching = True
            except SmokeFailure:
                pass
        require(matching, 'mounted volume does not contain expected cookie/localStorage')
        self.api('POST', f'/tabs/{tab}/navigate', {'userId': USER, 'url': ORIGIN + '/brotli'})
        def brotli():
            snapshot = self.snapshot(tab)
            require(BROTLI_SENTINEL in snapshot.get('snapshot', ''),
                    'browser did not decode real Brotli-compressed HTML')
            return True
        self.wait('browser Brotli decoding', brotli)
        self.wait('VNC and noVNC', self.vnc)

    def vnc(self):
        status = self.api('GET', '/vnc/status')
        require(status.get('enabled') is True and status.get('running') is True,
                'VNC plugin is not running')
        page = http_request(self.vnc_port, 'GET', '/vnc.html')
        require(b'<html' in page.lower(), 'noVNC HTML page missing')
        probe_vnc(self.vnc_port)
        return True

    def stop(self):
        self.live()
        self.docker('stop', '--time', '45', self.app)
        self.state(self.app, running=False)
        self.state(self.fixture)

    def diagnostics(self):
        for name in (self.app, self.fixture):
            for args in (('inspect', '--format', '{{json .State}}', name),
                         ('logs', '--tail', '120', name)):
                try:
                    result = self.docker(*args, check=False, timeout=20)
                    print(redact(name + ': ' + result.stdout + result.stderr,
                                 self.keys.values()), file=sys.stderr)
                except SmokeFailure:
                    print(name + ': diagnostics unavailable', file=sys.stderr)

    def reserve(self, kind, name):
        result = self.docker(kind, 'inspect', name, check=False)
        validate_absent(result.returncode, result.stderr)
        # Reserve before creation so a timeout/partially successful create is cleaned up too.
        self.owned.append((kind, name))

    def cleanup(self):
        errors = []
        for kind, name in reversed(self.owned):
            args = ('rm', '-f', name) if kind == 'container' else (kind, 'rm', name)
            try:
                result = self.docker(*args, check=False, timeout=60)
                # Read back the exact resource; a successful rm alone is not verification.
                remaining = self.docker(kind, 'inspect', name, check=False, timeout=20)
                validate_absent(remaining.returncode, remaining.stderr)
                if result.returncode:
                    validate_absent(result.returncode, result.stderr)
            except SmokeFailure as exc:
                errors.append(kind + ': ' + str(exc))
        require(not errors, 'resource cleanup failed: ' + '; '.join(errors))

    def run(self):
        failed = True
        try:
            self.docker('image', 'inspect', self.image)  # Refuse missing local images; no pulls.
            self.reserve('network', self.network)
            self.docker('network', 'create', '--internal', self.network)
            self.reserve('volume', self.volume)
            self.docker('volume', 'create', self.volume)
            self.reserve('container', self.fixture)
            self.docker('run', '-d', '--pull=never', '--name', self.fixture,
                        '--network', self.network, '--network-alias', 'fixture', '--init',
                        '--entrypoint', 'python3', '--mount',
                        f'type=bind,src={Path(__file__).resolve()},dst=/fixture.py,readonly',
                        self.image, '/fixture.py', '--fixture-server')
            self.reserve('container', self.app)
            self.start_app()
            self.navigation(seed=True)
            self.stop()
            self.docker('start', self.app)
            self.ports()
            self.wait('health after full stop/start', lambda: http_request(self.port, 'GET', '/health'))
            self.navigation()
            self.stop()
            self.docker('rm', self.app)
            self.start_app()  # New container and browser context; same volume and user.
            self.navigation()
            self.stop()
            failed = False
        except BaseException:
            self.diagnostics()
            raise
        finally:
            try:
                self.cleanup()
            except SmokeFailure:
                if not failed:
                    raise
                print('Cleanup failed; inspect disposable resources with prefix ' + self.prefix,
                      file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', help='already-built local image; never built or pulled')
    parser.add_argument('--suffix', type=safe_suffix, default='ci')
    parser.add_argument('--fixture-server', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.fixture_server:
        fixture_server()
        return 0
    if not args.image or args.image.startswith('-'):
        parser.error('--image must name an already-built local image')
    driver = Acceptance(args.image, args.suffix)
    try:
        driver.run()
    except (SmokeFailure, OSError, ValueError, http.client.HTTPException) as exc:
        print('FAIL: ' + redact(str(exc), driver.keys.values()), file=sys.stderr)
        return 1
    print('PASS: auth, real navigation, Brotli, durable cookie/localStorage across '
          'stop/start and recreation, noVNC WebSocket RFB, clean exits and cleanup')
    return 0


if __name__ == '__main__':
    sys.exit(main())