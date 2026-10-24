"""Offline resolver and CI policy tests; never invoke Docker or registry HTTP."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.github/scripts/resolve_camofox_inputs.py'


def resolver():
    spec = importlib.util.spec_from_file_location('resolve_camofox_inputs', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def index():
    return {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
            'manifests': [
                {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                 'digest': 'sha256:' + char * 64, 'size': 123,
                 'platform': {'os': 'linux', 'architecture': arch}}
                for arch, char in [('amd64', 'a'), ('arm64', 'b')]]}


def encoded(value):
    body = json.dumps(value).encode()
    return body, 'sha256:' + hashlib.sha256(body).hexdigest()


class ResolverTests(unittest.TestCase):
    def test_valid_index_and_explicit_unknown_attestation(self):
        value = index()
        value['manifests'].append({
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'digest': 'sha256:' + 'c' * 64, 'size': 123,
            'platform': {'os': 'unknown', 'architecture': 'unknown'}})
        body, digest = encoded(value)
        self.assertEqual(resolver().validate_index(body, digest), digest)
        value['mediaType'] = 'application/vnd.docker.distribution.manifest.list.v2+json'
        body, digest = encoded(value)
        self.assertEqual(resolver().validate_index(body, digest), digest)

    def test_rejects_missing_duplicate_and_unexpected_platforms(self):
        cases = []
        value = index(); value['manifests'].pop(); cases.append(value)
        value = index(); value['manifests'].append(copy.deepcopy(value['manifests'][0])); cases.append(value)
        for platform in ({}, {'os': 'linux', 'architecture': '386'},
                         {'os': 'unknown', 'architecture': 'amd64'}, None, 'linux/arm64'):
            value = index(); value['manifests'][0]['platform'] = platform; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolver().validate_index(*encoded(value))

    def test_rejects_malformed_indexes_and_descriptors(self):
        cases = [None, [], {}, {'schemaVersion': 2, 'mediaType': 'text/plain'}]
        for field, bad in [('schemaVersion', 1), ('schemaVersion', True),
                           ('mediaType', 'application/vnd.oci.image.manifest.v1+json'),
                           ('manifests', None), ('manifests', {})]:
            value = index(); value[field] = bad; cases.append(value)
        for field, bad in [('digest', 'sha256:bad'), ('digest', 'sha512:' + 'a'*64),
                           ('digest', 'sha256:' + 'A'*64), ('digest', None),
                           ('mediaType', 'text/plain'), ('size', 0), ('size', True),
                           ('size', '123')]:
            value = index(); value['manifests'][0][field] = bad; cases.append(value)
        for bad in [None, 'bad', [], {}]:
            value = index(); value['manifests'][0] = bad; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolver().validate_index(*encoded(value))
        value = index()
        value['manifests'].append({'platform': {'os': 'unknown', 'architecture': 'unknown'}})
        with self.assertRaises(ValueError):
            resolver().validate_index(*encoded(value))

    def test_requires_computed_digest_to_match_header(self):
        body, digest = encoded(index())
        for bad in [None, '', 'sha256:bad', 'sha256:' + '0'*64, digest.upper()]:
            with self.subTest(header=bad), self.assertRaises(ValueError):
                resolver().validate_index(body, bad)
        for body in [b'not json', b'{}\xff']:
            with self.assertRaises(ValueError):
                resolver().validate_index(body, digest)

    def test_fetch_rejects_redirects_oversized_and_unreadable_responses(self):
        module = resolver()

        class FakeResponse:
            def __init__(self, chunks, headers=None):
                self._chunks = list(chunks)
                self.headers = headers or {}

            def read(self, limit):
                return self._chunks.pop(0) if self._chunks else b''

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        opener_calls = []
        responses = []
        original_opener, original_request = module.build_opener, module.Request

        class FakeOpener:
            def __init__(self, handler):
                self.handler = handler

            def open(self, request, timeout):
                opener_calls.append((request.full_url, type(self.handler).__name__))
                if request.full_url.endswith('/moved'):
                    self.handler.redirect_request(None, None, 301, 'moved',
                                                  {}, 'http://evil.example/v2/target')
                    raise AssertionError('redirect must raise')
                return responses.pop(0)

        try:
            responses.append(FakeResponse([b'x' * (4 * 1024 * 1024 + 1)]))
            module.build_opener = FakeOpener
            module.Request = lambda url, headers=None: type('R', (), {'full_url': url})()
            with self.assertRaises(ValueError):
                module.fetch_registry('https://ghcr.io/v2/x/manifests/oversized', {})
            self.assertEqual(opener_calls[-1][1], 'NoRedirect')
            responses.append(FakeResponse([b'x' * 1024, b'y' * 2048]))
            body, _ = module.fetch_registry('https://ghcr.io/v2/x/manifests/ok', {})
            # A single read(limit) is the documented contract; chunked streams
            # beyond the first block are the caller's concern, not the resolver's.
            self.assertEqual(body, b'x' * 1024)
            # A redirect away from the pinned registry hosts is refused outright.
            responses.append(FakeResponse([]))
            with self.assertRaises(ValueError):
                module.fetch_registry('https://ghcr.io/v2/x/manifests/moved', {})
            self.assertEqual(opener_calls[-1][0].endswith('/moved'), True)
            self.assertEqual(opener_calls[-1][1], 'NoRedirect')
        finally:
            module.build_opener = original_opener
            module.Request = original_request

    def test_resolves_fixed_latest_and_node_once_without_credentials(self):
        calls = []
        body, digest = encoded(index())

        def fetch(url, headers):
            calls.append((url, headers))
            if '/token?' in url:
                self.assertNotIn('Authorization', headers)
                return b'{"token":"anonymous-pull-token"}', {}
            self.assertEqual(headers['Authorization'], 'Bearer anonymous-pull-token')
            return body, {'Docker-Content-Digest': digest,
                          'Content-Type': 'application/vnd.oci.image.index.v1+json'}

        result = resolver().resolve_inputs(fetch)
        self.assertEqual(result, {
            'base_pin': 'ghcr.io/jo-inc/camofox-browser@' + digest,
            'node_pin': 'node@' + digest})
        self.assertEqual([url for url, _ in calls], [
            'https://ghcr.io/token?service=ghcr.io&scope=repository%3Ajo-inc%2Fcamofox-browser%3Apull',
            'https://ghcr.io/v2/jo-inc/camofox-browser/manifests/latest',
            'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fnode%3Apull',
            'https://registry-1.docker.io/v2/library/node/manifests/22.23.4-trixie-slim'])

    def test_node_donor_accepts_its_additional_official_linux_architectures(self):
        base_body, base_digest = encoded(index())
        node_index = index()
        for arch, char in [('ppc64le', 'c'), ('s390x', 'd')]:
            node_index['manifests'].append({
                'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'digest': 'sha256:' + char * 64, 'size': 123,
                'platform': {'os': 'linux', 'architecture': arch}})
        node_body, node_digest = encoded(node_index)

        def fetch(url, headers):
            if '/token?' in url:
                return b'{"token":"anonymous"}', {}
            body, digest = ((node_body, node_digest) if 'registry-1.docker.io' in url
                            else (base_body, base_digest))
            return body, {'Docker-Content-Digest': digest,
                          'Content-Type': 'application/vnd.oci.image.index.v1+json'}

        try:
            result = resolver().resolve_inputs(fetch)
        except ValueError as error:
            self.fail(f'Official Node multiarchitecture index was rejected: {error}')
        self.assertEqual(result['node_pin'], 'node@' + node_digest)
        # The Camofox publisher is still restricted to the requested platforms.
        with self.assertRaises(ValueError):
            resolver().validate_index(node_body, node_digest)

    def test_resolution_rejects_missing_tokens_and_wrong_response_media_type(self):
        module = resolver()
        for token_body in [b'{}', b'{"token":null}', b'{"token":""}', b'{"token":123}']:
            with self.subTest(token=token_body), self.assertRaises(ValueError):
                module.resolve_inputs(lambda url, headers: (token_body, {}))
        body, digest = encoded(index())
        def fetch(url, headers):
            if '/token?' in url:
                return b'{"token":"anonymous"}', {}
            return body, {'Docker-Content-Digest': digest, 'Content-Type': 'text/plain'}
        with self.assertRaises(ValueError):
            module.resolve_inputs(fetch)

    def test_writes_github_outputs_and_json_without_environment_mutation(self):
        import contextlib
        import io
        import tempfile
        pins = {'base_pin': 'ghcr.io/jo-inc/camofox-browser@sha256:' + 'a'*64,
                'node_pin': 'node@sha256:' + 'b'*64}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'output'
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                resolver().emit_outputs(pins, target)
            self.assertEqual(json.loads(stdout.getvalue()), pins)
            self.assertEqual(target.read_text(), ''.join(f'{key}={value}\n' for key, value in pins.items()))


class WorkflowTests(unittest.TestCase):
    def test_shared_acceptance_is_the_only_native_build_path(self):
        action = (ROOT / '.github/actions/camofox-accept/action.yml').read_text()
        for name in ('verify', 'publish'):
            text = (ROOT / f'.github/workflows/camofox-{name}.yml').read_text()
            self.assertEqual(text.count('uses: ./.github/actions/camofox-accept'), 1)
            self.assertNotIn('docker build --', text)
            self.assertIn('needs: resolve', text)
            self.assertIn('BASE_PIN: ${{ needs.resolve.outputs.base_pin }}', text)
            self.assertIn('NODE_PIN: ${{ needs.resolve.outputs.node_pin }}', text)
            self.assertIn('TEST_IMAGE: camofox-security-overlay:ci', text)
        for required in ('python3 -I -m unittest discover -s images/camofox/tests',
                         '--build-arg BASE_IMAGE="$BASE_PIN"', '--build-arg NODE_IMAGE="$NODE_PIN"',
                         '--no-cache --progress=plain', 'org.opencontainers.image.source=',
                         'org.opencontainers.image.revision="$GITHUB_SHA"', '--compare-snapshots',
                         '"Architecture"', '"Entrypoint"', '"Cmd"', '"User"', '"WorkingDir"',
                         '"Volumes"', '"Env"', '"ExposedPorts"',
                         '/usr/local/share/camofox-overlay/verify_image.py',
                         'python3 images/camofox/tests/runtime_smoke.py --image "$TEST_IMAGE"'):
            self.assertIn(required, action)
        self.assertNotIn('continue-on-error', action)

    def test_manual_readonly_native_and_publish_guards(self):
        import re
        checkout = 'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09'
        guard = "github.repository == 'home-containers/container-images' && github.ref == 'refs/heads/main'"
        for name in ('verify', 'publish'):
            text = (ROOT / f'.github/workflows/camofox-{name}.yml').read_text()
            self.assertIn('on:\n  workflow_dispatch:\n', text)
            for forbidden in ('schedule:', 'pull_request:', 'push:', 'continue-on-error'):
                self.assertNotIn(forbidden, text)
            self.assertIn('permissions:\n  contents: read\n', text)
            self.assertIn('fail-fast: false', text)
            self.assertIn('runner: ubuntu-24.04-arm', text)
            self.assertIn('runner: ubuntu-24.04\n', text)
            self.assertIn('timeout-minutes: 45', text)
            self.assertEqual(text.count('persist-credentials: false'), text.count(checkout))
            self.assertEqual(text.count('uses: actions/checkout@'), text.count(checkout))
            jobs = re.findall(r'^  ([a-z]+):$', text, re.M)
            self.assertEqual(set(jobs), {'resolve', 'native', 'index'} if name == 'publish' else {'resolve', 'native'})
            if name == 'publish':
                self.assertEqual(text.count('if: ' + guard), len(jobs))
                self.assertEqual(text.count('packages: write'), 2)
                self.assertIn('needs: native', text)
                self.assertIn('verify_hermes_index.py', text)
                self.assertIn('test "$stable_digest" = "$digest"', text)
                self.assertLess(text.index('uses: ./.github/actions/camofox-accept'), text.index('docker login'))
                self.assertEqual(text.count('if: always()'), 2)
                self.assertEqual(text.count('docker logout ghcr.io'), 2)
                self.assertIn('REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}', text)
                self.assertIn('--password-stdin', text)
                self.assertIn('build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}', text)
                self.assertIn('test "$(docker image inspect "$tag" --format', text)
            else:
                self.assertNotIn('packages:', text)
                self.assertNotIn('GITHUB_TOKEN', text)
            self.assertEqual(text.count('python3 -I .github/scripts/resolve_camofox_inputs.py'), 1)
            self.assertIn('base_pin: ${{ steps.inputs.outputs.base_pin }}', text)
            self.assertIn('node_pin: ${{ steps.inputs.outputs.node_pin }}', text)


if __name__ == '__main__':
    unittest.main()
