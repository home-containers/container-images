"""Resolve official Node and the approved Camofox source revision, without login."""
import hashlib
import json
import re
import os
import sys
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

INDEX_TYPES = {
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
}


def validate_index(body, advertised_digest, allowed_extra_architectures=()):
    """Return the content digest after checking an index and native platforms."""
    digest = 'sha256:' + hashlib.sha256(body).hexdigest()
    if not isinstance(advertised_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', advertised_digest):
        raise ValueError('Missing or invalid Docker-Content-Digest')
    if digest != advertised_digest:
        raise ValueError('Registry content does not match Docker-Content-Digest')
    value = json.loads(body)
    if (not isinstance(value, dict) or type(value.get('schemaVersion')) is not int
            or value['schemaVersion'] != 2 or value.get('mediaType') not in INDEX_TYPES):
        raise ValueError('Expected a schema-2 multiarchitecture registry index')
    manifests = value.get('manifests')
    if not isinstance(manifests, list):
        raise ValueError('Index manifests must be an array')
    seen = set()
    for item in manifests:
        if not isinstance(item, dict):
            raise ValueError('Malformed manifest descriptor')
        if item.get('mediaType') not in {
            'application/vnd.oci.image.manifest.v1+json',
            'application/vnd.docker.distribution.manifest.v2+json',
        }:
            raise ValueError('Invalid manifest descriptor mediaType')
        child_digest = item.get('digest')
        if not isinstance(child_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', child_digest):
            raise ValueError('Invalid manifest descriptor digest')
        if type(item.get('size')) is not int or item['size'] <= 0:
            raise ValueError('Invalid manifest descriptor size')
        platform = item.get('platform')
        if not isinstance(platform, dict):
            raise ValueError('Missing descriptor platform')
        os_name, arch = platform.get('os'), platform.get('architecture')
        # BuildKit provenance/SBOM attestations are not runnable platforms.
        if os_name == 'unknown' and arch == 'unknown':
            continue
        if os_name != 'linux' or arch not in ('amd64', 'arm64', *allowed_extra_architectures):
            raise ValueError('Unexpected runnable platform')
        if arch in seen:
            raise ValueError('Duplicate native platform')
        seen.add(arch)
    if seen.intersection({'amd64', 'arm64'}) != {'amd64', 'arm64'}:
        raise ValueError('Index must contain Linux AMD64 and ARM64')
    return digest


class NoRedirect(HTTPRedirectHandler):
    """Never forward an anonymous registry bearer token to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Registry redirects are not permitted')


def fetch_registry(url, headers):
    """Bounded stdlib HTTPS GET; endpoints come only from the constants below."""
    opener = build_opener(NoRedirect())
    with opener.open(Request(url, headers=headers), timeout=30) as response:
        body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise ValueError('Registry metadata exceeds size limit')
        return body, response.headers


APPROVED_SOURCE = {
    'repository': 'jo-inc/camofox-browser',
    'revision': '39c82094013480b373df6600d44c7f036f58356e',
    'release': 'v1.18.1',
}


def source_revision(policy_path=None):
    """Only the reviewed release SHA is a valid source, never a tag or URL input."""
    if policy_path is None:
        policy_path = Path(__file__).resolve().parents[2] / 'images/camofox/policy.json'
    policy = json.loads(Path(policy_path).read_text(encoding='utf-8'))
    if not isinstance(policy, dict) or policy.get('source', APPROVED_SOURCE) != APPROVED_SOURCE:
        raise ValueError('Camofox source must match the approved immutable release')
    return APPROVED_SOURCE['revision']


def resolve_inputs(fetch=fetch_registry):
    """Resolve each fixed tag once, independently of Docker or login state."""
    targets = (
        ('node_pin', 'node', 'https://auth.docker.io/token',
         'registry.docker.io', 'library/node',
         'https://registry-1.docker.io/v2/library/node/manifests/22.23.4-trixie-slim'),
    )
    pins = {'source_revision': source_revision()}
    for key, image, token_url, service, repository, manifest_url in targets:
        query = urlencode({'service': service, 'scope': f'repository:{repository}:pull'})
        token_body, _ = fetch(token_url + '?' + query, {'Accept': 'application/json'})
        token_data = json.loads(token_body)
        token = token_data.get('token') if isinstance(token_data, dict) else None
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise ValueError('Missing or invalid anonymous pull token')
        body, headers = fetch(manifest_url, {
            'Accept': ', '.join(sorted(INDEX_TYPES)),
            'Authorization': 'Bearer ' + token,
        })
        if headers.get('Content-Type', '').split(';', 1)[0].strip() not in INDEX_TYPES:
            raise ValueError('Registry response is not an index mediaType')
        # Extra official Node platforms never expand our output platforms.
        extras = ('ppc64le', 's390x')
        digest = validate_index(body, headers.get('Docker-Content-Digest'), extras)
        pins[key] = image + '@' + digest
    return pins


def emit_outputs(pins, output_file=None):
    """Emit both machine-readable logs and Actions outputs, only after resolution."""
    if output_file is not None:
        with Path(output_file).open('a', encoding='utf-8') as output:
            for key, value in pins.items():
                output.write(f'{key}={value}\n')
    print(json.dumps(pins, sort_keys=True))


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('This resolver accepts no input overrides')
    emit_outputs(resolve_inputs(), os.environ.get('GITHUB_OUTPUT'))
