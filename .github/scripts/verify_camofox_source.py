"""Check immutable upstream /app COPY inputs without trusting an image's Python.

Consume `docker cp <stopped-container>:/app/. -` as a tar, never extract it.
Compare all source trees and package-lock; installed node_modules, browser data,
and generated output outside these COPY inputs are intentionally not compared.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

COPY_ROOTS = ('package.json', 'package-lock.json', 'postinstall.js', 'server.js',
              'camofox.config.json', 'lib', 'mcp', 'plugins', 'scripts')
DIRECTORIES = {'lib', 'mcp', 'plugins', 'scripts'}


def source_inventory(source):
    """Inventory exact COPY roots, including modes and non-followed symlinks."""
    source = Path(source)
    inventory = {}

    def visit(path):
        name = path.relative_to(source).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            inventory[name] = ('link', mode, os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            inventory[name] = ('dir', mode)
            for child in sorted(path.iterdir()):
                visit(child)
        elif stat.S_ISREG(info.st_mode):
            inventory[name] = ('file', mode, hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            raise ValueError(f'Unsupported upstream source type: {name}')

    for name in COPY_ROOTS:
        path = source / name
        if not path.exists() or path.is_symlink():
            raise ValueError(f'Missing or redirected upstream COPY root: {name}')
        if path.is_dir() != (name in DIRECTORIES):
            raise ValueError(f'Wrong upstream COPY root type: {name}')
        visit(path)
        if name in DIRECTORIES and not any(key.startswith(name + '/') for key in inventory):
            raise ValueError(f'Empty upstream source tree: {name}')
    return inventory


def verify_source(source, app_tar):
    """Fail on any missing, added, changed, retargeted or chmodded source item."""
    expected = source_inventory(source)
    actual = {}
    with tarfile.open(app_tar, 'r:*') as archive:
        for item in archive:
            path = PurePosixPath(item.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError(f'Unsafe app archive name: {item.name}')
            name = path.as_posix()
            if name.split('/', 1)[0] not in COPY_ROOTS:
                continue
            if name in actual:
                raise ValueError(f'Duplicate app source item: {name}')
            mode = item.mode & 0o7777
            if item.isdir():
                actual[name] = ('dir', mode)
            elif item.issym():
                actual[name] = ('link', mode, item.linkname)
            elif item.isfile():
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError(f'Unreadable app source item: {name}')
                with stream:
                    digest = hashlib.sha256()
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                    actual[name] = ('file', mode, digest.hexdigest())
            else:
                raise ValueError(f'Unsupported app source type: {name}')
    if actual != expected:
        missing = sorted(expected.keys() - actual.keys())
        added = sorted(actual.keys() - expected.keys())
        changed = sorted(key for key in actual.keys() & expected.keys() if actual[key] != expected[key])
        raise ValueError(f'Immutable upstream source differs: missing={missing}, added={added}, changed={changed}')
    return len(expected)


def verify_config(image, arch, packaging_revision, upstream_revision):
    """Assert the known source Dockerfile/official Node startup contract."""
    if arch not in ('amd64', 'arm64') or image.get('Architecture') != arch or image.get('Os') != 'linux':
        raise ValueError('Image architecture must match the explicit native matrix architecture')
    config = image.get('Config', {})
    expected = {
        'Entrypoint': ['docker-entrypoint.sh'],
        'Cmd': ['sh', '-c', 'node --max-old-space-size=${MAX_OLD_SPACE_SIZE:-128} server.js'],
        'User': '', 'WorkingDir': '/app', 'Volumes': None,
        'ExposedPorts': {'9377/tcp': {}},
    }
    for field, value in expected.items():
        if config.get(field) != value:
            raise ValueError(f'Known startup contract differs: {field}')
    expected_env = {
        'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'NODE_VERSION=22.23.4', 'YARN_VERSION=1.22.22',
        'NODE_ENV=production', 'CAMOFOX_PORT=9377',
    }
    env = config.get('Env')
    if not isinstance(env, list) or len(env) != len(expected_env) or set(env) != expected_env:
        raise ValueError('Known environment contract differs')
    labels = config.get('Labels', {})
    expected_labels = {
        'org.opencontainers.image.source': 'https://github.com/home-containers/container-images',
        'org.opencontainers.image.revision': packaging_revision,
        'io.camofox.upstream.revision': upstream_revision,
    }
    for key, value in expected_labels.items():
        if labels.get(key) != value:
            raise ValueError(f'Image provenance label differs: {key}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--app-tar', required=True)
    parser.add_argument('--image-inspect', required=True)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--packaging-revision', required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    images = json.loads(Path(args.image_inspect).read_text(encoding='utf-8'))
    if not isinstance(images, list) or len(images) != 1:
        raise ValueError('Expected exactly one inspected image')
    verify_config(images[0], args.arch, args.packaging_revision, args.source_revision)
    count = verify_source(args.source, args.app_tar)
    print(json.dumps({'immutable_upstream_source_entries': count}))


if __name__ == '__main__':
    main()
