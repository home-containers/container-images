"""Exercise immutable source equality with real files, modes, links and tar bytes."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.github/scripts/verify_camofox_source.py'
ROOTS = ('package.json', 'package-lock.json', 'postinstall.js', 'server.js',
         'camofox.config.json', 'lib', 'mcp', 'plugins', 'scripts')


def helper():
    spec = importlib.util.spec_from_file_location('verify_camofox_source', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'upstream'
        self.source.mkdir()
        for name in ROOTS:
            path = self.source / name
            if '.' in name:
                path.write_text('immutable ' + name)
                path.chmod(0o644)
            else:
                path.mkdir(mode=0o755)
                (path / 'source.js').write_text('export const source = 1;')
                (path / 'source.js').chmod(0o644)
        (self.source / 'scripts/tool').write_text('#!/bin/sh\ntrue\n')
        (self.source / 'scripts/tool').chmod(0o755)
        (self.source / 'lib/link.js').symlink_to('source.js')

    def archive(self, mutate=None):
        path = Path(self.temp.name) / 'app.tar'
        with tarfile.open(path, 'w') as archive:
            def filtr(info):
                return mutate(info) if mutate else info
            for name in ROOTS:
                archive.add(self.source / name, arcname='./' + name, filter=filtr)
            # Native installed dependencies/output are not immutable source.
            data = b'architecture-dependent native binary'
            info = tarfile.TarInfo('node_modules/better-sqlite3/build/Release/native.node')
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        return path

    def test_source_inventory_is_required_and_matches_real_tar(self):
        self.assertTrue(SCRIPT.is_file(), 'immutable source verifier is missing')
        helper().verify_source(self.source, self.archive())

    def test_rejects_missing_changed_source_modes_links_and_unexpected_files(self):
        self.assertTrue(SCRIPT.is_file(), 'immutable source verifier is missing')
        for target, operation in [('package-lock.json', 'missing'), ('server.js', 'content'),
                                  ('scripts/tool', 'mode'), ('lib/link.js', 'link'),
                                  ('lib/source.js', 'type')]:
            def mutate(info):
                if info.name.removeprefix('./') == target:
                    if operation == 'missing':
                        return None
                    if operation == 'content':
                        info.size = 1
                    if operation == 'mode':
                        info.mode = 0o644
                    if operation == 'link':
                        info.linkname = '/evil.js'
                    if operation == 'type':
                        info.type = tarfile.SYMTYPE
                        info.linkname = '../server.js'
                return info
            with self.subTest(target=target), self.assertRaises(ValueError):
                helper().verify_source(self.source, self.archive(mutate))
        archive = self.archive()
        with tarfile.open(archive, 'a') as out:
            out.addfile(tarfile.TarInfo('lib/injected.js'))
        with self.assertRaises(ValueError):
            helper().verify_source(self.source, archive)

    def test_rejects_unsafe_duplicate_and_special_tar_entries(self):
        for name, kind in [('../server.js', tarfile.REGTYPE), ('/server.js', tarfile.REGTYPE),
                           ('lib/source.js', tarfile.REGTYPE), ('lib/device', tarfile.CHRTYPE),
                           ('lib/hardlink', tarfile.LNKTYPE)]:
            archive = self.archive()
            with tarfile.open(archive, 'a') as out:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.linkname = 'server.js' if kind == tarfile.LNKTYPE else ''
                out.addfile(item)
            with self.subTest(name=name), self.assertRaises(ValueError):
                helper().verify_source(self.source, archive)

    def test_rejects_empty_source_trees_and_redirected_copy_roots(self):
        archive = self.archive()
        (self.source / 'mcp/source.js').unlink()
        with self.assertRaises(ValueError):
            helper().verify_source(self.source, archive)
        (self.source / 'mcp').rmdir()
        (self.source / 'mcp').symlink_to(self.source / 'lib', target_is_directory=True)
        with self.assertRaises(ValueError):
            helper().verify_source(self.source, archive)

    @staticmethod
    def known_config():
        return {'Architecture': 'arm64', 'Os': 'linux', 'Config': {
            'Entrypoint': ['docker-entrypoint.sh'],
            'Cmd': ['sh', '-c', 'node --max-old-space-size=${MAX_OLD_SPACE_SIZE:-128} server.js'],
            'User': '', 'WorkingDir': '/app', 'Volumes': None,
            'ExposedPorts': {'9377/tcp': {}},
            'Env': ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                    'NODE_VERSION=22.23.4', 'YARN_VERSION=1.22.22',
                    'NODE_ENV=production', 'CAMOFOX_PORT=9377'],
            'Labels': {'org.opencontainers.image.source': 'https://github.com/home-containers/container-images',
                       'org.opencontainers.image.revision': 'b'*40,
                       'io.camofox.upstream.revision': '39c82094013480b373df6600d44c7f036f58356e'}}}
    def test_known_startup_config_is_arch_specific_and_not_an_inherited_comparison(self):
        import copy
        config = self.known_config()
        self.assertTrue(hasattr(helper(), 'verify_config'), 'known startup contract verifier is missing')
        helper().verify_config(config, 'arm64', 'b'*40, '39c82094013480b373df6600d44c7f036f58356e')
        cases = []
        for field, bad in [('Architecture', 'amd64'), ('Os', 'windows')]:
            value = copy.deepcopy(config); value[field] = bad; cases.append(value)
        for field, bad in [('Entrypoint', []), ('Cmd', ['node', 'evil.js']),
                           ('User', 'node'), ('WorkingDir', '/'), ('Volumes', {'/app': {}}),
                           ('ExposedPorts', {}), ('Env', ['NODE_ENV=production']), ('Labels', {})]:
            value = copy.deepcopy(config); value['Config'][field] = bad; cases.append(value)
        value = copy.deepcopy(config); value['Config']['Env'].append('NODE_ENV=development'); cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                helper().verify_config(value, 'arm64', 'b'*40, '39c82094013480b373df6600d44c7f036f58356e')
        with self.assertRaises(ValueError):
            helper().verify_config(config, '', 'b'*40, '39c82094013480b373df6600d44c7f036f58356e')

    def test_cli_executes_both_real_source_and_config_checks(self):
        import json
        import subprocess
        import sys
        inspect = Path(self.temp.name) / 'inspect.json'
        inspect.write_text(json.dumps([self.known_config()]))
        command = [sys.executable, '-B', '-I', str(SCRIPT),
                   '--source', str(self.source), '--app-tar', str(self.archive()),
                   '--image-inspect', str(inspect), '--arch', 'arm64',
                   '--packaging-revision', 'b'*40,
                   '--source-revision', '39c82094013480b373df6600d44c7f036f58356e']
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(json.loads(result.stdout)['immutable_upstream_source_entries'], 0)
        (self.source / 'server.js').write_text('changed after immutable checkout')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Immutable upstream source differs', result.stderr)
        self.archive()
        config = self.known_config(); config['Architecture'] = 'amd64'
        inspect.write_text(json.dumps([config]))
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('architecture', result.stderr)

    def test_empty_or_incomplete_source_and_empty_archive_fail_closed(self):
        self.assertTrue(SCRIPT.is_file(), 'immutable source verifier is missing')
        archive = self.archive()
        (self.source / 'package-lock.json').unlink()
        with self.assertRaises(ValueError):
            helper().verify_source(self.source, archive)
        (self.source / 'package-lock.json').write_text('restored')
        with tarfile.open(archive, 'w'):
            pass
        with self.assertRaises(ValueError):
            helper().verify_source(self.source, archive)


if __name__ == '__main__':
    unittest.main()
