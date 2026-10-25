"""Execute recipe cleanup wrappers with inert package-manager stand-ins.

No network, APT installation, npm installation or container daemon is used.
Filesystem paths in the RUN instructions are redirected to a temporary sandbox.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]


def run_instructions():
    text = (HERE / 'Dockerfile').read_text()
    text = re.sub(r'(?m)^\s*#.*\n', '', text)
    return [line[4:] for line in text.replace('\\\n', ' ').splitlines()
            if line.startswith('RUN ')]


class SizeOptimizationTests(unittest.TestCase):
    def test_direct_apt_installs_skip_recommendations_but_keep_xauth(self):
        commands = [line for line in run_instructions() if 'apt-get install' in line]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertRegex(command, r'apt-get install -y --no-install-recommends\b')
        runtime = next(line for line in commands if 'libgtk-3-0' in line)
        self.assertRegex(runtime, r'\bxauth\b', 'Preserve xvfb-run authentication support explicitly')

    def test_plugin_apt_policy_is_scoped_and_preserves_failure_status(self):
        command = next(line for line in run_instructions() if 'sh scripts/install-plugin-deps.sh' in line)
        shell = shutil.which('sh')
        assert shell is not None, 'A POSIX shell is required for the recipe tests'
        for status in (0, 17):
            with self.subTest(plugin_exit=status), tempfile.TemporaryDirectory(prefix='camofox-plugin-test-') as temporary:
                root = Path(temporary)
                scripts = root / 'scripts'
                scripts.mkdir()
                (scripts / 'install-plugin-deps.sh').write_text('''#!/bin/sh
set -eu
if [ -z "${APT_CONFIG:-}" ]; then
    printf 'Missing build-only APT policy\\n' >&2
    exit 43
fi
cat "$APT_CONFIG" > "$POLICY_SEEN"
exit "$PLUGIN_EXIT"
''')
                policy = root / 'apt-no-recommends.conf'
                sandboxed = command.replace('/usr/local/share/camofox-build/apt-no-recommends.conf', str(policy))
                env = dict(os.environ, TARGETARCH='arm64', YT_DLP_SHA256_ARM64='fixture-hash',
                           POLICY_SEEN=str(root / 'policy-seen'), PLUGIN_EXIT=str(status))
                env.pop('APT_CONFIG', None)
                result = subprocess.run([shell, '-c', sandboxed], cwd=root, env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, status, result.stderr)
                seen = (root / 'policy-seen').read_text()
                self.assertIn('APT::Install-Recommends "false";', seen)
                self.assertIn('Binary::apt-get::APT::Install-Recommends "false";', seen)
                self.assertFalse(policy.exists(), 'Build-only APT configuration leaked into the final layer')

    def test_npm_download_cache_does_not_survive_its_install_layer(self):
        command = next(line for line in run_instructions() if 'npm ci' in line)
        with tempfile.TemporaryDirectory(prefix='camofox-size-test-') as temporary:
            root = Path(temporary)
            binaries = root / 'bin'
            binaries.mkdir()
            apt = binaries / 'apt-get'
            apt.write_text(f'#!{sys.executable}\nimport sys\nsys.exit(0)\n')
            apt.chmod(0o755)
            npm = binaries / 'npm'
            npm.write_text(f'#!{sys.executable}\n' + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
cache = Path(args[args.index('--cache') + 1] if '--cache' in args else os.environ['TEST_DEFAULT_CACHE'])
cache.mkdir(parents=True, exist_ok=True)
(cache / 'cached-tarball').write_bytes(b'nonsecret-test-fixture')
Path(os.environ['TEST_NPM_ARGS']).write_text(json.dumps(args))
''')
            npm.chmod(0o755)
            sandboxed = command.replace('/var/cache/camofox-npm', str(root / 'npm-cache'))
            sandboxed = sandboxed.replace('/var/lib/apt/lists/*', str(root / 'apt-lists') + '/*')
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'],
                       TEST_DEFAULT_CACHE=str(root / 'default-npm-cache'),
                       TEST_NPM_ARGS=str(root / 'npm-args.json'))
            shell = shutil.which('sh')
            assert shell is not None, 'A POSIX shell is required for the recipe tests'
            result = subprocess.run([shell, '-c', sandboxed], cwd=root,
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads((root / 'npm-args.json').read_text())
            self.assertEqual(args[:2], ['ci', '--omit=dev'])
            self.assertFalse(list(root.rglob('cached-tarball')),
                             'npm download cache remained in the installation layer')


if __name__ == '__main__':
    unittest.main()
