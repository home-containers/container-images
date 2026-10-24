"""Local, stdlib-only tests. No containers or network access required."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]


def load(name="build_overlay", path=None):
    spec = importlib.util.spec_from_file_location(name, path or HERE / "build_overlay.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SnapshotTests(unittest.TestCase):
    def fixture(self, root):
        for name in ("server.js", "package.json", "package-lock.json", "lib/a.js",
                     "plugins/a.js", "mcp/a.js", "scripts/a.sh",
                     "node_modules/better-sqlite3/build/Release/better_sqlite3.node",
                     "node_modules/better-sqlite3/package.json", "node_modules/other/index.js"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        (root / "node_modules/.bin").mkdir()
        (root / "node_modules/.bin/tool").symlink_to("../other/index.js")

    def test_snapshot_cli_stdin_and_compare_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app"
            self.fixture(app)
            source = (HERE / "build_overlay.py").read_text()
            result = subprocess.run([sys.executable, "-B", "-I", "-S", "-", "--snapshot-only", "--app-root", str(app)],
                                    input=source, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.strip(), "snapshot CLI not implemented")
            data = json.loads(result.stdout)
            a, b = root / "base.json", root / "derived.json"
            a.write_text(json.dumps(data))
            b.write_text(json.dumps(data))
            args = [sys.executable, "-B", str(HERE / "build_overlay.py"), "--compare-snapshots", str(a), str(b)]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            data["entries"]["node_modules/other/index.js"]["mode"] ^= 0o111
            b.write_text(json.dumps(data))
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 1)

    def test_snapshot_rejects_empty_category_files(self):
        helper = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / "lib/a.js").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "coverage"):
                helper.snapshot(root)

    def test_inventory_and_compare_detect_every_mutation(self):
        self.assertTrue((HERE / "build_overlay.py").exists(), "snapshot helper not implemented")
        helper = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            baseline = helper.snapshot(root)
            self.assertEqual(helper.compare_snapshots(baseline, baseline), [])
            for path, field, value in (("node_modules/other/index.js", "sha256", "changed"),
                                       ("scripts/a.sh", "mode", 0),
                                       ("node_modules/.bin/tool", "target", "elsewhere")):
                changed = copy.deepcopy(baseline)
                changed["entries"][path][field] = value
                self.assertTrue(helper.compare_snapshots(baseline, changed), (path, field))
            changed = copy.deepcopy(baseline)
            del changed["entries"]["node_modules/other/index.js"]
            self.assertTrue(helper.compare_snapshots(baseline, changed))
            changed = copy.deepcopy(baseline)
            changed["entries"]["new"] = {"type": "file", "mode": 420, "sha256": "a"}
            self.assertTrue(helper.compare_snapshots(baseline, changed))
            (root / "mcp/a.js").unlink()
            with self.assertRaisesRegex(ValueError, "coverage"):
                helper.snapshot(root)
            with self.assertRaisesRegex(ValueError, "coverage"):
                helper.compare_snapshots({"entries": {}}, {"entries": {}})


class NodeTests(unittest.TestCase):
    def test_node_override_changes_only_target_and_checks_candidate_before_copy(self):
        helper = load()
        self.assertTrue(hasattr(helper, "install_node"), "Node binary override not implemented")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate, target, unrelated = root / "candidate", root / "node", root / "npm"
            candidate.write_bytes(b"candidate-binary")
            target.write_bytes(b"upstream-binary")
            unrelated.write_bytes(b"inherited-npm")
            target.chmod(0o755)
            def patched(path):
                return {"version": "22.23.4", "marker": -17}
            record = helper.install_node(candidate, target, "22.23.4", patched)
            self.assertEqual(record["action"], "keep")
            self.assertEqual(target.read_bytes(), b"upstream-binary")
            def older(path):
                return {"version": "22.22.0" if path == target else "22.23.4", "marker": -17}
            record = helper.install_node(candidate, target, "22.23.4", older)
            self.assertEqual(record["action"], "replace")
            self.assertEqual(target.read_bytes(), b"candidate-binary")
            self.assertEqual(unrelated.read_bytes(), b"inherited-npm")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(ValueError):
                helper.select_node({"version": "22.24.0", "marker": None},
                                   {"version": "22.23.4", "marker": -17}, "22.23.4")

    def test_select_node_retains_newer_and_rejects_wrong_major_or_marker(self):
        helper = load()
        self.assertTrue(hasattr(helper, "select_node"), "Node selection not implemented")
        info = lambda v, marker=-17: {"version": v, "marker": marker}
        self.assertEqual(helper.select_node(info("22.24.0"), info("22.23.4"), "22.23.4"), "keep")
        self.assertEqual(helper.select_node(info("22.22.0", None), info("22.23.4"), "22.23.4"), "replace")
        self.assertEqual(helper.select_node(info("22.23.4", None), info("22.23.4"), "22.23.4"), "replace")
        for current, candidate in ((info("24.0.0"), info("22.23.4")),
                                   (info("22.20.0"), info("22.23.3")),
                                   (info("22.20.0"), info("22.23.4", None))):
            with self.assertRaises(ValueError):
                helper.select_node(current, candidate, "22.23.4")


class BrowserTests(unittest.TestCase):
    def policy(self):
        return {"node_minimum": "22.23.4", "python_package_minimum": "3.13.5-2+deb13u5",
                "brotli_package_minimum": "1.1.0-2+deb13u1", "browser": {
                    "version": "152.0.4", "release": "beta.30", "artifacts": {
                        arch: {"url": "https://github.com/daijro/camoufox/releases/download/v152.0.4-beta.30/"
                                      + "camoufox-152.0.4-beta.30-lin." + cpu + ".zip", "sha256": "a" * 64}
                        for arch, cpu in (("amd64", "x86_64"), ("arm64", "arm64"))}}}

    def test_hash_precedes_safe_archive_extraction(self):
        import hashlib
        import stat
        import zipfile
        helper = load()
        self.assertTrue(hasattr(helper, "extract_browser"), "safe extraction not implemented")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "browser.zip"
            def make(extra=None):
                with zipfile.ZipFile(archive, "w") as z:
                    for name, content in (("camoufox-bin", b"binary"), ("libxul.so", b"library")):
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | 0o755) << 16
                        z.writestr(info, content)
                    if extra:
                        z.writestr(*extra)
                return hashlib.sha256(archive.read_bytes()).hexdigest()
            digest = make()
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                helper.extract_browser(archive, root / "bad-hash", "0" * 64)
            self.assertFalse((root / "bad-hash").exists())
            helper.extract_browser(archive, root / "good", digest)
            self.assertEqual((root / "good/camoufox-bin").stat().st_mode & 0o777, 0o755)
            for name in ("../escape", "/absolute", "foo/../../escape", "foo\\escape", "camoufox-bin/child"):
                digest = make((name, b"bad"))
                with self.assertRaises(ValueError):
                    helper.extract_browser(archive, root / "bad-path", digest)
                self.assertFalse((root / "bad-path").exists())
            for kind in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO):
                info = zipfile.ZipInfo("evil")
                info.create_system = 3
                info.external_attr = (kind | 0o777) << 16
                digest = make((info, b"../escape"))
                with self.assertRaises(ValueError):
                    helper.extract_browser(archive, root / "bad-special", digest)

    def test_browser_install_and_retain_verified_newer(self):
        import errno as errno_module
        import hashlib
        import stat
        import zipfile
        helper = load()
        self.assertTrue(hasattr(helper, "install_browser"), "browser installation not implemented")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as z:
                for name, content in (("camoufox-bin", b"binary"),
                                      ("libxul.so", b"binary_ERROR_FORMAT_BLOCK_SWITCH"),
                                      ("version.json", json.dumps({"version": "152.0.4", "release": "beta.30"}).encode())):
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (stat.S_IFREG | 0o755) << 16
                    z.writestr(info, content)
            policy = self.policy()
            policy["browser"]["artifacts"]["amd64"]["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            target = root / "camoufox"
            policy["browser"]["artifacts"]["amd64"]["mirror_url"] = "https://github.com/jo-inc/camofox-browser/releases/download/camoufox-backup-380139564/" + archive.name.replace("source.zip", "camoufox-152.0.4-beta.30-lin.x86_64.zip")
            requests = []
            def fetch(url, output):
                import urllib.error
                requests.append(url)
                if len(requests) == 1:
                    output.write_bytes(b"partial failed download")
                    raise urllib.error.URLError("fixture primary unavailable")
                output.write_bytes(archive.read_bytes())
            record = helper.install_browser(policy, target, "amd64", fetch)
            self.assertEqual(len(requests), 2)
            self.assertEqual(record["action"], "replace")
            self.assertEqual(record["release"], "beta.30")
            # Replacing an inherited lower-layer directory can raise EXDEV on
            # overlayfs; the helper must remove the already-validated directory
            # instead of failing or masking other rename errors.
            (target / "version.json").write_text(json.dumps({"version": "152.0.4", "release": "beta.1"}))
            exdev = OSError(errno_module.EXDEV, "Invalid cross-device link")
            helper_path, original_rmtree = helper.Path, helper.shutil.rmtree
            original_rename = helper_path.rename
            class LowerLayerPath(helper_path):
                def rename(self, destination, *, _expected=target, _error=exdev):
                    if self == _expected:
                        raise _error
                    return original_rename(self, destination)
            def remove(path, **kwargs):
                return original_rmtree(path, **kwargs)
            try:
                helper.Path = LowerLayerPath
                helper.shutil.rmtree = remove
                record = helper.install_browser(policy, target, "amd64", fetch)
                self.assertEqual(record["action"], "replace")
            finally:
                helper.Path = helper_path
                helper.shutil.rmtree = original_rmtree
            (target / "version.json").write_text(json.dumps({"version": "153.0.0", "release": "beta.1"}))
            def forbidden(*args):
                self.fail("must not download/downgrade newer verified browser")
            self.assertEqual(helper.install_browser(policy, target, "amd64", forbidden)["action"], "keep")
            (target / "libxul.so").write_bytes(b"no marker")
            with self.assertRaisesRegex(ValueError, "newer"):
                helper.install_browser(policy, target, "amd64", forbidden)

    def test_mirror_fallback_is_exact_release_and_same_hash(self):
        import urllib.error
        helper = load()
        policy = self.policy()
        for arch, artifact in policy["browser"]["artifacts"].items():
            artifact["mirror_url"] = artifact["url"].replace("daijro/camoufox", "jo-inc/camofox-browser").replace("v152.0.4-beta.30/", "camoufox-backup-380139564/")
        helper.validate_policy(policy)
        changed = copy.deepcopy(policy)
        changed["browser"]["artifacts"]["amd64"]["mirror_url"] = policy["browser"]["artifacts"]["amd64"]["mirror_url"].replace("380139564", "404310733")
        with self.assertRaises(ValueError):
            helper.validate_policy(changed)

    def test_policy_validates_provenance_and_release_comparison(self):
        helper = load()
        self.assertTrue(hasattr(helper, "validate_policy"), "policy validation not implemented")
        policy = self.policy()
        helper.validate_policy(policy)
        for url in ("http://github.com/jo-inc/camoufox/releases/download/v152.0.4-beta.30/a.zip",
                    "https://github.com.evil.test/jo-inc/camoufox/releases/download/v152.0.4-beta.30/a.zip",
                    "https://github.com/evil/camoufox/releases/download/v152.0.4-beta.30/a.zip",
                    policy["browser"]["artifacts"]["amd64"]["url"] + "?evil=1"):
            changed = copy.deepcopy(policy)
            changed["browser"]["artifacts"]["amd64"]["url"] = url
            with self.assertRaises(ValueError):
                helper.validate_policy(changed)
        changed = copy.deepcopy(policy)
        changed["browser"]["artifacts"]["amd64"]["sha256"] = "not-a-hash"
        with self.assertRaises(ValueError):
            helper.validate_policy(changed)
        self.assertLess(helper.browser_version({"version": "152.0.4", "release": "beta.28"}),
                        helper.browser_version(policy["browser"]))
        self.assertGreater(helper.browser_version({"version": "153.0.0", "release": "beta.1"}),
                           helper.browser_version(policy["browser"]))
        with self.assertRaises(ValueError):
            helper.browser_version({"version": "152.0.4", "release": "nightly"})


class VerifierTests(unittest.TestCase):
    def verifier(self):
        self.assertTrue((HERE / "tests/verify_image.py").exists(), "security verifier not implemented")
        return load("verify_image", HERE / "tests/verify_image.py")

    def test_metadata_gate_precedes_import_and_rejects_unknown_bindings(self):
        verifier = self.verifier()
        verifier.validate_bindings([])
        verifier.validate_bindings([{"name": "Brotli", "version": "1.2.1"},
                                    {"name": "brotlicffi", "version": "1.2.1.0"}])
        for row in ({"name": "Brotli", "version": "1.2.0"},
                    {"name": "brotlicffi", "version": "1.2.0.2"},
                    {"name": "brotlipy", "version": "0.7.0"},
                    {"name": "brotli", "version": "1.2.1rc1"}):
            with self.assertRaisesRegex(ValueError, "ownership-aware"):
                verifier.validate_bindings([row])
        # A real metadata-only scan must not execute module or site startup code.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "brotli.py").write_text("raise RuntimeError('MUST NOT IMPORT')")
            meta = root / "brotli-1.2.0.dist-info"
            meta.mkdir()
            (meta / "METADATA").write_text("Name: Brotli\nVersion: 1.2.0\n")
            rows = verifier.metadata_inventory([root])
            self.assertEqual(rows[0]["name"], "Brotli")
            with self.assertRaises(ValueError):
                verifier.validate_bindings(rows)

    def test_isolated_inventory_finds_venv_metadata_without_site_startup(self):
        import venv
        verifier = self.verifier()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv.EnvBuilder(with_pip=False, symlinks=True).create(root)
            site = next((root / "lib").glob("python*/site-packages"))
            meta = site / "brotli-1.2.0.dist-info"
            meta.mkdir()
            (meta / "METADATA").write_text("Name: Brotli\nVersion: 1.2.0\n")
            (site / "sitecustomize.py").write_text("raise RuntimeError('startup must not execute')")
            info = verifier.python_inventory(root / "bin/python3")
            self.assertTrue(any(row["name"] == "Brotli" for row in info["distributions"]),
                            "-S inventory missed venv binding metadata")
            from unittest.mock import patch
            with patch.object(verifier.sys, "executable", str(root / "bin/python3")), \
                 patch.object(verifier.sys, "prefix", sys.base_prefix):
                self.assertIn(str(site), verifier.python_site_paths(),
                              "Python <=3.13 with -S needs explicit pyvenv.cfg discovery")

    def test_python_inventory_subprocess_and_runtime_programs(self):
        verifier = self.verifier()
        self.assertTrue(hasattr(verifier, "python_inventory"), "isolated Python inventory not implemented")
        info = verifier.python_inventory(sys.executable)
        self.assertEqual(info["runtime_version"].split(".")[:2], list(map(str, sys.version_info[:2])))
        self.assertIsInstance(info["distributions"], list)
        self.assertIn("sysconfig", info)
        self.assertIn("BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH", verifier.NODE_CHECK)
        self.assertIn("better-sqlite3", verifier.SQLITE_CHECK)
        self.assertIn(":memory:", verifier.SQLITE_CHECK)

    def test_distro_python_package_set_is_consistent_and_backported(self):
        verifier = self.verifier()
        self.assertTrue(hasattr(verifier, "validate_package_set"), "package set check not implemented")
        policy = BrowserTests().policy()
        packages = {name: "3.13.5-2+deb13u5" for name in (
            "python3.13", "python3.13-minimal", "libpython3.13-stdlib", "libpython3.13-minimal")}
        packages["libbrotli1"] = "1.1.0-2+deb13u1"
        verifier.validate_package_set(policy, packages, "3.13.5")
        for name, value in (("python3.13-minimal", "3.13.5-2+deb13u4"),
                            ("libpython3.13-stdlib", "3.13.5-2+deb13u6"),
                            ("libbrotli1", "1.1.0-2")):
            changed = dict(packages, **{name: value})
            with self.assertRaises(ValueError):
                verifier.validate_package_set(policy, changed, "3.13.5")
        with self.assertRaisesRegex(ValueError, "runtime"):
            verifier.validate_package_set(policy, packages, "3.13.4")

    def test_full_verifier_gates_all_metadata_before_extensions_and_checks_evidence(self):
        from unittest.mock import patch
        verifier = self.verifier()
        self.assertTrue(hasattr(verifier, "verify"), "image verification orchestration not implemented")
        policy = BrowserTests().policy()
        packages = {name: "3.13.5-2+deb13u5" for name in (
            "python3.13", "python3.13-minimal", "libpython3.13-stdlib", "libpython3.13-minimal")}
        packages["libbrotli1"] = "1.1.0-2+deb13u1"
        inventory = {"executable": "/usr/bin/python3", "runtime_version": "3.13.5",
                     "distributions": [], "binding_module_paths": [], "sites": []}
        browser = {"version": "152.0.4", "release": "beta.30", "hashes": {"libxul.so": "fixture"}}
        helper = load()
        with patch.object(verifier, "distro_info", return_value={"ID": "debian", "VERSION_CODENAME": "trixie"}), \
             patch.object(verifier, "installed_packages", return_value=packages), \
             patch.object(verifier, "discover_interpreters", return_value=["/usr/bin/python3"]), \
             patch.object(verifier, "python_inventory", return_value=inventory), \
             patch.object(verifier, "system_brotli_marker", return_value=b"_ERROR_FORMAT_BLOCK_SWITCH"), \
             patch.object(verifier, "binding_roundtrips") as roundtrip, \
             patch.object(verifier, "command", side_effect=lambda args, **kw: json.dumps({"version": "22.23.4", "marker": -17})), \
             patch.object(helper, "browser_evidence", return_value=browser), \
             patch.object(helper, "file_hash", return_value="node-hash"), \
             patch.object(verifier, "overlay_module", return_value=helper):
            result = verifier.verify(policy)
            self.assertEqual(result["node"]["version"], "22.23.4")
            self.assertEqual(roundtrip.call_count, 1)
            with self.assertRaisesRegex(ValueError, "evidence"):
                verifier.verify(policy, expected={"node": {"sha256": "wrong"}, "browser": browser})
            roundtrip.reset_mock()
            inventory["distributions"] = [{"name": "brotli", "version": "1.2.0"}]
            with self.assertRaisesRegex(ValueError, "ownership-aware"):
                verifier.verify(policy)
            roundtrip.assert_not_called()
            inventory["distributions"] = []
            inventory["executable"] = "/opt/unowned/bin/python3"
            with self.assertRaisesRegex(ValueError, "ownership-aware"):
                verifier.verify(policy)

    def test_exact_system_marker_and_package_comparison(self):
        verifier = self.verifier()
        verifier.validate_system_marker(b"_ERROR_FORMAT_BLOCK_SWITCH")
        for value in (b"ERROR_FORMAT_BLOCK_SWITCH", b"prefix_ERROR_FORMAT_BLOCK_SWITCH", None):
            with self.assertRaises(ValueError):
                verifier.validate_system_marker(value)
        self.assertTrue(verifier.debian_ge("3.13.5-2+deb13u5", "3.13.5-2+deb13u5"))
        self.assertFalse(verifier.debian_ge("3.13.5-2+deb13u4", "3.13.5-2+deb13u5"))


class ApplyTests(unittest.TestCase):
    def test_apply_keeps_app_unchanged_and_records_verified_evidence(self):
        from unittest.mock import patch
        helper = load()
        self.assertTrue(hasattr(helper, "apply_overlay"), "apply orchestration not implemented")
        verifier = load("verify_image", HERE / "tests/verify_image.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app"
            SnapshotTests().fixture(app)
            evidence = root / "evidence.json"
            with patch.object(helper.os, "geteuid", return_value=0), \
                 patch.object(helper, "image_verifier", return_value=verifier), \
                 patch.object(verifier, "distro_info", return_value={"ID": "debian", "VERSION_CODENAME": "trixie"}), \
                 patch.object(verifier, "discover_interpreters", return_value=["/usr/bin/python3"]), \
                 patch.object(verifier, "python_inventory", return_value={"distributions": [], "binding_module_paths": []}), \
                 patch.object(helper, "install_node", return_value={"sha256": "fixture"}), \
                 patch.object(helper, "install_browser", return_value={"hashes": {"libxul.so": "fixture"}}), \
                 patch.object(verifier, "verify", return_value={"verified": "test fixture"}):
                result = helper.apply_overlay(BrowserTests().policy(), root / "node-candidate", evidence, app)
                self.assertEqual(json.loads(evidence.read_text()), result)
                self.assertEqual(result["preservation"]["changed_paths"], [])
                self.assertTrue(result["preservation"]["entries"])


class PackagingTests(unittest.TestCase):
    def test_dockerfile_is_upstream_overlay_with_only_node_binary_mount(self):
        self.assertTrue((HERE / "Dockerfile").exists(), "thin Dockerfile not implemented")
        text = (HERE / "Dockerfile").read_text()
        self.assertIn("ARG BASE_IMAGE=ghcr.io/jo-inc/camofox-browser:latest", text)
        self.assertIn("ARG NODE_IMAGE=node:22.23.4-trixie-slim", text)
        self.assertIn("FROM ${BASE_IMAGE}", text)
        self.assertIn("from=node-runtime,source=/usr/local/bin/node,target=/tmp/camofox-node,ro", text)
        self.assertIn("VERSION_CODENAME", text)
        self.assertIn("apt-get upgrade", text)
        self.assertIn("--no-install-recommends", text)
        for name in ("x11vnc", "novnc", "python3-websockify", "net-tools", "procps"):
            self.assertIn(name, text)
        for line in text.splitlines():
            self.assertFalse(line.startswith(("CMD ", "ENTRYPOINT ", "ENV ", "WORKDIR ", "USER ", "VOLUME ")))
        for forbidden in ("npm ci", "npm install", "npm rebuild", "COPY --from", "git clone"):
            self.assertNotIn(forbidden, text)
        self.assertIn("tests/verify_image.py", text)
        self.assertTrue((HERE / ".dockerignore").exists(), "build context allowlist missing")
        ignore = (HERE / ".dockerignore").read_text().splitlines()
        self.assertEqual(ignore[0], "**")
        self.assertEqual({line for line in ignore if line.startswith("!")}, {
            "!Dockerfile", "!build_overlay.py", "!policy.json", "!tests/", "!tests/verify_image.py"})

    def test_apply_cli_requires_policy_and_candidate(self):
        result = subprocess.run([sys.executable, "-B", str(HERE / "build_overlay.py"), "--help"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--apply", result.stdout)
        self.assertIn("--node-candidate", result.stdout)
        self.assertIn("--policy", result.stdout)
        result = subprocess.run([sys.executable, "-B", str(HERE / "build_overlay.py"), "--apply"],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
