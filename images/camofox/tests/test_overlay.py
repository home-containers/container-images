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


class BrowserTests(unittest.TestCase):
    def policy(self):
        return {"source": {"repository": "jo-inc/camofox-browser",
                           "revision": "39c82094013480b373df6600d44c7f036f58356e", "release": "v1.18.1"},
                "node_minimum": "22.23.4", "python_package_minimum": "3.13.5-2+deb13u5",
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

    def test_initial_browser_install_uses_verified_mirror_and_cleans_archive(self):
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
            self.assertEqual(record["action"], "install")
            self.assertEqual(record["release"], "beta.30")
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["camoufox", "source.zip"])
            before = {path.name: path.read_bytes() for path in target.iterdir()}
            with self.assertRaisesRegex(ValueError, "must not exist"):
                helper.install_browser(policy, target, "amd64", fetch)
            self.assertEqual(len(requests), 2, "must not download over an existing browser")
            self.assertEqual(before, {path.name: path.read_bytes() for path in target.iterdir()})

    def test_bad_archive_never_installs_or_leaves_downloads_on_either_arch(self):
        helper = load()
        policy = self.policy()
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                requests = []
                def fetch(url, output):
                    requests.append(url)
                    output.write_bytes(b"not-the-approved-browser")
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    helper.install_browser(policy, root / "camoufox", arch, fetch)
                self.assertEqual(requests, [policy["browser"]["artifacts"][arch]["url"]])
                self.assertEqual(list(root.iterdir()), [])

    def test_browser_cli_requires_arch_policy_and_has_no_mutation_actions(self):
        helper = load()
        for name in ("install_node", "select_node", "apply_overlay", "snapshot", "compare_snapshots"):
            self.assertFalse(hasattr(helper, name), name)
        args = [sys.executable, "-B", "-I", "-S", str(HERE / "build_overlay.py")]
        result = subprocess.run(args + ["--help"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--install-browser", result.stdout)
        self.assertIn("--arch", result.stdout)
        self.assertNotIn("--apply", result.stdout)
        for extra in ([], ["--install-browser"], ["--apply"],
                      ["--install-browser", "--arch", "riscv64", "--policy", str(HERE / "policy.json")]):
            self.assertNotEqual(subprocess.run(args + extra, capture_output=True).returncode, 0)

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

    def test_source_policy_requires_pinned_upstream_provenance(self):
        helper = load()
        policy = json.loads((HERE / "policy.json").read_text())
        self.assertEqual(policy.get("source"), self.policy()["source"])
        helper.validate_policy(policy)
        for field, value in (("repository", "evil/camofox-browser"), ("revision", "latest"),
                             ("release", "v1.18.0")):
            changed = copy.deepcopy(policy)
            changed["source"][field] = value
            with self.assertRaisesRegex(ValueError, "source"):
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
    def test_cli_defaults_to_staged_policy_path(self):
        from unittest.mock import patch
        verifier = self.verifier()
        policy = json.loads((HERE / "policy.json").read_text())
        with patch.object(sys, "argv", ["verify_image.py"]), \
             patch.object(verifier, "Path", return_value=HERE / "policy.json") as path, \
             patch.object(verifier, "verify", return_value={"verified": True}) as verify, \
             patch("builtins.print"):
            self.assertEqual(verifier.main(), 0)
            path.assert_called_once_with("/usr/local/share/camofox-build/policy.json")
            verify.assert_called_once_with(policy, None)

    def test_staged_helpers_load_under_isolated_python(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for source in (HERE / "build_overlay.py", HERE / "policy.json", HERE / "tests/verify_image.py"):
                shutil.copyfile(source, root / source.name)
            result = subprocess.run([sys.executable, "-B", "-I", str(root / "verify_image.py"),
                                     "--python-inventory"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("runtime_version", json.loads(result.stdout))
            staged = load("staged_verifier", root / "verify_image.py")
            staged.overlay_module().validate_policy(json.loads((root / "policy.json").read_text()))
            self.assertFalse((root / "evidence.json").exists())

    def test_cli_verifies_source_build_without_overlay_evidence(self):
        from unittest.mock import patch
        verifier = self.verifier()
        policy = json.loads((HERE / "policy.json").read_text())
        with patch.object(sys, "argv", ["verify_image.py", "--policy", str(HERE / "policy.json")]), \
             patch.object(verifier, "verify", return_value={"verified": True}) as verify, \
             patch("builtins.print"):
            self.assertEqual(verifier.main(), 0)
            verify.assert_called_once_with(policy, None)

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


if __name__ == "__main__":
    unittest.main()
