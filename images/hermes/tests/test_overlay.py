"""Unit checks for the minimal manifest override; no containers or installs."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "build_overlay.py"


class ManifestOverrideTests(unittest.TestCase):
    def load(self):
        self.assertTrue(MODULE.is_file(), "the manifest-override implementation is missing")
        spec = importlib.util.spec_from_file_location("hermes_build_overlay", MODULE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def load_verify(self):
        path = Path(__file__).with_name("verify_image.py")
        spec = importlib.util.spec_from_file_location("hermes_verify_image", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_accepts_actual_native_decoder_error_string(self):
        self.load_verify().require_native_patch_marker(b"_ERROR_FORMAT_BLOCK_SWITCH")

    def test_rejects_an_unknown_native_decoder_error(self):
        for marker in (None, b"INVALID", b"_ERROR_FORMAT_PADDING_1"):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, "patch marker"):
                self.load_verify().require_native_patch_marker(marker)

    def test_overlay_never_recreates_environment_or_assembles_application(self):
        import ast
        tree = ast.parse(MODULE.read_text())
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                calls.append(ast.unparse(node.func))
        self.assertNotIn("shutil.rmtree", calls)
        self.assertNotIn("build_environment", calls)
        self.assertNotIn("docker.build_agent", MODULE.read_text())

    def test_extracts_hash_locked_brotli_requirement_only(self):
        lock = ('[[package]]\nname = "brotlicffi"\nversion = "1.2.1.0"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
                'wheels = [{hash = "sha256:' + 'a' * 64 + '"}]\n')
        self.assertEqual(self.load().locked_brotli_requirement(lock, "1.2.1.0"),
                         "brotlicffi==1.2.1.0 --hash=sha256:" + "a" * 64 + "\n")

    def test_snapshot_detects_unrelated_changes_but_ignores_brotli(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "agent.py").write_text("original")
            (root / ".venv/lib/python3.14/site-packages/brotlicffi").mkdir(parents=True)
            package = root / ".venv/lib/python3.14/site-packages/brotlicffi/__init__.py"
            package.write_text("old")
            snapshot = self.load().preserved_snapshot
            before = snapshot(root)
            package.write_text("fixed")
            self.assertEqual(before, snapshot(root))
            (root / "agent.py").write_text("changed")
            self.assertNotEqual(before, snapshot(root))

    def shipped_tree(self, root):
        paths = (
            "manifest.json", "install-stamp.json", "run_agent.py", "libexec/hermes",
            ".venv/pyvenv.cfg", "hermes_cli/web_dist/index.html",
            "hermes_cli/tui_dist/index.js", "tools/python-3.14/bin/python3",
            "tools/node-22/bin/node", ".venv/lib/python3.14/site-packages/httpx/__init__.py",
        )
        for name in paths:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("shipped " + name)
        (root / ".venv/bin").mkdir(parents=True)
        (root / ".venv/bin/python").symlink_to("../../tools/python-3.14/bin/python3")

    def test_comparison_accepts_complete_inventory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.shipped_tree(root)
            module = self.load()
            inventory = module.preserved_snapshot(root)
            module.compare_snapshots(inventory, dict(inventory))

    def test_comparison_rejects_missing_representative_coverage(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.shipped_tree(root)
            module = self.load()
            inventory = module.preserved_snapshot(root)
            for name in inventory:
                incomplete = {key: value for key, value in inventory.items() if key != name}
                for before, after in ((incomplete, incomplete), (incomplete, inventory),
                                      (inventory, incomplete)):
                    with self.subTest(missing=name, sides=(len(before), len(after))):
                        with self.assertRaisesRegex(RuntimeError, "coverage"):
                            module.compare_snapshots(before, after)

    def assert_rejects_shipped_mutation(self, relative, mutate):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.shipped_tree(root)
            module = self.load()
            before = module.preserved_snapshot(root)
            mutate(root / relative)
            with self.assertRaisesRegex(RuntimeError, "unrelated shipped files changed: " + relative):
                module.compare_snapshots(before, module.preserved_snapshot(root))

    def test_comparison_rejects_unrelated_dependency_mutation(self):
        self.assert_rejects_shipped_mutation(
            ".venv/lib/python3.14/site-packages/httpx/__init__.py",
            lambda path: path.write_text("unexpected dependency change"))

    def test_comparison_rejects_file_mode_change(self):
        self.assert_rejects_shipped_mutation("libexec/hermes", lambda path: path.chmod(0o711))

    def test_comparison_rejects_symlink_target_change(self):
        def retarget(path):
            path.unlink()
            path.symlink_to("../../tools/python-3.15/bin/python3")
        self.assert_rejects_shipped_mutation(".venv/bin/python", retarget)

    def test_compare_snapshots_cli_uses_fail_closed_comparison(self):
        import json
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.shipped_tree(root)
            inventory = self.load().preserved_snapshot(root)
            before, after = root / "before.json", root / "after.json"
            for evidence, expected in ((inventory, 0), ({}, 1)):
                before.write_text(json.dumps(evidence))
                after.write_text(json.dumps(evidence))
                result = subprocess.run(
                    [sys.executable, "-I", str(MODULE), "--compare-snapshots", str(before), str(after)],
                    capture_output=True, text=True, check=False)
                with self.subTest(empty=not evidence):
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if evidence:
                        self.assertIn(f"{len(inventory)} files", result.stdout)
                    else:
                        self.assertIn("inventory coverage is empty", result.stderr)

    def test_workflow_uses_tested_snapshot_comparison(self):
        workflow = MODULE.parents[2] / ".github/workflows/hermes-verify.yml"
        text = workflow.read_text()
        self.assertIn("python3 -I images/hermes/build_overlay.py --compare-snapshots", text)
        self.assertIn("upstream-inventory.json derived-inventory.json", text)
        self.assertNotIn("changed = sorted(name for name in before.keys()", text)

    def test_comparison_rejects_empty_inventories(self):
        with self.assertRaisesRegex(RuntimeError, "coverage.*empty"):
            self.load().compare_snapshots({}, {})

    def test_rejects_unreviewed_or_unhashed_brotli_artifacts(self):
        valid = ('[[package]]\nname = "brotlicffi"\nversion = "1.2.1.0"\n'
                 'source = { registry = "https://pypi.org/simple" }\n'
                 'wheels = [{hash = "sha256:' + 'a' * 64 + '"}]\n')
        cases = [valid.replace("1.2.1.0", "1.2.0.2"),
                 valid.replace("https://pypi.org/simple", "https://unreviewed.invalid/simple"),
                 valid.replace("sha256:" + "a" * 64, "missing"),
                 valid + valid]
        for lock in cases:
            with self.subTest(lock=lock), self.assertRaises(ValueError):
                self.load().locked_brotli_requirement(lock, "1.2.1.0")

    def test_updates_only_the_brotli_requirement(self):
        original = '[project]\nname = "example"\nversion = "1"\n[project.optional-dependencies]\nmessaging = ["aiohttp==3.14.5", "brotlicffi==1.2.0.2"]\n'
        patched, changed = self.load().rewrite_brotlicffi_pin(original, "1.2.1.0")
        self.assertTrue(changed)
        self.assertEqual(patched, original.replace("brotlicffi==1.2.0.2", "brotlicffi==1.2.1.0"))

    def test_is_idempotent(self):
        original = '[project]\ndependencies = ["brotlicffi==1.2.1.0"]\n'
        self.assertEqual(self.load().rewrite_brotlicffi_pin(original, "1.2.1.0"), (original, False))

    def test_refuses_downgrade(self):
        original = '[project]\ndependencies = ["brotlicffi==1.3.0.0"]\n'
        with self.assertRaisesRegex(ValueError, "downgrade"):
            self.load().rewrite_brotlicffi_pin(original, "1.2.1.0")

    def test_refuses_vulnerable_target(self):
        with self.assertRaisesRegex(ValueError, "fixed"):
            self.load().rewrite_brotlicffi_pin('[project]\ndependencies = ["brotlicffi==1.2.0.2"]\n', "1.2.0.2")

    def test_refuses_missing_or_ambiguous_pin(self):
        for deps in ('["requests==2.33.0"]', '["brotlicffi==1.2.0.2", "brotlicffi==1.2.0.2"]'):
            with self.subTest(deps=deps), self.assertRaisesRegex(ValueError, "exactly one"):
                self.load().rewrite_brotlicffi_pin('[project]\ndependencies = ' + deps + '\n', "1.2.1.0")

    def test_rejects_invalid_target(self):
        with self.assertRaisesRegex(ValueError, "version"):
            self.load().rewrite_brotlicffi_pin('[project]\ndependencies = ["brotlicffi==1.2.0.2"]\n', "1.2.1.0; bad")
    def test_security_exception_is_narrow(self):
        original = '[tool.uv]\nexclude-newer = "3 days"\nexclude-newer-package = { certifi = false }\n'
        updated = self.load().allow_brotli_security_release(original)
        import tomllib
        policy = tomllib.loads(updated)["tool"]["uv"]
        self.assertEqual(policy["exclude-newer"], "3 days")
        self.assertEqual(policy["exclude-newer-package"], {"certifi": False, "brotlicffi": False})
        self.assertEqual(self.load().allow_brotli_security_release(updated), updated)

    def test_does_not_add_a_policy_when_no_age_gate_exists(self):
        original = '[project]\nname = "example"\n'
        self.assertEqual(self.load().allow_brotli_security_release(original), original)

    def test_requires_review_for_an_existing_package_age_limit(self):
        original = '[tool.uv]\nexclude-newer = "3 days"\nexclude-newer-package = { brotlicffi = "5 days" }\n'
        with self.assertRaisesRegex(ValueError, "review"):
            self.load().allow_brotli_security_release(original)

    def test_lock_comparison_detects_artifact_changes(self):
        before = '[[package]]\nname = "example"\nversion = "1"\nwheels = [{url = "https://example.invalid/a.whl", hash = "sha256:abc"}]\n'
        after = before.replace("sha256:abc", "sha256:def")
        self.assertNotEqual(self.load().lock_identities(before), self.load().lock_identities(after))


if __name__ == "__main__":
    unittest.main()
